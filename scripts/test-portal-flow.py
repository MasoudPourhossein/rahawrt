#!/usr/bin/env python3
"""Real guest veth -> policy DNS/captive HTTP -> uhttpd TLS/CGI -> WAN gate.

DHCP/router settings and upstream DNS are fixtures. No firmware or PassWall core.
"""
import http.client
import importlib.util
import json
import os
from pathlib import Path
import secrets
import select
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler,HTTPServer

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from rahawrt.dns import DNSServer,Resolver,answer,encode_name,exact_read,question


def command(args,data=None):return subprocess.run(args,input=data,text=True,capture_output=True,check=True).stdout

if len(sys.argv)>1 and sys.argv[1]=='--wan':
    print(os.getpid(),flush=True);sys.stdin.readline()
    command(['ip','link','set','lo','up']);command(['ip','link','set','wan_peer','up'])
    command(['ip','addr','add','198.51.100.2/24','dev','wan_peer']);command(['ip','route','add','default','via','198.51.100.1'])
    class WAN(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            data=b'INTERNET_FIXTURE';self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    server=HTTPServer(('198.51.100.2',8080),WAN);print('ready',flush=True);server.serve_forever();sys.exit(0)

if len(sys.argv)>1 and sys.argv[1]=='--client':
    print(os.getpid(),flush=True);settings=json.loads(sys.stdin.readline())
    command(['ip','link','set','lo','up']);command(['ip','link','set','guest_peer','up'])
    command(['ip','addr','add','192.168.50.10/24','dev','guest_peer']);command(['ip','route','add','default','via','192.168.50.1'])
    context=ssl.create_default_context(cadata=settings['ca'])
    def dns(name,tcp=False):
        data=struct.pack('!6H',1234,0x100,1,0,0,0)+encode_name(name)+struct.pack('!HH',1,1)
        if tcp:
            with socket.create_connection(('192.168.50.1',53),timeout=3) as stream:
                stream.sendall(struct.pack('!H',len(data))+data);size=struct.unpack('!H',exact_read(stream,2))[0];result=exact_read(stream,size)
        else:
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as stream:
                stream.settimeout(3);stream.sendto(data,('192.168.50.1',53));result,_=stream.recvfrom(4096)
        assert result[:2]==data[:2]
        return result
    def request(path,method='GET',body=None,token=None):
        # Use the actual policy DNS result, retaining hostname verification/SNI.
        address=socket.inet_ntoa(dns('portal.test')[-4:])
        transport=socket.create_connection((address,8443),timeout=4)
        connection=http.client.HTTPConnection('portal.test',8443,timeout=4)
        connection.sock=context.wrap_socket(transport,server_hostname='portal.test')
        headers={'Content-Type':'application/json','X-RahaWRT-Request':'1','X-HTTP-Method-Override':method}
        if token:headers['Authorization']='Bearer '+token
        connection.request(method,path,json.dumps(body) if body is not None else None,headers)
        response=connection.getresponse();status=response.status;result=response.read();connection.close();return status,result
    def internet_allowed(expected):
        try:
            connection=http.client.HTTPConnection('198.51.100.2',8080,timeout=.7);connection.request('GET','/')
            response=connection.getresponse();allowed=response.status==200 and response.read()==b'INTERNET_FIXTURE';connection.close()
        except (OSError,http.client.HTTPException):allowed=False
        assert allowed==expected,'guest WAN gate differs from account state'
    probe=dns('captive.apple.com');assert socket.inet_ntoa(probe[-4:])=='192.168.50.1','closed probe DNS did not reach guest gateway'
    assert dns('ordinary.example')[3]&15==5,'pre-login upstream DNS opened'
    assert socket.inet_ntoa(dns('portal.test',tcp=True)[-4:])=='192.168.50.1','pre-login TCP portal DNS failed'
    connection=http.client.HTTPConnection('192.168.50.1',80,timeout=3);connection.request('GET','/hotspot-detect.html',headers={'Host':'captive.apple.com'})
    response=connection.getresponse();assert response.status==302 and response.getheader('Location')=='https://portal.test:8443/wrt/';response.read();connection.close()
    internet_allowed(False)
    assert request('/wrt/')[0]==200
    api='/cgi-bin/rahawrt/wrt/api/v1/'
    status,body=request(api+'login','POST',dict(name='guest',password=settings['password']));assert status==200,'real guest TLS login failed'
    token=json.loads(body)['token'];print('logged-in',flush=True);sys.stdin.readline()
    assert socket.inet_ntoa(dns('captive.apple.com')[-4:])=='198.51.100.2','authenticated probe DNS remained captive'
    internet_allowed(True)
    assert json.loads(request(api+'me',token=token)[1])['role']=='user'
    assert request(api+'logout','POST',{},token)[0]==200
    print('logged-out',flush=True);sys.stdin.readline()
    internet_allowed(False)
    assert socket.inet_ntoa(dns('captive.apple.com')[-4:])=='192.168.50.1'
    assert request('/wrt/')[0]==200,'closed account lost its portal'
    assert request(api+'me',token=token)[0]==401
    print('passed',flush=True);sys.exit(0)

if len(sys.argv)==1:
    sys.exit(subprocess.run(['unshare','-Urn',sys.executable,__file__,'--child',os.readlink('/proc/self/ns/net')]).returncode)
if len(sys.argv)!=3 or sys.argv[1]!='--child' or os.readlink('/proc/self/ns/net')==sys.argv[2]:sys.exit('Refusing parent network namespace')
from rahawrt.store import Store
from rahawrt.runtime import Runtime
from rahawrt.server import Server
from rahawrt.policy import compile_nft,device
from rahawrt.portal import PortalServer

command(['ip','link','set','lo','up']);Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
peers=[];services=[];threads=[];uhttpd=None;backend=None;store=Store(':memory:');exists=False
binary=ROOT/'.local/tools/usr/sbin/nft';NFT=['/lib64/ld-linux-x86-64.so.2','--library-path',str(ROOT/'.local/tools/usr/lib/x86_64-linux-gnu'),str(binary)] if binary.exists() else ['nft']
def runner(args,data=None):
    if args[0]=='nft':return command(NFT+args[1:],data)
    raise AssertionError('unexpected fixture router operation')
def phase(process,expected):
    if not select.select([process.stdout],[],[],15)[0]:raise RuntimeError('guest fixture phase timed out')
    if process.stdout.readline().strip()!=expected:raise RuntimeError('guest fixture failed at phase '+expected)
try:
    for mode,left,right in (('--wan','wan','wan_peer'),('--client','br-rahaguest','guest_peer')):
        process=subprocess.Popen(['unshare','-n',sys.executable,__file__,mode],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);peers.append(process)
        pid=int(process.stdout.readline());command(['ip','link','add',left,'type','veth','peer','name',right])
        if mode=='--client':command(['ip','link','set',right,'address','02:00:00:00:50:10'])
        command(['ip','link','set',right,'netns',str(pid)]);command(['ip','link','set',left,'up'])
        command(['ip','addr','add','198.51.100.1/24' if mode=='--wan' else '192.168.50.1/24','dev',left])
    wan,client=peers;wan.stdin.write('go\n');wan.stdin.flush();phase(wan,'ready')
    settings=dict(network='192.168.50.0/24',gateway='192.168.50.1',interface='br-rahaguest',portal_host='portal.test',portal_port=8443)
    password=secrets.token_urlsafe(24)
    store.put_device(device(dict(id='guest',ip='192.168.50.10',mac='02:00:00:00:50:10',hotspot=True)))
    store.account('guest',password,'user','guest')
    runtime=Runtime(store,True,runner);runtime.guest.settings=lambda:settings
    runtime.clients=lambda:[dict(ip='192.168.50.10',mac='02:00:00:00:50:10',name='Guest',expires='0')]
    queries=[]
    def upstream(data):
        queries.append(question(data)[1]);record=b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+socket.inet_aton('198.51.100.2');return answer(data,records=[record])
    resolver=Resolver(store,store.parental,transport=upstream,local_records=lambda:{'portal.test':'192.168.50.1'},captive_portal=lambda:settings)
    services=[DNSServer(('0.0.0.0',1053),resolver),PortalServer(('0.0.0.0',2080),lambda:settings)]
    for service in services:service.start()
    backend=Server(('127.0.0.1',9080),store,runtime,ROOT/'web',trusted_cgi=True)
    thread=threading.Thread(target=backend.serve_forever,daemon=True);threads.append(thread);thread.start()
    def apply():
        global exists
        if exists:runtime.sample()
        source=compile_nft(store.effective_devices(),store.usage(),store.online(),local_ips=['127.0.0.1','192.168.50.1','198.51.100.1'],guest=settings)
        command(NFT+['-f','-'],('delete table inet rahawrt\n' if exists else '')+source);exists=True
    with tempfile.TemporaryDirectory(prefix='rahawrt-portal-flow-') as temporary:
        temporary=Path(temporary);public=temporary/'public';spec=importlib.util.spec_from_file_location('builder',ROOT/'scripts/build-ipk.py');builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
        for name,(data,mode) in builder.payload().items():
            prefix='usr/share/rahawrt/public/'
            if name.startswith(prefix):
                path=public/name[len(prefix):];path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);path.chmod(mode)
        cert,key=temporary/'cert.pem',temporary/'key.pem'
        command(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=portal.test','-addext','subjectAltName=DNS:portal.test'])
        config=temporary/'httpd.conf';config.write_bytes(builder.payload()['usr/share/rahawrt/guest.httpd.conf'][0])
        env=dict(os.environ);env['LD_LIBRARY_PATH']=str(ROOT/'.local/uhttpd-tools/lib')+':'+str(ROOT/'.local/tools/usr/lib/x86_64-linux-gnu')
        with (temporary/'uhttpd.log').open('wb') as log:
            uhttpd=subprocess.Popen([str(ROOT/'.local/uhttpd-tools/bin/uhttpd'),'-f','-c',str(config),'-h',str(public),'-s','192.168.50.1:8443','-C',str(cert),'-K',str(key),'-x','/cgi-bin','-D','-S'],env=env,stdout=log,stderr=log)
            deadline=time.monotonic()+5
            while True:
                try:
                    with socket.create_connection(('192.168.50.1',8443),timeout=.2):break
                except OSError:
                    if time.monotonic()>deadline:raise RuntimeError('uhttpd listener readiness failed')
                    time.sleep(.03)
            apply();client.stdin.write(json.dumps(dict(password=password,ca=cert.read_text()))+'\n');client.stdin.flush()
            phase(client,'logged-in');assert queries==[],'closed guest sent DNS upstream';apply();client.stdin.write('go\n');client.stdin.flush()
            phase(client,'logged-out');apply();assert sum(store.usage()['guest'])>0,'real guest traffic missed SQLite accounting';client.stdin.write('go\n');client.stdin.flush()
            phase(client,'passed');assert client.wait(timeout=3)==0
            print('PASS: separate real guest/WAN namespaces: closed probe DNS stays local, UDP/TCP portal DNS, captive HTTP redirect, verified uhttpd TLS/CGI login, authenticated WAN traffic and SQLite accounting, logout closure with portal retained.')
            print('DHCP/router settings/upstream DNS are fixtures; direct-node policy only, no firmware or PassWall2/core/hardware claim.')
finally:
    if uhttpd:
        uhttpd.terminate()
        try:uhttpd.wait(timeout=4)
        except subprocess.TimeoutExpired:uhttpd.kill();uhttpd.wait()
    if backend:backend.shutdown();backend.server_close()
    for service in services:service.close()
    for thread in threads:thread.join(timeout=3)
    for process in peers:
        if process.poll() is None:process.terminate()
        try:process.communicate(timeout=3)
        except subprocess.TimeoutExpired:process.kill();process.communicate()
    store.db.close()
