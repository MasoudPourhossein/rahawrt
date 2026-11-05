#!/usr/bin/env python3
"""Real host-built uhttpd HTTPS/CGI; router adapters are fixtures, not firmware."""
import http.client
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
if len(sys.argv)==1:
    sys.exit(subprocess.run(['unshare','-Urn',sys.executable,__file__,'--child',os.readlink('/proc/self/ns/net')]).returncode)
if len(sys.argv)!=3 or sys.argv[1]!='--child' or os.readlink('/proc/self/ns/net')==sys.argv[2]:sys.exit('Refusing parent network namespace')
from rahawrt.store import Store
from rahawrt.runtime import Runtime
from rahawrt.server import Server
from rahawrt.policy import device


def command(args):return subprocess.run(args,check=True,capture_output=True,text=True).stdout
command(['ip','link','set','lo','up'])
for address in ('192.168.1.1/24','192.168.1.20/24','192.168.50.1/24','192.168.50.10/24'):command(['ip','addr','add',address,'dev','lo'])
spec=importlib.util.spec_from_file_location('builder',ROOT/'scripts/build-ipk.py');builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)

with tempfile.TemporaryDirectory(prefix='rahawrt-uhttpd-') as temporary:
    temporary=Path(temporary);roots={};children=[];backend=None;thread=None;store=Store(':memory:')
    password=secrets.token_urlsafe(24);guest_password=secrets.token_urlsafe(24)
    store.account('owner',password,'admin')
    store.put_device(device(dict(id='guest',ip='192.168.50.10',mac='02:00:00:00:50:10',hotspot=True)))
    store.account('guest',guest_password,'user','guest')
    key=store.create_key(dict(scopes=['usage:read']),'owner')['token']
    for label in ('admin','guest'):
        root=temporary/label;roots[label]=root
        prefix='usr/share/rahawrt/public/'
        for name,(data,mode) in builder.payload().items():
            if not name.startswith(prefix):continue
            path=root/name[len(prefix):];path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);path.chmod(mode)
    (roots['admin']/'admin-only.txt').write_text('ADMIN_ONLY_FIXTURE');(roots['admin']/'admin-only.txt').chmod(0o644)
    cgi_config=temporary/'guest.httpd.conf';cgi_config.write_bytes(builder.payload()['usr/share/rahawrt/guest.httpd.conf'][0])
    cert,keyfile=temporary/'cert.pem',temporary/'key.pem'
    command(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(keyfile),'-out',str(cert),'-days','1','-subj','/CN=RahaWRT test fixture','-addext','subjectAltName=IP:192.168.1.1,IP:192.168.50.1'])
    keyfile.chmod(0o600)
    context=ssl.create_default_context(cafile=str(cert))
    runtime=Runtime(store,True,lambda *args:'')
    runtime.guest.settings=lambda:dict(network='192.168.50.0/24',gateway='192.168.50.1',portal_host='192.168.50.1',portal_port=8443,interface='br-rahaguest')
    runtime.clients=lambda:[dict(ip='192.168.50.10',mac='02:00:00:00:50:10',name='Guest',expires='0')]
    env=dict(os.environ);env['LD_LIBRARY_PATH']=str(ROOT/'.local/uhttpd-tools/lib')+':'+str(ROOT/'.local/tools/usr/lib/x86_64-linux-gnu')+(':'+env['LD_LIBRARY_PATH'] if env.get('LD_LIBRARY_PATH') else '')
    log=(temporary/'uhttpd.log').open('wb')
    def request(path,method='GET',data=None,source='192.168.1.20',guest=False,secure=True,token=None,headers=None,tls=None):
        host='192.168.50.1' if guest else '192.168.1.1';port=8443 if guest else (18443 if secure else 18080)
        options=dict(timeout=8,source_address=(source,0))
        client=http.client.HTTPSConnection(host,port,context=tls or context,**options) if secure else http.client.HTTPConnection(host,port,**options)
        sent={'Content-Type':'application/json','X-RahaWRT-Request':'1','X-HTTP-Method-Override':method,**(headers or {})}
        if token:sent['Authorization']='Bearer '+token
        client.request(method,path,json.dumps(data) if data is not None else None,sent)
        result=client.getresponse();status=result.status;received=dict(result.getheaders());body=result.read();client.close()
        return status,received,body
    api='/cgi-bin/rahawrt/wrt/api/v1/'
    try:
        backend=Server(('127.0.0.1',9080),store,runtime,ROOT/'web',trusted_cgi=True)
        thread=threading.Thread(target=backend.serve_forever,daemon=True);thread.start()
        executable=ROOT/'.local/uhttpd-tools/bin/uhttpd'
        for label in ('admin','guest'):
            listen=['-s','192.168.50.1:8443'] if label=='guest' else ['-p','192.168.1.1:18080','-s','192.168.1.1:18443']
            children.append(subprocess.Popen([str(executable),'-f','-c',str(cgi_config),'-h',str(roots[label]),'-x','/cgi-bin','-D','-S','-n','8','-N','32','-t','30','-T','10','-C',str(cert),'-K',str(keyfile),*listen],env=env,stdout=log,stderr=log))
        deadline=time.monotonic()+8
        while True:
            try:
                status,_,body=request('/wrt/')
                if status==200:break
            except (OSError,ssl.SSLError):pass
            if any(p.poll() is not None for p in children):raise RuntimeError('uhttpd exited before HTTPS readiness')
            if time.monotonic()>deadline:raise RuntimeError('uhttpd HTTPS readiness timeout')
            time.sleep(.05)
        assert b'dir="rtl"' in body
        try:request('/wrt/',tls=ssl.create_default_context())
        except ssl.SSLCertVerificationError:pass
        else:raise AssertionError('untrusted certificate was accepted')
        status,headers,body=request(api+'login','POST',dict(name='owner',password=password));assert status==200,'TLS CGI admin login failed'
        parsed=json.loads(body)
        if 'token' not in parsed:raise RuntimeError('CGI response keys='+str(list(parsed))+' error='+str(parsed.get('error'))+' headers='+str({k:v for k,v in headers.items() if k.lower()!='set-cookie'}))
        token=parsed['token'];cookie=headers.get('Set-Cookie','')
        assert all(flag in cookie for flag in ('Secure','HttpOnly','SameSite=Strict')),'secure cookie attributes missing'
        assert request(api+'me',token=token)[0]==200
        assert request(api+'login','POST',dict(name='owner',password=password),headers={'X-HTTP-Method-Override':''})[0]==403,'missing forwarded request marker accepted'
        assert request(api+'login','POST',dict(name='owner',password=password),secure=False,headers={'X-RahaWRT-HTTPS':'on'})[0]==403,'HTTP TLS-header spoof accepted'
        spoof={'X-RahaWRT-Client':'192.168.1.20','X-RahaWRT-HTTPS':'on'}
        common=dict(source='192.168.50.10',guest=True,headers=spoof)
        status,_,body=request(api+'captive',**common);captive=json.loads(body)
        assert status==200 and captive['guest'] and captive['captive'] and ':8443/wrt/' in captive['user-portal-url'],'CGI source was spoofed'
        assert request(api+'login','POST',dict(name='owner',password=password),**common)[0]==403,'guest privilege login accepted'
        assert request(api+'reports',token=key,**common)[0]==403,'guest accounting key accepted'
        assert request(api+'me',token=token,**common)[0] in (401,403),'guest admin session replay accepted'
        assert request('/admin-only.txt')[0]==200
        for path in ('/admin-only.txt','/cgi-bin/luci','/ubus'):
            assert request(path,**common)[0]==404,'guest docroot exposed management fixture'
        assert request('/',**common)[0]==403,'guest directory listing enabled'
        status,_,body=request(api+'login','POST',dict(name='guest',password=guest_password),**common);assert status==200,'guest TLS login failed'
        guest_token=json.loads(body)['token']
        assert json.loads(request(api+'me',token=guest_token,**common)[2])['role']=='user'
        assert request(api+'reports?period=monthly&format=csv',token=guest_token,**common)[1]['Content-Type'].startswith('text/csv'),'CGI query string lost'
        assert request(api+'logout','POST',{},token=guest_token,**common)[0]==200
        assert request(api+'me',token=guest_token,**common)[0]==401
        print('PASS: real uhttpd/OpenSSL HTTPS and packaged CGI: verified fixture TLS, untrusted-cert rejection, secure cookies, login/logout, query forwarding, spoofed source/TLS headers refused, guest role/key isolation and separate document roots.')
        print('Host-built exact upstream sources in a disposable network namespace; no OpenWrt firmware, netifd/procd or real PassWall2 daemon claim.')
    finally:
        for child in children:
            child.terminate()
            try:child.wait(timeout=4)
            except subprocess.TimeoutExpired:child.kill();child.wait()
        if backend:backend.shutdown();backend.server_close()
        if thread:thread.join(timeout=3)
        store.db.close();log.close()
