#!/usr/bin/env python3
"""End-to-end native DNS TCP through a separate peer network namespace."""
import datetime as dt
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from rahawrt.dns import answer,encode_name,exact_read


def command(args,data=None):return subprocess.run(args,input=data,text=True,capture_output=True,check=True).stdout

if len(sys.argv)>1 and sys.argv[1]=='--server':
    print(os.getpid(),flush=True)
    sys.stdin.readline()
    command(['ip','link','set','dns_peer','up']);command(['ip','link','set','lo','up'])
    command(['ip','addr','add','198.51.100.2/24','dev','dns_peer'])
    command(['ip','link','set','wan_peer','up']);command(['ip','addr','add','192.0.2.2/24','dev','wan_peer'])
    command(['ip','route','add','default','dev','dns_peer'])
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);server.bind(('0.0.0.0',5310));server.listen()
        print('ready',flush=True)
        while True:
            client,_=server.accept()
            with client:
                client.settimeout(3)
                try:
                    length=struct.unpack('!H',exact_read(client,2))[0];query=exact_read(client,length)
                    record=b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+socket.inet_aton('203.0.113.77')
                    reply=answer(query,records=[record]);client.sendall(struct.pack('!H',len(reply))+reply)
                except (OSError,ValueError):pass
    sys.exit(0)
if len(sys.argv)==1:
    sys.exit(subprocess.run(['unshare','-Urn',sys.executable,__file__,'--child',os.readlink('/proc/self/ns/net')]).returncode)
if len(sys.argv)!=3 or sys.argv[1]!='--child' or os.readlink('/proc/self/ns/net')==sys.argv[2]:sys.exit('Refusing parent network namespace')

from rahawrt.store import Store
from rahawrt.changes import ChangeGuard
from rahawrt.routes import Routes
from rahawrt.native_dns import exchange

peer=subprocess.Popen(['unshare','-n',sys.executable,__file__,'--server'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
try:
    pid=int(peer.stdout.readline())
    command(['ip','link','add','rv_dns','type','veth','peer','name','dns_peer'])
    command(['ip','link','set','dns_peer','netns',str(pid)])
    command(['ip','link','set','lo','up']);command(['ip','link','set','rv_dns','up'])
    command(['ip','addr','add','10.8.0.1/32','dev','rv_dns'])
    command(['ip','link','add','wan','type','veth','peer','name','wan_peer']);command(['ip','link','set','wan','up'])
    command(['ip','addr','add','192.0.2.1/24','dev','wan']);command(['ip','route','add','default','dev','wan'])
    command(['ip','link','set','wan_peer','netns',str(pid)])
    peer.stdin.write('go\n');peer.stdin.flush()
    if peer.stdout.readline().strip()!='ready':raise RuntimeError('native DNS peer failed to start')
    binary=ROOT/'.local/tools/usr/sbin/nft'
    nft=['/lib64/ld-linux-x86-64.so.2','--library-path',str(ROOT/'.local/tools/usr/lib/x86_64-linux-gnu'),str(binary)] if binary.exists() else ['nft']
    # Model PassWall2's documented group bypass in the namespace's mapped GID 0.
    # A socket not matching it would be rejected by the stand-in global proxy rule.
    command(nft+['-f','-'],'table inet passwall2 {\nchain mangle_output { type route hook output priority -151; policy accept; meta skgid 0 return; tcp dport 5310 drop; }\nchain nat_output { type nat hook output priority -1; policy accept; meta skgid 0 return; tcp dport 5310 redirect to :5555; }\n}\n')
    store=Store(':memory:');ChangeGuard(store,command)
    with store.db:
        store.db.execute("INSERT INTO router_changes VALUES ('dns','vpn','{}','',0,'confirmed',NULL,'test')")
        store.db.execute("INSERT INTO tunnels VALUES ('rv_dns','wireguard','dns','{}')")
    def runner(args,data=None):
        if args[0]=='ubus':return json.dumps(dict(up=True,l3_device='rv_dns'))
        return command(args,data)
    routes=Routes(store,runner)
    from rahawrt.policy import device
    d=device(dict(id='test',ip='192.0.2.10',mac='02:00:00:00:00:10',node='direct',tunnel='rv_dns'))
    prepared=routes.prepare([d],dt.datetime.now());desired=routes.desired(prepared);routes.sync(desired);state=desired['test']
    query=struct.pack('!6H',1200,0x100,1,0,0,0)+encode_name('example.com')+struct.pack('!HH',1,1)
    response=exchange(query,'rv_dns',state['mark'],('198.51.100.2',5310))
    assert response[:2]==query[:2] and socket.inet_aton('203.0.113.77') in response
    # Exercise the same worker executable used by production's private GID wrapper.
    result=subprocess.run([sys.executable,'-m','rahawrt.native_dns','--interface','rv_dns','--mark',str(state['mark']),'--server','198.51.100.2','--port','5310'],input=query,capture_output=True,check=True,cwd=ROOT)
    assert socket.inet_aton('203.0.113.77') in result.stdout and not result.stderr
    command(['ip','link','set','rv_dns','down'])
    try:exchange(query,'rv_dns',state['mark'],('198.51.100.2',5310));raise AssertionError('DNS did not close after tunnel failure')
    except OSError:pass
    direct=exchange(query,None,None,('192.0.2.2',5310))
    assert socket.inet_aton('203.0.113.77') in direct,'direct DNS did not use the WAN path independently of the down tunnel'
    result=subprocess.run([sys.executable,'-m','rahawrt.native_dns','--direct','--server','192.0.2.2','--port','5310'],input=query,capture_output=True,check=True,cwd=ROOT)
    assert result.stdout[:2]==query[:2] and not result.stderr
    routes.sync({});store.db.close()
    print('PASS: marked, interface-bound native DNS reached a separate peer namespace through the owned route; worker framing, tunnel-down closure and independent direct/WAN DNS passed.')
finally:
    peer.terminate()
    try:peer.communicate(timeout=4)
    except subprocess.TimeoutExpired:peer.kill();peer.communicate()
