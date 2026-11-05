#!/usr/bin/env python3
"""Packet-path tests in a fresh namespace; no host interfaces are touched."""
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from rahawrt.policy import compile_nft,device

if len(sys.argv)==1:
    sys.exit(subprocess.run(['unshare','-Urn',sys.executable,__file__,'--child',os.readlink('/proc/self/ns/net')]).returncode)
if len(sys.argv)!=3 or sys.argv[1]!='--child' or os.readlink('/proc/self/ns/net')==sys.argv[2]:
    sys.exit('Refusing to use the parent network namespace')

def command(argv,source=None):
    result=subprocess.run(argv,input=source,text=True,capture_output=True)
    if result.returncode:raise RuntimeError(result.stderr)
    return result.stdout

binary=ROOT/'.local/tools/usr/sbin/nft'
NFT=['/lib64/ld-linux-x86-64.so.2','--library-path',str(ROOT/'.local/tools/usr/lib/x86_64-linux-gnu'),str(binary)] if binary.exists() else ['nft']
def nft(args,source=None):return command(NFT+args,source)
def ip(*args):return command(['ip',*args])

macs={'lan':'02:00:00:00:01:01','client':'02:00:00:00:01:10','wan':'02:00:00:00:02:01','server':'02:00:00:00:02:02'}
for left,right in (('lan','client'),('wan','server')):
    ip('link','add',left,'type','veth','peer','name',right)
    for name in (left,right):ip('link','set',name,'address',macs[name],'up')
ip('link','set','lo','up')
ip('addr','add','192.0.2.1/24','dev','lan');ip('addr','add','198.51.100.1/24','dev','wan')
ip('neigh','add','192.0.2.10','lladdr',macs['client'],'dev','lan','nud','permanent')
ip('neigh','add','198.51.100.2','lladdr',macs['server'],'dev','wan','nud','permanent')
Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
# Peer endpoints are raw test devices, not routers. Prevent looping a captured packet.
nft(['-f','-'],'table inet test_endpoints { chain ingress { type filter hook prerouting priority -400; policy accept; iifname { "client", "server" } drop; }\n}\n')
sockets={}
for name in ('client','server'):
    s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800));s.bind((name,0));s.settimeout(.15);s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,2**20);sockets[name]=s

def mac(value):return bytes.fromhex(value.replace(':',''))
def checksum(data):
    values=struct.unpack('!'+str(len(data)//2)+'H',data);total=sum(values)
    while total>>16:total=(total&65535)+(total>>16)
    return (~total)&65535

def frame(source='192.0.2.10',dest='198.51.100.2',source_mac=None,marker=b'RAHA_PACKET',size=200,dest_mac=None,source_port=49000,dest_port=443):
    payload=marker+b'x'*size
    udp=struct.pack('!HHHH',source_port,dest_port,8+len(payload),0)+payload
    header=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),1,0,64,17,0,socket.inet_aton(source),socket.inet_aton(dest))
    header=header[:10]+struct.pack('!H',checksum(header))+header[12:]
    return mac(dest_mac or macs['lan'])+mac(source_mac or macs['client'])+b'\x08\x00'+header+udp

def tcp_frame(source_port=49123):
    source,dest='192.0.2.10','198.51.100.2'
    payload=b'CAPTIVE_SYN'
    tcp=struct.pack('!HHIIBBHHH',source_port,80,1,0,5<<4,2,4096,0,0)+payload
    pseudo=socket.inet_aton(source)+socket.inet_aton(dest)+struct.pack('!BBH',0,6,len(tcp))
    padded=pseudo+tcp+(b'\0' if len(tcp)%2 else b'')
    tcp=tcp[:16]+struct.pack('!H',checksum(padded))+tcp[18:]
    header=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp),123,0,64,6,0,socket.inet_aton(source),socket.inet_aton(dest))
    header=header[:10]+struct.pack('!H',checksum(header))+header[12:]
    return mac(macs['lan'])+mac(macs['client'])+b'\x08\x00'+header+tcp

def drain(name):
    try:
        while True:sockets[name].recv(65536)
    except socket.timeout:pass

def received(name,marker):
    count=0
    try:
        while True:
            if marker in sockets[name].recv(65536):count+=1
    except socket.timeout:return count

exists=False
def policy(d,usage=None,guest=None):
    global exists
    rules=compile_nft([d] if d else [],usage or {},set(),local_ips=['192.0.2.1','198.51.100.1'],guest=guest)
    nft(['-f','-'],('delete table inet rahawrt\n' if exists else '')+rules)
    exists=True
    drain('server');drain('client')

def send(marker,count=1,**kw):
    packet=frame(marker=marker,**kw)
    for _ in range(count):sockets['client'].send(packet)

base=device(dict(id='client',ip='192.0.2.10',mac=macs['client'],node='direct'))
try:
    policy(base);send(b'BASELINE');assert received('server',b'BASELINE')>=1,'baseline routing broken'
    counters=json.loads(nft(['-j','list','table','inet','rahawrt']))
    up=sum(e['counter']['bytes'] for x in counters['nftables'] if x.get('rule',{}).get('comment')=='rw:client:up' for e in x['rule']['expr'] if isinstance(e.get('counter'),dict))
    assert up>=228,'upload accounting missed real packet'
    policy(dict(base,quota_bytes=100),{'client':[100,0]});send(b'QUOTA');assert received('server',b'QUOTA')==0,'quota bypass'
    policy(dict(base,node='node_a'));send(b'TUNNEL_DOWN');assert received('server',b'TUNNEL_DOWN')==0,'VPN-only forwarded leak'
    policy(dict(base,node='node_a',vpn_failure='direct'));send(b'EXPLICIT_DIRECT');assert received('server',b'EXPLICIT_DIRECT')>=1,'explicit forwarding failed'
    policy(base);send(b'WRONG_MAC',source_mac='02:00:00:00:01:11');assert received('server',b'WRONG_MAC')==0,'MAC binding bypass'
    policy(dict(base,hotspot=True));send(b'NO_LOGIN');assert received('server',b'NO_LOGIN')==0,'unauthenticated hotspot bypass'
    policy(dict(base,blocked_ips=['198.51.100.0/24']));send(b'PARENTAL');assert received('server',b'PARENTAL')==0,'parental IP block bypass'
    policy(None,guest=dict(network='192.0.2.0/24',interface='lan'));send(b'UNKNOWN_GUEST');assert received('server',b'UNKNOWN_GUEST')==0,'unregistered guest bypass'
    policy(base);send(b'RATE_BASELINE',count=32,size=1000);baseline=received('server',b'RATE_BASELINE');assert baseline>=20,baseline
    policy(dict(base,upload_kbps=1));send(b'RATE_CAP',count=32,size=1000);limited=received('server',b'RATE_CAP');assert limited<5,(baseline,limited)
    policy(base)
    for _ in range(32):sockets['server'].send(frame(source='198.51.100.2',dest='192.0.2.10',source_mac=macs['server'],dest_mac=macs['wan'],source_port=443,dest_port=49000,marker=b'DOWN_BASE',size=1000))
    down_base=received('client',b'DOWN_BASE');assert down_base>=20,down_base
    policy(dict(base,download_kbps=1))
    for _ in range(32):sockets['server'].send(frame(source='198.51.100.2',dest='192.0.2.10',source_mac=macs['server'],dest_mac=macs['wan'],source_port=443,dest_port=49000,marker=b'DOWN_CAP',size=1000))
    down_cap=received('client',b'DOWN_CAP');assert down_cap<5,(down_base,down_cap)
    group=[]
    for i in range(16):
        d=device(dict(id='group'+str(i),ip='192.0.2.'+str(10+i),mac='02:00:00:00:01:'+format(16+i,'02x'),node='direct'))
        d['_account_limit']=dict(id='shared_hotel',upload_kbps=1,download_kbps=0);group.append(d)
    nft(['-f','-'],'delete table inet rahawrt\n'+compile_nft(group,{},set(),local_ips=['192.0.2.1','198.51.100.1']))
    drain('server')
    for d in group:sockets['client'].send(frame(source=d['ip'],source_mac=d['mac'],marker=b'ACCOUNT_SHARED',size=1000))
    account_packets=received('server',b'ACCOUNT_SHARED');assert account_packets<5,account_packets
    dns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);dns.bind(('0.0.0.0',1053));dns.settimeout(.3)
    try:
        policy(dict(base,_parental={'block_encrypted_dns':True}))
        send(b'DNS_CAPTURE',dest_port=53)
        payload,peer=dns.recvfrom(4096);assert b'DNS_CAPTURE' in payload and peer[0]=='192.0.2.10'
        send(b'DOT_BLOCK',dest_port=853);assert received('server',b'DOT_BLOCK')==0
        policy(dict(base,node='vpn_node',_parental={'block_encrypted_dns':True}))
        send(b'VPN_DNS_CLOSED',dest_port=53)
        payload,peer=dns.recvfrom(4096);assert b'VPN_DNS_CLOSED' in payload
        # The real DNS resolver's separate tests verify SERVFAIL without upstream
        # traffic for VPN-only profiles; here verify capture cannot reach WAN.
        assert received('server',b'VPN_DNS_CLOSED')==0
        # Pre-login portal DNS must survive OUTPUT before reverse NAT changes
        # the listener's source port 1053 back to the client's requested 53.
        guest_dns=dict(network='192.0.2.0/24',interface='lan')
        policy(dict(base,hotspot=True),guest=guest_dns)
        send(b'PORTAL_DNS_QUERY',dest='192.0.2.1',dest_port=53,source_port=49031)
        payload,peer=dns.recvfrom(4096);assert b'PORTAL_DNS_QUERY' in payload
        dns.sendto(b'PORTAL_DNS_REPLY',peer)
        assert received('client',b'PORTAL_DNS_REPLY')>=1,'pre-login portal DNS reply blocked before reverse NAT'
    finally:dns.close()
    from rahawrt.routes import Routes
    from rahawrt.store import Store
    from rahawrt.changes import ChangeGuard
    import datetime as dt
    states={}
    for suffix in ('a','b'):
        tunnel='rv_'+suffix;peer='peer_'+suffix
        ip('link','add',tunnel,'type','veth','peer','name',peer)
        ip('link','set',tunnel,'up');ip('link','set',peer,'up')
        ip('neigh','add','198.51.100.2','lladdr',macs['server'],'dev',tunnel,'nud','permanent')
        nft(['-f','-'],'add rule inet test_endpoints ingress iifname "'+peer+'" drop\n')
        sock=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800));sock.bind((peer,0));sock.settimeout(.15);sockets[peer]=sock
        states[tunnel]=dict(up=True,l3_device=tunnel)
    def router_run(argv,data=None):
        if argv[0]=='ubus':return json.dumps(states[argv[2].removeprefix('network.interface.')])
        return subprocess.run(argv,input=data,text=True,capture_output=True,check=True).stdout
    store=Store(':memory:');ChangeGuard(store,router_run);routes=Routes(store,router_run)
    with store.db:
        for suffix in ('a','b'):
            store.db.execute('INSERT INTO router_changes VALUES (?,?,?,?,?,?,?,?)',('change_'+suffix,'vpn','{}','',0,'confirmed',None,'test'))
            store.db.execute('INSERT INTO tunnels VALUES (?,?,?,?)',('rv_'+suffix,'wireguard','change_'+suffix,'{}'))
    first=device(dict(base,tunnel='rv_a'))
    second=device(dict(base,id='second',ip='192.0.2.11',mac='02:00:00:00:01:11',tunnel='rv_b'))
    selected=routes.prepare([first,second],dt.datetime.now());desired=routes.desired(selected);routes.sync(desired)
    nft(['-f','-'],'delete table inet rahawrt\n'+compile_nft(selected,{},set(),local_ips=['192.0.2.1','198.51.100.1']))
    drain('server');send(b'NATIVE_A');assert received('peer_a',b'NATIVE_A')>=1 and received('server',b'NATIVE_A')==0
    send(b'NATIVE_B',source=second['ip'],source_mac=second['mac']);assert received('peer_b',b'NATIVE_B')>=1
    # Drop an observed tunnel, retain the source rule and terminal route.
    ip('link','set','rv_a','down');states['rv_a']['up']=False
    selected=routes.prepare([first,second],dt.datetime.now());routes.sync(routes.desired(selected))
    nft(['-f','-'],'delete table inet rahawrt\n'+compile_nft(selected,{},set(),local_ips=['192.0.2.1','198.51.100.1']))
    send(b'NATIVE_CLOSED');assert received('server',b'NATIVE_CLOSED')==0
    # Explicit direct fallback removes only the affected owned source rule.
    first['vpn_failure']='direct';selected=routes.prepare([first,second],dt.datetime.now());routes.sync(routes.desired(selected))
    nft(['-f','-'],'delete table inet rahawrt\n'+compile_nft(selected,{},set(),local_ips=['192.0.2.1','198.51.100.1']))
    send(b'NATIVE_FALLBACK');assert received('server',b'NATIVE_FALLBACK')>=1
    send(b'OTHER_STILL_B',source=second['ip'],source_mac=second['mac']);assert received('peer_b',b'OTHER_STILL_B')>=1
    # Repeated reconciliation must not duplicate rules; removal preserves main/local.
    routes.sync(routes.desired(selected));rules=json.loads(router_run(['ip','-j','-4','rule','show']))
    assert len([r for r in rules if str(r.get('protocol'))=='242'])==2
    routes.sync({});assert all(str(r.get('protocol'))!='242' for r in json.loads(router_run(['ip','-j','-4','rule','show'])))
    # A previously forwarded HTTP connection must not survive a captive gate.
    policy(base);sockets['client'].send(tcp_frame(49122));assert received('server',b'CAPTIVE_SYN')>=1
    guest=dict(network='192.0.2.0/24',interface='lan')
    policy(dict(base,hotspot=True),guest=guest)
    sockets['client'].send(tcp_frame(49122));assert received('server',b'CAPTIVE_SYN')==0,'cached HTTP NAT bypass'
    sockets['client'].send(tcp_frame(49123));assert received('server',b'CAPTIVE_SYN')==0,'captive HTTP forwarded'
    captured=json.loads(nft(['-j','list','table','inet','rahawrt']))
    portal_packets=sum(e['counter']['packets'] for x in captured['nftables'] if x.get('rule',{}).get('comment')=='rw:portal' for e in x['rule']['expr'] if isinstance(e.get('counter'),dict))
    assert portal_packets>=1,'HTTP captive redirect did not match a real TCP packet'
    policy(base,guest=guest);sockets['client'].send(tcp_frame(49124));assert received('server',b'CAPTIVE_SYN')>=1,'authorized HTTP blocked'
    # Simulate loss of the main policy during fw4 reload: independent boot guard
    # remains sufficient to stop managed Internet until a valid policy is back.
    from rahawrt.boot_guard import rules as guard_rules, remove as remove_guard
    nft(['-f','-'],guard_rules([base],['192.0.2.1','198.51.100.1']))
    nft(['delete','table','inet','rahawrt']);exists=False
    drain('server');send(b'BOOT_CLOSED');assert received('server',b'BOOT_CLOSED')==0,'boot/reload guard bypass'
    policy(base);remove_guard(lambda args,data=None:nft(args[1:],data))
    send(b'BOOT_RECOVERED');assert received('server',b'BOOT_RECOVERED')>=1,'guard recovery left Internet blocked'
    from rahawrt.runtime import Runtime
    import tempfile
    with tempfile.TemporaryDirectory() as temporary:
        lease=Path(temporary)/'leases';lease.write_text('0 '+base['mac']+' '+base['ip']+' Client *\n')
        observed=Runtime(store,True,router_run).clients(lease)[0]
        assert observed['observed_interface']=='lan' and 'PERMANENT' in observed['neighbor_state']
    store.db.close()
    print('PASS: real TCP captive redirect, previously tracked HTTP denied, authorized HTTP preserved; independent boot/reload guard blocks while main policy is absent and recovers.')
    print(f'PASS: real routed IPv4 packets: baseline, upload accounting, quota, tunnel-down forward guard, explicit direct, MAC binding, login gate, parental CIDR, unknown guest and byte policer ({limited}/{baseline} upload and {down_cap}/{down_base} download packets), shared account cap across 16 identities ({account_packets}/16 packets), real DNS capture, pre-login local portal DNS replies, DoT block local capture of VPN-only DNS, two native source routes, tunnel-down closure, explicit fallback and independent route preservation.')
finally:
    for s in sockets.values():s.close()
