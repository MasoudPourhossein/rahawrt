"""DNS-over-TCP through owned loopback SOCKS sidecars using existing PassWall2 nodes."""
import ipaddress
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import struct
import threading
import time
from .dns import exact_read,question
from .policy import active


def socks_connect(endpoint,target,timeout=3):
    address=ipaddress.IPv4Address(target[0]);port=target[1]
    if not 1<=port<=65535:raise ValueError('invalid DNS port')
    stream=socket.create_connection(endpoint,timeout=timeout)
    try:
        stream.sendall(b'\x05\x01\x00')
        if exact_read(stream,2)!=b'\x05\x00':raise ValueError('SOCKS authentication negotiation failed')
        stream.sendall(b'\x05\x01\x00\x01'+address.packed+struct.pack('!H',port))
        response=exact_read(stream,4)
        if response[:3]!=b'\x05\x00\x00':raise OSError('selected proxy refused DNS connection')
        if response[3]==1:exact_read(stream,4)
        elif response[3]==4:exact_read(stream,16)
        elif response[3]==3:exact_read(stream,exact_read(stream,1)[0])
        else:raise ValueError('invalid SOCKS address')
        exact_read(stream,2)
        return stream
    except Exception:stream.close();raise


def exchange(query,endpoint,target=('1.1.1.1',53)):
    ident,name,kind,_=question(query)
    original=query[:2];wire=secrets.token_bytes(2)+query[2:]
    with socks_connect(endpoint,target) as stream:
        stream.sendall(struct.pack('!H',len(wire))+wire)
        size=struct.unpack('!H',exact_read(stream,2))[0]
        if not 12<=size<=65535:raise ValueError('invalid DNS response length')
        response=exact_read(stream,size)
    if response[:2]!=wire[:2] or not response[2]&128:raise ValueError('invalid proxied DNS response')
    echoed=bytearray(response);echoed[2:4]=b'\x01\x00';echoed[4:6]=b'\x00\x01'
    if question(bytes(echoed),max_size=65535)[1:3]!=(name,kind):raise ValueError('proxied DNS question mismatch')
    return original+response[2:]


class ProxyDNS:
    def __init__(self,store,runner,root=Path('/tmp/etc/passwall2'),probe=None,owns=None):
        self.store,self.run,self.root=store,runner,Path(root)
        self.lock=threading.RLock();self.probe=probe or self._probe
        self.owns=owns or self._owns_listener
        with store.lock:
            store.db.execute('CREATE TABLE IF NOT EXISTS dns_helpers(node TEXT PRIMARY KEY,flag TEXT NOT NULL UNIQUE,port INTEGER NOT NULL)')
            store.db.commit()
        self.ready={};self.errors={};self.selection={}

    @staticmethod
    def _probe(port):
        try:
            with socket.create_connection(('127.0.0.1',port),timeout=.2) as stream:
                stream.sendall(b'\x05\x01\x00');return exact_read(stream,2)==b'\x05\x00'
        except (OSError,ValueError):return False

    def node(self,selected):
        node=self.run(['uci','-q','get','passwall2.@global[0].node']).strip() if selected=='default' else selected
        if not re.fullmatch(r'[A-Za-z0-9_]{1,64}',node):raise ValueError('invalid selected node')
        kind=self.run(['uci','-q','get','passwall2.'+node+'.type']).strip().lower()
        if kind not in ('xray','sing-box'):raise ValueError('parental proxy DNS currently requires an Xray/sing-box node')
        protocol=self.run(['uci','-q','get','passwall2.'+node+'.protocol']).strip()
        if protocol.startswith('_'):raise ValueError('strict DNS requires a concrete node, not a shunt/interface/balancer')
        return node

    def ensure(self,devices,now):
        wanted=set();errors={};selection={}
        for d in devices:
            if not (d.get('_parental') or d.get('hotspot')) or d.get('tunnel') or d['node']=='direct' or not active(d['vpn'],now):continue
            try:
                resolved=self.node(d['node']);wanted.add(resolved);selection[d['node']]=resolved
            except Exception:errors[d['id']]='selected node does not expose a supported concrete proxy path'
        with self.lock:
            for node in wanted:
                try:self._ensure_node(node)
                except Exception:errors[node]='parental DNS proxy unavailable; no implicit direct fallback'
            with self.store.lock:rows=self.store.db.execute('SELECT node,flag,port FROM dns_helpers').fetchall()
            for node,flag,port in rows:
                if node not in wanted:
                    self._stop(flag);self.ready.pop(node,None)
            self.errors=errors;self.selection=selection
        return dict(ready_nodes=sorted(self.ready),errors=errors)

    def _ensure_node(self,node):
        with self.store.lock:
            row=self.store.db.execute('SELECT flag,port FROM dns_helpers WHERE node=?',(node,)).fetchone()
        if row:
            flag,port=row
        else:
            flag='rw_dns_'+secrets.token_hex(8)
            # Reserve an available loopback port; a failed bind/start is surfaced,
            # never replaced by sending the query directly.
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1',0));port=reservation.getsockname()[1]
            with self.store.lock,self.store.db:self.store.db.execute('INSERT INTO dns_helpers VALUES (?,?,?)',(node,flag,port))
        if self.probe(port) and self.owns(flag,port):self.ready[node]=port;return
        self.ready.pop(node,None)
        if self.probe(port) and not self.owns(flag,port):
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1',0));port=reservation.getsockname()[1]
            with self.store.lock,self.store.db:self.store.db.execute('UPDATE dns_helpers SET port=? WHERE node=?',(port,node))
        self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        path=self.root/(flag+'.json')
        # Names are random and persisted before first creation; never follow links.
        descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
        os.fchmod(descriptor,0o600);os.close(descriptor)
        self.run(['/usr/share/passwall2/app.sh','run_socks','flag='+flag,'node='+node,'bind=127.0.0.1','socks_port='+str(port),'config_file='+str(path),'log_file=/dev/null'])
        deadline=time.monotonic()+2
        while not (self.probe(port) and self.owns(flag,port)):
            if time.monotonic()>=deadline:raise OSError('proxy listener did not become ready')
            time.sleep(.05)
        self.ready[node]=port

    def forward(self,query,device,target=('1.1.1.1',53)):
        with self.lock:
            node=self.selection.get(device['node']);port=self.ready.get(node)
        if not port:raise OSError('selected DNS proxy is not ready')
        return exchange(query,('127.0.0.1',port),target)

    def _owned_processes(self,flag):
        path=str(self.root/(flag+'.json')).encode()
        for entry in Path('/proc').iterdir():
            if not entry.name.isdigit() or int(entry.name)==os.getpid():continue
            try:
                if path in (entry/'cmdline').read_bytes().split(b'\0'):yield entry
            except OSError:pass

    def _owns_listener(self,flag,port):
        inodes=set()
        try:
            for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
                fields=line.split()
                if fields[1].upper()=='0100007F:'+format(port,'04X') and fields[3]=='0A':inodes.add(fields[9])
        except OSError:return False
        if not inodes:return False
        for process in self._owned_processes(flag):
            try:
                for descriptor in (process/'fd').iterdir():
                    target=os.readlink(descriptor)
                    if any(target=='socket:['+inode+']' for inode in inodes):return True
            except OSError:continue
        return False

    def _stop(self,flag):
        for process in self._owned_processes(flag):
            try:
                descriptor=os.pidfd_open(int(process.name))
                try:
                    expected=str(self.root/(flag+'.json')).encode()
                    # Recheck after opening the pidfd: the numeric PID may have
                    # been reused since the /proc ownership scan.
                    if expected in (process/'cmdline').read_bytes().split(b'\0'):
                        signal.pidfd_send_signal(descriptor,signal.SIGTERM)
                finally:os.close(descriptor)
            except (OSError,ProcessLookupError):pass

    def close(self):
        with self.lock:
            with self.store.lock:flags=[r[0] for r in self.store.db.execute('SELECT flag FROM dns_helpers')]
            for flag in flags:self._stop(flag)
            self.ready.clear()
