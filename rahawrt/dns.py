"""Small bounded DNS policy proxy. No query log; TLS verification is never disabled."""
import secrets
import ipaddress
import socket
import socketserver
import struct
import threading
from .parental import domain
from .policy import active
import datetime as dt

PROBE_HOSTS={'connectivitycheck.gstatic.com','connectivitycheck.android.com','clients3.google.com','captive.apple.com','www.apple.com','www.msftconnecttest.com','msftconnecttest.com','dns.msftncsi.com','www.msftncsi.com','detectportal.firefox.com','network-test.debian.org','nmcheck.gnome.org'}

SAFE={'google.com':'forcesafesearch.google.com','www.google.com':'forcesafesearch.google.com','bing.com':'strict.bing.com','www.bing.com':'strict.bing.com','youtube.com':'restrict.youtube.com','www.youtube.com':'restrict.youtube.com','m.youtube.com':'restrict.youtube.com','youtubei.googleapis.com':'restrict.youtube.com','youtube.googleapis.com':'restrict.youtube.com'}


def encode_name(name):
    return b''.join(bytes([len(part)])+part.encode('ascii') for part in domain(name).split('.'))+b'\0'


def question(data,max_size=4096):
    if len(data)<17 or len(data)>max_size:raise ValueError('invalid DNS size')
    ident,flags,count,_,_,_=struct.unpack('!6H',data[:12])
    if count!=1 or flags&0xf800:raise ValueError('one ordinary DNS question required')
    parts=[];offset=12
    while True:
        size=data[offset];offset+=1
        if size==0:break
        if size>63 or offset+size>=len(data):raise ValueError('invalid question label')
        parts.append(data[offset:offset+size].decode('ascii'));offset+=size
        if len(parts)>127:raise ValueError('too many labels')
    if offset+4>len(data):raise ValueError('truncated DNS question')
    qtype,qclass=struct.unpack('!HH',data[offset:offset+4])
    if qclass!=1:raise ValueError('only Internet DNS supported')
    return ident,domain('.'.join(parts)),qtype,data[12:offset+4]


def read_name(data,offset,seen=None):
    seen=set() if seen is None else seen
    if offset in seen or len(seen)>32:raise ValueError('DNS compression loop')
    seen.add(offset);parts=[]
    while True:
        if offset>=len(data):raise ValueError('truncated DNS name')
        size=data[offset];offset+=1
        if not size:return '.'.join(parts),offset
        if size&0xc0==0xc0:
            if offset>=len(data):raise ValueError('truncated DNS pointer')
            tail,_=read_name(data,((size&63)<<8)|data[offset],seen)
            return '.'.join(parts+[tail]),offset+1
        if size>63 or offset+size>len(data):raise ValueError('invalid DNS label')
        parts.append(data[offset:offset+size].decode('ascii'));offset+=size


def address_records(response,qtype,target):
    _,offset=read_name(response,12);offset+=4
    count=struct.unpack('!H',response[6:8])[0];records=[]
    for _ in range(count):
        _,offset=read_name(response,offset)
        kind,klass,ttl,size=struct.unpack('!HHIH',response[offset:offset+10]);offset+=10
        data=response[offset:offset+size];offset+=size
        if len(data)!=size:raise ValueError('truncated DNS answer')
        if kind==qtype and klass==1 and ((kind==1 and size==4) or (kind==28 and size==16)):
            records.append(encode_name(target)+struct.pack('!HHIH',kind,1,min(ttl,60),size)+data)
    return records


def answer(query,rcode=0,records=()):
    ident,name,qtype,q=question(query)
    header=struct.pack('!6H',ident,0x8080|(struct.unpack('!H',query[2:4])[0]&0x100)|rcode,1,len(records),0,0)
    return header+q+b''.join(records)


def exact_read(stream,size):
    result=b''
    while len(result)<size:
        chunk=stream.recv(size-len(result))
        if not chunk:raise ValueError('truncated DNS TCP frame')
        result+=chunk
    return result


class Resolver:
    def __init__(self,store,parental,upstream=('1.1.1.1',53),transport=None,local_records=None,proxy_transport=None,captive_portal=None):
        self.store,self.parental,self.upstream=store,parental,upstream
        self.transport=transport or self.forward
        self.local_records=local_records or (lambda: {})
        self.proxy_transport=proxy_transport
        self.captive_portal=captive_portal or (lambda: None)

    def forward(self,query):
        original=query[:2];wire=secrets.token_bytes(2)+query[2:]
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.settimeout(3);sock.connect(self.upstream);sock.send(wire);response=sock.recv(65535)
        if len(response)<12 or response[:2]!=wire[:2] or not response[2]&128:raise ValueError('invalid upstream DNS response')
        if response[2]&2:
            with socket.create_connection(self.upstream,timeout=3) as sock:
                sock.sendall(struct.pack('!H',len(wire))+wire);size=struct.unpack('!H',exact_read(sock,2))[0];response=exact_read(sock,size)
        if len(response)<12 or response[:2]!=wire[:2] or not response[2]&128:raise ValueError('invalid upstream DNS response')
        # Validate the echoed question independently of answer compression.
        echoed=bytearray(response);echoed[2:4]=b'\x01\x00';echoed[4:6]=b'\x00\x01'
        if question(bytes(echoed),max_size=65535)[1:3]!=question(query)[1:3]:raise ValueError('upstream question mismatch')
        return original+response[2:]

    def resolve(self,query,ip):
        try:
            ident,name,qtype,q=question(query)
        except (ValueError,IndexError,UnicodeError):return b''
        local=self.local_records().get(name)
        if local:
            record=b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+socket.inet_aton(local)
            return answer(query,records=[record] if qtype==1 else [])
        d=next((d for d in self.store.effective_devices() if d['ip']==ip),None)
        now=dt.datetime.now().astimezone()
        closed=bool(d and (not d['enabled'] or not active(d['internet'],now)
                  or (d['quota_bytes'] and sum(self.store.usage().get(d['id'],[0,0]))>=d['quota_bytes'])
                  or (d['hotspot'] and d['id'] not in self.store.online())))
        # Legacy OS HTTP probes need DNS before login. Map only known probe
        # names to this guest gateway, never resolve them upstream while closed.
        settings=self.captive_portal() if name in PROBE_HOSTS else None
        if (not d or closed) and settings and ipaddress.ip_address(ip) in ipaddress.ip_network(settings['network']):
            record=b'\xc0\x0c'+struct.pack('!HHIH',1,1,0,4)+socket.inet_aton(settings['gateway'])
            return answer(query,records=[record] if qtype==1 else [])
        if (not d and not ip.startswith('127.')) or closed:return answer(query,5)
        profile=self.parental.profile_for_ip(ip)
        try:
            transport=self.transport
            if d and (d['node']!='direct' or d.get('tunnel')) and active(d['vpn'],dt.datetime.now().astimezone()):
                if not self.proxy_transport:
                    if d['vpn_failure']=='block':return answer(query,2)
                else:
                    def selected_transport(wire):
                        try:return self.proxy_transport(wire,d)
                        except (OSError,ValueError):
                            if d['vpn_failure']=='block':raise
                            return self.transport(wire)
                    transport=selected_transport
            if profile:
                if self.parental.blocked(name,profile):return answer(query,3)
                if profile['safe_search'] and name in SAFE:
                    if qtype not in (1,28):return answer(query)
                    target=SAFE[name]
                    wire=struct.pack('!6H',ident,0x100,1,0,0,0)+encode_name(target)+struct.pack('!HH',qtype,1)
                    resolved=transport(wire)
                    cname=encode_name(target)
                    record=b'\xc0\x0c'+struct.pack('!HHIH',5,1,60,len(cname))+cname
                    if resolved[3]&15:return answer(query,2)
                    return answer(query,records=[record]+address_records(resolved,qtype,target))
            return transport(query)
        except (OSError,ValueError,IndexError,struct.error):return answer(query,2)


class Bounded:
    daemon_threads=True
    def process_request(self,request,address):
        if not self.slots.acquire(False):self.shutdown_request(request);return
        try:super().process_request(request,address)
        except Exception:self.slots.release();raise
    def process_request_thread(self,request,address):
        try:super().process_request_thread(request,address)
        finally:self.slots.release()


class UDPServer(Bounded,socketserver.ThreadingUDPServer):pass
class TCPServer(Bounded,socketserver.ThreadingTCPServer):allow_reuse_address=True
class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        query,sock=self.request
        result=self.server.resolver.resolve(query,self.client_address[0])
        if result:sock.sendto(result,self.client_address)
class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            size=struct.unpack('!H',exact_read(self.request,2))[0]
            if size>4096:return
            query=exact_read(self.request,size);result=self.server.resolver.resolve(query,self.client_address[0])
            if result:self.request.sendall(struct.pack('!H',len(result))+result)
        except (OSError,ValueError,struct.error):pass


class DNSServer:
    def __init__(self,address,resolver):
        tcp=TCPServer(address,TCPHandler)
        try:udp=UDPServer(tcp.server_address,UDPHandler)
        except Exception:tcp.server_close();raise
        self.servers=(tcp,udp);self.address=tcp.server_address
        for server in self.servers:server.resolver=resolver;server.slots=threading.BoundedSemaphore(32)
        self.threads=[]
    def start(self):
        for server in self.servers:
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();self.threads.append(thread)
    def close(self):
        for server in self.servers:server.shutdown();server.server_close()
        for thread in self.threads:thread.join(timeout=5)
