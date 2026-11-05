"""Local protocol peer for integration tests; never opens an upstream connection."""
import socket
import socketserver
import struct
import sys
from rahawrt.dns import answer,exact_read

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        try:
            if exact_read(self.request,3)!=b'\x05\x01\x00':return
            self.request.sendall(b'\x05\x00')
            request=exact_read(self.request,10)
            if request[:4]!=b'\x05\x01\x00\x01':return
            self.request.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
            size=struct.unpack('!H',exact_read(self.request,2))[0]
            query=exact_read(self.request,size)
            record=b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+socket.inet_aton(sys.argv[3])
            response=answer(query,records=[record])
            self.request.sendall(struct.pack('!H',len(response))+response)
        except (OSError,ValueError):pass

class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
with Server(('127.0.0.1',int(sys.argv[2])),Handler) as server:server.serve_forever()
