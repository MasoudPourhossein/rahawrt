"""Private marked DNS TCP worker; executed with PassWall2's documented direct GID."""
import argparse
import ipaddress
import secrets
import socket
import struct
import sys


def read_exact(stream,size):
    data=b''
    while len(data)<size:
        part=stream.recv(size-len(data))
        if not part:raise OSError('incomplete DNS response')
        data+=part
    return data


def exchange(query,interface,mark,target):
    if not 12<=len(query)<=4096:raise ValueError('invalid DNS packet size')
    direct=interface is None and mark is None
    if not direct and (type(mark) is not int or not 0x52410001<=mark<=0x5241270f):raise ValueError('invalid owned routing mark')
    address=str(ipaddress.IPv4Address(target[0]))
    if not 1<=target[1]<=65535:raise ValueError('invalid DNS port')
    if not direct and (not interface or len(interface)>15 or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-' for c in interface)):raise ValueError('invalid native interface')
    original=query[:2];wire=secrets.token_bytes(2)+query[2:]
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as stream:
        stream.settimeout(3)
        if not direct:
            stream.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,mark)
            stream.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,interface.encode()+b'\0')
        stream.connect((address,target[1]))
        stream.sendall(struct.pack('!H',len(wire))+wire)
        size=struct.unpack('!H',read_exact(stream,2))[0]
        if not 12<=size<=65535:raise ValueError('invalid DNS response size')
        response=read_exact(stream,size)
    if response[:2]!=wire[:2] or not response[2]&128:raise ValueError('invalid DNS response')
    return original+response[2:]


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--interface');parser.add_argument('--mark',type=int);parser.add_argument('--direct',action='store_true')
    parser.add_argument('--server',required=True);parser.add_argument('--port',type=int,default=53)
    args=parser.parse_args()
    if args.direct and (args.interface is not None or args.mark is not None):parser.error('direct and native route options are exclusive')
    if not args.direct and (args.interface is None or args.mark is None):parser.error('native route requires both interface and mark')
    try:
        query=sys.stdin.buffer.read(4097)
        sys.stdout.buffer.write(exchange(query,args.interface,args.mark,(args.server,args.port)))
    except (OSError,ValueError):
        # Never include DNS names or configuration in stderr/logs.
        sys.exit(1)


if __name__=='__main__':main()
