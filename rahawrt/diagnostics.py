"""Bounded local observations. A route lookup is not an end-to-end VPN test."""
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
from .vpn import host


def resources(store):
    memory={}
    path=Path('/proc/meminfo')
    if path.exists():
        for line in path.read_text().splitlines():
            name,value=line.split(':',1)
            if name in ('MemTotal','MemAvailable','MemFree'):memory[name]=int(value.split()[0])*1024
    try:uptime=float(Path('/proc/uptime').read_text().split()[0])
    except (OSError,ValueError):uptime=None
    disk=shutil.disk_usage('/etc/rahawrt' if Path('/etc/rahawrt').exists() else '.')
    return dict(uptime_seconds=uptime,load=list(os.getloadavg()),memory_bytes=memory,storage_bytes=dict(total=disk.total,free=disk.free),authenticated_devices=len(store.online()),devices=len(store.devices()),account_usage=store.usage())


def client_route(runtime,data):
    ident=data['device'];target=host(data['target'])
    d=next((d for d in runtime.store.effective_devices() if d['id']==ident),None)
    if not d:raise ValueError('unknown device')
    addresses=sorted({r[4][0] for r in socket.getaddrinfo(target,None,socket.AF_INET)})
    if not addresses:raise ValueError('target has no IPv4 address')
    interfaces=json.loads(runtime.run(['ubus','call','network.interface','dump']))
    interface=None
    for info in interfaces.get('interface',[]):
        for address in info.get('ipv4-address',[]):
            if ipaddress.IPv4Address(d['ip']) in ipaddress.IPv4Network(address['address']+'/'+str(address['mask']),strict=False):interface=info.get('l3_device') or info.get('device')
    if not interface:raise ValueError('client ingress interface could not be observed')
    route=runtime.run(['ip','-j','route','get',addresses[0],'from',d['ip'],'iif',interface])
    return dict(device=ident,target=target,router_dns_addresses=addresses,kernel_route=json.loads(route),configured_node=d['node'],internet_enabled=d['enabled'],hotspot_session=(not d['hotspot'] or ident in runtime.store.online()),limitation='Router DNS and kernel FIB only; transparent-proxy interception and end-to-end tunnel egress require packet tests.')
