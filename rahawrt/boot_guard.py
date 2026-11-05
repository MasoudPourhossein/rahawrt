"""Independent fail-closed guard for boot, fw4 reload and stalled policy workers."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time
from .policy import device

HEARTBEAT=Path('/var/run/rahawrt/heartbeat.json')
MARKER='RahaWRT boot guard v1'


def run(argv,data=None):
    return subprocess.run(argv,input=data,text=True,capture_output=True,check=True,timeout=30).stdout


def rules(devices,local_ips,guest=None):
    ips=[str(ipaddress.IPv4Address(v)) for v in local_ips]
    if not ips:raise ValueError('guard requires observed router IPv4 addresses')
    lines=['table inet rahawrt_boot {', 'comment "'+MARKER+'"',
           'set router4 { type ipv4_addr; elements = { '+', '.join(ips)+' }; }',
           'chain ingress { type filter hook prerouting priority -310; policy accept;',
           'ip saddr 0.0.0.0 ip daddr 255.255.255.255 udp sport 68 udp dport 67 return']
    # Retain console/admin and local captive access, without opening router DNS.
    lines+=['ip daddr @router4 tcp dport { 22, 80, 443, 8443, 2080 } return',
            'ip daddr @router4 udp sport 68 udp dport 67 return']
    for original in devices:
        d=device(original)
        lines += [f'ether saddr {d["mac"]} drop',f'ip saddr {d["ip"]} drop']
    if guest:
        network=str(ipaddress.IPv4Network(guest['network']))
        interface=guest['interface']
        if interface!='br-rahaguest':raise ValueError('unrecognized guest guard interface')
        lines += ['iifname "br-rahaguest" drop',f'ip saddr {network} drop']
    return '\n'.join(lines+['}', '}'])+'\n'


def owned(runner=run):
    try:table=json.loads(runner(['nft','-j','list','table','inet','rahawrt_boot']))
    except subprocess.CalledProcessError as exc:
        if 'No such file' in (exc.stderr or ''):return False
        raise
    if not any(x.get('table',{}).get('comment')==MARKER for x in table.get('nftables',[])):
        raise ValueError('refusing an unowned boot-guard table')
    return True


def remove(runner=run):
    if owned(runner):runner(['nft','delete','table','inet','rahawrt_boot'])


def snapshot(runner=run,path=Path('/etc/rahawrt/state.db')):
    db=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True)
    try:
        db.execute('PRAGMA trusted_schema=OFF')
        devices=[json.loads(r[0]) for r in db.execute('SELECT config FROM devices')]
    finally:db.close()
    interfaces=json.loads(runner(['ubus','call','network.interface','dump']))
    local=[a['address'] for i in interfaces.get('interface',[]) for a in i.get('ipv4-address',[])]
    try:name=runner(['uci','-q','get','rahawrt.main.guest_network']).strip()
    except subprocess.CalledProcessError:name=''
    guest=None
    if name:
        if name!='rw_guest':raise ValueError('unrecognized guest configuration')
        address=runner(['uci','-q','get','network.rw_guest.ipaddr']).strip()
        mask=runner(['uci','-q','get','network.rw_guest.netmask']).strip()
        guest=dict(network=str(ipaddress.IPv4Network(address+'/'+mask,strict=False)),interface='br-rahaguest')
    return devices,local,guest


def apply(runner=run,path=Path('/etc/rahawrt/state.db')):
    devices,local,guest=snapshot(runner,path)
    source=rules(devices,local,guest)
    exists=owned(runner)
    runner(['nft','-f','-'],('delete table inet rahawrt_boot\n' if exists else '')+source)


def healthy(path=HEARTBEAT,now=None):
    try:
        if path.is_symlink() or path.stat().st_mode&0o077:return False
        value=json.loads(path.read_text())
        age=(time.monotonic() if now is None else now)-value['monotonic']
        return value.get('pid') is not None and 0<=age<=15
    except (OSError,ValueError,KeyError,TypeError):return False


def beat(path=HEARTBEAT):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if path.parent.is_symlink():raise ValueError('refusing symlink heartbeat directory')
    path.parent.chmod(0o700)
    temporary=path.with_name('heartbeat-'+os.urandom(8).hex())
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(fd,'w') as stream:json.dump(dict(pid=os.getpid(),monotonic=time.monotonic()),stream)
        os.replace(temporary,path)
    finally:
        if temporary.exists():temporary.unlink()


def install(runner=run):
    if runner(['uci','changes','firewall']).strip():raise ValueError('save or revert pending firewall edits first')
    try:existing=runner(['uci','-q','get','firewall.rw_guard']).strip()
    except subprocess.CalledProcessError:existing=None
    if existing is not None:
        if existing!='include' or runner(['uci','-q','get','firewall.rw_guard.rahawrt_owner']).strip()!='1':
            raise ValueError('refusing unowned firewall include')
    for option,value in {'':'include','.path':'/usr/libexec/rahawrt-guard','.type':'script','.fw4_compatible':'1','.enabled':'1','.rahawrt_owner':'1'}.items():
        runner(['uci','set','firewall.rw_guard'+option+'='+value])
    runner(['uci','commit','firewall'])


def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=('once','watch','install','remove','routes-cleanup','uninstall'));args=p.parse_args()
    if args.action=='install':install();apply();return
    if args.action=='remove':remove();return
    if args.action=='uninstall':
        if run(['uci','changes','firewall']).strip():raise ValueError('save or revert pending firewall edits first')
        from .runtime import Runtime
        from .store import Store
        store=Store('/etc/rahawrt/state.db')
        try:
            runtime=Runtime(store,True,run)
            runtime.routes.sync({})
            runtime.set_native_firewall({})
            runtime.proxy_dns.close()
        finally:store.db.close()
        try:section=run(['uci','-q','get','firewall.rw_guard']).strip()
        except subprocess.CalledProcessError:section=None
        if section is not None:
            if section!='include' or run(['uci','-q','get','firewall.rw_guard.rahawrt_owner']).strip()!='1':raise ValueError('unowned firewall include')
            run(['uci','delete','firewall.rw_guard']);run(['uci','commit','firewall'])
        HEARTBEAT.unlink(missing_ok=True)
        remove();return
    if args.action=='routes-cleanup':
        from .store import Store
        from .routes import Routes
        store=Store('/etc/rahawrt/state.db')
        try:Routes(store,run).sync({})
        finally:store.db.close()
        return
    if args.action=='once':apply();return
    while True:
        try:
            if not healthy():apply()
        except Exception:
            # Never print subprocess arguments (may contain private UCI values).
            print('RahaWRT guard could not refresh; inspect from console.',flush=True)
        time.sleep(5)


if __name__=='__main__':main()
