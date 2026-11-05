#!/usr/bin/env python3
"""Real nft parser/kernel test. Run only inside a NEW network namespace."""
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from rahawrt.policy import device, compile_nft
from rahawrt.guest import bootstrap_rules
from rahawrt.boot_guard import rules as boot_rules, remove as remove_boot

if len(sys.argv) == 1:
    sys.exit(subprocess.run(['unshare', '-Urn', sys.executable, __file__, '--child', os.readlink('/proc/self/ns/net')]).returncode)
if len(sys.argv) != 3 or sys.argv[1] != '--child' or os.readlink('/proc/self/ns/net') == sys.argv[2]:
    sys.exit('Refusing to change the parent network namespace.')
nft = root/'.local/tools/usr/sbin/nft'
command = ['/lib64/ld-linux-x86-64.so.2', '--library-path', str(root/'.local/tools/usr/lib/x86_64-linux-gnu'), str(nft)] if nft.exists() else ['nft']

def run(args, source=None):
    result = subprocess.run(command+args, input=source, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stderr)
    return result.stdout

d = device(dict(id='test', ip='192.0.2.10', mac='02:00:00:00:00:01', node='node_a', upload_kbps=80, download_kbps=160, quota_bytes=10000, blocked_ips=['203.0.113.0/24']))
try:
    rules = compile_nft([d], {}, set(), dt.datetime(2026,11,9,10))
    run(['-c','-f','-'], rules)
    run(['-f','-'], rules)
    actual = json.loads(run(['-j','list','table','inet','rahawrt']))
    chains = {x['chain']['name'] for x in actual['nftables'] if 'chain' in x}
    assert chains == {'upload','forward','download','dns'}, chains
    assert sum('rule' in x for x in actual['nftables']) >= 15
    quota = compile_nft([d], {'test':[10000,0]}, set())
    run(['-f','-'], 'delete table inet rahawrt\n'+quota)
    assert 'ip saddr 192.0.2.10 drop' in run(['list','table','inet','rahawrt'])
    parental=dict(d,_parental={'block_encrypted_dns':True})
    extra=compile_nft([parental],{},set(),guest=dict(network='192.0.2.0/24',interface='br-rahaguest'))
    run(['-f','-'],'delete table inet rahawrt\n'+extra)
    run(['-f','-'],bootstrap_rules('192.0.2.1/24'))
    run(['delete','table','inet','rahawrt_guest_guard'])
    run(['-f','-'],boot_rules([d],['192.0.2.1'],dict(network='192.0.2.0/24',interface='br-rahaguest')))
    remove_boot(lambda args,data=None:run(args[1:],data))
    print('PASS: kernel installed policies, byte policers, quota drops, DNS/IPv6 and forward guards; atomic replacement passed.')
finally:
    subprocess.run(command+['delete','table','inet','rahawrt'], capture_output=True)
