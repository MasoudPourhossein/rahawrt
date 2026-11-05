#!/usr/bin/env python3
"""Real OpenWrt UCI transaction checks; no firmware boot or network service claim."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import tempfile

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from rahawrt.store import Store
from rahawrt.changes import ChangeGuard
from rahawrt.guest import guest_plan

IMAGE='openwrt/rootfs@sha256:9972a4b4747cd136abd597475d7b88c51a49fd849d0d53f069a2f4bf446061b9'


def main():
    env=dict(os.environ)
    for name in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'):env.pop(name,None)
    docker=['docker','--host=unix:///var/run/docker.sock']
    def invoke(args,data=None):
        result=subprocess.run(docker+args,input=data,text=True,capture_output=True,env=env,timeout=120)
        if result.returncode:raise subprocess.CalledProcessError(result.returncode,args,stderr=result.stderr)
        return result.stdout
    name='rahawrt-userspace-'+str(os.getpid())
    invoke(['pull',IMAGE])
    (ROOT/'.local').mkdir(exist_ok=True)
    fixture=tempfile.NamedTemporaryFile(prefix='installer-',suffix='.sh',dir=ROOT/'.local')
    fixture.write((ROOT/'scripts/install.sh').read_bytes());fixture.flush();Path(fixture.name).chmod(0o644)
    invoke(['run','-d','--name',name,'--network','none','--cap-drop','ALL','--pids-limit','128','--memory','256m','--mount','type=bind,src='+fixture.name+',dst=/run/installer.sh,readonly','--entrypoint','/bin/sh',IMAGE,'-c','exec sleep 3600'])
    store=Store(':memory:')
    try:
        def runner(args,data=None):return invoke(['exec','-i',name,*args],data)
        release=runner(['cat','/etc/openwrt_release'])
        if "DISTRIB_RELEASE='24.10.8'" not in release or "DISTRIB_ARCH='x86_64'" not in release:raise RuntimeError('unexpected OpenWrt userspace identity')
        failed=subprocess.run(docker+['exec',name,'/bin/sh','/run/installer.sh','fixture.ipk','manifest','signature','trusted.pub'],env=env,text=True,capture_output=True,timeout=15)
        assert failed.returncode!=0 and 'Install and configure PassWall2 first' in failed.stderr,failed.stderr
        sections=guest_plan(dict(address='192.168.50.1/24',portal_host='portal.example'),['192.168.1.0/24'])
        # Empty rootfs images need fixture baseline configs; no live daemon runs.
        before={}
        for config in sections:
            try:before[config]=runner(['uci','export',config])
            except subprocess.CalledProcessError:
                runner(['uci','import',config],"config test 'preserved'\n option marker 'before'\n");runner(['uci','commit',config])
                before[config]=runner(['uci','export',config])
        guard=ChangeGuard(store,runner)
        result=guard.start('guest',sections,[],'test')
        deadline=time.monotonic()+90
        while guard.status()[0]['status']=='applying':
            if time.monotonic()>deadline:raise RuntimeError('UCI transaction timeout')
            time.sleep(.05)
        assert guard.status()[0]['status']=='awaiting',guard.status()
        for key,value in {'network.rw_guest.ipaddr':'192.168.50.1','firewall.rw_guest.input':'REJECT','firewall.rw_guest_portal.dest_port':'8443 2080','uhttpd.rw_guest.home':'/usr/share/rahawrt/public'}.items():assert runner(['uci','get',key]).strip()==value,key
        assert ':8443/cgi-bin/rahawrt/wrt/api/v1/captive' in runner(['uci','get','dhcp.rw_guest.dhcp_option'])
        assert guard.rollback(result['id'])['ok']
        for config,source in before.items():assert runner(['uci','export',config])==source,config
        runner(['uci','set','network.unrelated=interface'])
        try:guard.start('guest',sections,[],'test')
        except ValueError as exc:assert 'existing UCI edits' in str(exc)
        else:raise AssertionError('pending UCI edits were not refused')
        assert 'network.unrelated' in runner(['uci','changes','network'])
        print('PASS: official OpenWrt 24.10.8 x86_64 userspace: mandatory missing-PassWall2 installer rejection, real UCI guest/DHCP/firewall/uhttpd serialization, exact rollback and unrelated pending-edit preservation.')
        print('No firmware/emulator boot, procd/netifd/uhttpd daemon, PassWall2 core, router networking or hardware test claimed.')
    finally:
        store.db.close()
        try:invoke(['rm','-f',name])
        finally:fixture.close()


if __name__=='__main__':main()
