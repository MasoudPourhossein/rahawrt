#!/usr/bin/env python3
"""Build OpenWrt-style noarch APK v3 with its pinned native packaging utility."""
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import re

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('ipk_builder',ROOT/'scripts/build-ipk.py')
ipk=importlib.util.module_from_spec(spec);spec.loader.exec_module(ipk)


def build(destination=None,sign_key=None):
    tool=ROOT/'.local/apk-build/src/apk'
    if not tool.exists():raise RuntimeError('run sh scripts/apk-setup.sh first')
    meta=ipk.metadata();version=meta['version']
    destination=Path(destination) if destination else ROOT/'dist'/(meta['name']+'-'+version+'.apk')
    destination.parent.mkdir(parents=True,exist_ok=True)
    files=ipk.payload()
    # OpenWrt keeps these sidecars alongside APK's own database metadata.
    prefix='lib/apk/packages/'+meta['name']
    listing=''.join('/'+name+'\n' for name in sorted(files))
    config='/etc/config/rahawrt'
    files[prefix+'.list']=(listing.encode(),0o644)
    files[prefix+'.conffiles']=((config+'\n').encode(),0o644)
    files[prefix+'.conffiles_static']=((config+' '+hashlib.sha256(files[config.lstrip('/')][0]).hexdigest()+'\n').encode(),0o644)
    with tempfile.TemporaryDirectory(prefix='apk-stage-',dir=ROOT/'.local') as temporary:
        stage=Path(temporary);stage.chmod(0o755)
        for name,(data,mode) in files.items():
            path=stage/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(data);path.chmod(mode);os.utime(path,(0,0))
        (stage/'etc/rahawrt').mkdir(parents=True,exist_ok=True);(stage/'etc/rahawrt').chmod(0o700)
        for path in stage.rglob('*'):
            if path.is_dir():
                if path.relative_to(stage).as_posix()!='etc/rahawrt':path.chmod(0o755)
                os.utime(path,(0,0))
        os.utime(stage,(0,0))
        command=['unshare','-Ur',str(tool),'--no-network','--compression','deflate:9','mkpkg','--files',str(stage),'--output',str(destination)]
        if sign_key:command[3:3]=['--sign-key',str(Path(sign_key).resolve())]
        fields={'name':meta['name'],'version':version,'arch':'noarch','license':meta['license'],'description':meta['title'],'origin':'rahawrt','url':'https://github.com/MasoudPourhossein/rahawrt','maintainer':'RahaWRT maintainers','build-time':'0','depends':' '.join(meta['dependencies'])}
        for key,value in fields.items():command+=['--info',key+':'+value]
        env=dict(os.environ,SOURCE_DATE_EPOCH='0')
        subprocess.run(command,check=True,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    # Metadata inspection is not a signature bypass or installation operation.
    result=subprocess.run([str(tool),'adbdump',str(destination)],capture_output=True,text=True,check=True)
    for expected in ('name: rahawrt','version: '+version,'arch: noarch','name: usr/lib/rahawrt/rahawrt','name: server.py'):
        if expected not in result.stdout:raise RuntimeError('APK metadata/payload inspection failed: '+expected)
    actual={};directory=None;filename=None
    for line in result.stdout.splitlines():
        match=re.fullmatch(r'  - name: (.+)',line)
        if match:directory=match[1];filename=None
        match=re.fullmatch(r'      - name: (.+)',line)
        if match:filename=(directory+'/' if directory else '')+match[1]
        match=re.fullmatch(r'        hash: ([a-f0-9]+)',line)
        if match and filename:actual[filename]=match[1]
        if re.fullmatch(r'\s+(user|group): (?!root$).+',line):raise RuntimeError('non-root APK ownership')
    if set(actual)!=set(files) or any(actual[name]!=hashlib.sha256(data).hexdigest() for name,(data,mode) in files.items()):raise RuntimeError('APK file digest mismatch')
    digest=hashlib.sha256(destination.read_bytes()).hexdigest()
    (destination.parent/(destination.name+'.sha256')).write_text(digest+'  '+destination.name+'\n')
    return destination,digest


if __name__=='__main__':
    path,digest=build();print(digest+'  '+path.name)
