#!/usr/bin/env python3
"""Validate an actual SDK IPK against the repository deployment contract."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile

spec=importlib.util.spec_from_file_location('builder',Path(__file__).with_name('build-ipk.py'))
builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)


def verify(path,source_root=None,receipt=None):
    if source_root:builder.ROOT=Path(source_root).resolve()
    path=Path(path);meta=builder.metadata()
    with tarfile.open(path) as outer:
        if outer.extractfile('./debian-binary').read()!=b'2.0\n':raise ValueError('invalid IPK envelope')
        with tarfile.open(fileobj=io.BytesIO(outer.extractfile('./control.tar.gz').read())) as control:
            fields=dict(line.split(': ',1) for line in control.extractfile('./control').read().decode().splitlines() if ': ' in line)
            for key,value in {'Package':meta['name'],'Version':meta['version'],'Architecture':'all','License':meta['license']}.items():
                if fields.get(key)!=value:raise ValueError('SDK control mismatch: '+key)
            if set(fields['Depends'].split(', '))!=set(meta['dependencies'])|{'libc'}:raise ValueError('SDK dependencies differ')
            if control.extractfile('./conffiles').read().strip()!=b'/etc/config/rahawrt':raise ValueError('SDK conffiles differ')
        with tarfile.open(fileobj=io.BytesIO(outer.extractfile('./data.tar.gz').read())) as payload:
            files={m.name.removeprefix('./'):m for m in payload.getmembers() if m.isfile()}
            expected=builder.payload()
            if set(files)!=set(expected):raise ValueError('SDK deployment paths differ')
            for name,(data,mode) in expected.items():
                member=files[name]
                if payload.extractfile(member).read()!=data or member.mode!=mode or member.uid!=0 or member.gid!=0:raise ValueError('SDK bytes/modes/ownership differ: '+name)
            state=next(m for m in payload.getmembers() if m.name.rstrip('/')=='./etc/rahawrt')
            if state.mode!=0o700:raise ValueError('SDK state directory must be private')
    digest=hashlib.sha256(path.read_bytes()).hexdigest()
    if receipt:
        payload={name:dict(sha256=hashlib.sha256(data).hexdigest(),mode=oct(mode)) for name,(data,mode) in sorted(expected.items())}
        record=dict(format=1,package=meta['name'],version=meta['version'],architecture='all',artifact_sha256=digest,payload_sha256=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest(),verification='metadata, complete payload, modes, root ownership and private state')
        archive=path.parent/'source.tar.gz'
        if archive.exists():record['source_archive_sha256']=hashlib.sha256(archive.read_bytes()).hexdigest()
        Path(receipt).write_text(json.dumps(record,indent=2)+'\n')
    print('PASS: actual SDK IPK metadata, every payload byte, modes, root ownership and private state directory verified.')
    print(digest+'  '+path.name)
    return digest


if __name__=='__main__':verify(sys.argv[1],sys.argv[2] if len(sys.argv)>2 else None,sys.argv[3] if len(sys.argv)>3 else None)
