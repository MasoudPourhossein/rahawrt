#!/usr/bin/env python3
"""Native packaging integration: official IPK tool and APK signature/integrity checks."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

ROOT=Path(__file__).resolve().parents[1]

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result

ipk=module('build_ipk',ROOT/'scripts/build-ipk.py');apk=module('build_apk',ROOT/'scripts/build-apk.py')

def run(args,**kwargs):
    result=subprocess.run(args,capture_output=True,**kwargs)
    if result.returncode:raise RuntimeError(result.stderr.decode(errors='replace')+result.stdout.decode(errors='replace'))
    return result

def members(data):
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        return {m.name.removeprefix('./'):(archive.extractfile(m).read(),m.uid,m.gid,m.mode) for m in archive.getmembers() if m.isfile()}


def main():
    reference=ROOT/'.local/openwrt-ipkg-build'
    if not reference.exists() or hashlib.sha256(reference.read_bytes()).hexdigest()!='60714afe9b93fd0d3ecfd2fcef7839928b1a99e826ae30e2e3c0e24f1efde474':raise RuntimeError('run scripts/packaging-setup.sh; official IPK tool must match the pinned checksum')
    with tempfile.TemporaryDirectory(prefix='rahawrt-packages-') as temporary:
        temporary=Path(temporary);stage=temporary/'stage';stage.mkdir(mode=0o755)
        expected=ipk.payload()
        for name,(data,mode) in expected.items():
            path=stage/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);path.chmod(mode)
        for path in stage.rglob('*'):
            if path.is_dir():path.chmod(0o755)
        (stage/'etc/rahawrt').mkdir(exist_ok=True);(stage/'etc/rahawrt').chmod(0o700)
        own,digest=ipk.build(temporary/'own.ipk')
        own_members=members(own.read_bytes())
        assert own_members['debian-binary'][0]==b'2.0\n'
        control=members(own_members['control.tar.gz'][0]);controls=stage/'CONTROL';controls.mkdir()
        for name,(data,_,_,mode) in control.items():(controls/name).write_bytes(data);(controls/name).chmod(mode)
        run(['unshare','-Ur','sh',str(reference),str(stage),str(temporary)],env=dict(os.environ,SOURCE_DATE_EPOCH='0',TZ='UTC'))
        official=next(p for p in temporary.glob('*.ipk') if p.name!='own.ipk')
        official_members=members(official.read_bytes())
        assert set(official_members)==set(own_members)
        assert members(official_members['data.tar.gz'][0])==members(own_members['data.tar.gz'][0]),'official IPK payload mismatch'
        ipk.build(own);assert hashlib.sha256(own.read_bytes()).hexdigest()==digest
        print('PASS: architecture-all IPK payload matches the official OpenWrt packager; contents, modes, root ownership and repeat-build hash passed.')
        package,first=apk.build(temporary/'own.apk');apk.build(package)
        assert hashlib.sha256(package.read_bytes()).hexdigest()==first
        tool=ROOT/'.local/apk-build/src/apk';keys=temporary/'keys';keys.mkdir(mode=0o700)
        rejected=subprocess.run([str(tool),'--no-network','--keys-dir',str(keys),'verify',str(package)],capture_output=True)
        assert rejected.returncode!=0,'unsigned package unexpectedly verified'
        # Test keys are temporary fixtures, never project release credentials.
        private=temporary/'fixture-private.pem';public=keys/'fixture.pub'
        run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',str(private)])
        private.chmod(0o600)
        run(['openssl','pkey','-in',str(private),'-pubout','-out',str(public)])
        signed=temporary/'signed-fixture.apk'
        apk.build(signed,sign_key=private)
        run([str(tool),'--no-network','--keys-dir',str(keys),'verify',str(signed)])
        extracted=temporary/'extracted';extracted.mkdir()
        run([str(tool),'--no-network','--keys-dir',str(keys),'extract','--destination',str(extracted),str(signed)])
        for name,(data,mode) in expected.items():assert (extracted/name).read_bytes()==data and (extracted/name).stat().st_mode&0o777==mode
        corrupted=temporary/'corrupt.apk';raw=bytearray(signed.read_bytes());raw[-20]^=1;corrupted.write_bytes(raw)
        rejected=subprocess.run([str(tool),'--no-network','--keys-dir',str(keys),'verify',str(corrupted)],capture_output=True)
        assert rejected.returncode!=0,'corrupt package unexpectedly verified'
        print('PASS: noarch APK v3 reproducible build, unsigned rejection, temporary-key trusted signature verification, real extraction and tamper rejection. No router install or release signature claimed.')

if __name__=='__main__':main()
