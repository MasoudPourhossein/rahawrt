#!/usr/bin/env python3
"""Reproducible architecture-all IPK using OpenWrt's GNU-tar container format.

This assembles a native package archive, not an SDK cross-build or router install.
"""
import gzip
import hashlib
import io
from pathlib import Path
import re
import tarfile

ROOT=Path(__file__).resolve().parents[1]


def metadata():
    source=(ROOT/'openwrt/Makefile').read_text()
    def field(name):
        match=re.search(r'^\s*'+re.escape(name)+r':=(.+)$',source,re.M)
        if not match:raise ValueError('missing package '+name)
        return match[1].strip()
    dependencies=[]
    for value in field('DEPENDS').split():
        if not re.fullmatch(r'\+[A-Za-z0-9_.+-]+',value):raise ValueError('standalone builder requires unconditional package dependencies')
        dependencies.append(value[1:])
    return dict(name=field('PKG_NAME'),version=field('PKG_VERSION')+'-r'+field('PKG_RELEASE'),architecture=field('PKGARCH'),title=field('TITLE'),dependencies=dependencies,license=field('PKG_LICENSE'))


def payload():
    result={'lib/upgrade/keep.d/rahawrt':(b'/etc/rahawrt/\n',0o644)}
    def add(path,source,mode=0o644):result[path]=(Path(source).read_bytes(),mode)
    for source in (ROOT/'rahawrt').glob('*.py'):add('usr/lib/rahawrt/rahawrt/'+source.name,source)
    for source in (ROOT/'web').iterdir():
        if source.is_file():
            add('usr/share/rahawrt/web/'+source.name,source)
            add('www/wrt/'+source.name,source)
            add('usr/share/rahawrt/public/wrt/'+source.name,source)
    add('usr/share/rahawrt/public/cgi-bin/rahawrt',ROOT/'openwrt/files/rahawrt.cgi',0o755)
    add('www/cgi-bin/rahawrt',ROOT/'openwrt/files/rahawrt.cgi',0o755)
    add('usr/share/rahawrt/guest.httpd.conf',ROOT/'openwrt/files/guest.httpd.conf')
    add('usr/libexec/rahawrt-guard',ROOT/'openwrt/files/rahawrt.guard',0o755)
    add('etc/init.d/rahawrt',ROOT/'openwrt/files/rahawrt.init',0o755)
    add('etc/config/rahawrt',ROOT/'openwrt/files/rahawrt.config',0o600)
    add('usr/share/rahawrt/scripts/router.sh',ROOT/'scripts/router.sh',0o755)
    add('usr/share/doc/rahawrt/LICENSE',ROOT/'LICENSE')
    add('usr/share/doc/rahawrt/THIRD_PARTY.md',ROOT/'THIRD_PARTY.md')
    return result


def archive(files,directories=None):
    directories=dict(directories or {})
    directories.setdefault('',0o755)
    for name in files:
        for parent in Path(name).parents:
            text=str(parent)
            if text!='.':directories.setdefault(text,0o755)
    output=io.BytesIO()
    with gzip.GzipFile(filename='',mode='wb',fileobj=output,mtime=0) as compressed:
        with tarfile.open(fileobj=compressed,mode='w|',format=tarfile.GNU_FORMAT) as tar:
            entries={name:None for name in directories};entries.update(files)
            for name,value in sorted(entries.items()):
                info=tarfile.TarInfo('./'+name if name else '.')
                info.uid=info.gid=0;info.uname=info.gname='';info.mtime=0
                if value is None:
                    info.type=tarfile.DIRTYPE;info.mode=directories[name];tar.addfile(info)
                else:
                    data,mode=value;info.mode=mode;info.size=len(data);tar.addfile(info,io.BytesIO(data))
    return output.getvalue()


def build(destination=None):
    meta=metadata()
    if meta['architecture']!='all':raise ValueError('this builder is for architecture-independent payloads only')
    files=payload();data=archive(files,{'etc/rahawrt':0o700})
    installed_size=len(gzip.decompress(data))
    control=('Package: '+meta['name']+'\nVersion: '+meta['version']+'\nArchitecture: all\nLicense: '+meta['license']+'\nSection: net\nPriority: optional\nMaintainer: RahaWRT maintainers\nDepends: '+', '.join(meta['dependencies'])+'\nInstalled-Size: '+str(installed_size)+'\nDescription: '+meta['title']+'\n')
    controls=archive({'control':(control.encode(),0o644),'conffiles':(b'/etc/config/rahawrt\n',0o644)})
    result=archive({'debian-binary':(b'2.0\n',0o644),'data.tar.gz':(data,0o644),'control.tar.gz':(controls,0o644)})
    destination=Path(destination) if destination else ROOT/'dist'/(meta['name']+'_'+meta['version']+'_all.ipk')
    destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(result)
    # Verify every deployment path and byte before reporting a successful build.
    with tarfile.open(fileobj=io.BytesIO(result)) as package:
        assert package.extractfile('./debian-binary').read()==b'2.0\n'
        with tarfile.open(fileobj=io.BytesIO(package.extractfile('./data.tar.gz').read())) as content:
            actual={m.name.removeprefix('./'):m for m in content.getmembers() if m.isfile()}
            if set(actual)!=set(files):raise ValueError('IPK payload mismatch')
            for name,(expected,mode) in files.items():
                item=actual[name]
                if item.uid!=0 or item.gid!=0 or item.mode!=mode or content.extractfile(item).read()!=expected:raise ValueError('invalid IPK member')
    digest=hashlib.sha256(result).hexdigest()
    (destination.parent/(destination.name+'.sha256')).write_text(digest+'  '+destination.name+'\n')
    return destination,digest


if __name__=='__main__':
    path,digest=build();print(digest+'  '+path.name)
