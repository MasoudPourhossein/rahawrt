"""Sensitive bounded backups and offline restore with a preimage and rollback."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import zipfile
from .store import Store
from .runtime import run

CONFIGS=('network','firewall','dhcp','wireless','passwall2','rahawrt','openvpn','uhttpd')
MAX_SIZE=64*1024*1024


def allowed_file(name):
    path=Path(name)
    if path.is_absolute() or '..' in path.parts:return False
    return (path.parent==Path('etc/rahawrt/vpn') and path.name.startswith('rv_') and path.suffix=='.ovpn') or (path.parent==Path('etc/openconnect') and path.name.startswith('ca-vpn-rv_') and path.suffix=='.pem')


def build(store,runner=run,root=Path('/')):
    entries={}
    with store.lock:
        if store.db.execute("SELECT 1 FROM sqlite_master WHERE name='router_changes'").fetchone() and store.db.execute("SELECT 1 FROM router_changes WHERE status IN ('applying','awaiting','rollback_failed')").fetchone():
            raise ValueError('confirm or roll back pending router changes before backup')
        with tempfile.NamedTemporaryFile() as temporary:
            target=sqlite3.connect(temporary.name)
            store.db.backup(target);target.close()
            entries['state.db']=Path(temporary.name).read_bytes()
        for config in CONFIGS:
            if (root/'etc/config'/config).exists():entries['config/'+config+'.uci']=runner(['uci','export',config]).encode()
        for pattern in ('etc/rahawrt/vpn/rv_*.ovpn','etc/openconnect/ca-vpn-rv_*.pem'):
            for path in root.glob(pattern):
                if path.is_symlink() or not path.is_file():raise ValueError('refusing symlink in managed VPN files')
                if not path.resolve().is_relative_to(root.resolve()):raise ValueError('managed VPN file escapes root')
                entries['files/'+str(path.relative_to(root))]=path.read_bytes()
    if sum(map(len,entries.values()))>MAX_SIZE:raise ValueError('backup exceeds 64 MiB')
    manifest=dict(format=1,created=int(time.time()),sha256={name:hashlib.sha256(data).hexdigest() for name,data in entries.items()})
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as archive:
        for name,data in entries.items():archive.writestr(name,data)
        archive.writestr('manifest.json',json.dumps(manifest,sort_keys=True))
    return output.getvalue()


def validate(payload):
    if len(payload)>MAX_SIZE:raise ValueError('backup exceeds 64 MiB')
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        infos=archive.infolist()
        if len(infos)>256 or sum(i.file_size for i in infos)>MAX_SIZE or len({i.filename for i in infos})!=len(infos):raise ValueError('invalid/oversized archive')
        entries={i.filename:archive.read(i) for i in infos}
    manifest=json.loads(entries.pop('manifest.json'))
    if manifest.get('format')!=1 or set(manifest.get('sha256',{}))!=set(entries) or 'state.db' not in entries:raise ValueError('unsupported backup manifest')
    for name,data in entries.items():
        if name!='state.db' and name not in {'config/'+c+'.uci' for c in CONFIGS} and not (name.startswith('files/') and allowed_file(name[6:])):raise ValueError('unexpected backup path')
        if hashlib.sha256(data).hexdigest()!=manifest['sha256'][name]:raise ValueError('backup checksum mismatch')
    with tempfile.NamedTemporaryFile() as temporary:
        Path(temporary.name).write_bytes(entries['state.db'])
        db=sqlite3.connect('file:'+temporary.name+'?mode=ro',uri=True)
        try:
            db.execute('PRAGMA trusted_schema=OFF')
            if db.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise ValueError('backup database failed integrity check')
            names={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {'accounts','devices','usage','controls','plans','api_keys','session_history','audit','sessions'}.issubset(names):raise ValueError('wrong database schema')
            if db.execute("SELECT 1 FROM accounts WHERE role='admin'").fetchone() is None:raise ValueError('backup requires an administrator')
        finally:db.close()
    return entries


def write_private(path,data):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if path.is_symlink():raise ValueError('refusing symlink restore destination')
    temporary=path.with_name(path.name+'.restore-'+os.urandom(6).hex())
    descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(descriptor,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally:
        if temporary.exists():temporary.unlink()


def apply(entries,root,runner):
    for config in CONFIGS:
        name='config/'+config+'.uci'
        if name in entries:runner(['uci','import',config],entries[name].decode());runner(['uci','commit',config])
    for name,data in entries.items():
        if name.startswith('files/'):
            destination=root/name[6:]
            if not destination.parent.resolve().is_relative_to(root.resolve()):raise ValueError('restore path escapes root')
            write_private(destination,data)
    dbpath=root/'etc/rahawrt/state.db'
    if not dbpath.parent.resolve().is_relative_to(root.resolve()):raise ValueError('database restore path escapes root')
    for suffix in ('-wal','-shm'):
        path=Path(str(dbpath)+suffix)
        if path.exists():path.unlink()
    write_private(dbpath,entries['state.db'])
    db=sqlite3.connect(dbpath)
    try:
        with db:
            db.execute('DELETE FROM sessions')
            db.execute('UPDATE api_keys SET active=0')
            db.execute("UPDATE session_history SET ended=?,reason='restore' WHERE ended IS NULL",(int(time.time()),))
            db.execute("INSERT INTO audit(created,actor,action,subject) VALUES (?,'console','backup.restore','state')",(int(time.time()),))
    finally:db.close()
    for service in ('network','firewall','dnsmasq','passwall2','uhttpd'):
        runner(['/etc/init.d/'+service,'reload' if service=='network' else 'restart'])


def restore(payload,runner=run,root=Path('/')):
    entries=validate(payload)
    dbpath=root/'etc/rahawrt/state.db'
    source=Store(str(dbpath))
    try:preimage=build(source,runner,root)
    finally:source.db.close()
    recovery=root/'etc/rahawrt/recovery'/('before-restore-'+str(time.time_ns())+'.zip')
    write_private(recovery,preimage)
    # Remove the current database's owned kernel selectors before replacing its
    # journal. A restored older database cannot safely identify newer rules.
    source=Store(str(dbpath))
    try:
        if source.db.execute("SELECT 1 FROM sqlite_master WHERE name='native_routes'").fetchone():
            from .routes import Routes
            Routes(source,runner).sync({})
    finally:source.db.close()
    try:apply(entries,root,runner)
    except Exception:
        # Keep the preimage even if rollback itself fails; never print credentials.
        try:apply(validate(preimage),root,runner)
        except Exception:raise RuntimeError('restore and rollback failed; use the private recovery archive from console') from None
        raise RuntimeError('restore failed; previous database and configuration restored') from None
    return recovery


def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=('backup','restore'));p.add_argument('file');args=p.parse_args()
    path=Path(args.file);os.umask(0o077)
    if args.action=='backup':
        if path.exists():p.error('backup destination already exists')
        store=Store('/etc/rahawrt/state.db')
        try:payload=build(store)
        finally:store.db.close()
        descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(descriptor,'wb') as stream:stream.write(payload)
        print('Sensitive backup created; preserve it offline.')
    else:
        import subprocess
        if subprocess.run(['/etc/init.d/rahawrt','status'],capture_output=True).returncode==0:p.error('stop RahaWRT before offline restore')
        recovery=restore(path.read_bytes())
        print('Restored. All sessions and API keys revoked. Private recovery archive: '+str(recovery))


if __name__=='__main__':main()
