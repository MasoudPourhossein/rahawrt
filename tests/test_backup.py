import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import zipfile
from rahawrt.backup import build,validate,restore
from rahawrt.store import Store
from test_policy import sample


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        (self.root/'etc/config').mkdir(parents=True)
        for config in ('network','firewall','dhcp','passwall2','rahawrt'):(self.root/'etc/config'/config).write_text('configuration')
        self.path=self.root/'etc/rahawrt/state.db';self.path.parent.mkdir()
        self.store=Store(str(self.path));self.store.account('owner','backup-password-123','admin');self.store.put_device(sample())
        self.calls=[];self.fail_once=False
        def runner(args,data=None):
            self.calls.append((args,data))
            if args[:2]==['uci','export']:return "config test 'existing'\n option name 'preserve'\n"
            if self.fail_once and args==['/etc/init.d/firewall','restart']:
                self.fail_once=False;raise RuntimeError('injected failure')
            return ''
        self.runner=runner

    def tearDown(self):
        try:self.store.db.close()
        except Exception:pass
        self.tmp.cleanup()

    def test_restore_recovers_usage_and_revokes_keys_and_sessions(self):
        self.store.add_usage({'phone':(10,20)})
        token,_=self.store.login('owner','backup-password-123','127.0.0.1')
        key=self.store.create_key(dict(scopes=['usage:read']),'owner')
        payload=build(self.store,self.runner,self.root)
        self.assertIn('state.db',validate(payload))
        self.store.add_usage({'phone':(1000,2000)});self.store.db.close()
        recovery=restore(payload,self.runner,self.root)
        self.assertTrue(recovery.exists());self.assertEqual(recovery.stat().st_mode&0o777,0o600)
        self.store=Store(str(self.path));self.assertEqual(self.store.usage()['phone'],[10,20])
        self.assertIsNone(self.store.principal(token,'127.0.0.1'));self.assertIsNone(self.store.key_principal(key['token']))

    def test_failed_restore_automatically_restores_preimage(self):
        payload=build(self.store,self.runner,self.root)
        self.store.add_usage({'phone':(55,66)});self.store.db.close();self.fail_once=True
        with self.assertRaisesRegex(RuntimeError,'previous database'):
            restore(payload,self.runner,self.root)
        self.store=Store(str(self.path));self.assertEqual(self.store.usage()['phone'],[55,66])

    def test_corruption_and_path_traversal_rejected_before_mutation(self):
        payload=build(self.store,self.runner,self.root)
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:entries={name:archive.read(name) for name in archive.namelist()}
        entries['state.db']=b'corrupt'
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w') as archive:
            for name,data in entries.items():archive.writestr(name,data)
        with self.assertRaises(ValueError):validate(out.getvalue())
        entries['../../escape']=b'bad'
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w') as archive:
            for name,data in entries.items():archive.writestr(name,data)
        with self.assertRaises(ValueError):validate(out.getvalue())

    def test_pending_router_change_blocks_snapshot(self):
        self.store.db.execute('CREATE TABLE router_changes(status TEXT)');self.store.db.execute("INSERT INTO router_changes VALUES ('awaiting')");self.store.db.commit()
        with self.assertRaises(ValueError):build(self.store,self.runner,self.root)

    def test_native_routes_cleaned_before_replacing_current_journal(self):
        from unittest.mock import patch
        from rahawrt.routes import Routes
        Routes(self.store,self.runner)
        payload=build(self.store,self.runner,self.root)
        self.store.db.close()
        def cleanup(routes,desired):
            self.assertEqual(desired,{})
            self.assertFalse(any(a[:2]==['uci','import'] for a,d in self.calls))
        with patch('rahawrt.routes.Routes.sync',autospec=True,side_effect=cleanup) as cleaned:
            restore(payload,self.runner,self.root)
            cleaned.assert_called_once()
