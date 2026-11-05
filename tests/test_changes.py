import concurrent.futures
import json
import threading
import time
import unittest
from rahawrt.changes import ChangeGuard
from rahawrt.store import Store


class ChangesTests(unittest.TestCase):
    def setUp(self):
        self.store=Store(':memory:');self.calls=[];self.fail=False
        def runner(args,data=None):
            self.calls.append((args,data))
            if self.fail and args[:2]==['uci','set']:raise RuntimeError('sensitive-key=DO-NOT-LOG')
            if args[:2]==['uci','export']:return "config interface 'lan'\n option proto 'static'\n"
            return ''
        self.guard=ChangeGuard(self.store,runner)
        self.sections={'network':{'rw_guest':dict(type='interface',options=dict(proto='static',ipaddr='192.168.50.1'))}}

    def tearDown(self):self.store.db.close()

    def wait(self):
        deadline=time.monotonic()+2
        while self.guard.status()[0]['status']=='applying':
            if time.monotonic()>deadline:self.fail('worker timed out')
            time.sleep(.01)

    def test_confirm_purges_sensitive_snapshots(self):
        result=self.guard.start('guest',self.sections,[],'owner');self.wait()
        with self.assertRaises(ValueError):self.guard.confirm(result['id'],'bad-token','owner')
        self.guard.confirm(result['id'],result['confirmation_token'],'owner')
        row=self.store.db.execute('SELECT exports,token,status FROM router_changes').fetchone()
        self.assertEqual(row,('{}','','confirmed'))
        self.assertNotIn('confirmation_token',json.dumps(self.guard.status()))

    def test_timeout_and_restart_recover_uci(self):
        result=self.guard.start('guest',self.sections,[['service','reload']],'owner');self.wait()
        self.store.db.execute('UPDATE router_changes SET deadline=0');self.store.db.commit()
        self.guard.check()
        self.assertEqual(self.guard.status()[0]['status'],'rolled_back')
        self.assertTrue(any(a==['uci','import','network'] for a,d in self.calls))
        self.guard.start('guest',self.sections,[],'owner');self.wait()
        restarted=ChangeGuard(self.store,self.guard.run);restarted.recover()
        self.assertTrue(all(r['status']=='rolled_back' for r in restarted.status()))

    def test_failed_apply_rolls_back_without_secret_errors(self):
        self.fail=True
        self.guard.start('guest',self.sections,[],'owner');self.wait()
        self.assertEqual(self.guard.status()[0]['status'],'rolled_back')
        self.assertNotIn('DO-NOT-LOG',json.dumps(self.guard.status()))
        self.assertTrue(any(a==['uci','import','network'] for a,d in self.calls))

    def test_parallel_changes_refused_until_confirmed(self):
        self.guard.start('guest',self.sections,[],'owner');self.wait()
        with self.assertRaisesRegex(ValueError,'previous'):
            self.guard.start('guest',self.sections,[],'owner')

    def test_failed_exclusive_file_create_never_deletes_existing_file(self):
        original=self.guard.run
        def runner(args,data=None):
            if args==['exclusive-create']:raise FileExistsError('pre-existing file')
            return original(args,data)
        self.guard.run=runner
        self.guard.start('vpn',self.sections,[],'owner',prepare=[(['exclusive-create'],'new secret')],cleanup=[['rm','old-user-file']])
        self.wait()
        self.assertFalse(any(a==['rm','old-user-file'] for a,d in self.calls))
