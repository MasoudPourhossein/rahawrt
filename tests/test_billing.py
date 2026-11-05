import concurrent.futures
import json
import tempfile
import time
import unittest
from unittest.mock import patch
from rahawrt.billing import plan
from rahawrt.store import Store
from test_policy import sample


class BillingTests(unittest.TestCase):
    def setUp(self):
        self.s=Store(':memory:')
        self.s.put_device(sample(hotspot=True))
        self.s.put_plan(dict(id='hotel',quota_bytes=1000,upload_kbps=100,download_kbps=200,valid_seconds=3600,online_seconds=600,max_devices=1,max_sessions=1,node='default'),'owner')

    def tearDown(self):
        self.s.db.close()

    def issue(self, **kw):
        return self.s.issue(dict(invoice_id='bill_1',plan_id='hotel',**kw),'cash_register')

    def test_invoice_concurrent_retry_never_duplicates(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            replies=list(pool.map(lambda _: self.issue(),range(6)))
        self.assertEqual(sum(r['created'] for r in replies),1)
        self.assertEqual(len({r['username'] for r in replies}),1)
        self.assertEqual(sum(r['password'] is not None for r in replies),1)
        self.assertEqual(self.s.db.execute("SELECT COUNT(*) FROM accounts WHERE role='user'").fetchone()[0],1)
        with self.assertRaisesRegex(ValueError,'conflict'):
            self.s.issue(dict(invoice_id='bill_1',plan_id='different'),'cash_register')

    def test_hash_only_and_audit_redaction(self):
        credentials=self.issue(password='printer-password-123')
        blob=' '.join(str(tuple(row)) for row in self.s.db.execute('SELECT * FROM invoices'))+' '.join(str(tuple(row)) for row in self.s.db.execute('SELECT * FROM audit'))+' '.join(str(tuple(row)) for row in self.s.db.execute('SELECT * FROM accounts'))
        self.assertNotIn(credentials['password'],blob)
        self.assertIsNone(self.issue(password='printer-password-123')['password'])
        with self.assertRaises(ValueError): self.issue(password='other-password-123')

    def test_plan_applies_after_login_and_quota_closes_gate(self):
        c=self.issue()
        self.s.login(c['username'],c['password'],'192.168.1.20')
        effective=self.s.effective_devices()[0]
        self.assertEqual((effective['node'],effective['_account_limit']['upload_kbps'],effective['_account_limit']['download_kbps']),('default',100,200))
        self.assertEqual(self.s.online(),{'phone'})
        self.s.add_usage({'phone':(200,800)})
        self.assertFalse(self.s.effective_devices()[0]['enabled'])
        self.assertEqual(self.s.online(),set())
        self.assertEqual(self.s.account_state(c['username'])['remaining_bytes'],0)

    def test_throttle_plan_and_device_cap(self):
        self.s.put_plan(dict(id='slow',quota_bytes=100,quota_action='throttle',reduced_upload_kbps=10,reduced_download_kbps=20,upload_kbps=1000,download_kbps=2000),'owner')
        c=self.s.issue(dict(invoice_id='slow_invoice',plan_id='slow'),'owner')
        self.s.login(c['username'],c['password'],'192.168.1.20')
        d=sample(hotspot=True,upload_kbps=5);self.s.put_device(d)
        self.s.add_usage({'phone':(100,0)})
        d=self.s.effective_devices()[0]
        self.assertTrue(d['enabled']);self.assertEqual((d['upload_kbps'],d['_account_limit']['download_kbps']),(5,20))

    def test_device_and_simultaneous_session_limits(self):
        second=sample(hotspot=True);second.update(id='tablet',ip='192.168.1.21',mac='02:11:22:33:44:56');self.s.put_device(second)
        c=self.issue();token,_=self.s.login(c['username'],c['password'],'192.168.1.20')
        with self.assertRaisesRegex(PermissionError,'limit'):
            self.s.login(c['username'],c['password'],'192.168.1.21')
        replacement,_=self.s.login(c['username'],c['password'],'192.168.1.20')
        self.assertIsNone(self.s.principal(token,'192.168.1.20'));self.assertIsNotNone(self.s.principal(replacement,'192.168.1.20'))

    def test_suspend_renew_idempotency_and_deleted_gate(self):
        c=self.issue();name=c['username'];token,_=self.s.login(name,c['password'],'192.168.1.20')
        self.s.manage_account(dict(name=name,action='suspend'),'owner')
        self.assertIsNone(self.s.principal(token,'192.168.1.20'))
        self.assertFalse(self.s.effective_devices()[0]['enabled'])
        self.s.add_usage({'phone':(1000,0)})
        action=dict(name=name,action='renew',plan_id='hotel',invoice_id='renew_1')
        self.s.manage_account(action,'cash_register')
        self.s.add_usage({'phone':(100,0)})
        replay=self.s.manage_account(action,'cash_register')
        self.assertTrue(replay['replayed']);self.assertEqual(self.s.account_state(name)['consumed_bytes'],100)
        self.s.manage_account(dict(name=name,action='delete'),'owner')
        self.assertFalse(self.s.effective_devices()[0]['enabled'])
        self.assertEqual(self.issue()['username'],name)
        self.assertIsNone(self.issue()['password'])

    def test_online_time_expiry_and_reports(self):
        c=self.issue();name=c['username']
        now=int(time.time())
        with patch('time.time',return_value=now): self.s.login(name,c['password'],'192.168.1.20')
        self.s.tick_accounts(now+601)
        self.assertFalse(self.s.account_state(name)['allowed'])
        self.s.add_usage({'phone':(12,34)})
        report=self.s.report(name,'monthly')
        self.assertEqual((report[0]['upload_bytes'],report[0]['download_bytes']),(12,34))
        self.s.db.execute('UPDATE controls SET online_used=0,expires=? WHERE name=?',(now-1,name));self.s.db.commit()
        self.assertFalse(self.s.effective_devices()[0]['enabled'])

    def test_keys_scopes_rate_limit_revoke_and_no_plaintext(self):
        key=self.s.create_key(dict(scopes=['accounts:issue'],ttl_seconds=60),'owner')
        self.assertEqual(self.s.key_principal(key['token'])[2],['accounts:issue'])
        self.assertNotIn(key['token'],str(self.s.db.execute('SELECT * FROM api_keys').fetchone()))
        for _ in range(59): self.s.key_principal(key['token'])
        with self.assertRaises(OverflowError): self.s.key_principal(key['token'])
        self.s.revoke_key(key['id'],'owner');self.assertIsNone(self.s.key_principal(key['token']))

    def test_plan_rejects_invalid_limits(self):
        for d in (dict(id='bad',max_devices=0),dict(id='bad',quota_action='throttle'),dict(id='bad',node='x;sh'),dict(id='bad',valid_seconds=True)):
            with self.assertRaises(ValueError): plan(d)

    def test_batch_spec_cannot_change_on_retry(self):
        data=dict(batch_id='print_batch',plan_id='hotel',count=2)
        first=self.s.issue_batch(data,'register')
        replay=self.s.issue_batch(data,'register')
        self.assertEqual([c['username'] for c in first],[c['username'] for c in replay])
        self.assertTrue(all(c['password'] is None for c in replay))
        with self.assertRaisesRegex(ValueError,'conflict'):self.s.issue_batch(dict(data,count=3),'register')

    def test_password_reset_recovers_lost_printout_without_duplicate_account(self):
        c=self.issue();name=c['username'];old,_=self.s.login(name,c['password'],'192.168.1.20')
        reset=self.s.manage_account(dict(name=name,action='password-reset'),'register')
        self.assertIsNone(self.s.principal(old,'192.168.1.20'))
        with self.assertRaises(PermissionError):self.s.login(name,c['password'],'192.168.1.20')
        self.s.login(name,reset['password'],'192.168.1.20')
        self.assertEqual(self.s.db.execute("SELECT COUNT(*) FROM accounts WHERE role='user'").fetchone()[0],1)
        self.assertNotIn(reset['password'],str(self.s.db.execute('SELECT * FROM audit').fetchall()))
