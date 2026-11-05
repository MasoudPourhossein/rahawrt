import tempfile
import unittest
from rahawrt.store import Store, password_ok
from test_policy import sample


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = self.tmp.name+'/state.db'
        self.s = Store(self.path)
        self.s.put_device(sample(hotspot=True))
        self.s.account('guest', 'secure-password-123', 'user', 'phone')

    def tearDown(self):
        self.s.db.close()
        self.tmp.cleanup()

    def test_password_hash_and_device_binding(self):
        hashed = self.s.db.execute('SELECT hash FROM accounts').fetchone()[0]
        self.assertNotIn('secure-password', hashed)
        self.assertTrue(password_ok('secure-password-123', hashed))
        with self.assertRaises(PermissionError):
            self.s.login('guest', 'secure-password-123', '192.168.1.21')
        token, role = self.s.login('guest', 'secure-password-123', '192.168.1.20')
        self.assertEqual(role, 'user')
        self.assertIsNone(self.s.principal(token, '192.168.1.21'))
        self.assertEqual(self.s.online(), {'phone'})
        self.s.logout(token)
        self.assertFalse(self.s.online())

    def test_expiry_and_password_change_revoke(self):
        token, _ = self.s.login('guest', 'secure-password-123', '192.168.1.20')
        with self.s.db:
            self.s.db.execute('UPDATE sessions SET expires=0')
        self.assertIsNone(self.s.principal(token, '192.168.1.20'))
        token, _ = self.s.login('guest', 'secure-password-123', '192.168.1.20')
        self.s.account('guest', 'new-password-456', 'user', 'phone')
        self.assertIsNone(self.s.principal(token, '192.168.1.20'))

    def test_persistent_accounting_and_restart_checkpoint(self):
        self.s.sample_counters({('g1','phone','up'):100})
        self.s.sample_counters({('g1','phone','up'):140})
        self.s.db.close()
        self.s = Store(self.path)
        self.s.sample_counters({('g1','phone','up'):180})
        self.s.sample_counters({('g2','phone','up'):25})
        self.assertEqual(self.s.usage()['phone'], [205,0])

    def test_duplicate_ip_and_mac(self):
        d = sample(); d['id'] = 'another'
        with self.assertRaises(ValueError):
            self.s.put_device(d)

    def test_receipt_idempotency_conflict(self):
        receipt = dict(id='invoice_1', account='guest', amount_minor=100, currency='IRR', reference='test')
        self.s.receipt(receipt); self.s.receipt(receipt)
        self.assertEqual(self.s.db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0], 1)
        with self.assertRaises(ValueError):
            self.s.receipt(dict(receipt, amount_minor=200))

    def test_large_counter_snapshot_respects_embedded_sqlite_variable_limit(self):
        import sqlite3
        self.s.db.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER,100)
        counts={('g1','device_'+str(i),'up'):i for i in range(500)}
        self.s.sample_counters(counts)
        self.s.sample_counters({(g,i,d):count+10 for (g,i,d),count in counts.items()})
        self.assertEqual(self.s.usage()['device_499'],[509,0])
        self.assertEqual(self.s.db.execute('SELECT COUNT(*) FROM checkpoints').fetchone()[0],500)
