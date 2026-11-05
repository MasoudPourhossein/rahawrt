import datetime as dt
import json
import subprocess
import unittest
from rahawrt.runtime import Runtime
from rahawrt.store import Store
from test_policy import sample


class FakeRouter:
    def __init__(self):
        self.calls = []
        self.fail = False
        self.fail_nft = False

    def __call__(self, args, data=None):
        self.calls.append((args,data))
        if args[0] == 'ubus':
            return json.dumps({'interface':[{'ipv4-address':[{'address':'192.168.1.1'}]}]})
        if args[:3] == ['uci','-q','show']:
            return 'passwall2.testnode=nodes\n'
        if args[:2] == ['uci','export']:
            return "config global\n option enabled '1'\n"
        if args[:3] == ['nft','-j','list']:
            return json.dumps({'nftables':[]})
        if (self.fail and args == ['/etc/init.d/passwall2','restart']) or (self.fail_nft and args == ['nft','-f','-'] and 'table inet rahawrt {' in data):
            raise subprocess.CalledProcessError(1,args)
        return ''


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.s = Store(':memory:')
        self.s.put_device(sample(node='testnode'))
        self.router = FakeRouter()
        self.r = Runtime(self.s, True, self.router)

    def tearDown(self):
        self.s.db.close()

    def test_adapter_uses_node_schema_and_preserves_other_sections(self):
        self.r.tick()
        batch = next(d for a,d in self.router.calls if a == ['uci','batch'])
        self.assertIn('passwall2.rw_phone.node=testnode', batch)
        self.assertNotIn('tcp_node', batch)
        self.assertNotIn('delete passwall2.testnode', batch)
        applied = next(d for a,d in self.router.calls if a == ['nft','-f','-'] and 'table inet rahawrt {' in d)
        self.assertIn('delete table inet rahawrt', applied)
        self.assertNotIn('flush ruleset', applied)
        self.assertTrue(self.r.status['applied'])

    def test_independent_vpn_schedule(self):
        d = sample(node='testnode', vpn=[{'days':[0],'start':'10:00','end':'11:00'}])
        self.assertEqual(self.r.passwall_plan([d], dt.datetime(2026,11,9,10))[0][2], 'testnode')
        self.assertEqual(self.r.passwall_plan([d], dt.datetime(2026,11,9,11))[0][2], 'direct')

    def test_unknown_node_keeps_existing_rules(self):
        self.s.put_device(sample(node='missing'))
        with self.assertRaises(ValueError): self.r.tick()
        self.assertFalse(any(a == ['uci','batch'] for a,d in self.router.calls))
        self.assertFalse(self.r.status['applied'])

    def test_failed_nft_restores_passwall(self):
        self.router.fail_nft = True
        with self.assertRaises(subprocess.CalledProcessError): self.r.tick()
        self.assertTrue(any(a == ['uci','import','passwall2'] for a,d in self.router.calls))
        self.assertFalse(self.r.status['applied'])
        self.router.fail_nft = False
        self.r.tick()
        self.assertTrue(self.r.status['applied'])

    def test_failed_restart_never_applies_nft(self):
        self.router.fail = True
        with self.assertRaisesRegex(RuntimeError,'console recovery required for PassWall2'): self.r.tick()
        self.assertTrue(any(a == ['uci','import','passwall2'] for a,d in self.router.calls))
        self.assertFalse(any(a == ['nft','-f','-'] and 'table inet rahawrt {' in d for a,d in self.router.calls))

    def test_preview_never_mutates_router(self):
        r = Runtime(self.s, False, self.router)
        r.tick()
        self.assertEqual(self.router.calls, [])
        self.assertIn('table inet rahawrt', r.status['plan'])

    def test_existing_acl_overlap_refused(self):
        original = self.router
        def run(args, data=None):
            value = original(args, data)
            if args == ['uci', '-q', 'show', 'passwall2']:
                return value+"passwall2.other=acl_rule\npasswall2.other.enabled='1'\npasswall2.other.sources='192.168.1.0/24'\n"
            return value
        self.r.run = run
        with self.assertRaisesRegex(ValueError, 'overlap'):
            self.r.tick()
        self.assertFalse(any(a == ['uci','batch'] for a,d in original.calls))

    def test_pending_user_edits_refused(self):
        original = self.router
        def run(args, data=None):
            if args == ['uci','changes','passwall2']:
                return "passwall2.testnode.remarks='pending'"
            return original(args, data)
        self.r.run = run
        with self.assertRaisesRegex(ValueError, 'pending'):
            self.r.tick()

    def test_guard_precedes_restart(self):
        self.r.tick()
        guard = next(i for i,(a,d) in enumerate(self.router.calls) if a == ['nft','-f','-'] and 'table inet rahawrt_transition' in d)
        restart = next(i for i,(a,d) in enumerate(self.router.calls) if a == ['/etc/init.d/passwall2','restart'])
        self.assertLess(guard,restart)

    def test_client_observation_uses_neighbor_mac_without_claiming_presence(self):
        import tempfile
        from pathlib import Path
        entries=[dict(dst='192.168.1.20',lladdr='02:11:22:33:44:55',state=['STALE'],dev='br-lan'),dict(dst='192.168.1.21',lladdr='02:11:22:33:44:99',state=['REACHABLE'],dev='br-lan')]
        runtime=Runtime(self.s,True,lambda *args:json.dumps(entries))
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'leases'
            path.write_text('0 02:11:22:33:44:55 192.168.1.20 Phone *\n0 02:11:22:33:44:56 192.168.1.21 Other *\n0 02:11:22:33:44:57 192.168.1.22 Third *\n')
            clients=runtime.clients(path)
        self.assertEqual([c['neighbor_state'] for c in clients],[['STALE'],['MAC_MISMATCH'],['UNKNOWN']])
        self.assertEqual(clients[0]['observed_interface'],'br-lan')
        self.assertNotIn('online',clients[0])

    def test_strict_shunt_rejected_before_policy_mutation_even_outside_window(self):
        original=self.router
        def runner(args,data=None):
            if args==['uci','-q','get','passwall2.testnode.protocol']:return '_shunt'
            return original(args,data)
        runtime=Runtime(self.s,True,runner)
        with self.assertRaisesRegex(ValueError,'concrete remote node'):runtime.tick()
        self.assertFalse(any(a[:3]==['nft','-f','-'] for a,d in self.router.calls))
        runtime.validate_strict_nodes([dict(sample(node='testnode'),vpn_failure='direct')])
