import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from rahawrt.boot_guard import beat,healthy,install,owned,rules,MARKER
from test_policy import sample


class GuardTests(unittest.TestCase):
    def test_private_heartbeat_expiry_and_future_clock_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'run/heartbeat.json';self.assertFalse(healthy(path))
            beat(path);self.assertTrue(healthy(path))
            value=json.loads(path.read_text());self.assertFalse(healthy(path,value['monotonic']+16));self.assertFalse(healthy(path,value['monotonic']-1))
            path.chmod(0o644);self.assertFalse(healthy(path))

    def test_guard_preserves_only_local_management_and_blocks_ipv6_mac(self):
        source=rules([sample()],['192.168.1.1'],dict(network='192.168.50.0/24',interface='br-rahaguest'))
        self.assertIn('priority -310',source);self.assertIn('ether saddr 02:11:22:33:44:55 drop',source)
        self.assertIn('ip saddr 192.168.1.20 drop',source);self.assertIn('ip saddr 192.168.50.0/24 drop',source)
        self.assertNotIn('dport 53 return',source);self.assertNotIn('flush ruleset',source)

    def test_foreign_table_and_pending_firewall_edits_are_never_overwritten(self):
        calls=[]
        def foreign(args,data=None):
            calls.append(args);return json.dumps({'nftables':[{'table':{'name':'rahawrt_boot','comment':'someone else'}}]})
        with self.assertRaisesRegex(ValueError,'unowned'):owned(foreign)
        self.assertEqual(len(calls),1)
        with self.assertRaisesRegex(ValueError,'pending'):install(lambda *args:'staged edit')

    def test_install_refuses_foreign_include(self):
        calls=[]
        def runner(args,data=None):
            calls.append(args)
            if args[:2]==['uci','changes']:return ''
            if args[-1]=='firewall.rw_guard':return 'include'
            return '0'
        with self.assertRaisesRegex(ValueError,'unowned'):install(runner)
        self.assertFalse(any(a[:2]==['uci','set'] for a in calls))
