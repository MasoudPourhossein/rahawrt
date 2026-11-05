import datetime as dt
import unittest
from rahawrt.policy import active, compile_nft, device


def sample(**kwargs):
    return device(dict(id='phone', name='Phone', ip='192.168.1.20', mac='02:11:22:33:44:55', **kwargs))


class PolicyTests(unittest.TestCase):
    def test_injection_and_types(self):
        for change in ({'id':'x; delete table inet fw4'}, {'node':'a\nexec'}, {'ip':'1.2.3.4;drop'}, {'mac':'*'}, {'quota_bytes':True}, {'internet':[{'days':[7],'start':'00:00','end':'01:00'}]}, {'blocked_ips':['::/0']}, {'enabled':'false'}):
            with self.subTest(change=change), self.assertRaises((ValueError, TypeError)):
                d = sample(); d.update(change); device(d)

    def test_overnight_and_week_boundary(self):
        w = [{'days':[6], 'start':'22:00', 'end':'02:00'}]
        self.assertTrue(active(w, dt.datetime(2026,11,8,23)))
        self.assertTrue(active(w, dt.datetime(2026,11,9,1)))
        self.assertFalse(active(w, dt.datetime(2026,11,9,2)))
        self.assertFalse(active(w, dt.datetime(2026,11,9,23)))

    def test_schedule_half_open(self):
        w = [{'days':[0], 'start':'10:00', 'end':'11:00'}]
        self.assertTrue(active(w, dt.datetime(2026,11,9,10)))
        self.assertFalse(active(w, dt.datetime(2026,11,9,11)))

    def test_quota_and_hotspot(self):
        d = sample(quota_bytes=100, hotspot=True)
        self.assertIn('ip saddr 192.168.1.20 drop', compile_nft([d], {}, set()))
        self.assertNotIn('ip saddr 192.168.1.20 drop', compile_nft([d], {'phone':[40,59]}, {'phone'}))
        self.assertIn('ip saddr 192.168.1.20 drop', compile_nft([d], {'phone':[40,60]}, {'phone'}))

    def test_policers_parental_and_ipv6(self):
        d = sample(upload_kbps=80, download_kbps=160, blocked_ips=['203.0.113.0/24'])
        rules = compile_nft([d], {}, set())
        self.assertIn('rate over 10000 bytes/second', rules)
        self.assertIn('rate over 20000 bytes/second', rules)
        self.assertIn('ip daddr 203.0.113.0/24 drop', rules)
        self.assertIn('meta nfproto ipv6 drop', rules)
        self.assertIn('ip saddr != 192.168.1.20 drop', rules)
        self.assertNotIn('flush ruleset', rules)

    def test_proxy_traffic_hooks_and_guard(self):
        d = sample(node='node_a')
        rules = compile_nft([d], {}, set(), local_ips=['192.168.1.1'])
        self.assertIn('hook prerouting priority -300',rules)
        self.assertIn('hook output priority 0',rules)
        self.assertIn('ip saddr 192.168.1.20 drop',rules)
        self.assertIn('ip saddr @router4 ip daddr 192.168.1.20 tcp sport',rules)
        self.assertIn('ip saddr 192.168.1.20 ip daddr @router4 tcp dport 53 drop',rules)
        permissive = compile_nft([sample(node='node_a',vpn_failure='direct')],{},set())
        self.assertNotIn('ip saddr 192.168.1.20 drop',permissive)

    def test_non_unicast_identities_rejected(self):
        for ip in ('0.0.0.0','127.0.0.1','224.0.0.1','169.254.1.1','255.255.255.255'):
            d = sample(); d['ip'] = ip
            with self.assertRaises(ValueError): device(d)
        for mac in ('ff:ff:ff:ff:ff:ff','01:00:5e:00:00:01','00:00:00:00:00:00'):
            d = sample(); d['mac'] = mac
            with self.assertRaises(ValueError): device(d)
