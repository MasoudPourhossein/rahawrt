import ipaddress
import time
import unittest
from rahawrt.guest import Guest,guest_plan,bootstrap_rules
from rahawrt.policy import compile_nft
from rahawrt.store import Store
from test_policy import sample


class GuestTests(unittest.TestCase):
    def setUp(self):self.store=Store(':memory:')
    def tearDown(self):self.store.db.close()

    def test_isolated_guest_plan_and_portal_discovery(self):
        sections=guest_plan(dict(address='192.168.50.1/24',radio='radio0',ssid='Hotel',password='wifi-password-123'),['192.168.1.0/24'])
        zone=sections['firewall']['rw_guest']['options']
        self.assertEqual((zone['input'],zone['forward']),('REJECT','REJECT'))
        self.assertEqual(sections['wireless']['rw_guest']['options']['isolate'],'1')
        self.assertNotIn('lan',str(sections))
        self.assertEqual(sections['uhttpd']['rw_guest']['options']['home'],'/usr/share/rahawrt/public')
        self.assertEqual(sections['uhttpd']['rw_guest']['options']['config'],'/usr/share/rahawrt/guest.httpd.conf')
        self.assertEqual(sections['firewall']['rw_guest_portal']['options']['dest_port'],'8443 2080')
        self.assertIn('114,https://192.168.50.1:8443/',sections['dhcp']['rw_guest']['options']['dhcp_option'][0])
        self.assertIn('ip saddr 192.168.50.0/24 drop',bootstrap_rules('192.168.50.1/24'))

    def test_invalid_or_overlapping_networks_rejected(self):
        for data in (dict(address='192.168.1.1/24'),dict(address='127.0.0.1/24'),dict(address='192.168.50.2/24'),dict(address='192.168.50.1/16'),dict(address='192.168.50.1/24',radio='radio0',password='short')):
            with self.assertRaises(ValueError):guest_plan(data,['192.168.1.0/24'])

    def test_unknown_guest_default_denied_and_dhcp_not_blocked(self):
        guest=dict(network='192.168.50.0/24',gateway='192.168.50.1',interface='br-rahaguest')
        policy=compile_nft([],{},set(),local_ips=['192.168.50.1'],guest=guest)
        self.assertIn('iifname "br-rahaguest" meta nfproto ipv6 drop',policy)
        self.assertIn('ip saddr 192.168.50.0/24 drop',policy)
        self.assertIn('udp sport 68 udp dport 67 return',policy)
        self.assertIn('ip daddr 192.168.50.0/24 drop',policy)

    def test_lease_enrollment_mac_rebinding_revokes_session(self):
        guest=Guest(self.store,None)
        settings=dict(network='192.168.50.0/24',gateway='192.168.50.1',interface='br-rahaguest')
        client=dict(ip='192.168.50.10',mac='02:11:22:33:44:55',name='Guest')
        guest.sync([client],settings)
        d=self.store.devices()[0];self.assertTrue(d['hotspot'])
        self.store.account('guest','guest-password-123','user',d['id'])
        token,_=self.store.login('guest','guest-password-123',client['ip'])
        self.assertFalse(guest.captive(client['ip'],settings)['captive'])
        guest.sync([dict(client,ip='192.168.50.11')],settings)
        self.assertEqual(self.store.devices()[0]['id'],d['id'])
        self.assertIsNone(self.store.principal(token,client['ip']))
        self.assertTrue(guest.captive('192.168.50.11',settings)['captive'])
        self.assertFalse(guest.captive('192.168.1.10',settings)['guest'])
