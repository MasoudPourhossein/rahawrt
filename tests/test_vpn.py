import base64
import unittest
import secrets
from rahawrt.vpn import provision,openvpn_profile,wg_import

KEY=base64.b64encode(secrets.token_bytes(32)).decode()
CA='-----BEGIN CERTIFICATE-----\nTEST-ONLY-NOT-A-REAL-CERTIFICATE\n-----END CERTIFICATE-----\n'


class VPNTests(unittest.TestCase):
    def test_wireguard_import_has_no_default_route_or_scripts(self):
        profile='[Interface]\nPrivateKey = '+KEY+'\nAddress = 10.8.0.2/32\nDNS = 1.1.1.1\nMTU = 1380\n[Peer]\nPublicKey = '+KEY+'\nEndpoint = vpn.example:51820\nAllowedIPs = 0.0.0.0/0\n'
        prepared=provision(dict(id='wg1',kind='wireguard',profile=profile))
        interface=prepared['sections']['network']['rv_wg1']['options'];peer=prepared['sections']['network']['rv_wg1_peer']['options']
        self.assertEqual(interface['defaultroute'],'0');self.assertEqual(interface['peerdns'],'0');self.assertEqual(interface['mtu'],'1380')
        self.assertEqual(peer['route_allowed_ips'],'0')
        with self.assertRaises(ValueError):provision(dict(id='wg1',kind='wireguard',profile=profile+'PostUp=touch /tmp/pwn\n'))

    def test_openvpn_manual_requires_complete_server_and_ca(self):
        prepared=provision(dict(id='ov1',kind='openvpn',server='vpn.example',username='vpn-user',password='vpn-pass',ca=CA))
        source=prepared['prepare'][0][1]
        for option in ('remote vpn.example 1194','remote-cert-tls server','tls-version-min 1.2','route-nopull','auth-nocache'):self.assertIn(option,source)
        self.assertNotIn('vpn-pass',source)
        self.assertEqual(prepared['sections']['network']['rv_ov1']['options']['defaultroute'],'0')
        with self.assertRaises((KeyError,ValueError)):provision(dict(id='ov1',kind='openvpn',username='user',password='pass'))

    def test_openvpn_import_rejects_execution_and_external_files(self):
        base='client\nremote vpn.example 1194\n<ca>\n'+CA+'</ca>\n'
        for malicious in ('up /tmp/run\n','plugin /tmp/plugin.so\n','script-security 2\n','auth-user-pass /etc/shadow\n','ca /etc/secret\n','tls-verify /tmp/run\n','proto tcp-server\n','verb 9\n'):
            with self.subTest(malicious=malicious),self.assertRaises(ValueError):openvpn_profile(base+malicious,'rv_ov1')

    def test_openconnect_preserves_certificate_verification(self):
        result=provision(dict(id='oc1',kind='openconnect',server='vpn.example',username='user',password='pass'))
        options=result['sections']['network']['rv_oc1']['options']
        self.assertEqual(options['vpn_protocol'],'anyconnect');self.assertEqual(options['defaultroute'],'0');self.assertNotIn('serverhash',options)
        with self.assertRaises(ValueError):provision(dict(id='oc1',kind='openconnect',server='vpn.example',username='user',password='pass',serverhash='*'))

    def test_l2tp_is_not_enabled_without_ipsec_guard(self):
        result=provision(dict(id='l2',kind='l2tp-ipsec',server='203.0.113.5',username='user',password='pass',ipsec_reqid=42))
        self.assertEqual(result['sections']['network']['rv_l2']['options']['auto'],'0')
        guard=result['prepare'][0][1]
        self.assertIn('ipsec out reqid 42 return',guard);self.assertIn('udp dport 1701 drop',guard)
        with self.assertRaises((KeyError,ValueError)):provision(dict(id='l2',kind='l2tp-ipsec',server='203.0.113.5',username='user',password='pass'))
