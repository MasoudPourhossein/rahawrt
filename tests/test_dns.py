import datetime as dt
import hashlib
import json
import socket
import struct
import unittest
from rahawrt.dns import DNSServer,Resolver,answer,encode_name,question,read_name
from rahawrt.store import Store
from test_policy import sample


def query(name,kind=1):return struct.pack('!6H',1234,0x100,1,0,0,0)+encode_name(name)+struct.pack('!HH',kind,1)


class DNSTests(unittest.TestCase):
    def setUp(self):
        self.store=Store(':memory:');self.parental=self.store.parental
        self.parental.save(dict(id='child',block=['blocked.example'],allow=['allowed.blocked.example']),'owner')
        self.store.put_device(dict(sample(),parental_profile='child'))
        self.calls=[]
        def transport(data):
            self.calls.append(question(data)[1]);record=b'\xc0\x0c'+struct.pack('!HHIH',1,1,300,4)+socket.inet_aton('203.0.113.9')
            return answer(data,records=[record])
        self.resolver=Resolver(self.store,self.parental,transport=transport)

    def tearDown(self):self.store.db.close()

    def test_suffix_allow_precedence_and_known_encrypted_dns_block(self):
        for name in ('blocked.example','www.blocked.example','dns.google'):
            response=self.resolver.resolve(query(name),'192.168.1.20');self.assertEqual(response[3]&15,3)
        response=self.resolver.resolve(query('allowed.blocked.example'),'192.168.1.20');self.assertEqual(response[3]&15,0)
        self.assertEqual(self.calls,['allowed.blocked.example'])
        self.assertEqual(self.resolver.resolve(query('notblocked.example'),'192.168.1.20')[3]&15,0)

    def test_safesearch_has_complete_cname_and_address_answer(self):
        response=self.resolver.resolve(query('www.google.com'),'192.168.1.20')
        self.assertEqual(struct.unpack('!H',response[6:8])[0],2)
        self.assertIn(encode_name('forcesafesearch.google.com'),response)
        self.assertIn(socket.inet_aton('203.0.113.9'),response)
        self.assertEqual(self.calls,['forcesafesearch.google.com'])

    def test_vpn_only_never_leaks_to_direct_upstream(self):
        d=self.store.devices()[0];d['node']='vpn_node';self.store.put_device(d)
        response=self.resolver.resolve(query('example.com'),'192.168.1.20')
        self.assertEqual(response[3]&15,2);self.assertEqual(self.calls,[])

    def test_unknown_client_refused_and_malformed_query_is_safe(self):
        self.assertEqual(self.resolver.resolve(query('example.com'),'198.51.100.99')[3]&15,5)
        self.assertEqual(self.resolver.resolve(b'bad','192.168.1.20'),b'')
        with self.assertRaises(ValueError):read_name(b'\xc0\x00',0)

    def test_category_license_checksum_and_atomic_bad_refresh(self):
        text=b'# test-only list\nbad.example\nother.example\n';pin=hashlib.sha256(text).hexdigest()
        def fetch(url,limit):return b'Example list license and attribution' if url.endswith('/LICENSE') else text
        result=self.parental.refresh('adult','owner',pin,fetch)
        self.assertEqual(result['count'],2)
        self.parental.save(dict(id='category',categories=['adult']),'owner')
        profile=self.parental.profiles()[0]
        self.assertTrue(self.parental.blocked('www.bad.example',profile))
        with self.assertRaises(ValueError):self.parental.refresh('adult','owner','0'*64,fetch)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM category_domains').fetchone()[0],2)
        self.assertIn('license',self.store.db.execute('SELECT license FROM category_sources').fetchone()[0])

    def test_real_udp_and_tcp_dns_transport(self):
        # Bind the loopback test to a policy identity through an explicit test adapter.
        original=self.parental.profile_for_ip
        self.parental.profile_for_ip=lambda ip: original('192.168.1.20')
        server=DNSServer(('127.0.0.1',0),self.resolver);server.start()
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                client.settimeout(3);client.sendto(query('blocked.example'),server.address);response=client.recv(4096)
                self.assertEqual(response[3]&15,3)
            with socket.create_connection(server.address,timeout=3) as client:
                packet=query('www.google.com');client.sendall(struct.pack('!H',len(packet))+packet)
                from rahawrt.dns import exact_read
                size=struct.unpack('!H',exact_read(client,2))[0];response=exact_read(client,size)
                self.assertEqual(struct.unpack('!H',response[6:8])[0],2)
        finally:server.close()

    def test_portal_record_remains_available_without_vpn_dns_leak(self):
        self.resolver.local_records=lambda:{'portal.example':'192.168.50.1'}
        d=self.store.devices()[0];d['node']='vpn_node';self.store.put_device(d)
        response=self.resolver.resolve(query('portal.example'),'192.168.1.20')
        self.assertIn(socket.inet_aton('192.168.50.1'),response);self.assertEqual(response[3]&15,0)
        self.assertEqual(self.calls,[])

    def test_blocked_clients_only_receive_local_portal_dns(self):
        self.resolver.local_records=lambda:{'portal.example':'192.168.50.1'}
        original=self.store.devices()[0]
        cases=[dict(enabled=False),dict(internet=[{'days':[(dt.datetime.now().astimezone().weekday()+1)%7], 'start':'00:00','end':'23:59'}]),dict(quota_bytes=10),dict(hotspot=True)]
        self.store.add_usage({'phone':(10,0)})
        for fields in cases:
            with self.subTest(fields=fields):
                self.store.put_device(dict(original,**fields))
                self.assertEqual(self.resolver.resolve(query('example.com'),original['ip'])[3]&15,5)
                self.assertEqual(self.resolver.resolve(query('portal.example'),original['ip'])[3]&15,0)
        self.assertEqual(self.calls,[])

    def test_unfiltered_strict_client_cannot_use_listener_for_direct_dns(self):
        d=self.store.devices()[0];d['node']='vpn_node';d['parental_profile']=None;self.store.put_device(d)
        self.assertEqual(self.resolver.resolve(query('example.com'),d['ip'])[3]&15,2)
        self.assertEqual(self.calls,[])

    def test_legacy_probe_dns_stays_local_until_guest_authenticates(self):
        self.resolver.captive_portal=lambda:dict(network='192.168.1.0/24',gateway='192.168.1.1')
        d=self.store.devices()[0];d['hotspot']=True;self.store.put_device(d)
        for address in (d['ip'],'192.168.1.99'):
            result=self.resolver.resolve(query('captive.apple.com'),address)
            self.assertIn(socket.inet_aton('192.168.1.1'),result)
            self.assertEqual(self.resolver.resolve(query('ordinary.example'),address)[3]&15,5)
        self.assertEqual(self.calls,[])
        self.assertEqual(self.resolver.resolve(query('captive.apple.com'),'198.51.100.1')[3]&15,5)
        self.store.account('guest','guest-password-123','user',d['id']);self.store.login('guest','guest-password-123',d['ip'])
        result=self.resolver.resolve(query('captive.apple.com'),d['ip'])
        self.assertIn(socket.inet_aton('203.0.113.9'),result)
        self.assertEqual(self.calls,['captive.apple.com'])
