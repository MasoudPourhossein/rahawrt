import datetime as dt
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from rahawrt.proxy_dns import ProxyDNS
from rahawrt.dns import Resolver,answer
from rahawrt.store import Store
from test_policy import sample
from test_dns import query

ROOT=Path(__file__).resolve().parents[1]

class ProxyDNSTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(':memory:');self.processes=[]
        self.store.parental.save(dict(id='child'),'owner')
        self.store.put_device(dict(sample(node='node_a'),parental_profile='child'))
        self.direct=[]
        def runner(args,data=None):
            if args[:3]==['uci','-q','get']:
                if args[3].endswith('.type'):return 'Xray'
                if args[3].endswith('.protocol'):return 'vless'
                return 'node_a'
            if args[:2]==['/usr/share/passwall2/app.sh','run_socks']:
                options=dict(arg.split('=',1) for arg in args[2:])
                address='203.0.113.10' if options['node']=='node_a' else '203.0.113.11'
                self.processes.append(subprocess.Popen([sys.executable,str(ROOT/'tests/socks_stub.py'),options['config_file'],options['socks_port'],address],cwd=ROOT,env=dict(__import__('os').environ,PYTHONPATH=str(ROOT)),stdout=subprocess.DEVNULL,stderr=subprocess.PIPE))
            return ''
        self.runner=runner;self.pool=ProxyDNS(self.store,runner,Path(self.tmp.name)/'helpers')
        def direct(wire):self.direct.append(wire);return answer(wire)
        self.resolver=Resolver(self.store,self.store.parental,transport=direct,proxy_transport=lambda wire,d:self.pool.forward(wire,d))

    def tearDown(self):
        self.pool.close()
        for process in self.processes:
            if process.poll() is None:
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=3)
            if process.stderr:process.stderr.close()
        self.store.db.close();self.tmp.cleanup()

    def test_real_socks_dns_selects_node_and_does_not_use_direct_transport(self):
        self.pool.ensure(self.store.effective_devices(),dt.datetime.now())
        result=self.resolver.resolve(query('example.com'),'192.168.1.20')
        self.assertIn(socket.inet_aton('203.0.113.10'),result);self.assertEqual(self.direct,[])
        d=self.store.devices()[0];d['node']='node_b';self.store.put_device(d)
        self.pool.ensure(self.store.effective_devices(),dt.datetime.now())
        result=self.resolver.resolve(query('www.google.com'),'192.168.1.20')
        self.assertIn(socket.inet_aton('203.0.113.11'),result);self.assertEqual(self.direct,[])
        for path in (Path(self.tmp.name)/'helpers').glob('*.json'):self.assertEqual(path.stat().st_mode&0o777,0o600)

    def test_failed_proxy_closes_dns_unless_fallback_was_explicit(self):
        self.pool.ensure(self.store.effective_devices(),dt.datetime.now());self.pool.close()
        result=self.resolver.resolve(query('example.com'),'192.168.1.20')
        self.assertEqual(result[3]&15,2);self.assertEqual(self.direct,[])
        d=self.store.devices()[0];d['vpn_failure']='direct';self.store.put_device(d)
        result=self.resolver.resolve(query('example.com'),'192.168.1.20')
        self.assertEqual(result[3]&15,0);self.assertEqual(len(self.direct),1)

    def test_shunt_node_cannot_silently_become_a_direct_dns_path(self):
        def runner(args,data=None):
            if args[-1].endswith('.protocol'):return '_shunt'
            return self.runner(args,data)
        self.pool.run=runner
        state=self.pool.ensure(self.store.effective_devices(),dt.datetime.now())
        self.assertTrue(state['errors']);self.assertFalse(state['ready_nodes'])
        self.assertEqual(self.resolver.resolve(query('example.com'),'192.168.1.20')[3]&15,2)
        self.assertEqual(self.direct,[])

    def test_pid_reuse_does_not_signal_an_unrelated_process(self):
        from unittest.mock import patch
        process=Path(self.tmp.name)/'4242';process.mkdir()
        flag='rw_dns_fixture'
        (process/'cmdline').write_bytes(str(self.pool.root/(flag+'.json')).encode()+b'\0')
        def open_reused_pid(pid):
            (process/'cmdline').write_bytes(b'unrelated-program\0')
            return 99
        with patch.object(self.pool,'_owned_processes',return_value=iter([process])),patch('rahawrt.proxy_dns.os.pidfd_open',side_effect=open_reused_pid),patch('rahawrt.proxy_dns.signal.pidfd_send_signal') as sent,patch('rahawrt.proxy_dns.os.close') as closed:
            self.pool._stop(flag)
            sent.assert_not_called();closed.assert_called_once_with(99)
