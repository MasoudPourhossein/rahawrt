import json
import subprocess
import struct
import unittest
from unittest.mock import patch
from rahawrt.runtime import Runtime
from rahawrt.store import Store
from rahawrt.dns import answer
from test_dns import query


def bypass_rules():
    return [{'rule':dict(chain=chain,expr=[{'match':{'left':{'meta':{'key':'skgid'}},'op':'==','right':9912}},{'counter':{'packets':0,'bytes':0}},{'return':None}])} for chain in ('mangle_output','nat_output')]


class WorkerTests(unittest.TestCase):
    def setUp(self):self.store=Store(':memory:')
    def tearDown(self):self.store.db.close()
    def runtime(self,rules):return Runtime(self.store,True,lambda *args:json.dumps({'nftables':rules}))

    def test_conditional_or_preceded_group_rule_cannot_authorize_bypass(self):
        conditional=bypass_rules();conditional[0]['rule']['expr'].insert(0,{'match':{'left':{'payload':{'protocol':'ip','field':'daddr'}},'op':'==','right':'1.1.1.1'}})
        preceding=[{'rule':dict(chain='mangle_output',expr=[{'drop':None}])}]+bypass_rules()
        with patch('rahawrt.runtime.subprocess.run') as worker:
            for rules in ([],conditional,preceding):
                with self.subTest(rules=rules),self.assertRaises(OSError):self.runtime(rules).direct_dns(query('example.com'),('1.1.1.1',53))
            worker.assert_not_called()

    def test_worker_timeout_is_a_closed_dns_error_and_group_is_isolated(self):
        runtime=self.runtime(bypass_rules())
        with patch('rahawrt.runtime.subprocess.run',side_effect=subprocess.TimeoutExpired('worker',4)) as worker:
            with self.assertRaises(OSError):runtime.direct_dns(query('example.com'),('1.1.1.1',53))
            self.assertEqual(worker.call_args.kwargs['group'],9912)
            self.assertIn('--direct',worker.call_args.args[0])

    def test_large_tcp_answer_and_question_integrity(self):
        runtime=self.runtime(bypass_rules());packet=query('example.com',16);text=bytes([250])+b'x'*250
        record=b'\xc0\x0c'+struct.pack('!HHIH',16,1,60,len(text))+text
        response=answer(packet,records=[record]*20)
        with patch('rahawrt.runtime.subprocess.run',return_value=subprocess.CompletedProcess([],0,stdout=response)):
            self.assertEqual(runtime.direct_dns(packet,('1.1.1.1',53)),response)
        other=answer(query('other.example'))
        with patch('rahawrt.runtime.subprocess.run',return_value=subprocess.CompletedProcess([],0,stdout=other)):
            with self.assertRaises(ValueError):runtime.direct_dns(packet,('1.1.1.1',53))
