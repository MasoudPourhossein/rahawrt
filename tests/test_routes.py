import datetime as dt
import json
import subprocess
import unittest
from rahawrt.changes import ChangeGuard
from rahawrt.routes import Routes,PROTO
from rahawrt.store import Store
from test_policy import sample


class RoutingKernel:
    def __init__(self):self.rules=[];self.tables={};self.calls=[];self.fail_dns=False
    def __call__(self,args,data=None):
        self.calls.append(args)
        if args[0]=='ubus':return json.dumps(dict(up=True,l3_device='rv_test'))
        if args[:6]==['ip','-N','-j','-4','rule','show']:return json.dumps(self.rules)
        if args[:6]==['ip','-N','-j','-4','route','show']:return json.dumps(self.tables.get(int(args[-1]),[]))
        if args[:3]==['ip','-4','rule']:
            priority=int(args[args.index('priority')+1]);table=int(args[args.index('lookup')+1])
            if args[3]=='del':self.rules=[r for r in self.rules if r['priority']!=priority];return ''
            if 'fwmark' in args:
                if self.fail_dns:self.fail_dns=False;raise subprocess.CalledProcessError(1,args,stderr='injected failure')
                mark=args[args.index('fwmark')+1].split('/')[0];rule=dict(priority=priority,src='all',table=table,fwmark=mark,protocol=PROTO)
            else:rule=dict(priority=priority,src=args[args.index('from')+1],table=table,protocol=PROTO)
            self.rules.append(rule);return ''
        if args[:3]==['ip','-4','route']:
            table=int(args[args.index('table')+1]);current=self.tables.setdefault(table,[])
            if args[3]=='flush':self.tables[table]=[]
            elif args[3]=='replace':
                kind='unreachable' if 'unreachable' in args else 'unicast'
                self.tables[table]=[r for r in current if r.get('type')!=kind]+[dict(type=kind,protocol=PROTO,**({'dev':args[args.index('dev')+1]} if 'dev' in args else {}))]
            elif args[3]=='del':self.tables[table]=[r for r in current if not r.get('dev')]
            return ''
        raise AssertionError(args)


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.store=Store(':memory:');ChangeGuard(self.store,lambda *args:'')
        self.store.db.execute("INSERT INTO router_changes VALUES ('test','vpn','{}','',0,'confirmed',NULL,'test')")
        self.store.db.execute("INSERT INTO tunnels VALUES ('rv_test','wireguard','test','{}')");self.store.db.commit()
        self.kernel=RoutingKernel();self.routes=Routes(self.store,self.kernel)
    def tearDown(self):self.store.db.close()
    def desired(self,**values):
        return self.routes.desired(self.routes.prepare([dict(sample(tunnel='rv_test'),**values)],dt.datetime.now()))

    def test_collision_free_allocation_preserves_foreign_table_and_rule(self):
        self.kernel.rules=[dict(priority=10001,src='all',table=100,protocol=99)]
        self.kernel.tables[40002]=[dict(protocol=99,dev='foreign')]
        desired=self.desired();self.assertEqual(desired['phone']['table'],40003)
        self.routes.sync(desired);self.routes.sync(desired)
        self.assertEqual(len(self.kernel.rules),3)
        self.routes.sync({});self.assertEqual(len(self.kernel.rules),1);self.assertEqual(self.kernel.tables[40002][0]['dev'],'foreign')

    def test_partial_install_is_journaled_and_can_be_cleaned_after_restart(self):
        desired=self.desired();self.kernel.fail_dns=True
        with self.assertRaises(subprocess.CalledProcessError):self.routes.sync(desired)
        self.assertEqual(len(self.kernel.rules),1)
        Routes(self.store,self.kernel).sync({})
        self.assertEqual(self.kernel.rules,[]);self.assertEqual(self.kernel.tables[40001],[])
        self.assertIsNone(self.store.db.execute('SELECT state FROM native_routes').fetchone()[0])

    def test_foreign_takeover_refused_before_any_mutation(self):
        desired=self.desired();self.routes.sync(desired)
        self.kernel.rules[0]['protocol']=99;before=len(self.kernel.calls)
        with self.assertRaisesRegex(ValueError,'owned by another'):self.routes.sync({})
        self.assertFalse(any(a[:3]==['ip','-4','rule'] or a[:3]==['ip','-4','route'] for a in self.kernel.calls[before:]))

    def test_ip_rebind_replaces_selectors_and_keeps_terminal_route(self):
        self.routes.sync(self.desired());self.routes.sync(self.desired(ip='192.168.1.21'))
        source=[r for r in self.kernel.rules if 'fwmark' not in r]
        self.assertEqual([r['src'] for r in source],['192.168.1.21/32'])
        self.assertTrue(any(r['type']=='unreachable' for r in self.kernel.tables[40001]))

    def test_matching_protocol_does_not_authorize_extra_foreign_selectors(self):
        desired=self.desired();self.routes.sync(desired)
        self.kernel.rules[0]['dst']='203.0.113.0/24'
        before=len(self.kernel.calls)
        with self.assertRaisesRegex(ValueError,'owned by another'):self.routes.sync({})
        self.assertFalse(any(a[:3]==['ip','-4','rule'] or a[:3]==['ip','-4','route'] for a in self.kernel.calls[before:]))
