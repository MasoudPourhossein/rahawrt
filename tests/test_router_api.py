import base64
import http.client
import json
from pathlib import Path
import subprocess
import secrets
import threading
import time
import unittest
from rahawrt.runtime import Runtime
from rahawrt.server import Server
from rahawrt.store import Store
from test_policy import sample


class Router:
    def __init__(self):self.values={'wireless.radio0':'wifi-device','uhttpd.main.cert':'/etc/uhttpd.crt','uhttpd.main.key':'/etc/uhttpd.key'};self.calls=[]
    def __call__(self,args,data=None):
        self.calls.append((args,data))
        if args[0]=='ubus':return json.dumps({'interface':[{'interface':'lan','l3_device':'br-lan','ipv4-address':[dict(address='192.168.1.1',mask=24)]}]})
        if args[:2]==['uci','changes']:return ''
        if args[:2]==['uci','export']:return "config saved 'original'\n"
        if args[:3]==['uci','-q','get']:
            if args[3] not in self.values:raise subprocess.CalledProcessError(1,args)
            return self.values[args[3]]
        if args[:3]==['uci','-q','show']:
            prefix=args[3]+'.'
            return '\n'.join(k+'='+v for k,v in self.values.items() if k.startswith(prefix))
        if args[:2]==['uci','set']:
            k,v=args[2].split('=',1);self.values[k]=v
        if args[:2]==['uci','add_list']:
            k,v=args[2].split('=',1);self.values[k]=v
        return ''


class RouterAPITests(unittest.TestCase):
    def setUp(self):
        self.store=Store(':memory:');self.store.account('owner','owner-password-123','admin');self.store.put_device(sample())
        self.router=Router();self.runtime=Runtime(self.store,True,self.router)
        self.server=Server(('127.0.0.1',0),self.store,self.runtime,Path(__file__).resolve().parents[1]/'web',trusted_cgi=True)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        status,data=self.request('login','POST',dict(name='owner',password='owner-password-123'));self.assertEqual(status,200);self.token=data['token']

    def tearDown(self):self.server.shutdown();self.server.server_close();self.thread.join();self.store.db.close()

    def request(self,path,method='GET',data=None):
        connection=http.client.HTTPConnection(*self.server.server_address,timeout=5)
        headers={'Content-Type':'application/json','X-RahaWRT-Request':'1','X-RahaWRT-Client':'192.168.1.20','X-RahaWRT-HTTPS':'on'}
        if hasattr(self,'token'):headers['Authorization']='Bearer '+self.token
        connection.request(method,'/wrt/api/v1/'+path,json.dumps(data) if data is not None else None,headers)
        response=connection.getresponse();payload=response.read();status=response.status;connection.close();return status,json.loads(payload)

    def confirm(self,result):
        deadline=time.monotonic()+3
        while True:
            changes=self.request('changes')[1]['changes'];change=next(c for c in changes if c['id']==result['id'])
            if change['status']!='applying':break
            if time.monotonic()>deadline:self.fail('change worker timeout')
            time.sleep(.01)
        self.assertEqual(change['status'],'awaiting')
        self.assertEqual(self.request('changes/confirm','POST',dict(id=result['id'],token=result['confirmation_token']))[0],200)

    def test_wireguard_create_confirm_control_and_secret_redaction(self):
        key=base64.b64encode(secrets.token_bytes(32)).decode()
        data=dict(id='wg1',kind='wireguard',private_key=key,addresses=['10.8.0.2/32'],public_key=key,server='vpn.example',port=51820,allowed_ips=['0.0.0.0/0'])
        status,result=self.request('tunnels','POST',data);self.assertEqual(status,202)
        self.confirm(result)
        self.assertEqual(self.request('tunnels/action','POST',dict(id='rv_wg1',action='up'))[0],200)
        state=self.request('tunnels')[1];self.assertNotIn(key,json.dumps(state))
        self.assertNotIn(key,json.dumps(self.request('changes')[1]))
        self.assertEqual(self.request('tunnels','POST',data)[0],400)

    def test_guest_isolated_setup_guard_before_network_activation(self):
        status,result=self.request('guest','POST',dict(address='192.168.50.1/24'))
        self.assertEqual(status,202);self.confirm(result)
        calls=self.router.calls
        guard=next(i for i,(a,d) in enumerate(calls) if a==['nft','-f','-'])
        network=next(i for i,(a,d) in enumerate(calls) if a[:2]==['uci','set'] and a[2].startswith('network.'))
        self.assertLess(guard,network)
        self.assertEqual(self.router.values['firewall.rw_guest.input'],'REJECT')
        self.assertEqual(self.router.values['firewall.rw_guest.forward'],'REJECT')

    def test_dhcp_reservation_requires_confirmation(self):
        status,result=self.request('reservations','POST',dict(device='phone'))
        self.assertEqual(status,202);self.confirm(result)
        self.assertEqual(self.router.values['dhcp.rw_phone.mac'],'02:11:22:33:44:55')
        self.assertEqual(self.request('reservations','POST',dict(device='phone'))[0],400)

    def test_preview_cannot_mutate_router_and_admin_can_save_profiles(self):
        self.runtime.enforce=False
        for endpoint,data in (('guest',dict(address='192.168.50.1/24')),('tunnels',dict(kind='wireguard')),('reservations',dict(device='phone'))):
            self.assertEqual(self.request(endpoint,'POST',data)[0],403)
        self.assertEqual(self.request('parental','PUT',dict(id='kid',block=['blocked.example']))[0],200)
        self.assertEqual(self.request('parental')[1]['profiles'][0]['id'],'kid')

    def test_guest_sources_cannot_reuse_admin_sessions_or_accounting_keys(self):
        self.router.values.update({'rahawrt.main.guest_network':'rw_guest','network.rw_guest.ipaddr':'192.168.1.1','network.rw_guest.netmask':'255.255.255.0','rahawrt.main.portal_host':'portal.example','rahawrt.main.portal_port':'8443'})
        self.assertEqual(self.request('me')[0],403)
        self.assertEqual(self.request('login','POST',dict(name='owner',password='owner-password-123'))[0],403)
        key=self.store.create_key(dict(scopes=['usage:read']),'owner')
        self.token=key['token'];self.assertEqual(self.request('reports')[0],403)
        self.store.account('guest','guest-password-123','user','phone')
        status,data=self.request('login','POST',dict(name='guest',password='guest-password-123'))
        self.assertEqual(status,200);self.token=data['token']
        self.assertEqual(self.request('me')[1]['role'],'user')
        self.assertEqual(self.request('devices')[0],403)
