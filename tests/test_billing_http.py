import http.client
import json
from pathlib import Path
import threading
import unittest
from rahawrt.server import Server
from rahawrt.runtime import Runtime
from rahawrt.store import Store
from test_policy import sample


class BillingHTTPTests(unittest.TestCase):
    def setUp(self):
        self.store=Store(':memory:')
        self.store.account('admin','admin-password-123','admin')
        self.store.account('cash','cash-password-123','accounting')
        self.store.put_device(sample(hotspot=True))
        self.server=Server(('127.0.0.1',0),self.store,Runtime(self.store),Path(__file__).resolve().parents[1]/'web',trusted_cgi=True)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.admin=self.login('admin','admin-password-123')
        self.request('plans','PUT',dict(id='daily',quota_bytes=100,valid_seconds=86400),self.admin)

    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join();self.store.db.close()

    def request(self,path,method='GET',body=None,token=None):
        connection=http.client.HTTPConnection(*self.server.server_address,timeout=10)
        headers={'Content-Type':'application/json','X-RahaWRT-Request':'1','X-RahaWRT-Client':'192.168.1.20','X-RahaWRT-HTTPS':'on'}
        if token:headers['Authorization']='Bearer '+token
        connection.request(method,'/wrt/api/v1/'+path,json.dumps(body) if body is not None else None,headers)
        response=connection.getresponse();payload=response.read();status=response.status;mime=response.getheader('Content-Type');connection.close()
        return status,json.loads(payload) if mime.startswith('application/json') else payload.decode()

    def login(self,name,password):
        status,body=self.request('login','POST',dict(name=name,password=password));self.assertEqual(status,200)
        return body['token']

    def test_cash_register_invoice_flow_and_role_denial(self):
        token=self.login('cash','cash-password-123')
        status,c=self.request('issue','POST',dict(invoice_id='invoice_5',plan_id='daily'),token)
        self.assertEqual(status,200);self.assertTrue(c['created'])
        self.assertEqual(self.request('issue','POST',dict(invoice_id='invoice_5',plan_id='daily'),token)[1]['username'],c['username'])
        self.assertEqual(self.request('plans','PUT',dict(id='forbidden'),token)[0],403)
        self.assertEqual(self.request('api-keys','POST',dict(scopes=['usage:read']),token)[0],403)
        user=self.login(c['username'],c['password'])
        self.assertEqual(self.request('me',token=user)[1]['account']['remaining_bytes'],100)
        self.assertEqual(self.request('accounts',token=user)[0],403)
        self.store.add_usage({'phone':(60,40)})
        self.assertFalse(self.store.effective_devices()[0]['enabled'])
        self.assertEqual(self.request('me',token=user)[1]['account']['remaining_bytes'],0)
        self.assertEqual(self.request('account-action','POST',dict(name=c['username'],action='suspend'),self.admin)[0],200)
        self.assertEqual(self.request('me',token=user)[0],401)

    def test_scoped_key_cannot_escalate_and_revoke_is_immediate(self):
        status,key=self.request('api-keys','POST',dict(scopes=['accounts:issue']),self.admin)
        self.assertEqual(status,201)
        self.assertEqual(self.request('issue','POST',dict(invoice_id='api_1',plan_id='daily'),key['token'])[0],200)
        self.assertEqual(self.request('accounts',token=key['token'])[0],403)
        self.assertEqual(self.request('account-action','POST',dict(name='admin',action='delete'),key['token'])[0],403)
        self.assertEqual(self.request('api-keys','POST',dict(scopes=['accounts:manage']),key['token'])[0],403)
        self.request('api-keys/revoke','POST',dict(id=key['id']),self.admin)
        self.assertEqual(self.request('issue','POST',dict(invoice_id='api_2',plan_id='daily'),key['token'])[0],401)

    def test_batch_and_csv_report_are_real(self):
        data=dict(batch_id='batch_3',plan_id='daily',count=3)
        status,body=self.request('vouchers','POST',data,self.admin)
        self.assertEqual(status,200);self.assertEqual(len(body['vouchers']),3)
        replay=self.request('vouchers','POST',data,self.admin)[1]['vouchers']
        self.assertEqual([r['username'] for r in replay],[r['username'] for r in body['vouchers']])
        self.assertTrue(all(r['password'] is None for r in replay))
        c=body['vouchers'][0];token=self.login(c['username'],c['password'])
        self.store.add_usage({'phone':(10,20)})
        status,text=self.request('reports?format=csv&period=monthly',token=token)
        self.assertEqual(status,200);self.assertIn('upload_bytes',text);self.assertIn(c['username'],text)
        status,history=self.request('sessions',token=token)
        self.assertEqual(status,200);self.assertEqual(history['sessions'][0]['name'],c['username']);self.assertNotIn('token',history['sessions'][0])
        audit=self.request('audit',token=self.admin)[1]
        self.assertNotIn(c['password'],json.dumps(audit));self.assertNotIn(token,json.dumps(audit))
