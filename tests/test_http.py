import http.client
import json
from pathlib import Path
import threading
import unittest
from rahawrt.server import Server
from rahawrt.runtime import Runtime
from rahawrt.store import Store
from test_policy import sample


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = Store(':memory:')
        cls.store.account('admin', 'admin-password-123', 'admin')
        cls.store.account('operator', 'operator-password-123', 'operator')
        cls.store.put_device(sample())
        cls.store.account('user', 'user-password-123', 'user', 'phone')
        cls.server = Server(('127.0.0.1',0), cls.store, Runtime(cls.store), Path(__file__).resolve().parents[1]/'web')
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join(); cls.store.db.close()

    def request(self, path, method='GET', data=None, token=None, csrf=True):
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        headers = {'Content-Type':'application/json'}
        if csrf: headers['X-RahaWRT-Request'] = '1'
        if token: headers['Authorization'] = 'Bearer '+token
        conn.request(method, path, json.dumps(data) if data is not None else None, headers)
        res = conn.getresponse(); payload = res.read(); status = res.status; hdr = dict(res.getheaders()); conn.close()
        return status, payload, hdr

    def login(self, name):
        status, body, headers = self.request('/wrt/api/v1/login','POST',{'name':name, 'password':name+'-password-123'})
        self.assertEqual(status,200)
        self.assertIn('HttpOnly', headers['Set-Cookie'])
        return json.loads(body)['token']

    def test_real_panel_assets(self):
        for path in ('/wrt/','/wrt/app.js','/wrt/style.css'):
            status, body, headers = self.request(path)
            self.assertEqual(status,200); self.assertTrue(body)
            self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])

    def test_authorization_csrf_and_logout(self):
        self.assertEqual(self.request('/wrt/api/v1/devices')[0],401)
        admin = self.login('admin')
        self.assertEqual(self.request('/wrt/api/v1/devices',token=admin)[0],200)
        self.assertEqual(self.request('/wrt/api/v1/accounts','POST',{},admin,False)[0],403)
        self.assertEqual(self.request('/wrt/api/v1/logout','POST',{},admin)[0],200)
        self.assertEqual(self.request('/wrt/api/v1/devices',token=admin)[0],401)

    def test_operator_read_only(self):
        token = self.login('operator')
        self.assertEqual(self.request('/wrt/api/v1/devices',token=token)[0],200)
        self.assertEqual(self.request('/wrt/api/v1/devices','PUT',sample(),token)[0],403)

    def test_cgi_route_and_device_edit(self):
        token = self.login('admin')
        d = sample(upload_kbps=100)
        self.assertEqual(self.request('/cgi-bin/rahawrt/wrt/api/v1/devices','PUT',d,token)[0],200)
        status, body, _ = self.request('/wrt/api/v1/devices',token=token)
        self.assertEqual(status,200); self.assertEqual(json.loads(body)['devices'][0]['upload_kbps'],100)

    def test_user_cannot_login_from_other_device(self):
        self.assertEqual(self.request('/wrt/api/v1/login','POST',{'name':'user','password':'user-password-123'})[0],403)

    def test_traversal_not_served(self):
        self.assertEqual(self.request('/wrt/../../LICENSE')[0],404)
