import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from rahawrt.runtime import Runtime
from rahawrt.server import Server
from rahawrt.store import Store


class CGITests(unittest.TestCase):
    def test_bridge_uses_remote_addr_and_protects_cookie(self):
        root = Path(__file__).resolve().parents[1]
        store = Store(':memory:')
        store.account('admin', 'secret-password-123', 'admin')
        server = Server(('127.0.0.1',9080),store,Runtime(store),root/'web', trusted_cgi=True)
        thread = threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        try:
            payload = json.dumps({'name':'admin','password':'secret-password-123'}).encode()
            cgi_env = dict(os.environ, PATH_INFO='/wrt/api/v1/login', REMOTE_ADDR='192.168.1.30', HTTPS='on', REQUEST_METHOD='POST', CONTENT_TYPE='application/json', CONTENT_LENGTH=str(len(payload)), HTTP_X_RAHAWRT_REQUEST='1', HTTP_X_RAHAWRT_CLIENT='198.51.100.5')
            result = subprocess.run([sys.executable,str(root/'openwrt/files/rahawrt.cgi')],input=payload,env=cgi_env,capture_output=True,check=True)
            headers, body = result.stdout.split(b'\r\n\r\n',1)
            self.assertIn(b'Status: 200 OK\r\n',headers+b'\r\n')
            self.assertIn(b'; Secure',headers)
            token = json.loads(body)['token']
            self.assertIsNotNone(store.principal(token,'192.168.1.30'))
            self.assertIsNone(store.principal(token,'198.51.100.5'))
            insecure=dict(cgi_env,HTTPS='off')
            rejected=subprocess.run([sys.executable,str(root/'openwrt/files/rahawrt.cgi')],input=payload,env=insecure,capture_output=True,check=True)
            self.assertIn(b'Status: 403 Forbidden\r\n',rejected.stdout)
            self.assertIn(b'HTTPS is required',rejected.stdout)
            forwarded=dict(cgi_env,HTTP_X_HTTP_METHOD_OVERRIDE='POST');forwarded.pop('HTTP_X_RAHAWRT_REQUEST')
            native=subprocess.run([sys.executable,str(root/'openwrt/files/rahawrt.cgi')],input=payload,env=forwarded,capture_output=True,check=True)
            self.assertIn(b'Status: 200 OK\r\n',native.stdout)
            wrong=dict(forwarded,HTTP_X_HTTP_METHOD_OVERRIDE='DELETE')
            denied=subprocess.run([sys.executable,str(root/'openwrt/files/rahawrt.cgi')],input=payload,env=wrong,capture_output=True,check=True)
            self.assertIn(b'Status: 403 Forbidden\r\n',denied.stdout)
        finally:
            server.shutdown();server.server_close();thread.join();store.db.close()
