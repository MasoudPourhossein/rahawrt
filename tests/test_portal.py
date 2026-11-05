import http.client
import unittest
from rahawrt.portal import PortalServer
from rahawrt.store import Store


class PortalTests(unittest.TestCase):
    def test_redirect_ignores_attacker_host_and_rejects_credentials(self):
        settings=dict(network='127.0.0.0/8',gateway='192.168.50.1',portal_host='portal.example',portal_port=8443)
        server=PortalServer(('127.0.0.1',0),lambda:settings);server.start()
        try:
            for method,status in [('GET',302),('HEAD',302),('POST',405)]:
                client=http.client.HTTPConnection(*server.address,timeout=3)
                client.request(method,'http://attacker.example/login',headers={'Host':'attacker.example'})
                response=client.getresponse();self.assertEqual(response.status,status)
                if method!='POST':self.assertEqual(response.getheader('Location'),'https://portal.example:8443/wrt/')
                self.assertEqual(response.read(),b'');client.close()
            settings['network']='192.168.50.0/24'
            client=http.client.HTTPConnection(*server.address,timeout=3);client.request('GET','/')
            response=client.getresponse();self.assertEqual(response.status,403);self.assertIsNone(response.getheader('Location'));response.read();client.close()
        finally:server.close()

    def test_guest_admin_login_cannot_create_or_rotate_privileged_session(self):
        store=Store(':memory:')
        try:
            store.account('owner','owner-password-123','admin')
            token,_=store.login('owner','owner-password-123','192.168.50.10')
            with self.assertRaises(PermissionError):store.login('owner','owner-password-123','192.168.50.10',user_only=True)
            self.assertIsNotNone(store.principal(token,'192.168.50.10'))
            self.assertEqual(store.db.execute('SELECT COUNT(*) FROM sessions').fetchone()[0],1)
        finally:store.db.close()
