import http.client
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import unittest
from rahawrt.store import Store


class ProcessTests(unittest.TestCase):
    def test_saved_startup_command_and_functional_login(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            db = directory+'/state.db'
            password = secrets.token_urlsafe(24)
            store = Store(db);store.account('owner',password,'admin');store.db.close()
            process = subprocess.Popen([sys.executable,'-m','rahawrt.server','--db',db,'--web',str(root/'web'),'--port','19080','--timezone','Asia/Tehran'],cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic()+5
                while True:
                    try:
                        connection = http.client.HTTPConnection('127.0.0.1',19080,timeout=1)
                        connection.request('GET','/wrt/')
                        response = connection.getresponse()
                        self.assertEqual(response.status,200);self.assertIn(b'RahaWRT',response.read());connection.close()
                        break
                    except (OSError, http.client.HTTPException):
                        if time.monotonic() >= deadline or process.poll() is not None:
                            self.fail('preview process failed to become ready')
                        time.sleep(0.05)
                connection = http.client.HTTPConnection('127.0.0.1',19080,timeout=5)
                connection.request('POST','/wrt/api/v1/login',json.dumps(dict(name='owner',password=password)),{'Content-Type':'application/json','X-RahaWRT-Request':'1'})
                response = connection.getresponse();self.assertEqual(response.status,200);token=json.loads(response.read())['token'];connection.close()
                connection = http.client.HTTPConnection('127.0.0.1',19080,timeout=5)
                connection.request('GET','/wrt/api/v1/status',headers={'Authorization':'Bearer '+token})
                response=connection.getresponse();self.assertEqual(response.status,200)
                state=json.loads(response.read());self.assertEqual(state['mode'],'preview');self.assertEqual(state['utc_offset'],'+0330');self.assertFalse(state['applied']);self.assertIn('table inet rahawrt',state['plan']);connection.close()
            finally:
                process.terminate()
                process.communicate(timeout=5)

    def test_enforcement_cannot_use_a_database_invisible_to_the_watchdog(self):
        with tempfile.TemporaryDirectory() as directory:
            db=Path(directory)/'different.db'
            result=subprocess.run([sys.executable,'-m','rahawrt.server','--enforce','--db',str(db)],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('independent guard sees the same policy',result.stderr)
            self.assertFalse(db.exists())
