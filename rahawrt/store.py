import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from .policy import device
from .billing import Billing
from .parental import Parental


def password_hash(password, salt=None):
    if not isinstance(password, str) or not 12 <= len(password) <= 256:
        raise ValueError('password must contain 12–256 characters')
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 250000).hex()
    return salt + ':' + digest


def password_ok(password, stored):
    try:
        return hmac.compare_digest(password_hash(password, stored.split(':')[0]), stored)
    except (ValueError, AttributeError):
        return False


class Store(Billing):
    def __init__(self, path):
        os.umask(0o077)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS tunnels(id TEXT PRIMARY KEY,kind TEXT NOT NULL,change_id TEXT NOT NULL,metadata TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY, config TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS usage(device TEXT PRIMARY KEY, up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS accounts(name TEXT PRIMARY KEY, hash TEXT NOT NULL, role TEXT NOT NULL, device TEXT);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, name TEXT NOT NULL, expires INTEGER NOT NULL, ip TEXT NOT NULL);
        CREATE TEMP TABLE IF NOT EXISTS live_checkpoints(key TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS checkpoints(key TEXT PRIMARY KEY, bytes INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS receipts(id TEXT PRIMARY KEY, payload TEXT NOT NULL, created INTEGER NOT NULL);
        ''')
        self.init_billing()
        self.parental=Parental(self)

    def devices(self):
        with self.lock:
            return [json.loads(r[0]) for r in self.db.execute('SELECT config FROM devices ORDER BY id')]

    def validate_tunnel(self,target):
        if not target:return
        with self.lock:
            if not self.db.execute("SELECT 1 FROM sqlite_master WHERE name='router_changes'").fetchone() or not self.db.execute("SELECT 1 FROM tunnels t JOIN router_changes c ON c.id=t.change_id WHERE t.id=? AND c.status='confirmed'",(target,)).fetchone():
                raise ValueError('native tunnel must exist and be confirmed first')

    def put_device(self, data, actor='local'):
        d = device(data)
        with self.lock, self.db:
            if d.get('parental_profile') and not self.db.execute('SELECT 1 FROM parental_profiles WHERE id=?',(d['parental_profile'],)).fetchone():
                raise ValueError('unknown parental profile')
            self.validate_tunnel(d.get('tunnel'))
            for other in self.devices():
                if other['id'] != d['id'] and (other['ip'] == d['ip'] or other['mac'] == d['mac']):
                    raise ValueError('IP or MAC already registered')
            old = next((x for x in self.devices() if x['id'] == d['id']), None)
            if old and (old['ip'], old['mac']) != (d['ip'], d['mac']):
                self.db.execute('DELETE FROM sessions WHERE ip=? AND name IN (SELECT name FROM bindings WHERE device=? UNION SELECT name FROM accounts WHERE device=?)',(old['ip'],d['id'],d['id']))
                self.db.execute("UPDATE session_history SET ended=?,reason='device_rebind' WHERE device=? AND ended IS NULL",(int(time.time()),d['id']))
            self.db.execute('INSERT OR REPLACE INTO devices VALUES (?,?)', (d['id'], json.dumps(d)))
            self.audit(actor,'device.save',d['id'])
        return d

    def usage(self):
        with self.lock:
            return {r[0]: list(r[1:]) for r in self.db.execute('SELECT device,up,down FROM usage')}

    def _record_usage(self, ident, up, down):
        self.db.execute('INSERT INTO usage VALUES (?,?,?) ON CONFLICT(device) DO UPDATE SET up=up+excluded.up,down=down+excluded.down', (ident, up, down))
        bound = self.db.execute('SELECT name FROM bindings WHERE device=?', (ident,)).fetchone()
        name = bound[0] if bound else ''
        if name:
            self.db.execute('INSERT INTO account_usage VALUES (?,?,?) ON CONFLICT(name) DO UPDATE SET up=up+excluded.up,down=down+excluded.down', (name,up,down))
        day=time.strftime('%Y-%m-%d',time.gmtime())
        self.db.execute('INSERT INTO daily_usage VALUES (?,?,?,?,?) ON CONFLICT(day,device,name) DO UPDATE SET up=up+excluded.up,down=down+excluded.down', (day,ident,name,up,down))

    def add_usage(self, values):
        with self.lock, self.db:
            for ident, (up, down) in values.items():
                self._record_usage(ident, up, down)

    def sample_counters(self, counts):
        # Checkpoint and cumulative usage commit atomically. Generation in the key
        # distinguishes replaced nft chains, including across daemon restarts.
        with self.lock, self.db:
            for (generation, ident, direction), count in counts.items():
                key = generation+':'+ident+':'+direction
                old = self.db.execute('SELECT bytes FROM checkpoints WHERE key=?', (key,)).fetchone()
                delta = max(0, count-(old[0] if old else 0))
                up, down = (delta, 0) if direction == 'up' else (0, delta)
                self._record_usage(ident,up,down)
                self.db.execute('INSERT OR REPLACE INTO checkpoints VALUES (?,?)', (key, count))
            # Keep only current generation checkpoints to bound flash storage.
            keys = [g+':'+i+':'+d for g, i, d in counts]
            self.db.execute('DELETE FROM live_checkpoints')
            self.db.executemany('INSERT INTO live_checkpoints VALUES (?)',((key,) for key in keys))
            self.db.execute('DELETE FROM checkpoints WHERE key NOT IN (SELECT key FROM live_checkpoints)')


    def account(self, name, password, role, ident=None, actor='local'):
        import re
        if not isinstance(name, str) or not re.fullmatch(r'[a-zA-Z0-9_]{1,32}', name) or role not in ('admin', 'operator', 'accounting', 'user'):
            raise ValueError('invalid account')
        if role == 'user' and ident not in [d['id'] for d in self.devices()]:
            raise ValueError('user requires registered device')
        hashed = password_hash(password)
        with self.lock, self.db:
            if role == 'user':
                bound=self.db.execute('SELECT name FROM bindings WHERE device=?',(ident,)).fetchone()
                if bound and bound[0] != name:
                    raise ValueError('device is already assigned to another account')
                self.db.execute('INSERT OR IGNORE INTO controls(name,last_tick) VALUES (?,?)',(name,int(time.time())))
                self.db.execute('INSERT OR REPLACE INTO bindings VALUES (?,?)',(ident,name))
            else:
                self.db.execute('DELETE FROM bindings WHERE name=?',(name,))
            self.db.execute('INSERT OR REPLACE INTO accounts VALUES (?,?,?,?)', (name, hashed, role, ident))
            self.db.execute("UPDATE session_history SET ended=?,reason='password_change' WHERE name=? AND ended IS NULL",(int(time.time()),name))
            self.db.execute('DELETE FROM sessions WHERE name=?', (name,))
            self.audit(actor,'account.save',name)

    def login(self, name, password, ip, user_only=False):
        self.tick_accounts()
        with self.lock, self.db:
            row = self.db.execute('SELECT hash,role,device FROM accounts WHERE name=?', (name,)).fetchone()
            valid=password_ok(password,row[0]) if row else False
            if not row:
                try:password_hash(password)
                except ValueError:pass
            if not valid or (user_only and row[1]!='user'):
                raise PermissionError('invalid credentials')
            ident=row[2]
            if row[1] == 'user':
                d = next((d for d in self.devices() if d['ip'] == ip and (not ident or d['id'] == ident)), None)
                if not d:
                    raise PermissionError('account requires a registered device at this IP')
                state=self._account_state(name)
                if not state or state['status']!='active':
                    raise PermissionError('account suspended or deleted')
                selected=state['plan']
                if selected and not d['hotspot']:
                    raise PermissionError('voucher login requires a managed guest device')
                binding=self.db.execute('SELECT name FROM bindings WHERE device=?',(d['id'],)).fetchone()
                if binding and binding[0] != name:
                    old_online=self.db.execute('SELECT 1 FROM sessions WHERE name=? AND ip=? AND expires>?',(binding[0],ip,int(time.time()))).fetchone()
                    if old_online:
                        raise PermissionError('device has another active account; log it out first')
                if selected:
                    count=self.db.execute('SELECT COUNT(*) FROM bindings WHERE name=? AND device!=?',(name,d['id'])).fetchone()[0]
                    sessions=self.db.execute('SELECT COUNT(*) FROM sessions WHERE name=? AND ip!=? AND expires>?',(name,ip,int(time.time()))).fetchone()[0]
                    if count >= selected['max_devices'] or sessions >= selected['max_sessions']:
                        raise PermissionError('account device or session limit reached')
                ident=d['id']
                self.db.execute('INSERT OR REPLACE INTO bindings VALUES (?,?)',(ident,name))
                self.db.execute('UPDATE controls SET last_tick=? WHERE name=?',(int(time.time()),name))
            # Reauthentication from the same IP rotates rather than duplicates sessions.
            self.db.execute("UPDATE session_history SET ended=?,reason='reauthenticate' WHERE name=? AND ip=? AND ended IS NULL",(int(time.time()),name,ip))
            self.db.execute('DELETE FROM sessions WHERE name=? AND ip=?',(name,ip))
            token = secrets.token_urlsafe(32)
            digest=hashlib.sha256(token.encode()).hexdigest()
            expires=int(time.time())+3600
            self.db.execute('INSERT INTO sessions VALUES (?,?,?,?)', (digest, name, expires, ip))
            self.db.execute('INSERT INTO session_history(token,name,device,ip,started,expires) VALUES (?,?,?,?,?,?)',(digest,name,ident,ip,int(time.time()),expires))
            self.audit(name,'session.login',ident or name)
            return token, row[1]

    def principal(self, token, ip):
        with self.lock:
            row=self.db.execute('SELECT a.name,a.role,a.device FROM sessions s JOIN accounts a ON s.name=a.name WHERE s.token=? AND s.expires>? AND s.ip=?', (hashlib.sha256(token.encode()).hexdigest(), int(time.time()), ip)).fetchone()
            if row and row[1]=='user':
                state=self._account_state(row[0])
                if not state or state['status'] != 'active':
                    return None
                # A quota/expiry should still allow the account page and logout;
                # only suspension/deletion invalidates authentication here.
            return row

    def logout(self, token):
        self.tick_accounts()
        with self.lock, self.db:
            digest=hashlib.sha256(token.encode()).hexdigest()
            row=self.db.execute('SELECT name FROM sessions WHERE token=?',(digest,)).fetchone()
            self.db.execute("UPDATE session_history SET ended=?,reason='logout' WHERE token=? AND ended IS NULL",(int(time.time()),digest))
            self.db.execute('DELETE FROM sessions WHERE token=?', (digest,))
            if row:
                self.audit(row[0],'session.logout',row[0])

    def online(self):
        with self.lock:
            result=set()
            for ident,name,ip in self.db.execute("SELECT b.device,b.name,s.ip FROM sessions s JOIN bindings b ON s.name=b.name JOIN accounts a ON a.name=b.name WHERE a.role='user' AND s.expires>?", (int(time.time()),)):
                d=next((d for d in self.devices() if d['id']==ident),None)
                state=self._account_state(name)
                if d and d['ip']==ip and state and state['allowed']:
                    result.add(ident)
            return result

    def receipt(self, payload):
        if not isinstance(payload, dict) or set(payload) != {'id', 'account', 'amount_minor', 'currency', 'reference'}:
            raise ValueError('receipt requires id, account, amount_minor, currency, reference')
        import re
        if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', payload['id']) or not re.fullmatch(r'[A-Z]{3}', payload['currency']):
            raise ValueError('invalid receipt id or currency')
        if type(payload['amount_minor']) is not int or not 0 <= payload['amount_minor'] <= 10**12 or not isinstance(payload['reference'], str) or len(payload['reference']) > 256:
            raise ValueError('invalid amount or reference')
        encoded = json.dumps(payload, sort_keys=True)
        with self.lock, self.db:
            if not self.db.execute('SELECT 1 FROM accounts WHERE name=?', (payload['account'],)).fetchone():
                raise ValueError('unknown account')
            old = self.db.execute('SELECT payload FROM receipts WHERE id=?', (payload['id'],)).fetchone()
            if old and old[0] != encoded:
                raise ValueError('idempotency conflict')
            self.db.execute('INSERT OR IGNORE INTO receipts VALUES (?,?,?)', (payload['id'], encoded, int(time.time())))
        return payload
