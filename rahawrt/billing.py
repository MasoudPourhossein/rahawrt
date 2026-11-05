"""Local plans, invoice-idempotent issuance, scoped keys and accounting reports."""
import hashlib
import hmac
import json
import re
import secrets
import time
from .policy import integer


def identifier(value, maximum=64):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,'+str(maximum)+'}', value):
        raise ValueError('invalid identifier')
    return value


def plan(data):
    allowed = {'id', 'name', 'quota_bytes', 'upload_kbps', 'download_kbps', 'valid_seconds', 'online_seconds', 'max_devices', 'max_sessions', 'node', 'quota_action', 'reduced_upload_kbps', 'reduced_download_kbps','tunnel'}
    if not isinstance(data, dict) or set(data)-allowed:
        raise ValueError('unknown plan fields')
    d = dict(data)
    identifier(d.get('id'), 32)
    if not isinstance(d.get('name', d['id']), str) or len(d.get('name', '')) > 80:
        raise ValueError('invalid plan name')
    d.setdefault('name', d['id'])
    limits = {'quota_bytes': (0, 2**53-1, 0), 'upload_kbps': (0, 10**7, 0), 'download_kbps': (0, 10**7, 0), 'valid_seconds': (0, 10*365*86400, 0), 'online_seconds': (0, 10*365*86400, 0), 'max_devices': (1,32,1), 'max_sessions': (1,32,1), 'reduced_upload_kbps': (0,10**7,0), 'reduced_download_kbps': (0,10**7,0)}
    for key, (low, high, default) in limits.items():
        d[key] = integer(d.get(key, default), low, high)
    d.setdefault('node', 'direct')
    if not isinstance(d['node'], str) or not re.fullmatch(r'[A-Za-z0-9_]{1,64}', d['node']):
        raise ValueError('invalid plan node')
    d.setdefault('tunnel',None)
    if d['tunnel'] is not None and (not isinstance(d['tunnel'],str) or not re.fullmatch(r'rv_[A-Za-z0-9_]{1,7}',d['tunnel'])):raise ValueError('invalid native tunnel')
    if d['tunnel'] and d['node']!='direct':raise ValueError('choose a native tunnel or a PassWall2 node')
    d.setdefault('quota_action', 'block')
    if d['quota_action'] not in ('block', 'throttle'):
        raise ValueError('invalid quota action')
    if d['quota_action'] == 'throttle' and not (d['reduced_upload_kbps'] and d['reduced_download_kbps']):
        raise ValueError('throttled plans require both reduced speeds')
    return d


class Billing:
    def init_billing(self):
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS plans(id TEXT PRIMARY KEY, config TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS controls(name TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT 'active', plan TEXT, expires INTEGER NOT NULL DEFAULT 0, online_used INTEGER NOT NULL DEFAULT 0, last_tick INTEGER NOT NULL, usage_base INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS bindings(device TEXT PRIMARY KEY, name TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS account_usage(name TEXT PRIMARY KEY, up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS daily_usage(day TEXT NOT NULL, device TEXT NOT NULL, name TEXT NOT NULL, up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(day,device,name));
        CREATE TABLE IF NOT EXISTS voucher_batches(id TEXT PRIMARY KEY,request TEXT NOT NULL,plan TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS invoices(id TEXT PRIMARY KEY, request TEXT NOT NULL, name TEXT NOT NULL, created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS session_history(token TEXT PRIMARY KEY, name TEXT NOT NULL, device TEXT, ip TEXT NOT NULL, started INTEGER NOT NULL, expires INTEGER NOT NULL, ended INTEGER, reason TEXT);
        CREATE TABLE IF NOT EXISTS api_keys(id TEXT PRIMARY KEY, hash TEXT NOT NULL UNIQUE, scopes TEXT NOT NULL, expires INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, created INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, subject TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS key_limits(id TEXT PRIMARY KEY, window INTEGER NOT NULL, count INTEGER NOT NULL);
        ''')
        now = int(time.time())
        with self.db:
            self.db.execute('UPDATE controls SET last_tick=?', (now,))
            self.db.execute("INSERT OR IGNORE INTO controls(name,last_tick) SELECT name,? FROM accounts WHERE role='user'", (now,))
            self.db.execute("INSERT OR IGNORE INTO bindings SELECT device,name FROM accounts WHERE role='user' AND device IS NOT NULL")

    def audit(self, actor, action, subject):
        # Deliberately fixed metadata only: never request bodies/passwords/tokens.
        self.db.execute('INSERT INTO audit(created,actor,action,subject) VALUES (?,?,?,?)', (int(time.time()), actor, action, subject))

    def put_plan(self, data, actor):
        d = plan(data)
        self.validate_tunnel(d.get('tunnel'))
        with self.lock, self.db:
            self.db.execute('INSERT OR REPLACE INTO plans VALUES (?,?)', (d['id'], json.dumps(d)))
            self.audit(actor, 'plan.save', d['id'])
        return d

    def plans(self):
        with self.lock:
            return [json.loads(row[0]) for row in self.db.execute('SELECT config FROM plans ORDER BY id')]

    def issue(self, data, actor, selected_override=None):
        from .store import password_hash, password_ok
        allowed = {'invoice_id', 'plan_id', 'username', 'password'}
        if not isinstance(data, dict) or set(data)-allowed:
            raise ValueError('unknown issuance fields')
        invoice = identifier(data['invoice_id'])
        plan_id = identifier(data['plan_id'], 32)
        requested_name = data.get('username')
        if requested_name is not None:
            if not isinstance(requested_name, str) or not re.fullmatch(r'[A-Za-z0-9_]{1,32}', requested_name):
                raise ValueError('invalid username')
        supplied = data.get('password')
        normalized = json.dumps(dict(plan_id=plan_id, username=requested_name, supplied=supplied is not None), sort_keys=True)
        with self.lock, self.db:
            existing = self.db.execute('SELECT request,name FROM invoices WHERE id=?', (invoice,)).fetchone()
            if existing:
                if existing[0] != normalized:
                    raise ValueError('invoice idempotency conflict')
                row = self.db.execute('SELECT hash FROM accounts WHERE name=?', (existing[1],)).fetchone()
                if supplied is not None and (not row or not password_ok(supplied, row[0])):
                    raise ValueError('invoice password conflict')
                return dict(invoice_id=invoice, username=existing[1], password=None, created=False)
            row = self.db.execute('SELECT config FROM plans WHERE id=?', (plan_id,)).fetchone()
            if not row:
                raise ValueError('unknown plan')
            selected = selected_override or json.loads(row[0])
            username = requested_name or 'rw_'+secrets.token_hex(6)
            if self.db.execute('SELECT 1 FROM accounts WHERE name=?', (username,)).fetchone():
                raise ValueError('username already exists')
            password = supplied if supplied is not None else secrets.token_urlsafe(18)
            hashed = password_hash(password)
            now = int(time.time())
            self.db.execute('INSERT INTO accounts VALUES (?,?,?,NULL)', (username, hashed, 'user'))
            self.db.execute('INSERT INTO controls(name,plan,expires,last_tick) VALUES (?,?,?,?)', (username, json.dumps(selected), now+selected['valid_seconds'] if selected['valid_seconds'] else 0, now))
            self.db.execute('INSERT INTO invoices VALUES (?,?,?,?)', (invoice, normalized, username, now))
            self.audit(actor, 'account.issue', username)
            return dict(invoice_id=invoice, username=username, password=password, created=True)

    def issue_batch(self,data,actor):
        if not isinstance(data,dict) or set(data)!={'batch_id','plan_id','count'}:raise ValueError('batch requires batch_id, plan_id and count')
        batch=identifier(data['batch_id'],48);plan_id=identifier(data['plan_id'],32);count=integer(data['count'],1,50)
        normalized=json.dumps(dict(plan_id=plan_id,count=count),sort_keys=True)
        with self.lock:
            old=self.db.execute('SELECT request,plan FROM voucher_batches WHERE id=?',(batch,)).fetchone()
            if old:
                if old[0]!=normalized:raise ValueError('batch idempotency conflict')
                selected=json.loads(old[1])
            else:
                row=self.db.execute('SELECT config FROM plans WHERE id=?',(plan_id,)).fetchone()
                if not row:raise ValueError('unknown plan')
                selected=json.loads(row[0])
                with self.db:self.db.execute('INSERT INTO voucher_batches VALUES (?,?,?)',(batch,normalized,row[0]))
            return [self.issue(dict(invoice_id='b_'+batch+'_'+str(i+1),plan_id=plan_id),actor,selected) for i in range(count)]

    def create_key(self, data, actor):
        scopes = data.get('scopes')
        allowed = {'accounts:issue', 'accounts:manage', 'usage:read', 'receipts:write'}
        if not isinstance(scopes, list) or not scopes or any(s not in allowed for s in scopes):
            raise ValueError('invalid API key scopes')
        ttl = integer(data.get('ttl_seconds', 86400), 60, 365*86400)
        key_id, secret = secrets.token_hex(8), secrets.token_urlsafe(32)
        token = 'rwk_'+key_id+'_'+secret
        with self.lock, self.db:
            self.db.execute('INSERT INTO api_keys(id,hash,scopes,expires) VALUES (?,?,?,?)', (key_id, hashlib.sha256(token.encode()).hexdigest(), json.dumps(sorted(set(scopes))), int(time.time())+ttl))
            self.audit(actor, 'key.create', key_id)
        return dict(id=key_id, token=token, scopes=sorted(set(scopes)), expires=int(time.time())+ttl)

    def key_principal(self, token):
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self.lock, self.db:
            row = self.db.execute('SELECT id,scopes FROM api_keys WHERE hash=? AND active=1 AND expires>?', (digest, int(time.time()))).fetchone()
            if not row:
                return None
            window = int(time.time())//60
            old = self.db.execute('SELECT window,count FROM key_limits WHERE id=?', (row[0],)).fetchone()
            count = old[1]+1 if old and old[0] == window else 1
            if count > 60:
                raise OverflowError('API key limit: 60 requests per minute')
            self.db.execute('INSERT OR REPLACE INTO key_limits VALUES (?,?,?)', (row[0],window,count))
            return ('key:'+row[0], 'key', json.loads(row[1]))

    def revoke_key(self, key_id, actor):
        identifier(key_id)
        with self.lock, self.db:
            self.db.execute('UPDATE api_keys SET active=0 WHERE id=?', (key_id,))
            self.audit(actor, 'key.revoke', key_id)

    def _account_state(self, name, now=None):
        now = int(time.time()) if now is None else now
        row = self.db.execute('SELECT status,plan,expires,online_used,last_tick,usage_base FROM controls WHERE name=?', (name,)).fetchone()
        if not row:
            return None
        selected = json.loads(row[1]) if row[1] else None
        usage = self.db.execute('SELECT up,down FROM account_usage WHERE name=?', (name,)).fetchone() or (0,0)
        consumed = max(0, sum(usage)-row[5])
        valid = row[0] == 'active' and (not row[2] or now < row[2])
        exhausted = bool(selected and selected['quota_bytes'] and consumed >= selected['quota_bytes'])
        if selected:
            valid = valid and (not selected['online_seconds'] or row[3] < selected['online_seconds']) and not (exhausted and selected['quota_action'] == 'block')
        return dict(name=name, status=row[0], plan=selected, expires=row[2], online_used=row[3], usage=list(usage), consumed_bytes=consumed, remaining_bytes=max(0,selected['quota_bytes']-consumed) if selected and selected['quota_bytes'] else None, allowed=valid, throttled=exhausted and selected['quota_action']=='throttle' if selected else False)

    def account_state(self, name):
        with self.lock:
            return self._account_state(name)

    def tick_accounts(self, now=None):
        now = int(time.time()) if now is None else now
        with self.lock, self.db:
            for name,last,status,expires,used,encoded in self.db.execute('SELECT name,last_tick,status,expires,online_used,plan FROM controls').fetchall():
                if now<=last:continue
                row=self.db.execute('SELECT MAX(expires) FROM sessions WHERE name=?',(name,)).fetchone()
                until=min(now,row[0]) if row and row[0] else last
                if expires:until=min(until,expires)
                elapsed=max(0,until-last) if status=='active' else 0
                selected=json.loads(encoded) if encoded else None
                if selected and selected['online_seconds']:elapsed=min(elapsed,max(0,selected['online_seconds']-used))
                self.db.execute('UPDATE controls SET online_used=online_used+?,last_tick=? WHERE name=?',(elapsed,now,name))
            self.db.execute("UPDATE session_history SET ended=expires,reason='expired' WHERE ended IS NULL AND expires<=?", (now,))
            self.db.execute('DELETE FROM sessions WHERE expires<=?', (now,))

    def manage_account(self, data, actor):
        name = identifier(data['name'],32)
        action = data['action']
        with self.lock, self.db:
            row = self.db.execute("SELECT 1 FROM accounts WHERE name=? AND role='user'", (name,)).fetchone()
            if not row:
                raise ValueError('unknown user account')
            renewal=None
            replacement_password=None
            if action=='renew':
                invoice=identifier(data['invoice_id'])
                renewal=json.dumps(dict(action='renew',name=name,plan_id=identifier(data['plan_id'],32)),sort_keys=True)
                old=self.db.execute('SELECT request,name FROM invoices WHERE id=?',(invoice,)).fetchone()
                if old:
                    if old!=(renewal,name):
                        raise ValueError('invoice idempotency conflict')
                    return dict(ok=True,replayed=True)
            if action in ('suspend','activate'):
                self.db.execute('UPDATE controls SET status=? WHERE name=?', ('suspended' if action=='suspend' else 'active',name))
            elif action == 'renew':
                selected_row = self.db.execute('SELECT config FROM plans WHERE id=?',(identifier(data['plan_id'],32),)).fetchone()
                if not selected_row:
                    raise ValueError('unknown plan')
                selected = json.loads(selected_row[0]);now=int(time.time())
                usage=self.db.execute('SELECT up+down FROM account_usage WHERE name=?',(name,)).fetchone()
                self.db.execute("UPDATE controls SET status='active',plan=?,expires=?,online_used=0,last_tick=?,usage_base=? WHERE name=?", (json.dumps(selected),now+selected['valid_seconds'] if selected['valid_seconds'] else 0,now,usage[0] if usage else 0,name))
            elif action=='password-reset':
                from .store import password_hash
                replacement_password=data.get('password') or secrets.token_urlsafe(18)
                self.db.execute('UPDATE accounts SET hash=? WHERE name=?',(password_hash(replacement_password),name))
            elif action=='unbind':
                ident=identifier(data['device'],24)
                if not self.db.execute('SELECT 1 FROM bindings WHERE device=? AND name=?',(ident,name)).fetchone():raise ValueError('device is not bound to this account')
                self.db.execute('DELETE FROM bindings WHERE device=? AND name=?',(ident,name))
            elif action not in ('disconnect','delete'):
                raise ValueError('unknown account action')
            self.db.execute("UPDATE session_history SET ended=?,reason=? WHERE name=? AND ended IS NULL",(int(time.time()),action,name))
            self.db.execute('DELETE FROM sessions WHERE name=?',(name,))
            if action == 'delete':
                self.db.execute('DELETE FROM accounts WHERE name=?',(name,))
                self.db.execute("UPDATE controls SET status='deleted' WHERE name=?",(name,))
                # Retain bindings as a closed gate until explicit reassignment.
            if renewal:
                self.db.execute('INSERT INTO invoices VALUES (?,?,?,?)',(invoice,renewal,name,int(time.time())))
            self.audit(actor,'account.'+action,name)
        return dict(ok=True,**({'password':replacement_password} if replacement_password else {}))

    def effective_devices(self):
        self.tick_accounts()
        with self.lock:
            devices = self.devices()
            for d in devices:
                if d.get('parental_profile'):
                    d['_parental']=self.parental.profile_for_ip(d['ip'])
                    if not d['_parental']:d['enabled']=False
                bound=self.db.execute('SELECT name FROM bindings WHERE device=?',(d['id'],)).fetchone()
                if not bound:
                    continue
                state=self._account_state(bound[0])
                if not state:
                    continue
                d['enabled'] = d['enabled'] and state['allowed']
                selected=state['plan']
                if not selected:
                    continue
                d['hotspot']=True
                d['node']=selected['node']
                d['tunnel']=selected.get('tunnel')
                d['_account_limit']={'id':bound[0]}
                for key in ('upload_kbps','download_kbps'):
                    d['_account_limit'][key]=selected['reduced_'+key] if state['throttled'] else selected[key]

            return devices

    def report(self, name=None, period='daily'):
        if period not in ('daily','monthly'):
            raise ValueError('period must be daily or monthly')
        with self.lock:
            expression='day' if period=='daily' else 'substr(day,1,7)'
            query=f'SELECT {expression},device,name,SUM(up),SUM(down) FROM daily_usage'
            args=()
            if name:
                query+=' WHERE name=?';args=(name,)
            query+=f' GROUP BY {expression},device,name ORDER BY 1 DESC LIMIT 1000'
            return [dict(period=r[0],device=r[1],account=r[2],upload_bytes=r[3],download_bytes=r[4]) for r in self.db.execute(query,args)]
