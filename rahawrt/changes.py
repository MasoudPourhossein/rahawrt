"""Persistent confirmation watchdog for explicitly requested router changes."""
import hashlib
import hmac
import json
import secrets
import threading
import time
import subprocess


class ChangeGuard:
    def __init__(self, store, runner):
        self.store,self.run=store,runner
        self.lock=threading.RLock()
        with store.lock:
            store.db.executescript('''CREATE TABLE IF NOT EXISTS router_changes(
            id TEXT PRIMARY KEY,kind TEXT NOT NULL,exports TEXT NOT NULL,token TEXT NOT NULL,
            deadline INTEGER NOT NULL,status TEXT NOT NULL,error TEXT,actor TEXT NOT NULL);''')

    def start(self, kind, sections, reloads, actor, timeout=180, prepare=(), cleanup=()):
        if kind not in ('guest','reservation','vpn'):
            raise ValueError('unknown router change kind')
        with self.lock,self.store.lock,self.store.db:
            if self.store.db.execute("SELECT 1 FROM router_changes WHERE status IN ('applying','awaiting','rollback_failed')").fetchone():
                raise ValueError('confirm or recover the previous router change first')
            exports={}
            for config in sorted(sections):
                if self.run(['uci','changes',config]).strip():
                    raise ValueError('save or revert existing UCI edits before applying')
                exports[config]=self.run(['uci','export',config])
            ident,token=secrets.token_hex(12),secrets.token_urlsafe(32)
            deadline=int(time.time())+timeout
            self.store.db.execute('INSERT INTO router_changes VALUES (?,?,?,?,?,?,NULL,?)',(ident,kind,json.dumps(dict(configs=exports,reloads=reloads,cleanup=[])),hashlib.sha256(token.encode()).hexdigest(),deadline,'applying',actor))
            self.store.audit(actor,kind+'.apply',ident)
        thread=threading.Thread(target=self._apply,args=(ident,sections,reloads,prepare,cleanup),daemon=True)
        thread.start()
        return dict(id=ident,confirmation_token=token,deadline=deadline,status='applying')

    def _apply(self, ident, sections, reloads, prepare, cleanup):
        with self.lock:
            try:
                for index,(command,source) in enumerate(prepare):
                    self.run(command,source)
                    if index<len(cleanup):
                        with self.store.lock,self.store.db:
                            saved=json.loads(self.store.db.execute('SELECT exports FROM router_changes WHERE id=?',(ident,)).fetchone()[0])
                            saved['cleanup'].append(cleanup[index])
                            self.store.db.execute('UPDATE router_changes SET exports=? WHERE id=?',(json.dumps(saved),ident))
                for config, entries in sections.items():
                    for name, entry in entries.items():
                        key=config+'.'+name
                        if entry is None:
                            self.run(['uci','delete',key]);continue
                        self.run(['uci','set',key+'='+entry['type']])
                        for option,value in entry['options'].items():
                            if isinstance(value,list):
                                for item in value:self.run(['uci','add_list',key+'.'+option+'='+str(item)])
                            else:
                                self.run(['uci','set',key+'.'+option+'='+str(value)])
                    self.run(['uci','commit',config])
                for command in reloads:self.run(command)
                with self.store.lock,self.store.db:
                    self.store.db.execute("UPDATE router_changes SET status='awaiting' WHERE id=?",(ident,))
            except Exception:
                # Exception arguments can include UCI secrets: do not persist/print them.
                self.rollback(ident)

    def status(self):
        with self.store.lock:
            return [dict(zip(('id','kind','deadline','status','error'),r)) for r in self.store.db.execute('SELECT id,kind,deadline,status,error FROM router_changes ORDER BY deadline DESC LIMIT 20')]

    def confirm(self, ident, token, actor):
        with self.lock,self.store.lock,self.store.db:
            row=self.store.db.execute('SELECT token,deadline,status,kind FROM router_changes WHERE id=?',(ident,)).fetchone()
            if not row or row[2]!='awaiting' or row[1]<=int(time.time()) or not hmac.compare_digest(row[0],hashlib.sha256(token.encode()).hexdigest()):
                raise ValueError('invalid, expired or not-ready confirmation')
            self.store.db.execute("UPDATE router_changes SET status='confirmed',exports='{}',token='' WHERE id=?",(ident,))
            self.store.audit(actor,row[3]+'.confirm',ident)
        return dict(ok=True)

    def rollback(self, ident):
        with self.lock:
            with self.store.lock:
                row=self.store.db.execute('SELECT exports,status,kind FROM router_changes WHERE id=?',(ident,)).fetchone()
            if not row or row[1] in ('confirmed','rolled_back'):
                raise ValueError('no pending change to roll back')
            saved=json.loads(row[0]);failed=False
            for config,source in saved['configs'].items():
                try:
                    self.run(['uci','import',config],source);self.run(['uci','commit',config])
                except Exception:failed=True
            for command in saved['reloads']:
                try:self.run(command)
                except Exception:failed=True
            for command in saved.get('cleanup',[]):
                try:
                    if command[:3]==['nft','delete','table']:
                        try:self.run(['nft','list','table',*command[3:]])
                        except subprocess.CalledProcessError as exc:
                            if 'No such file' in (exc.stderr or ''):continue
                            raise
                    self.run(command)
                except Exception:failed=True
            with self.store.lock,self.store.db:
                self.store.db.execute('UPDATE router_changes SET status=?,error=? WHERE id=?',('rollback_failed' if failed else 'rolled_back','Console recovery required' if failed else None,ident))
                if not failed:self.store.db.execute("UPDATE router_changes SET exports='{}',token='' WHERE id=?",(ident,))
                self.store.audit('watchdog',row[2]+'.rollback',ident)
            return dict(ok=not failed)

    def recover(self):
        with self.store.lock:
            pending=[r[0] for r in self.store.db.execute("SELECT id FROM router_changes WHERE status IN ('applying','awaiting','rollback_failed')")]
        for ident in pending:self.rollback(ident)

    def check(self):
        with self.store.lock:
            expired=[r[0] for r in self.store.db.execute("SELECT id FROM router_changes WHERE status IN ('applying','awaiting','rollback_failed') AND deadline<=?",(int(time.time()),))]
        for ident in expired:self.rollback(ident)
