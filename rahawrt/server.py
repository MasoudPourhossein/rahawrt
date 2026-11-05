import argparse
import getpass
import http.cookies
import ipaddress
import json
import os
from pathlib import Path
import threading
import time
import urllib.parse
import csv
import io
import re
import subprocess
import signal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .runtime import Runtime
from .store import Store
from .changes import ChangeGuard
from .dns import DNSServer,Resolver
from .vpn import provision,REQUIREMENTS
from .diagnostics import resources,client_route
from .guest import guest_plan, bootstrap_rules


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, store, runtime, web, trusted_cgi=False, changes=None):
        self.request_slots = threading.BoundedSemaphore(32)
        super().__init__(address, Handler)
        self.store, self.runtime, self.web, self.trusted_cgi = store, runtime, Path(web), trusted_cgi
        with store.lock:
            store.db.execute('CREATE TABLE IF NOT EXISTS tunnels(id TEXT PRIMARY KEY,kind TEXT NOT NULL,change_id TEXT NOT NULL,metadata TEXT NOT NULL)')
            store.db.commit()
        self.changes=changes or ChangeGuard(store,runtime.run)
        runtime.changes=self.changes
        self.attempts = {}
        self.attempt_lock = threading.Lock()

    def process_request(self, request, client_address):
        if not self.request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.request_slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = 'RahaWRT'

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, fmt, *args):
        pass  # Do not log credentials, cookies or receipt contents.

    def reply(self, code, body, cookie=None, content_type='application/json'):
        payload = json.dumps(body, ensure_ascii=False).encode() if content_type == 'application/json' else body
        self.send_response(code)
        self.send_header('Content-Type', content_type+('; charset=utf-8' if content_type.startswith('text/') or content_type.endswith('json') else ''))
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def do_PUT(self):
        self.handle_request()

    def handle_request(self):
        try:
            self.dispatch()
        except OverflowError as exc:
            self.reply(429, {'error': str(exc)})
        except PermissionError as exc:
            self.reply(403, {'error': str(exc)})
        except (ValueError, KeyError, TypeError, UnicodeError) as exc:
            self.reply(400, {'error': str(exc)})
        except Exception:
            self.reply(500, {'error': 'internal error'})

    def reply_captive(self, payload):
        return self.reply(200,json.dumps(payload).encode(),content_type='application/captive+json')

    def body(self):
        size = int(self.headers.get('Content-Length', '0'))
        if not 0 < size <= 65536:
            raise ValueError('JSON body must be 1–65536 bytes')
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            raise ValueError('application/json required')
        data = json.loads(self.rfile.read(size))
        if not isinstance(data, dict):
            raise ValueError('JSON object required')
        return data

    def dispatch(self):
        s = self.server
        path = self.path.split('?')[0]
        if path.startswith('/cgi-bin/rahawrt/'):
            path = path[len('/cgi-bin/rahawrt'):]
        if self.command == 'GET' and path in ('/wrt/', '/wrt/app.js', '/wrt/style.css'):
            name = {'/wrt/': 'index.html', '/wrt/app.js': 'app.js', '/wrt/style.css': 'style.css'}[path]
            mime = {'index.html': 'text/html', 'app.js': 'text/javascript', 'style.css': 'text/css'}[name]
            return self.reply(200, (s.web/name).read_bytes(), content_type=mime)
        if not path.startswith('/wrt/api/v1/'):
            return self.reply(404, {'error': 'not found'})
        ip = self.client_address[0]
        if s.trusted_cgi:
            # Only the loopback-only CGI transport may assert REMOTE_ADDR.
            ip = str(ipaddress.ip_address(self.headers.get('X-RahaWRT-Client', '')))
        guest=s.runtime.guest.settings() if s.runtime.enforce else None
        is_guest=bool(s.runtime.guest.captive(ip,guest).get('guest'))
        if path == '/wrt/api/v1/captive' and self.command=='GET':
            guest=s.runtime.guest.settings() if s.runtime.enforce else None
            return self.reply_captive(dict(s.runtime.guest.captive(ip,guest),**{'https-required':s.trusted_cgi}))
        if s.trusted_cgi and self.headers.get('X-RahaWRT-HTTPS')!='on':
            raise PermissionError('HTTPS is required for the router API')
        token = self.headers.get('Authorization', '').removeprefix('Bearer ')
        if not token:
            cookies = http.cookies.SimpleCookie(self.headers.get('Cookie', ''))
            token = cookies['rahawrt'].value if 'rahawrt' in cookies else ''
        if self.command != 'GET' and self.headers.get('X-RahaWRT-Request') != '1':
            raise PermissionError('request header required')
        if path == '/wrt/api/v1/login' and self.command == 'POST':
            now = time.monotonic()
            with s.attempt_lock:
                s.attempts = {k: v for k, v in s.attempts.items() if v[0] > now-60}
                started, count = s.attempts.get(ip, (now, 0))
                if count >= 10 or len(s.attempts) > 4096:
                    return self.reply(429, {'error': 'retry in one minute'})
                s.attempts[ip] = (started, count+1)
            data = self.body()
            if s.runtime.enforce:
                with s.runtime.lock:
                    guest=s.runtime.guest.settings()
                    if s.runtime.guest.captive(ip,guest).get('guest'):
                        if not s.trusted_cgi or self.headers.get('X-RahaWRT-HTTPS')!='on':
                            raise PermissionError('guest login requires HTTPS')
                        s.runtime.guest.sync(s.runtime.clients(),guest)
            token, role = s.store.login(data['name'], data['password'], ip,user_only=is_guest)
            secure = '; Secure' if s.trusted_cgi and self.headers.get('X-RahaWRT-HTTPS') == 'on' else ''
            return self.reply(200, {'role': role, 'token': token}, cookie='rahawrt='+token+'; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600'+secure)
        principal = s.store.key_principal(token) if token.startswith('rwk_') else s.store.principal(token, ip)
        if not principal:
            return self.reply(401, {'error': 'login required'})
        name, role, ident = principal
        if is_guest and role!='user':raise PermissionError('management access is unavailable from the guest network')
        scopes=set(ident) if role=='key' else set()
        def permitted(scope, roles=('admin','accounting')):
            if role not in roles and not (role=='key' and scope in scopes):
                raise PermissionError('insufficient role or API key scope')
        if path == '/wrt/api/v1/logout' and self.command == 'POST':
            if role=='key':
                raise PermissionError('revoke API keys through key management')
            s.store.logout(token)
            return self.reply(200, {'ok': True}, cookie='rahawrt=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0')
        if path == '/wrt/api/v1/me' and self.command == 'GET':
            return self.reply(200, {'name': name, 'role': role, 'device': ident if role!='key' else None, 'usage': s.store.usage().get(ident, [0, 0]) if role!='key' else None, 'account': s.store.account_state(name) if role=='user' else None})
        if path == '/wrt/api/v1/receipts' and self.command == 'POST':
            permitted('receipts:write')
            return self.reply(200, s.store.receipt(self.body()))
        if path=='/wrt/api/v1/resources' and self.command=='GET':
            permitted('',('admin','operator'))
            return self.reply(200,resources(s.store))
        if path=='/wrt/api/v1/diagnostics' and self.command=='POST':
            permitted('',('admin','operator'))
            return self.reply(200,client_route(s.runtime,self.body()))
        if path=='/wrt/api/v1/backup' and self.command=='GET':
            permitted('',('admin',))
            if s.trusted_cgi and self.headers.get('X-RahaWRT-HTTPS')!='on':raise PermissionError('backup download requires HTTPS')
            from .backup import build
            return self.reply(200,build(s.store,s.runtime.run),content_type='application/zip')
        if path=='/wrt/api/v1/reservations' and self.command=='POST':
            permitted('',('admin',))
            if not s.runtime.enforce:raise PermissionError('DHCP reservations require router enforcement mode')
            data=self.body()
            d=next((d for d in s.store.devices() if d['id']==data['device']),None)
            if not d:raise ValueError('unknown device')
            current=s.runtime.run(['uci','-q','show','dhcp'])
            if d['ip'] in current or d['mac'] in current:raise ValueError('existing DHCP settings may already reserve this IP/MAC; review them first')
            section='rw_'+d['id']
            if 'dhcp.'+section+'=' in current:raise ValueError('reservation section already exists')
            sections={'dhcp':{section:dict(type='host',options=dict(name=d['id'].replace('_','-').lower(),mac=d['mac'],ip=d['ip'],leasetime='infinite'))}}
            return self.reply(202,s.changes.start('reservation',sections,[['/etc/init.d/dnsmasq','restart'],['/etc/init.d/uhttpd','restart']],name))
        if path=='/wrt/api/v1/tunnels' and self.command=='GET':
            permitted('',('admin','operator'))
            with s.store.lock:
                rows=[dict(id=r[0],kind=r[1],change_id=r[2],configuration_status=r[3]) for r in s.store.db.execute('SELECT t.id,t.kind,t.change_id,c.status FROM tunnels t LEFT JOIN router_changes c ON c.id=t.change_id')]
            for tunnel in rows:
                try:
                    state=json.loads(s.runtime.run(['ubus','call','network.interface.'+tunnel['id'],'status']))
                    tunnel['up']=bool(state.get('up'));tunnel['device']=state.get('l3_device')
                except Exception:tunnel['up']=False
            return self.reply(200,{'tunnels':rows,'requirements':REQUIREMENTS})
        if path=='/wrt/api/v1/tunnels' and self.command=='POST':
            permitted('',('admin',))
            if not s.runtime.enforce:raise PermissionError('tunnel provisioning requires explicit router enforcement mode')
            data=self.body();prepared=provision(data)
            with s.store.lock,s.store.db:
                previous=s.store.db.execute('SELECT c.status FROM tunnels t LEFT JOIN router_changes c ON c.id=t.change_id WHERE t.id=?',(prepared['id'],)).fetchone()
                if previous:
                    if previous[0]!='rolled_back':raise ValueError('tunnel already exists or requires recovery')
                    s.store.db.execute('DELETE FROM tunnels WHERE id=?',(prepared['id'],))
            for filename in prepared['requirements']:s.runtime.run(['test','-e',filename])
            for config,entries in prepared['sections'].items():
                current=s.runtime.run(['uci','-q','show',config])
                if any(config+'.'+key+'=' in current for key in entries):raise ValueError('tunnel section already exists')
            for command,contents in prepared['prepare']:
                if command[0]=='nft':s.runtime.run(['nft','-c','-f','-'],contents)
                elif command[0]=='/usr/bin/python3' and len(command)>3:
                    if Path(command[-1]).exists():raise ValueError('tunnel file already exists; refusing to replace it')
            if prepared['kind']=='l2tp-ipsec':
                sas=s.runtime.run(['swanctl','--list-sas','--raw'])
                if not re.search(r'\breqid='+str(data['ipsec_reqid'])+r'\b',sas):raise ValueError('establish the matching IPsec transport child SA before enabling L2TP')
            change=s.changes.start('vpn',prepared['sections'],prepared['reloads'],name,prepare=prepared['prepare'],cleanup=prepared['cleanup'])
            with s.store.lock,s.store.db:
                metadata={key:data[key] for key in ('server','ipsec_reqid') if key in data} if prepared['kind']=='l2tp-ipsec' else {}
                s.store.db.execute('INSERT INTO tunnels VALUES (?,?,?,?)',(prepared['id'],prepared['kind'],change['id'],json.dumps(metadata)))
            return self.reply(202,dict(change,tunnel=prepared['id']))
        if path=='/wrt/api/v1/tunnels/action' and self.command=='POST':
            permitted('',('admin',))
            if not s.runtime.enforce:raise PermissionError('tunnel control requires router enforcement mode')
            data=self.body()
            with s.store.lock:
                row=s.store.db.execute('SELECT kind,change_id,metadata FROM tunnels WHERE id=?',(data['id'],)).fetchone()
                valid=s.store.db.execute("SELECT 1 FROM router_changes WHERE id=? AND status='confirmed'",(row[1],)).fetchone() if row else None
            if not valid:raise ValueError('unknown or unconfirmed tunnel')
            if data['action'] not in ('up','down'):raise ValueError('action must be up or down')
            if row[0]=='l2tp-ipsec' and data['action']=='up':
                metadata=json.loads(row[2]);sas=s.runtime.run(['swanctl','--list-sas','--raw'])
                if not re.search(r'\breqid='+str(metadata['ipsec_reqid'])+r'\b',sas):raise ValueError('matching IPsec child SA is not established')
                # After reboot, L2TP stays disabled until its XFRM guard is restored.
                plan=provision(dict(id=data['id'][3:],kind='l2tp-ipsec',server=metadata['server'],username='guard-only',password='guard-only',ipsec_reqid=metadata['ipsec_reqid']))
                try:s.runtime.run(['nft','list','table','inet',data['id']+'_ipsec'])
                except Exception:s.runtime.run(*plan['prepare'][0])
            s.runtime.run(['if'+data['action'],data['id']])
            with s.store.lock,s.store.db:s.store.audit(name,'tunnel.'+data['action'],data['id'])
            return self.reply(200,{'ok':True})
        if path=='/wrt/api/v1/parental':
            permitted('',('admin',))
            if self.command=='GET':return self.reply(200,{'profiles':s.store.parental.profiles()})
            if self.command=='PUT':return self.reply(200,{'profile':s.store.parental.save(self.body(),name)})
        if path=='/wrt/api/v1/parental/sources' and self.command=='GET':
            permitted('',('admin',))
            with s.store.lock:
                sources=[dict(zip(('category','source','attribution','license','sha256','updated','count'),r)) for r in s.store.db.execute('SELECT category,source,attribution,license,sha256,updated,count FROM category_sources')]
            return self.reply(200,{'sources':sources})
        if path=='/wrt/api/v1/parental/refresh' and self.command=='POST':
            permitted('',('admin',))
            data=self.body()
            try:return self.reply(200,s.store.parental.refresh(data['category'],name,data.get('sha256')))
            except OSError:return self.reply(502,{'error':'category refresh failed; previous list preserved'})
        if path.startswith('/wrt/api/v1/changes'):
            permitted('',('admin',))
            if self.command=='GET' and path=='/wrt/api/v1/changes':
                return self.reply(200,{'changes':s.changes.status()})
            if self.command=='POST' and path=='/wrt/api/v1/changes/confirm':
                data=self.body()
                return self.reply(200,s.changes.confirm(data['id'],data['token'],name))
            if self.command=='POST' and path=='/wrt/api/v1/changes/rollback':
                return self.reply(200,s.changes.rollback(self.body()['id']))
        if path=='/wrt/api/v1/guest' and self.command=='POST':
            permitted('',('admin',))
            if not s.runtime.enforce:
                raise PermissionError('guest provisioning requires explicit router enforcement mode')
            data=self.body()
            interfaces=json.loads(s.runtime.run(['ubus','call','network.interface','dump']))
            subnets=[a['address']+'/'+str(a['mask']) for i in interfaces.get('interface',[]) for a in i.get('ipv4-address',[])]
            sections=guest_plan(data,subnets)
            # Reuse the owner's existing HTTPS identity, through a separate docroot.
            for option in ('cert','key'):
                value=s.runtime.run(['uci','-q','get','uhttpd.main.'+option]).strip()
                if not value.startswith('/') or any(ord(c)<32 for c in value):raise ValueError('configure the main uhttpd HTTPS certificate and key first')
                s.runtime.run(['test','-f',value])
                sections['uhttpd']['rw_guest']['options'][option]=value
            for config,entries in sections.items():
                current=s.runtime.run(['uci','-q','show',config])
                for section in entries:
                    if config+'.'+section+'=' in current and not (config=='rahawrt' and section=='main'):
                        raise ValueError('guest section already exists; refusing to overwrite it')
            if data.get('radio'):
                s.runtime.run(['uci','-q','get','wireless.'+data['radio']])
            reloads=[['/etc/init.d/network','reload'],['/etc/init.d/firewall','restart'],['/etc/init.d/dnsmasq','restart']]
            if data.get('radio'):reloads.append(['wifi','reload'])
            bootstrap=bootstrap_rules(data['address'])
            s.runtime.run(['nft','-c','-f','-'],bootstrap)
            return self.reply(202,s.changes.start('guest',sections,reloads,name,prepare=[(['nft','-f','-'],bootstrap)],cleanup=[['nft','delete','table','inet','rahawrt_guest_guard']]))
        if path == '/wrt/api/v1/plans':
            if self.command == 'GET':
                permitted('accounts:issue', ('admin','operator','accounting'))
                return self.reply(200, {'plans':s.store.plans()})
            if self.command == 'PUT':
                permitted('', ('admin',))
                return self.reply(200, {'plan':s.store.put_plan(self.body(),name)})
        if path == '/wrt/api/v1/issue' and self.command == 'POST':
            permitted('accounts:issue')
            return self.reply(200,s.store.issue(self.body(),name))
        if path == '/wrt/api/v1/vouchers' and self.command == 'POST':
            permitted('accounts:issue')
            issued=s.store.issue_batch(self.body(),name)
            return self.reply(200,{'vouchers':issued,'replay_note':'Passwords are returned once; retries never create duplicate accounts.'})
        if path == '/wrt/api/v1/account-action' and self.command == 'POST':
            permitted('accounts:manage',('admin',))
            return self.reply(200,s.store.manage_account(self.body(),name))
        if path == '/wrt/api/v1/accounts' and self.command == 'GET':
            permitted('usage:read',('admin','operator','accounting'))
            with s.store.lock:
                accounts=[dict(name=r[0],role=r[1],device=r[2],account=s.store.account_state(r[0])) for r in s.store.db.execute('SELECT name,role,device FROM accounts ORDER BY name')]
            return self.reply(200,{'accounts':accounts})
        if path == '/wrt/api/v1/api-keys' and self.command == 'POST':
            permitted('',('admin',))
            return self.reply(201,s.store.create_key(self.body(),name))
        if path == '/wrt/api/v1/api-keys/revoke' and self.command == 'POST':
            permitted('',('admin',))
            s.store.revoke_key(self.body()['id'],name)
            return self.reply(200,{'ok':True})
        if path == '/wrt/api/v1/reports' and self.command == 'GET':
            if role!='user':
                permitted('usage:read',('admin','operator','accounting'))
            query=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            report=s.store.report(name if role=='user' else None,query.get('period',['daily'])[0])
            if query.get('format')==['csv']:
                out=io.StringIO();writer=csv.DictWriter(out,fieldnames=['period','device','account','upload_bytes','download_bytes']);writer.writeheader();writer.writerows(report)
                return self.reply(200,out.getvalue().encode(),content_type='text/csv')
            return self.reply(200,{'timezone':'UTC','rows':report})
        if path == '/wrt/api/v1/sessions' and self.command == 'GET':
            if role!='user':
                permitted('usage:read',('admin','operator','accounting'))
            with s.store.lock:
                query='SELECT name,device,ip,started,expires,ended,reason FROM session_history'
                args=()
                if role=='user': query+=' WHERE name=?';args=(name,)
                query+=' ORDER BY started DESC LIMIT 200'
                rows=[dict(zip(('name','device','ip','started','expires','ended','reason'),r)) for r in s.store.db.execute(query,args)]
            return self.reply(200,{'sessions':rows})
        if path == '/wrt/api/v1/audit' and self.command == 'GET':
            permitted('',('admin',))
            with s.store.lock:
                rows=[dict(zip(('id','time','actor','action','subject'),r)) for r in s.store.db.execute('SELECT seq,created,actor,action,subject FROM audit ORDER BY seq DESC LIMIT 200')]
            return self.reply(200,{'events':rows})
        if role not in ('admin', 'operator'):
            raise PermissionError('operator or admin required')
        if role == 'operator' and self.command != 'GET':
            raise PermissionError('admin required')
        if self.command == 'GET' and path == '/wrt/api/v1/status':
            return self.reply(200, s.runtime.status)
        if self.command == 'GET' and path == '/wrt/api/v1/devices':
            return self.reply(200, {'devices': s.store.devices(), 'usage': s.store.usage()})
        if self.command == 'GET' and path == '/wrt/api/v1/clients':
            return self.reply(200, {'clients': s.runtime.clients()})
        if self.command == 'GET' and path == '/wrt/api/v1/nodes':
            try:
                return self.reply(200, {'nodes': ['direct', 'default']+s.runtime.nodes()})
            except Exception:
                return self.reply(503, {'error': 'PassWall2 UCI unavailable'})
        if self.command == 'PUT' and path == '/wrt/api/v1/devices':
            from .policy import device
            data=device(self.body())
            if s.runtime.enforce:s.runtime.validate_strict_nodes([data])
            return self.reply(200, {'device': s.store.put_device(data,name), 'activation': 'pending next policy tick; inspect status'})
        if self.command == 'POST' and path == '/wrt/api/v1/accounts':
            d = self.body()
            s.store.account(d['name'], d['password'], d['role'], d.get('device'),name)
            return self.reply(201, {'ok': True})
        if self.command == 'GET' and path == '/wrt/api/v1/receipts':
            with s.store.lock:
                rows = [json.loads(r[0]) for r in s.store.db.execute('SELECT payload FROM receipts ORDER BY created DESC LIMIT 100')]
            return self.reply(200, {'receipts': rows})
        return self.reply(404, {'error': 'not found'})


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--db', default='/etc/rahawrt/state.db')
    p.add_argument('--web', default='/usr/share/rahawrt/web')
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=9080)
    p.add_argument('--enforce', action='store_true')
    p.add_argument('--trusted-cgi', action='store_true')
    p.add_argument('--create-admin', metavar='NAME')
    p.add_argument('--timezone', help='POSIX/IANA timezone; otherwise use OpenWrt system timezone when enforcing')
    p.add_argument('--dns-upstream',default='1.1.1.1')
    p.add_argument('--dns-upstream-port',type=int,default=53)
    args = p.parse_args()
    if args.enforce and Path(args.db).resolve()!=Path('/etc/rahawrt/state.db').resolve():
        p.error('enforcement requires the service database /etc/rahawrt/state.db so the independent guard sees the same policy')
    os.umask(0o077)
    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    store = Store(args.db)
    if args.create_admin:
        store.account(args.create_admin, getpass.getpass('Password (12+ characters): '), 'admin')
        return
    if args.host != '127.0.0.1':
        p.error('backend requires loopback binding; expose the panel through uhttpd HTTPS')
    timezone=args.timezone
    if args.enforce and not timezone:
        timezone=subprocess.run(['uci','-q','get','system.@system[0].timezone'],text=True,capture_output=True,check=True).stdout.strip()
    if timezone:
        if len(timezone)>128 or any(ord(c)<32 for c in timezone):p.error('invalid timezone')
        os.environ['TZ']=timezone
        time.tzset()
    upstream=str(ipaddress.IPv4Address(args.dns_upstream))
    if not 1<=args.dns_upstream_port<=65535:p.error('invalid DNS upstream port')
    runtime = Runtime(store, args.enforce)
    runtime.status['timezone']=list(time.tzname)
    runtime.status['utc_offset']=time.strftime('%z')
    changes=ChangeGuard(store,runtime.run)
    changes.recover()
    if args.enforce:
        runtime.preflight()
        runtime.tick()
    dns=None
    portal=None
    if args.enforce:
        dns=DNSServer(('0.0.0.0',1053),Resolver(store,store.parental,(upstream,args.dns_upstream_port),captive_portal=lambda:runtime.status.get('guest'),transport=lambda query:runtime.direct_dns(query,(upstream,args.dns_upstream_port)),proxy_transport=lambda query,d: runtime.parental_dns(query,d,(upstream,args.dns_upstream_port)),local_records=lambda: {runtime.status['guest'].get('portal_host',runtime.status['guest']['gateway']):runtime.status['guest']['gateway']} if runtime.status.get('guest') else {}))
        dns.start()
        from .portal import PortalServer
        portal=PortalServer(('0.0.0.0',2080),lambda:runtime.status.get('guest'))
        portal.start()
    stop = threading.Event()
    thread = threading.Thread(target=runtime.loop, args=(stop,), daemon=True)
    server = Server((args.host, args.port), store, runtime, args.web, args.trusted_cgi, changes)
    runtime.boot_guard=args.enforce
    thread.start()
    def shutdown(signum,frame):
        stop.set()
        threading.Thread(target=server.shutdown,daemon=True).start()
    signal.signal(signal.SIGTERM,shutdown)
    try:
        server.serve_forever()
    finally:
        stop.set()
        thread.join(timeout=35)
        server.server_close()
        if dns:dns.close()
        if portal:portal.close()
        runtime.proxy_dns.close()
        if args.enforce:
            from .boot_guard import HEARTBEAT
            HEARTBEAT.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
