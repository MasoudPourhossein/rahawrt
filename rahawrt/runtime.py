"""OpenWrt adapters. Preview is the default; enforcement is explicit."""
import datetime as dt
import json
import subprocess
import threading
from pathlib import Path
import re
import secrets
import ipaddress
import shlex
import sys
from .policy import active, compile_nft
from .guest import Guest
from .routes import Routes
from .proxy_dns import ProxyDNS


def run(argv, data=None):
    return subprocess.run(argv, input=data, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30).stdout


class Runtime:
    def __init__(self, store, enforce=False, runner=run):
        self.store, self.enforce, self.run = store, enforce, runner
        self.lock = threading.RLock()
        self.previous = {}
        self.signature = None
        self.guest=Guest(store,runner)
        self.changes=None
        self.boot_guard=False
        self.routes=Routes(store,runner)
        self.proxy_dns=ProxyDNS(store,runner)
        self.status = {'mode': 'enforce' if enforce else 'preview', 'applied': False, 'error': None}

    def preflight(self):
        self.run(['uci', '-q', 'show', 'passwall2'])
        self.run(['test', '-x', '/etc/init.d/passwall2'])
        if self.run(['uci', '-q', 'get', 'passwall2.@global[0].enabled']).strip() != '1':
            raise ValueError('PassWall2 must already be enabled')
        if self.run(['uci', '-q', 'get', 'passwall2.@global[0].acl_enable']).strip() != '1':
            raise ValueError('enable PassWall2 access control before enforcement')
        schema = Path('/usr/lib/lua/luci/model/cbi/passwall2/client/acl_config.lua')
        if not schema.exists() or not re.search(r'''["']node["']''', schema.read_text()) or not re.search(r'''["']mode["']''', schema.read_text()):
            raise ValueError('unrecognized PassWall2 ACL schema; adapter must be verified before activation')
        self.run(['nft', '--version'])
        if 'flowtable ' in self.run(['nft', 'list', 'ruleset']):
            raise ValueError('active flowtable detected; reload firewall after disabling offload')
        firewall = self.run(['uci', '-q', 'show', 'firewall'])
        if '=defaults' not in firewall:
            raise ValueError('unrecognized firewall defaults')
        for line in firewall.splitlines():
            if any('.'+option+'=' in line for option in ('flow_offloading', 'flow_offloading_hw')):
                if shlex.split(line.split('=', 1)[1]) != ['0']:
                    raise ValueError('disable firewall flow offloading before enforcement')

    def clients(self,path=Path('/tmp/dhcp.leases')):
        path = Path(path)
        if not path.exists():
            return []
        result = []
        for line in path.read_text().splitlines():
            fields = line.split()
            if len(fields) >= 4:
                result.append(dict(expires=fields[0], mac=fields[1], ip=fields[2], name=fields[3]))
        observations={}
        if result and self.enforce:
            try:
                for entry in json.loads(self.run(['ip','-j','-4','neigh','show'])):
                    observations.setdefault(entry.get('dst'),[]).append(entry)
            except (ValueError,OSError,subprocess.SubprocessError):pass
        for client in result:
            entries=observations.get(client['ip'],[])
            matching=[entry for entry in entries if entry.get('lladdr','').lower()==client['mac'].lower()]
            observed=matching[0] if matching else None
            state=observed.get('state',[]) if observed else []
            if isinstance(state,str):state=[state]
            client['neighbor_state']=state or (['MAC_MISMATCH'] if entries else ['UNKNOWN'])
            client['observed_interface']=observed.get('dev') if observed else None
        return result

    def nodes(self):
        text = self.run(['uci', '-q', 'show', 'passwall2'])
        return sorted(line.split('=')[0].split('.', 1)[1] for line in text.splitlines() if line.endswith('=nodes'))

    def sample(self):
        try:
            data = json.loads(self.run(['nft', '-j', 'list', 'table', 'inet', 'rahawrt']))
        except subprocess.CalledProcessError as exc:
            if 'No such file' in (exc.stderr or ''):
                self.signature=None
                self.status['accounting_warning']='managed table was absent; reapplying policy, unsampled bytes may be lost'
                return
            raise
        counts = {}
        for item in data.get('nftables', []):
            rule = item.get('rule', {})
            tag = rule.get('comment', '').split(':')
            if len(tag) != 3 or tag[0] != 'rw':
                continue
            count = sum(expr.get('counter', {}).get('bytes', 0) for expr in rule.get('expr', []) if isinstance(expr.get('counter'), dict))
            counts[(rule['chain'], tag[1], tag[2])] = count
        self.store.sample_counters(counts)

    def passwall_plan(self, devices, now):
        known = self.nodes()
        rules = []
        for d in sorted(devices, key=lambda x: x['id']):
            node = d['node'] if active(d['vpn'], now) and not d.get('tunnel') else 'direct'
            if node not in ('direct', 'default') and node not in known:
                raise ValueError('unknown PassWall2 node: '+node)
            rules.append((d['id'], d['ip'], node))
        return rules

    def check_acl_conflicts(self, devices):
        if self.run(['uci', 'changes', 'passwall2']).strip():
            raise ValueError('save or revert pending PassWall2 edits before applying RahaWRT')
        sections = {}
        for line in self.run(['uci', '-q', 'show', 'passwall2']).splitlines():
            key, sep, value = line.partition('=')
            parts = key.split('.')
            if sep and len(parts) >= 2:
                sections.setdefault(parts[1], {})[parts[2] if len(parts) == 3 else '_type'] = shlex.split(value)
        for sid, section in sections.items():
            if section.get('_type') != ['acl_rule'] or section.get('enabled', ['1']) == ['0']:
                continue
            if sid.startswith('rw_') and section.get('rahawrt_owner') == ['1']:
                continue
            for source in section.get('sources', ['any']):
                for d in devices:
                    overlaps = source.lower() in ('any', d['mac'])
                    if not overlaps:
                        try:
                            overlaps = ipaddress.IPv4Address(d['ip']) in ipaddress.IPv4Network(source, strict=False)
                        except ValueError:
                            # Unknown source syntax may match this client; do not override it.
                            overlaps = True
                    if overlaps:
                        raise ValueError('existing ACL '+sid+' may overlap device '+d['id']+'; resolve explicitly in PassWall2')

    def validate_strict_nodes(self,devices):
        checked=set()
        for d in devices:
            selected=d['node']
            if selected=='direct' or d.get('tunnel') or d['vpn_failure']!='block':continue
            if selected in checked:continue
            checked.add(selected)
            node=self.run(['uci','-q','get','passwall2.@global[0].node']).strip() if selected=='default' else selected
            if not re.fullmatch(r'[A-Za-z0-9_]{1,64}',node):raise ValueError('strict global VPN requires a concrete node')
            try:protocol=self.run(['uci','-q','get','passwall2.'+node+'.protocol']).strip().lower()
            except subprocess.CalledProcessError:protocol=''
            if protocol.startswith('_') or protocol in ('direct','freedom'):
                raise ValueError('VPN-only requires a concrete remote node; shunt/balancer/interface nodes may send traffic directly')

    def transition_guard(self, devices, local_ips):
        try:
            self.run(['nft', 'list', 'table', 'inet', 'rahawrt_transition'])
            prefix = 'delete table inet rahawrt_transition\n'
        except subprocess.CalledProcessError:
            prefix = ''
        rules = ['table inet rahawrt_transition {', 'chain ingress { type filter hook prerouting priority -310; policy accept;',
                 'ip daddr { '+', '.join(local_ips)+' } return']
        for d in devices:
            rules.append('ip saddr '+d['ip']+' drop')
        rules += ['}', '}']
        self.run(['nft', '-f', '-'], prefix+'\n'.join(rules)+'\n')

    def set_passwall(self, rules):
        current = self.run(['uci', '-q', 'show', 'passwall2'])
        commands = []
        for line in current.splitlines():
            key = line.split('=')[0]
            if '.' not in key[len('passwall2.'): ] and key.startswith('passwall2.rw_'):
                if self.run(['uci', '-q', 'get', key+'.rahawrt_owner']).strip() != '1':
                    raise ValueError('unowned ACL section conflicts with RahaWRT namespace')
                commands.append('delete '+key)
        for ident, ip, node in rules:
            key = 'passwall2.rw_'+ident
            commands += [f'set {key}=acl_rule', f'set {key}.enabled=1', f'set {key}.rahawrt_owner=1', f"set {key}.remarks='RahaWRT {ident}'", f'add_list {key}.sources={ip}', f'set {key}.mode={0 if node == "direct" else 2 if node == "default" else 1}', f'set {key}.tcp_redir_ports=1:65535', f'set {key}.udp_redir_ports=1:65535']
            if node not in ('direct', 'default'):
                commands.append(f'set {key}.node={node}')
        self.run(['uci', 'batch'], '\n'.join(commands)+'\n')
        self.run(['uci', 'commit', 'passwall2'])
        self.run(['/etc/init.d/passwall2', 'restart'])

    def set_native_firewall(self,rules):
        current=self.run(['uci','-q','show','firewall']);commands=[]
        for line in current.splitlines():
            key,sep,value=line.partition('=')
            if sep and key.startswith('firewall.rw_route_') and '.' not in key[len('firewall.'):]:
                if self.run(['uci','-q','get',key+'.rahawrt_owner']).strip()!='1':raise ValueError('unowned native-route firewall section')
                commands.append('delete '+key)
        for ident,options in rules.items():
            key='firewall.rw_route_'+ident
            commands += ['set '+key+'=rule','set '+key+'.rahawrt_owner=1']
            commands += ['set '+key+'.'+option+'='+shlex.quote(value) for option,value in options.items()]
        if commands:
            self.run(['uci','batch'],'\n'.join(commands)+'\n');self.run(['uci','commit','firewall']);self.run(['/etc/init.d/firewall','restart'])

    def parental_dns(self,query,device,target):
        if not device.get('tunnel'):return self.proxy_dns.forward(query,device,target)
        state=self.status.get('native_routes',{}).get(device['id'])
        if not state or not state['enabled'] or not state['interface']:raise OSError('native DNS route unavailable')
        return self._dns_worker(query,target,state)

    def direct_dns(self,query,target):
        return self._dns_worker(query,target)

    def _dns_worker(self,query,target,state=None):
        # PassWall2 installs PSW2_DIRECT for sockets created by GID 9912 in both
        # output chains. Verify it, rather than accidentally using its global node.
        try:table=json.loads(self.run(['nft','-n','-j','list','table','inet','passwall2']))
        except (OSError,subprocess.SubprocessError):raise OSError('PassWall2 DNS bypass table unavailable') from None
        bypass=set();seen=set()
        expected={'left':{'meta':{'key':'skgid'}},'op':'==','right':9912}
        for entry in table.get('nftables',[]):
            rule=entry.get('rule',{});chain=rule.get('chain')
            if chain not in ('mangle_output','nat_output') or chain in seen:continue
            seen.add(chain)
            expressions=rule.get('expr',[])
            if (any('return' in expr for expr in expressions)
                and any(expr.get('match')==expected for expr in expressions)
                and all(set(expr)<= {'match','counter','return'} and ('match' not in expr or expr['match']==expected) for expr in expressions)):
                bypass.add(chain)
        if bypass!={'mangle_output','nat_output'}:raise OSError('PassWall2 native DNS bypass contract unavailable')
        command=[sys.executable,'-m','rahawrt.native_dns','--server',target[0],'--port',str(target[1])]
        command+=['--interface',state['interface'],'--mark',str(state['mark'])] if state else ['--direct']
        try:result=subprocess.run(command,input=query,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=4,group=9912)
        except (OSError,subprocess.SubprocessError):raise OSError('private DNS worker unavailable') from None
        if result.returncode:raise OSError('native DNS exchange failed')
        from .dns import question
        echoed=bytearray(result.stdout)
        if len(echoed)<12:raise ValueError('invalid native DNS response')
        echoed[2:4]=b'\x01\x00';echoed[4:6]=b'\x00\x01'
        if question(bytes(echoed),max_size=65535)[1:3]!=question(query)[1:3]:raise ValueError('native DNS question mismatch')
        return result.stdout

    def tick(self):
        with self.lock:
            try:
                if self.changes:
                    self.changes.check()
                if self.enforce:
                    self.sample()
                guest=self.guest.settings() if self.enforce else None
                if self.enforce:self.guest.sync(self.clients(),guest)
                now = dt.datetime.now().astimezone()
                devices = self.store.effective_devices()
                if self.enforce:devices=self.routes.prepare(devices,now)
                else:
                    for d in devices:
                        if d.get('tunnel'):d['_native']=dict(active=active(d['vpn'],now),up=False,interface=None)
                local_ips = None
                if self.enforce:
                    interfaces = json.loads(self.run(['ubus', 'call', 'network.interface', 'dump']))
                    local_ips = [a['address'] for i in interfaces.get('interface', []) for a in i.get('ipv4-address', [])]
                    if any(d['ip'] in local_ips for d in devices):
                        raise ValueError('a managed device cannot use a router address')
                    if not local_ips:
                        raise ValueError('no router IPv4 addresses discovered; refusing to risk management access')
                nft = compile_nft(devices, self.store.usage(), self.store.online(), now, local_ips, guest)
                self.status['plan'] = nft
                if not self.enforce:
                    return
                self.validate_strict_nodes(devices)
                rules = self.passwall_plan(devices, now)
                desired_routes=self.routes.desired(devices)
                route_signature=self.routes.fingerprint(desired_routes)
                signature = (nft, tuple(rules),route_signature)
                if signature != self.signature:
                    self.check_acl_conflicts(devices)
                    old_uci = self.run(['uci', 'export', 'passwall2'])
                    with self.store.lock:
                        old_routes={ident:json.loads(state) for ident,state in self.store.db.execute('SELECT device,state FROM native_routes WHERE state IS NOT NULL')}
                    route_changed=bool(desired_routes or old_routes) and (self.signature is None or route_signature!=self.signature[2])
                    if route_changed and self.run(['uci','changes','firewall']).strip():raise ValueError('save or revert pending firewall edits before native routing')
                    old_firewall=self.run(['uci','export','firewall']) if route_changed else None
                    exists = True
                    try:
                        self.run(['nft', 'list', 'table', 'inet', 'rahawrt'])
                    except subprocess.CalledProcessError:
                        exists = False
                    generation = secrets.token_hex(8)
                    generated = nft
                    for chain in ('upload', 'forward', 'download','dns'):
                        generated = generated.replace('chain '+chain+' {', 'chain g_'+generation+'_'+chain+' {')
                    transaction = ('delete table inet rahawrt\n' if exists else '') + generated
                    self.run(['nft', '-c', '-f', '-'], transaction)
                    self.transition_guard(devices, local_ips)
                    try:
                        if self.signature is None or tuple(rules) != self.signature[1]:
                            self.set_passwall(rules)
                        if route_changed:self.set_native_firewall(self.routes.firewall(desired_routes))
                        self.routes.sync(desired_routes)
                        # Include traffic accrued during the PassWall2 restart.
                        self.sample()
                        self.run(['nft', '-f', '-'], transaction)
                    except Exception as activation_error:
                        failures=[]
                        try:self.routes.sync(old_routes)
                        except Exception:failures.append('native routes')
                        if old_firewall is not None:
                            try:
                                self.run(['uci','import','firewall'],old_firewall)
                                self.run(['uci','commit','firewall'])
                                self.run(['/etc/init.d/firewall','restart'])
                            except Exception:failures.append('firewall')
                        try:
                            self.run(['uci','import','passwall2'],old_uci)
                            self.run(['uci','commit','passwall2'])
                            self.run(['/etc/init.d/passwall2','restart'])
                        except Exception:failures.append('PassWall2')
                        if failures:raise RuntimeError('activation failed; console recovery required for '+', '.join(failures)) from activation_error
                        raise
                    self.run(['nft', 'delete', 'table', 'inet', 'rahawrt_transition'])
                    self.previous = {}
                    self.signature = signature
                self.status['parental_proxy_dns']=self.proxy_dns.ensure(devices,now)
                # Reconcile after unrelated netifd rule deletion without replacing nft counters.
                self.routes.sync(desired_routes)
                self.status['native_routes']=desired_routes
                if guest:
                    try:self.run(['nft','list','table','inet','rahawrt_guest_guard'])
                    except subprocess.CalledProcessError:pass
                    else:self.run(['nft','delete','table','inet','rahawrt_guest_guard'])
                if self.boot_guard:
                    from .boot_guard import beat,remove
                    beat();remove(self.run)
                self.status.update(applied=True, error=None, guest=guest)
            except Exception as exc:
                if self.boot_guard:
                    try:
                        from .boot_guard import apply
                        apply(self.run)
                    except Exception:pass
                self.status.update(applied=False, error=str(exc))
                raise

    def loop(self, stop):
        while not stop.is_set():
            try:
                self.tick()
            except Exception:
                pass  # Visible in authenticated status API; retain last valid nft transaction.
            stop.wait(5)
