"""Owned source-policy routing for confirmed native tunnels, with terminal routes."""
import ipaddress
import json
import re
import subprocess
from .policy import active

PROTO=242


def interface_name(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}',value):
        raise ValueError('invalid observed tunnel interface')
    return value


class Routes:
    def __init__(self,store,runner):
        self.store,self.run=store,runner
        with store.lock:
            store.db.execute('CREATE TABLE IF NOT EXISTS native_routes(device TEXT PRIMARY KEY,slot INTEGER UNIQUE NOT NULL,state TEXT,previous TEXT)')
            if 'previous' not in {r[1] for r in store.db.execute('PRAGMA table_info(native_routes)')}:store.db.execute('ALTER TABLE native_routes ADD COLUMN previous TEXT')
            store.db.commit()

    def _rules(self):return json.loads(self.run(['ip','-N','-j','-4','rule','show']))

    def _table(self,number):
        try:return json.loads(self.run(['ip','-N','-j','-4','route','show','table',str(number)]))
        except subprocess.CalledProcessError as exc:
            if any(message in (exc.stderr or '') for message in ('FIB table does not exist','No such file')):return []
            raise

    def _slot(self,ident):
        with self.store.lock,self.store.db:
            row=self.store.db.execute('SELECT slot FROM native_routes WHERE device=?',(ident,)).fetchone()
            if row:return row[0]
            occupied={r[0] for r in self.store.db.execute('SELECT slot FROM native_routes')}
            rules=self._rules()
            for slot in range(1,10000):
                if slot in occupied:continue
                priority=10000+slot
                if any(r.get('priority') in (priority,20000+slot) or str(r.get('table'))==str(40000+slot) for r in rules):continue
                if self._table(40000+slot):continue
                self.store.db.execute('INSERT INTO native_routes(device,slot) VALUES (?,?)',(ident,slot))
                return slot
        raise ValueError('no collision-free routing table available')

    def prepare(self,devices,now):
        """Attach observed state; this does not mutate the router."""
        result=[];observations={}
        for original in devices:
            d=dict(original);target=d.get('tunnel')
            if not target:
                result.append(d);continue
            selected=active(d['vpn'],now)
            if target not in observations:
                with self.store.lock:
                    row=self.store.db.execute("SELECT t.kind FROM tunnels t JOIN router_changes c ON c.id=t.change_id WHERE t.id=? AND c.status='confirmed'",(target,)).fetchone()
                state={}
                if row:
                    try:state=json.loads(self.run(['ubus','call','network.interface.'+target,'status']))
                    except (subprocess.CalledProcessError,ValueError):state={}
                expected={'wireguard':target,'openvpn':target,'openconnect':'vpn-'+target,'l2tp-ipsec':'l2tp-'+target}.get(row[0] if row else '')
                observed=state.get('l3_device')
                up=bool(state.get('up') and observed==expected)
                observations[target]=dict(up=up,interface=interface_name(observed) if up else None)
            observed=observations[target]
            slot=self._slot(d['id'])
            # A terminal route makes strict tunnel failure independent of an absent
            # usable default route in the selected policy table.
            d['_native']=dict(active=selected,up=selected and observed['up'],interface=observed['interface'] if selected else None,table=40000+slot,priority=10000+slot,slot=slot)
            result.append(d)
        return result

    def desired(self,devices):
        result={}
        for d in devices:
            state=d.get('_native')
            if not state:continue
            enabled=state['active'] and (state['up'] or d['vpn_failure']=='block')
            result[d['id']]=dict(ip=d['ip'],table=state['table'],priority=state['priority'],interface=state['interface'] if state['up'] else None,enabled=enabled,tunnel=d['tunnel'],mark=0x52410000|state['slot'],dns_priority=20000+state['slot'])
        return result

    @staticmethod
    def fingerprint(desired):return json.dumps(desired,sort_keys=True)

    def firewall(self,desired):
        return {ident:dict(src='*',dest=state['tunnel'],src_ip=state['ip'],target='ACCEPT',family='ipv4') for ident,state in desired.items() if state['enabled'] and state['interface']}

    @staticmethod
    def _number(value):
        return int(value,0) if isinstance(value,str) else int(value)

    def _check(self,state,rules,owned):
        priorities={state['priority'],state.get('dns_priority')}
        for rule in rules:
            if rule.get('priority') not in priorities:continue
            same=False
            for candidate in owned:
                if str(rule.get('table'))!=str(candidate['table']):continue
                try:
                    if rule.get('priority')==candidate['priority']:
                        same |= set(rule)<= {'priority','src','table','protocol','flags'} and not rule.get('flags') and ipaddress.IPv4Network(rule.get('src','all'),strict=False)==ipaddress.IPv4Network(candidate['ip']+'/32')
                    if candidate.get('dns_priority')==rule.get('priority') and candidate.get('mark') is not None:
                        same |= set(rule)<= {'priority','src','table','protocol','flags','fwmark','fwmask'} and not rule.get('flags') and rule.get('src','all')=='all' and self._number(rule.get('fwmark',0))==candidate['mark'] and self._number(rule.get('fwmask','0xffffffff'))==0xffffffff
                except (ValueError,TypeError):pass
            if not same or str(rule.get('protocol'))!=str(PROTO):raise ValueError('routing priority is owned by another policy')
        for route in self._table(state['table']):
            if str(route.get('protocol'))!=str(PROTO):raise ValueError('routing table contains an unowned route')

    def sync(self,desired):
        """Reconcile only registered tables/rules; never flush shared routing state."""
        with self.store.lock:
            old={ident:json.loads(state) for ident,state in self.store.db.execute('SELECT device,state FROM native_routes WHERE state IS NOT NULL')}
            previous=[json.loads(r[0]) for r in self.store.db.execute('SELECT previous FROM native_routes WHERE previous IS NOT NULL')]
        rules=self._rules() if desired or old else []
        owned=[*old.values(),*desired.values(),*previous]
        for state in owned:self._check(state,rules,owned)
        with self.store.lock,self.store.db:
            for ident,state in desired.items():
                self.store.db.execute('UPDATE native_routes SET previous=state,state=? WHERE device=?',(json.dumps(state),ident))
        for state in previous:
            if not any(state==s for s in desired.values()):self._remove_rule(state,rules)
        for ident,state in old.items():
            if ident not in desired or state!=desired[ident]:self._remove_rule(state,rules)
        for ident,state in desired.items():
            table=str(state['table'])
            if not state['enabled']:
                self._remove_rule(state,rules)
                self.run(['ip','-4','route','flush','table',table,'proto',str(PROTO)])
            else:
                self.run(['ip','-4','route','replace','unreachable','default','table',table,'metric','32767','proto',str(PROTO)])
                if state['interface']:
                    self.run(['ip','-4','route','replace','default','dev',state['interface'],'table',table,'metric','10','proto',str(PROTO)])
                else:
                    for route in self._table(state['table']):
                        if route.get('dev'):
                            self.run(['ip','-4','route','del','default','table',table,'metric',str(route.get('metric',10)),'proto',str(PROTO)])
                # Refresh after removal so duplicate rules are not accumulated.
                current=self._rules()
                if not any(r.get('priority')==state['priority'] for r in current):
                    self.run(['ip','-4','rule','add','priority',str(state['priority']),'from',state['ip']+'/32','lookup',table,'protocol',str(PROTO)])
                if state.get('mark') and not any(r.get('priority')==state['dns_priority'] for r in self._rules()):
                    self.run(['ip','-4','rule','add','priority',str(state['dns_priority']),'fwmark',hex(state['mark'])+'/0xffffffff','lookup',table,'protocol',str(PROTO)])
            with self.store.lock,self.store.db:
                self.store.db.execute('UPDATE native_routes SET state=?,previous=NULL WHERE device=?',(json.dumps(state),ident))
        for ident,state in old.items():
            if ident not in desired:
                self.run(['ip','-4','route','flush','table',str(state['table']),'proto',str(PROTO)])
                with self.store.lock,self.store.db:self.store.db.execute('UPDATE native_routes SET state=NULL,previous=NULL WHERE device=?',(ident,))

    def _remove_rule(self,state,rules):
        if any(r.get('priority')==state['priority'] for r in rules):
            # Include every owned selector: a concurrent foreign rule is not removed.
            try:self.run(['ip','-4','rule','del','priority',str(state['priority']),'from',state['ip']+'/32','lookup',str(state['table']),'protocol',str(PROTO)])
            except subprocess.CalledProcessError as exc:
                if 'No such file' not in (exc.stderr or ''):raise

        if state.get('dns_priority') and any(r.get('priority')==state['dns_priority'] for r in rules):
            try:self.run(['ip','-4','rule','del','priority',str(state['dns_priority']),'fwmark',hex(state['mark'])+'/0xffffffff','lookup',str(state['table']),'protocol',str(PROTO)])
            except subprocess.CalledProcessError as exc:
                if 'No such file' not in (exc.stderr or ''):raise
