"""Isolated guest UCI plan and DHCP/Captive Portal discovery (RFC 8908/8910)."""
import ipaddress
import re
import subprocess
import time
from .parental import domain
from .policy import device


def guest_plan(data, existing_networks=()):
    if not isinstance(data,dict) or set(data)-{'address','radio','ssid','password','open_wifi','portal_host'}:
        raise ValueError('unknown guest settings')
    interface=ipaddress.IPv4Interface(data['address'])
    network=interface.network
    if not any(interface.ip in ipaddress.IPv4Network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')) or network.prefixlen<24 or network.prefixlen>28 or interface.ip != network.network_address+1:
        raise ValueError('guest address requires a private /24–/28 subnet and usable gateway')
    for other in existing_networks:
        if network.overlaps(ipaddress.IPv4Network(other,strict=False)):
            raise ValueError('guest subnet overlaps an existing network')
    radio=data.get('radio')
    if radio is not None and (not isinstance(radio,str) or not re.fullmatch(r'radio[0-9]+',radio)):
        raise ValueError('invalid wireless radio')
    ssid=data.get('ssid','RahaWRT Guest')
    if not isinstance(ssid,str) or not 1<=len(ssid.encode())<=32 or any(ord(c)<32 for c in ssid):
        raise ValueError('SSID must be 1–32 UTF-8 bytes without control characters')
    open_wifi=data.get('open_wifi',False)
    if type(open_wifi) is not bool:raise ValueError('open_wifi must be boolean')
    password=data.get('password','')
    if radio and not open_wifi and (not isinstance(password,str) or not 8<=len(password)<=63 or not password.isascii() or any(ord(c)<32 for c in password)):
        raise ValueError('WPA2 guest Wi-Fi requires an 8–63 character ASCII password')
    def entry(kind,**options):return dict(type=kind,options=options)
    gateway=str(interface.ip)
    portal_host=domain(data.get('portal_host') or gateway)
    sections={
        'network':{'rw_guest_bridge':entry('device',name='br-rahaguest',type='bridge'), 'rw_guest':entry('interface',device='br-rahaguest',proto='static',ipaddr=gateway,netmask=str(network.netmask))},
        'dhcp':{'rw_guest':entry('dhcp',interface='rw_guest',start='2',limit=str(network.num_addresses-3),leasetime='1h',dhcp_option=['114,https://'+portal_host+':8443/cgi-bin/rahawrt/wrt/api/v1/captive'])},
        'firewall':{
            'rw_guest':entry('zone',name='rw_guest',network=['rw_guest'],input='REJECT',output='ACCEPT',forward='REJECT'),
            'rw_guest_wan':entry('forwarding',src='rw_guest',dest='wan'),
            'rw_guest_dhcp':entry('rule',name='RahaWRT Guest DHCP',src='rw_guest',proto='udp',dest_port='67',target='ACCEPT',family='ipv4'),
            'rw_guest_dns':entry('rule',name='RahaWRT Guest DNS',src='rw_guest',proto='tcp udp',dest_port='53 1053',target='ACCEPT',family='ipv4'),
            'rw_guest_portal':entry('rule',name='RahaWRT Guest Portal',src='rw_guest',proto='tcp',dest_port='8443 2080',target='ACCEPT',family='ipv4')},
        'rahawrt':{'main':entry('service',enabled='1',enforce='1',guest_network='rw_guest',portal_host=portal_host,portal_port='8443')},
        'uhttpd':{'rw_guest':entry('uhttpd',listen_https=[gateway+':8443'],home='/usr/share/rahawrt/public',config='/usr/share/rahawrt/guest.httpd.conf',cgi_prefix='/cgi-bin',cert='/etc/uhttpd.crt',key='/etc/uhttpd.key',max_requests='8',max_connections='32',no_dirlists='1',no_symlinks='1',script_timeout='30',network_timeout='30')}}
    if portal_host!=gateway:sections['dhcp']['rw_guest_portal']=entry('domain',name=portal_host,ip=gateway)
    if radio:
        options=dict(device=radio,network='rw_guest',mode='ap',ssid=ssid,isolate='1',encryption='none' if open_wifi else 'psk2')
        if not open_wifi:options['key']=password
        sections['wireless']={'rw_guest':entry('wifi-iface',**options)}
    return sections


def portal_url(settings):
    host=domain(settings.get('portal_host',settings['gateway']))
    port=settings.get('portal_port',443)
    if port not in (443,8443):raise ValueError('invalid portal port')
    return 'https://'+host+(':'+str(port) if port!=443 else '')+'/wrt/'


class Guest:
    def __init__(self, store, runner):self.store,self.run=store,runner

    def settings(self):
        try:name=self.run(['uci','-q','get','rahawrt.main.guest_network']).strip()
        except subprocess.CalledProcessError:return None
        if not name:return None
        if name!='rw_guest':raise ValueError('unrecognized managed guest network')
        address=self.run(['uci','-q','get','network.rw_guest.ipaddr']).strip()
        mask=self.run(['uci','-q','get','network.rw_guest.netmask']).strip()
        try:portal_host=domain(self.run(['uci','-q','get','rahawrt.main.portal_host']).strip())
        except subprocess.CalledProcessError:portal_host=address
        try:portal_port=int(self.run(['uci','-q','get','rahawrt.main.portal_port']).strip())
        except subprocess.CalledProcessError:portal_port=443
        if portal_port not in (443,8443):raise ValueError('invalid managed portal port')
        return dict(portal_port=portal_port,network=str(ipaddress.IPv4Network(address+'/'+mask,strict=False)),gateway=str(ipaddress.IPv4Address(address)),interface='br-rahaguest',portal_host=portal_host)

    def sync(self, clients, settings):
        subnet=ipaddress.IPv4Network(settings['network']) if settings else None
        known=self.store.devices()
        for client in clients:
            try:
                if int(client.get('expires',0)) and int(client['expires'])<int(time.time()):continue
                address=ipaddress.IPv4Address(client['ip'])
                is_guest=bool(subnet and address in subnet and client['ip']!=settings['gateway'])
                previous=next((d for d in known if d['mac']==client['mac'].lower()),None)
                if previous:
                    updated=dict(previous,ip=client['ip'],hotspot=previous['hotspot'] or is_guest)
                    if updated==previous:continue
                else:
                    if not is_guest:continue
                    updated=device(dict(id='g_'+client['mac'].replace(':','').lower(),ip=client['ip'],mac=client['mac'],name=client['name'],hotspot=True))
                self.store.put_device(updated,'dhcp')
            except (ValueError,KeyError):
                continue  # Unknown/malformed/conflicting clients remain in the default-deny subnet.

    def captive(self, ip, settings):
        address=ipaddress.ip_address(ip)
        guest=bool(settings and address.version==4 and address in ipaddress.IPv4Network(settings['network']))
        if not guest:return dict(guest=False,captive=False)
        d=next((d for d in self.store.devices() if d['ip']==ip),None)
        online=bool(d and d['id'] in self.store.online())
        result={'guest':True,'captive':not online,'user-portal-url':portal_url(settings),'can-extend-session':False}
        if d and online:
            with self.store.lock:
                row=self.store.db.execute('SELECT name FROM bindings WHERE device=?',(d['id'],)).fetchone()
                state=self.store.account_state(row[0]) if row else None
            if state and state['remaining_bytes'] is not None:result['bytes-remaining']=state['remaining_bytes']
        return result


def bootstrap_rules(address):
    interface=ipaddress.IPv4Interface(address)
    return '\n'.join(['table inet rahawrt_guest_guard {',
        'chain ingress { type filter hook prerouting priority -305; policy accept;',
        'iifname "br-rahaguest" meta nfproto ipv6 drop',
        'ip saddr 0.0.0.0 ip daddr 255.255.255.255 udp sport 68 udp dport 67 return',
        f'ip daddr {interface.ip} return', f'ip saddr {interface.network} drop', '}', '}'])+'\n'
