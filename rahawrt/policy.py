"""Validated, deterministic policy compilation. No shell interpolation."""
import datetime as dt
import ipaddress
import re
import hashlib


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('integer outside allowed range')
    return value


def schedule(value):
    if not isinstance(value, list) or len(value) > 32:
        raise ValueError('schedule must be a list of at most 32 windows')
    for w in value:
        if set(w) != {'days', 'start', 'end'} or not w['days']:
            raise ValueError('window requires days, start, end')
        for day in w['days']:
            integer(day, 0, 6)
        for key in ('start', 'end'):
            if not re.fullmatch(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]', w[key]):
                raise ValueError('time must be HH:MM')
        if w['start'] == w['end']:
            raise ValueError('empty window')
    return value


def active(windows, now):
    if not windows:
        return True
    minute = now.strftime('%H:%M')
    for w in windows:
        if w['start'] < w['end']:
            if now.weekday() in w['days'] and w['start'] <= minute < w['end']:
                return True
        elif (now.weekday() in w['days'] and minute >= w['start']) or ((now.weekday()-1) % 7 in w['days'] and minute < w['end']):
            return True
    return False


def device(data):
    allowed = {'id', 'name', 'ip', 'mac', 'node', 'internet', 'vpn', 'upload_kbps', 'download_kbps', 'quota_bytes', 'blocked_ips', 'hotspot', 'enabled', 'vpn_failure', 'parental_profile','tunnel'}
    if not isinstance(data, dict) or set(data) - allowed:
        raise ValueError('unknown device fields')
    d = dict(data)
    if not re.fullmatch(r'[a-zA-Z0-9_]{1,24}', d.get('id', '')):
        raise ValueError('invalid device id')
    address = ipaddress.IPv4Address(d['ip'])
    if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local or address.is_reserved:
        raise ValueError('device requires a unicast LAN IPv4 address')
    d['ip'] = str(address)
    if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', d['mac']):
        raise ValueError('invalid MAC')
    d['mac'] = d['mac'].lower()
    if int(d['mac'][:2], 16) & 1 or d['mac'] == '00:00:00:00:00:00':
        raise ValueError('device requires a unicast MAC')
    if not isinstance(d.get('name', ''), str) or len(d.get('name', '')) > 80:
        raise ValueError('invalid name')
    d.setdefault('name', d['id'])
    if not re.fullmatch(r'[a-zA-Z0-9_]{1,64}', d.get('node', 'direct')):
        raise ValueError('invalid PassWall2 node id')
    d.setdefault('node', 'direct')
    d.setdefault('tunnel',None)
    if d['tunnel'] is not None and (not isinstance(d['tunnel'],str) or not re.fullmatch(r'rv_[A-Za-z0-9_]{1,7}',d['tunnel'])):raise ValueError('invalid native tunnel ID')
    if d['tunnel'] and d['node']!='direct':raise ValueError('choose a native tunnel or a PassWall2 node, not both')
    d.setdefault('vpn_failure', 'block')
    if d['vpn_failure'] not in ('block', 'direct'):
        raise ValueError('vpn_failure must be block or direct')
    d.setdefault('parental_profile',None)
    if d['parental_profile'] is not None and (not isinstance(d['parental_profile'],str) or not re.fullmatch(r'[A-Za-z0-9_]{1,32}',d['parental_profile'])):
        raise ValueError('invalid parental profile')
    for k in ('internet', 'vpn'):
        d[k] = schedule(d.get(k, []))
    for k in ('upload_kbps', 'download_kbps'):
        d[k] = integer(d.get(k, 0), 0, 10000000)
    d['quota_bytes'] = integer(d.get('quota_bytes', 0), 0, 2**53-1)
    for k in ('hotspot', 'enabled'):
        d.setdefault(k, k == 'enabled')
        if type(d[k]) is not bool:
            raise ValueError('expected boolean')
    blocked = d.get('blocked_ips', [])
    if not isinstance(blocked, list) or len(blocked) > 256:
        raise ValueError('too many parental IP networks')
    d['blocked_ips'] = [str(ipaddress.ip_network(x, strict=False)) for x in blocked]
    if any(':' in x for x in d['blocked_ips']):
        raise ValueError('IPv4 parental networks required')
    return d


def compile_nft(devices, usage, sessions, now=None, local_ips=None, guest=None):
    now = now or dt.datetime.now().astimezone()
    devices = sorted(devices, key=lambda x: x['id'])
    router_ips = [str(ipaddress.IPv4Address(ip)) for ip in (local_ips or ['127.0.0.1'])]
    lines = ['table inet rahawrt {', 'set router4 { type ipv4_addr; elements = { '+', '.join(router_ips)+' }; }']
    limits={}
    for d in devices:
        for name,rate in _limits(d,'up')+_limits(d,'down'):
            if rate:limits[name]=rate
    for name,rate in sorted(limits.items()):
        lines.append(f'limit {name} {{ rate over {rate*125} bytes/second burst {max(rate*125,1500)} bytes; }}')
    if guest:
        allowed=[d['ip'] for d in devices if not blocked(d,usage,sessions,now)]
        elements=' elements = { '+', '.join(allowed)+' };' if allowed else ''
        lines.append('set portal_allowed { type ipv4_addr;'+elements+' }')
    lines.append('chain upload { type filter hook prerouting priority -300; policy accept;')
    if guest:
        subnet=str(ipaddress.IPv4Network(guest['network']))
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}',guest['interface']):
            raise ValueError('invalid guest interface')
        lines.append(f'iifname \"{guest["interface"]}\" meta nfproto ipv6 drop')
    lines.append('ip saddr 0.0.0.0 ip daddr 255.255.255.255 udp sport 68 udp dport 67 return')
    for d in devices:
        ip = d['ip']
        lines += [f'ether saddr {d["mac"]} meta nfproto ipv6 drop',
                  f'ether saddr {d["mac"]} ip saddr != {ip} drop',
                  f'ip saddr {ip} ether saddr != {d["mac"]} drop']
        if (d.get('_parental') or {}).get('block_encrypted_dns'):
            lines += [f'ip saddr {ip} tcp dport 853 drop',f'ip saddr {ip} udp dport 853 drop']
        if (d['node'] != 'direct' or d.get('tunnel')) and d['vpn_failure'] == 'block' and active(d['vpn'], now) and not d.get('_parental') and not d.get('hotspot') and not (guest and ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(guest['network'])):
            for proto in ('tcp', 'udp'):
                lines.append(f'ip saddr {ip} ip daddr @router4 {proto} dport 53 drop')
    # Preserve IPv4 access to the router, including administration and portal.
    lines.append('ip daddr @router4 return')
    if guest:lines.append(f'ip saddr {subnet} ip saddr != @portal_allowed tcp dport 80 return')
    for d in devices:
        lines += _direction(d, 'saddr', 'up', usage, sessions, now)
    if guest:
        lines.append(f'ip saddr {subnet} drop')
    lines += ['}', 'chain forward { type filter hook forward priority -10; policy accept;']
    if guest:lines.append(f'ip saddr {subnet} ip saddr != @portal_allowed tcp dport 80 drop')
    for d in devices:
        native=d.get('_native')
        if native and native['active']:
            if native['up']:
                iface=native['interface']
                if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}',iface):raise ValueError('invalid native interface')
                lines += [f'ip saddr {d["ip"]} oifname != "{iface}" drop',f'ip daddr {d["ip"]} iifname != "{iface}" drop']
            elif d['vpn_failure']=='block':
                lines += [f'ip saddr {d["ip"]} drop',f'ip daddr {d["ip"]} drop']
        if d['node'] != 'direct' and d['vpn_failure'] == 'block' and active(d['vpn'], now):
            # Transparent proxies terminate in INPUT and originate in OUTPUT;
            # any remaining forwarded packet would bypass the selected proxy.
            lines += [f'ip saddr {d["ip"]} drop', f'ip daddr {d["ip"]} drop']
        lines += _direction(d, 'daddr', 'down', usage, sessions, now)
    if guest:
        lines.append(f'ip daddr {subnet} drop')
    lines += ['}', 'chain download { type filter hook output priority 0; policy accept;']
    if guest:
        lines += [f'ip saddr @router4 ip daddr {subnet} tcp sport {{ 80, 443, 8443, 2080, 1053 }} return',f'ip saddr @router4 ip daddr {subnet} udp sport {{ 53, 67, 1053 }} return']
    for d in devices:
        # Administrative responses stay reachable when a quota is exhausted.
        lines += [f'ip saddr @router4 ip daddr {d["ip"]} tcp sport {{ 22, 80, 443, 9080, 8443, 2080, 1053 }} return',
                  f'ip saddr @router4 ip daddr {d["ip"]} udp sport {{ 53, 67, 1053 }} return']
        lines += _direction(d, 'daddr', 'down', usage, sessions, now)
    if guest:
        lines.append(f'ip daddr {subnet} drop')
    if guest:
        lines += ['}', 'chain portal { type nat hook prerouting priority -190; policy accept;',f'ip saddr {subnet} ip saddr != @portal_allowed tcp dport 80 counter redirect to :2080 comment "rw:portal"',
                  '}', 'chain portal_input { type filter hook input priority -10; policy accept;',
                  f'ip saddr {subnet} ip saddr != @portal_allowed meta l4proto tcp ct original proto-dst 80 tcp dport != 2080 drop']
    lines += ['}', 'chain dns { type nat hook prerouting priority -110; policy accept;']
    for d in devices:
        if d.get('_parental') or d.get('hotspot'):
            lines += [f'ip saddr {d["ip"]} udp dport 53 redirect to :1053',f'ip saddr {d["ip"]} tcp dport 53 redirect to :1053']
    if guest:
        lines += [f'ip saddr {subnet} udp dport 53 redirect to :1053',f'ip saddr {subnet} tcp dport 53 redirect to :1053']
    return '\n'.join(lines + ['}', '}']) + '\n'


def _direction(d, direction, label, usage, sessions, now):
    ip, ident = d['ip'], d['id']
    match = f'ip {direction} {ip}'
    denied=blocked(d,usage,sessions,now)
    lines = [match+' drop'] if denied else []
    for net in d['blocked_ips']:
        other = 'daddr' if direction == 'saddr' else 'saddr'
        lines += [f'{match} ip {other} {net} drop']
    for name,rate in _limits(d,label):
        if rate:lines.append(f'{match} limit name "{name}" drop')
    return lines + [f'{match} counter comment "rw:{ident}:{label}"',match+' return']


def _limits(d,label):
    key='upload_kbps' if label=='up' else 'download_kbps'
    result=[('d_'+label+'_'+d['id'],d[key])]
    account=d.get('_account_limit')
    if account:
        digest=hashlib.sha256(account['id'].encode()).hexdigest()[:16]
        result.append(('a_'+label+'_'+digest,account[key]))
    return result


def blocked(d,usage,sessions,now):
    ident=d['id']
    native=d.get('_native')
    native_down=bool(native and native['active'] and not native['up'] and d['vpn_failure']=='block')
    return native_down or not d['enabled'] or not active(d['internet'], now) or (d['quota_bytes'] > 0 and sum(usage.get(ident, [0, 0])) >= d['quota_bytes']) or (d['hotspot'] and ident not in sessions)
