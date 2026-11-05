"""Optional native tunnels, deliberately separate from PassWall2 node IDs."""
import base64
import ipaddress
import re
import shlex

REQUIREMENTS={'wireguard':['/lib/netifd/proto/wireguard.sh','/usr/bin/wg'],'openvpn':['/etc/init.d/openvpn','/usr/sbin/openvpn'],'openconnect':['/lib/netifd/proto/openconnect.sh','/usr/sbin/openconnect'],'l2tp-ipsec':['/lib/netifd/proto/l2tp.sh','/usr/sbin/swanctl']}


def text(value,maximum=256):
    if not isinstance(value,str) or not 1<=len(value)<=maximum or any(ord(c)<32 for c in value):raise ValueError('invalid text or credential')
    return value


def host(value):
    text(value,253)
    try:return str(ipaddress.ip_address(value))
    except ValueError:
        if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?',value) or '..' in value:raise ValueError('invalid hostname')
        return value


def number(value,low=1,high=65535):
    if type(value) is not int or not low<=value<=high:raise ValueError('invalid numeric option')
    return value


def key(value):
    try:valid=isinstance(value,str) and len(base64.b64decode(value,validate=True))==32
    except Exception:valid=False
    if not valid:raise ValueError('WireGuard key must encode 32 bytes')
    return value


def pem(value):
    if not isinstance(value,str) or len(value)>32768 or '\x00' in value or not value.strip().startswith('-----BEGIN CERTIFICATE-----') or not value.strip().endswith('-----END CERTIFICATE-----'):raise ValueError('inline CA certificate required')
    return value.strip()+'\n'


def wg_import(profile):
    if not isinstance(profile,str) or len(profile)>65536:raise ValueError('invalid WireGuard profile')
    groups={};current=None
    for raw in profile.splitlines():
        line=raw.strip()
        if not line or line.startswith(('#',';')):continue
        if line in ('[Interface]','[Peer]'):
            if line in groups:raise ValueError('one Interface and Peer supported')
            groups[line]={};current=groups[line];continue
        if current is None or '=' not in line:raise ValueError('invalid WireGuard line')
        k,v=line.split('=',1);k=k.strip().lower()
        if k in current:raise ValueError('duplicate WireGuard field')
        current[k]=v.strip()
    interface,peer=groups.get('[Interface]',{}),groups.get('[Peer]',{})
    if set(interface)-{'privatekey','address','dns','mtu','listenport'} or set(peer)-{'publickey','presharedkey','endpoint','allowedips','persistentkeepalive'}:raise ValueError('unsupported WireGuard field; script hooks forbidden')
    match=re.fullmatch(r'(?:\[([^]]+)\]|([^:]+)):([0-9]+)',peer.get('endpoint',''))
    if not match:raise ValueError('endpoint requires host:port')
    result=dict(private_key=interface.get('privatekey'),addresses=[a.strip() for a in interface.get('address','').split(',')],public_key=peer.get('publickey'),server=match[1] or match[2],port=int(match[3]),allowed_ips=[a.strip() for a in peer.get('allowedips','').split(',')])
    if 'presharedkey' in peer:result['preshared_key']=peer['presharedkey']
    if 'persistentkeepalive' in peer:result['keepalive']=int(peer['persistentkeepalive'])
    for k,name in (('mtu','mtu'),('listenport','listen_port')):
        if k in interface:result[name]=int(interface[k])
    return result


def openvpn_profile(profile,device):
    if not isinstance(profile,str) or not 1<=len(profile)<=65536 or '\x00' in profile:raise ValueError('invalid OpenVPN profile')
    allowed={'client','nobind','persist-key','persist-tun','remote','proto','tun-mtu','mssfix','auth','cipher','data-ciphers','data-ciphers-fallback','auth-nocache','verify-x509-name','tls-cipher','key-direction','verb','explicit-exit-notify','resolv-retry','connect-retry','connect-timeout','ping','ping-restart','keepalive','reneg-sec','auth-retry','topology','pull','route-nopull'}
    lines=[];block=None;contents=[];present=set();remote=False
    for raw in profile.splitlines():
        line=raw.strip()
        if block:
            if line=='</'+block+'>':
                if block=='ca':pem('\n'.join(contents))
                lines+=['<'+block+'>',*contents,'</'+block+'>'];present.add(block);block=None;contents=[]
            else:contents.append(raw)
            continue
        if not line or line.startswith(('#',';')):continue
        if line.startswith('<'):
            match=re.fullmatch(r'<(ca|cert|key|tls-auth|tls-crypt)>',line)
            if not match:raise ValueError('unsupported inline block')
            block=match[1];continue
        args=shlex.split(line,comments=True)
        if not args:continue
        if args[0]=='dev':
            if len(args)!=2 or not args[1].startswith('tun'):raise ValueError('only TUN supported')
            continue
        if args[0]=='remote-cert-tls':continue
        if args[0]=='tls-version-min':
            if len(args)!=2 or args[1] not in ('1.2','1.3'):raise ValueError('TLS 1.2+ required')
            lines.append(line);continue
        if args[0]=='auth-user-pass':
            if len(args)!=1:raise ValueError('external credential files forbidden')
            present.add('auth-user-pass');continue
        if args[0] not in allowed:raise ValueError('unsafe or unsupported OpenVPN directive')
        if args[0]=='proto' and (len(args)!=2 or args[1] not in ('udp','udp4','udp6','tcp-client','tcp4-client','tcp6-client')):raise ValueError('client transport required')
        if args[0]=='remote':
            if not 2<=len(args)<=4:raise ValueError('invalid remote')
            host(args[1]);remote=True
            if len(args)>2:number(int(args[2]))
            if len(args)>3 and args[3] not in ('udp','udp4','udp6','tcp-client','tcp4-client','tcp6-client'):raise ValueError('client transport required')
        if args[0]=='verb' and (len(args)!=2 or not 0<=int(args[1])<=3):raise ValueError('verbose logs forbidden')
        lines.append(line)
    if block or not remote or 'ca' not in present:raise ValueError('remote and complete inline CA required')
    if ('cert' in present)!=('key' in present):raise ValueError('client certificate/key required together')
    lines+=['dev '+device,'dev-type tun','remote-cert-tls server','tls-version-min 1.2','route-nopull','pull-filter ignore "redirect-gateway"','pull-filter ignore "dhcp-option"','auth-nocache','verb 3']
    return '\n'.join(lines)+'\n',present


def provision(data):
    if not isinstance(data,dict):raise ValueError('settings must be an object')
    ident=data.get('id','');kind=data.get('kind')
    if not isinstance(ident,str) or not re.fullmatch(r'[A-Za-z0-9_]{1,7}',ident):raise ValueError('tunnel ID must be 1–7 letters/digits/underscores')
    if kind not in REQUIREMENTS:raise ValueError('unknown tunnel type')
    name='rv_'+ident
    def entry(kind,**options):return dict(type=kind,options=options)
    common=dict(defaultroute='0',peerdns='0',auto='1');files={};prepare=[];cleanup=[]
    if kind=='wireguard':
        allowed={'id','kind','profile','private_key','addresses','public_key','preshared_key','server','port','allowed_ips','keepalive','mtu','listen_port'}
        if set(data)-allowed:raise ValueError('unknown WireGuard setting')
        d=dict(data)
        if 'profile' in d:
            if set(d)-{'id','kind','profile'}:raise ValueError('choose imported or manual settings')
            d.update(wg_import(d['profile']))
        addresses=[str(ipaddress.ip_interface(a)) for a in d['addresses']]
        ips=[str(ipaddress.ip_network(a,strict=False)) for a in d['allowed_ips']]
        if not 1<=len(addresses)<=16 or not any(':' not in a for a in addresses) or not 1<=len(ips)<=128:raise ValueError('IPv4 address and allowed networks required')
        options=dict(common,proto='wireguard',private_key=key(d['private_key']),addresses=addresses)
        if 'mtu' in d:options['mtu']=str(number(d['mtu'],576,9000))
        if 'listen_port' in d:options['listen_port']=str(number(d['listen_port']))
        peer=dict(public_key=key(d['public_key']),allowed_ips=ips,route_allowed_ips='0',endpoint_host=host(d['server']),endpoint_port=str(number(d['port'])),persistent_keepalive=str(number(d.get('keepalive',25),0)))
        if d.get('preshared_key'):peer['preshared_key']=key(d['preshared_key'])
        sections={'network':{name:entry('interface',**options),name+'_peer':entry('wireguard_'+name,**peer)}};reloads=[['/etc/init.d/network','reload']]
    elif kind=='openconnect':
        if set(data)-{'id','kind','server','port','username','password','authgroup','ca','serverhash'}:raise ValueError('unknown OpenConnect setting')
        options=dict(common,proto='openconnect',server=host(data['server']),port=str(number(data.get('port',443))),username=text(data['username']),password=text(data['password']),vpn_protocol='anyconnect',interface='wan',reconnect_timeout='300')
        if data.get('authgroup'):options['authgroup']=text(data['authgroup'])
        if data.get('serverhash'):
            if not re.fullmatch('sha256:[A-Fa-f0-9]{64}',data['serverhash']):raise ValueError('pin must be sha256:HEX')
            options['serverhash']=data['serverhash']
        if data.get('ca'):files['/etc/openconnect/ca-vpn-'+name+'.pem']=pem(data['ca'])
        sections={'network':{name:entry('interface',**options)}};reloads=[['/etc/init.d/network','reload']]
    elif kind=='openvpn':
        if set(data)-{'id','kind','profile','server','port','proto','username','password','ca','cert','key','server_name'}:raise ValueError('unknown OpenVPN setting')
        profile=data.get('profile')
        if profile is None:
            proto=data.get('proto','udp')
            if proto not in ('udp','tcp-client'):raise ValueError('invalid OpenVPN transport')
            profile='client\nnobind\nremote '+host(data['server'])+' '+str(number(data.get('port',1194)))+'\nproto '+proto+'\n<ca>\n'+pem(data['ca'])+'</ca>\n'
            if data.get('cert') or data.get('key'):
                if not data.get('cert') or not data.get('key'):raise ValueError('certificate/key required together')
                profile+='<cert>\n'+pem(data['cert'])+'</cert>\n<key>\n'+data['key'].strip()+'\n</key>\n'
            if data.get('server_name'):
                server_name=text(data['server_name'])
                if not re.fullmatch(r'[A-Za-z0-9_.-]+',server_name):raise ValueError('invalid certificate name')
                profile+='verify-x509-name '+server_name+' name\n'
        profile,present=openvpn_profile(profile,name)
        options=dict(enabled='1',config='/etc/rahawrt/vpn/'+name+'.ovpn')
        if data.get('username'):options.update(username=text(data['username']),password=text(data['password']))
        elif 'cert' not in present:raise ValueError('complete credentials or client certificate/key required')
        files[options['config']]=profile
        sections={'openvpn':{name:entry('openvpn',**options)},'network':{name:entry('interface',proto='none',device=name,**common)}};reloads=[['/etc/init.d/openvpn','restart'],['/etc/init.d/network','reload']]
    else:
        if set(data)-{'id','kind','server','username','password','ipsec_reqid'}:raise ValueError('unknown L2TP/IPsec setting')
        server=str(ipaddress.IPv4Address(data['server']));reqid=number(data['ipsec_reqid'],1,2**31-1)
        username,password=text(data['username']),text(data['password'])
        if any(c in username+password for c in ('"',"'",'\\')):raise ValueError('upstream L2TP adapter cannot safely quote these credentials')
        sections={'network':{name:entry('interface',proto='l2tp',server=server,username=username,password=password,ipv6='0',**dict(common,auto='0'))}}
        guard='table inet '+name+'_ipsec {\nchain output { type filter hook output priority 10; policy accept;\nip daddr '+server+' udp dport 1701 ipsec out reqid '+str(reqid)+' return\nip daddr '+server+' udp dport 1701 drop\n}\n}\n'
        prepare.append((['nft','-f','-'],guard));cleanup.append(['nft','delete','table','inet',name+'_ipsec'])
        secure_directory="import os,stat; p='/tmp/l2tp'; os.makedirs(p,mode=0o700,exist_ok=True); s=os.lstat(p); assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not (s.st_mode & 0o077), 'L2TP options directory must be private and root-owned'"
        prepare.append((['/usr/bin/python3','-c',secure_directory],None));cleanup.append(['/usr/bin/python3','-c','pass']);reloads=[['/etc/init.d/network','reload'],['ifup',name]]
    sections['firewall']={name:entry('zone',name=name,network=[name],input='REJECT',output='ACCEPT',forward='REJECT',masq='1')};reloads.append(['/etc/init.d/firewall','restart'])
    writer="import os,sys; p=sys.argv[1]; os.makedirs(os.path.dirname(p),mode=0o700,exist_ok=True); f=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); s=os.fdopen(f,'wb'); s.write(sys.stdin.buffer.read()); s.close()"
    for filename,contents in files.items():
        prepare.append((['/usr/bin/python3','-c',writer,filename],contents));cleanup.append(['/bin/rm','-f',filename])
    return dict(id=name,kind=kind,sections=sections,prepare=prepare,cleanup=cleanup,reloads=reloads,requirements=REQUIREMENTS[kind])
