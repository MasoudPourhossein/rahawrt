"""Per-device domain policies and attributed, bounded HTTPS category refreshes."""
import hashlib
import json
import re
import time
import urllib.request

SOURCES={'adult':dict(url='https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt',license='https://raw.githubusercontent.com/hagezi/dns-blocklists/main/LICENSE',attribution='HaGeZi DNS Blocklists')}


def domain(value):
    if not isinstance(value,str):raise ValueError('domain must be a string')
    value=value.rstrip('.').lower().encode('idna').decode('ascii')
    if len(value)>253 or not value or any(not re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?',part) for part in value.split('.')):
        raise ValueError('invalid domain')
    return value


def suffixes(name):
    parts=domain(name).split('.')
    return ['.'.join(parts[i:]) for i in range(len(parts))]


class Parental:
    def __init__(self,store):
        self.store=store
        with store.lock:
            store.db.executescript('''
            CREATE TABLE IF NOT EXISTS parental_profiles(id TEXT PRIMARY KEY,config TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS category_domains(category TEXT NOT NULL,domain TEXT NOT NULL,PRIMARY KEY(category,domain));
            CREATE TABLE IF NOT EXISTS category_sources(category TEXT PRIMARY KEY,source TEXT NOT NULL,attribution TEXT NOT NULL,license TEXT NOT NULL,sha256 TEXT NOT NULL,updated INTEGER NOT NULL,count INTEGER NOT NULL);
            ''')

    def save(self,data,actor):
        if not isinstance(data,dict) or set(data)-{'id','name','allow','block','categories','safe_search','block_encrypted_dns'}:
            raise ValueError('unknown parental profile fields')
        d=dict(data)
        if not re.fullmatch(r'[A-Za-z0-9_]{1,32}',d.get('id','')):raise ValueError('invalid profile id')
        d.setdefault('name',d['id'])
        if not isinstance(d['name'],str) or len(d['name'])>80:raise ValueError('invalid name')
        for key in ('allow','block'):
            values=d.get(key,[])
            if not isinstance(values,list) or len(values)>1024:raise ValueError('domain lists are limited to 1024 entries')
            d[key]=sorted(set(domain(v) for v in values))
        d.setdefault('categories',[])
        if not isinstance(d['categories'],list) or len(d['categories'])>len(SOURCES) or any(c not in SOURCES for c in d['categories']):raise ValueError('unknown category')
        for key in ('safe_search','block_encrypted_dns'):
            d.setdefault(key,True)
            if type(d[key]) is not bool:raise ValueError('expected boolean')
        with self.store.lock,self.store.db:
            for category in d['categories']:
                if not self.store.db.execute('SELECT 1 FROM category_sources WHERE category=? AND count>0',(category,)).fetchone():
                    raise ValueError('refresh category '+category+' before enabling it')
            self.store.db.execute('INSERT OR REPLACE INTO parental_profiles VALUES (?,?)',(d['id'],json.dumps(d)))
            self.store.audit(actor,'parental.save',d['id'])
        return d

    def profiles(self):
        with self.store.lock:return [json.loads(r[0]) for r in self.store.db.execute('SELECT config FROM parental_profiles ORDER BY id')]

    def refresh(self,category,actor,expected_sha256=None,fetch=None):
        if category not in SOURCES:raise ValueError('unknown category')
        if expected_sha256 is not None and not re.fullmatch('[a-f0-9]{64}',expected_sha256):raise ValueError('invalid SHA-256 pin')
        source=SOURCES[category]
        def download(url,limit):
            with urllib.request.urlopen(url,timeout=10) as response:
                if response.url!=url:raise ValueError('unexpected category redirect')
                data=response.read(limit+1)
                if len(data)>limit:raise ValueError('category source exceeds size limit')
                return data
        fetch=fetch or download
        raw=fetch(source['url'],16*1024*1024)
        digest=hashlib.sha256(raw).hexdigest()
        if expected_sha256 and digest!=expected_sha256:raise ValueError('category checksum mismatch')
        license_text=fetch(source['license'],256*1024).decode('utf-8')
        if not license_text.strip():raise ValueError('missing upstream license')
        names=set()
        for line in raw.decode('utf-8-sig').splitlines():
            line=line.strip()
            if not line or line.startswith(('#','!')):continue
            names.add(domain(line))
        if not names or len(names)>500000:raise ValueError('invalid category size')
        with self.store.lock,self.store.db:
            self.store.db.execute('DELETE FROM category_domains WHERE category=?',(category,))
            self.store.db.executemany('INSERT INTO category_domains VALUES (?,?)',((category,name) for name in sorted(names)))
            self.store.db.execute('INSERT OR REPLACE INTO category_sources VALUES (?,?,?,?,?,?,?)',(category,source['url'],source['attribution'],license_text,digest,int(time.time()),len(names)))
            self.store.audit(actor,'parental.refresh',category)
        return dict(category=category,source=source['url'],attribution=source['attribution'],sha256=digest,count=len(names))

    def profile_for_ip(self,ip):
        with self.store.lock:
            d=next((d for d in self.store.devices() if d['ip']==ip),None)
            if not d or not d.get('parental_profile'):return None
            row=self.store.db.execute('SELECT config FROM parental_profiles WHERE id=?',(d['parental_profile'],)).fetchone()
            if not row:return None
            return json.loads(row[0])

    def blocked(self,name,profile):
        candidates=suffixes(name)
        if set(candidates)&set(profile['allow']):return False
        if set(candidates)&set(profile['block']):return True
        if profile['block_encrypted_dns'] and set(candidates)&{'dns.google','cloudflare-dns.com','dns.quad9.net','dns.nextdns.io','dns.adguard-dns.com'}:return True
        if profile['categories']:
            with self.store.lock:
                args=profile['categories']+candidates
                query='SELECT 1 FROM category_domains WHERE category IN ('+','.join('?' for _ in profile['categories'])+') AND domain IN ('+','.join('?' for _ in candidates)+') LIMIT 1'
                if self.store.db.execute(query,args).fetchone():return True
        return False
