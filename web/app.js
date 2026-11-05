'use strict';
const $ = id => document.getElementById(id);
let lang = localStorage.getItem('rahawrt-language') || 'fa';
const en = {deviceidentity:'Device / ID',navigation:'Network management',overview:'Network overview',devicesnav:'Devices',reportsnav:'Reports',navnote:'Network settings and traffic in one place',loginnote:'Sign in to manage the network or view your account.',overviewnote:'Policy execution, devices and recorded traffic',technical:'Technical policy details',neighbor:'Connection observation',nativeselect:'Confirmed native tunnel (select direct as the PassWall2 node)',portalhost:'Portal hostname with a trusted certificate (optional; default gateway IP)',diagnostics:'Kernel route diagnostics (not a tunnel egress test)',target:'Target hostname or IP',diagnose:'Check',reservation:'Reserve DHCP for a registered device',reserve:'Create reservation with confirmation timeout',backup:'Sensitive configuration and accounting backup',backupnote:'This file contains private configuration. Keep it secure. Restore from console after stopping the service.',backupdownload:'Download backup ZIP',nativetunnel:'Optional native tunnel; separate from PassWall2 nodes, no default-route change',vpnjson:'JSON settings including kind and id (ID at most 7 characters)',vpnfile:'Import WireGuard/OpenVPN file into profile',provisionvpn:'Provision tunnel with confirmation timeout',tunnels:'Native tunnels (interface up is not end-to-end health)',tunnelid:'Interface ID such as rv_wg1',parentalprofile:'Parental profile ID (empty: none)',routertools:'Guest network and parental control',guestsetup:'Create isolated guest network (requires router enforcement mode)',guestaddress:'Guest gateway address/prefix',radio:'Radio (empty: bridge only)',wifipassword:'Wi-Fi password (WPA2)',openwifi:'Open Wi-Fi; login does not encrypt the wireless connection',applyguest:'Create; rolls back in three minutes without confirmation',pendingchanges:'Router changes and connectivity confirmation',parentaledit:'Save parental profile',allowdomains:'Allowed domains (JSON)',blockdomains:'Blocked domains including subdomains (JSON)',adultcategory:'Adult category (download list first)',safesearch:'SafeSearch for supported Google, Bing and YouTube names',blockdns:'Block DoT/DoQ and known DoH names (not complete protection)',categoryupdate:'Refresh adult list with upstream attribution and license',optionalsha:'Expected SHA-256 (optional; empty uses TLS verification)',updatecategory:'Refresh list',billing:'Billing and plans', planedit:'Create or update plan', validity:'Validity from issuance (seconds; zero unlimited)', duration:'Online duration (seconds; zero unlimited)', maxdevices:'Maximum devices',maxsessions:'Concurrent sessions',quotaaction:'After quota exhaustion',slowup:'Reduced upload (kbps)',slowdown:'Reduced download (kbps)',issue:'Issue account for invoice',invoice:'Unique invoice ID',plan:'Plan',optionaluser:'Username (empty: automatic)',batch:'Issue voucher batch',batchid:'Unique batch ID',count:'Count (1–50)',manage:'Manage user account',action:'Action',renewinvoice:'Renewal invoice ID (required for renew)',apply:'Apply',accountlist:'Accounts',apikey:'Create API key (shown once)',scopes:'Scopes',keyttl:'Key validity (seconds)',createkey:'Create key',revokekey:'Key ID to revoke',revoke:'Revoke key',printnote:'Passwords appear only once. Print before closing; retrying never creates duplicate accounts.',print:'Print vouchers',clear:'Clear sensitive information',reports:'Usage reports (UTC)',csv:'Download CSV',sessions:'Session history',audit:'Operation history',failure:'VPN forwarding policy (block prevents forwarded bypass)',logout:'Log out', login:'Log in', username:'Username', password:'Password', account:'My account', status:'Policy status', warning:'Preview does not change the network. Check application status after saving.', refresh:'Refresh', clients:'DHCP leases (not proof of online status)', name:'Name', devices:'Registered devices and usage', node:'Node', edit:'Register or edit device', static:'Static IP or DHCP reservation required. Use the existing ID to edit.', upload:'Upload cap (kbps; zero unlimited)', download:'Download cap (kbps)', quota:'Quota bytes (zero unlimited)', internet:'Internet windows (JSON; Monday=0)', vpn:'VPN windows (JSON)', parental:'Blocked IPv4 networks (JSON)', enabled:'Enabled', hotspot:'Require account login for internet', save:'Save', create:'Create/update account (revokes previous sessions)', role:'Role', deviceid:'Device ID for user'};
const fa = {};
document.querySelectorAll('[data-i18n]').forEach(e => { fa[e.dataset.i18n] = e.textContent; });
function translate() {
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === 'fa' ? 'rtl' : 'ltr';
  document.querySelectorAll('[data-i18n]').forEach(e => {e.textContent = (lang === 'fa' ? fa : en)[e.dataset.i18n];});
  $('language').textContent = lang === 'fa' ? 'English' : 'فارسی';
  renderCachedViews();
}
$('language').onclick = () => {lang = lang === 'fa' ? 'en' : 'fa'; localStorage.setItem('rahawrt-language',lang); translate();};
function message(text) { $('message').textContent = text; }
async function api(path, method='GET', body) {
  const response = await fetch('/cgi-bin/rahawrt/wrt/api/v1/'+path, {method, headers:{'Content-Type':'application/json','X-RahaWRT-Request':'1','X-HTTP-Method-Override':method}, body:body === undefined ? undefined : JSON.stringify(body)});
  const data = await response.json();
  if (response.status===401) resetSessionView();
  if (!response.ok) throw new Error(data.error || String(response.status));
  return data;
}
function resetSessionView() {
  for(const key of Object.keys(viewState))delete viewState[key];
  document.body.classList.remove('signed-in');
  $('login').hidden=false;$('logout').hidden=true;$('navigation').hidden=true;$('mode-badge').hidden=true;
  for(const id of ['user','dashboard','billing','reports','router-tools','print-vouchers'])$(id).hidden=true;
  $('voucher-cards').replaceChildren();$('new-key').textContent='';
  for(const id of ['me','status','resources','policy-debug','devices','clients','plans-list','accounts-list','report-data','session-data','audit-data','parental-list','tunnels-list','diagnostics-result'])$(id).replaceChildren();
  document.querySelectorAll('form').forEach(form=>form.reset());confirmations.clear();currentRole='';
}
function neighborLabel(states=[]) {
  const labels={REACHABLE:['پاسخ اخیر','Recent response'],STALE:['ثبت قبلی','Cached'],FAILED:['پاسخی نرسید','Unreachable'],INCOMPLETE:['در انتظار پاسخ','Resolving'],DELAY:['در حال بررسی','Checking'],PROBE:['در حال بررسی','Checking'],PERMANENT:['ورودی ثابت','Static entry'],MAC_MISMATCH:['MAC متفاوت','MAC mismatch'],UNKNOWN:['نامشخص','Unknown']};
  const pair=labels[states[0]]||labels.UNKNOWN;
  return pair[lang==='fa'?0:1];
}
function row(target, values) { const tr = document.createElement('tr'); values.forEach(value => {const td = document.createElement('td'); if(value instanceof Node)td.append(value);else td.textContent=value; tr.append(td);}); target.append(tr); return tr; }
function renderDeviceViews(){
  const {me,devices,clients}=viewState;if(!me||!devices||!clients)return;
  $('device-action-head').hidden=me.role!=='admin';
  $('devices').replaceChildren();
  devices.devices.forEach(d => {const usage = devices.usage[d.id] || [0,0]; const tr = row($('devices'),[deviceLabel(d),d.ip,nodeName(d.node,d.tunnel),...usage.map(bytes)]); if (me.role === 'admin') { const cell = document.createElement('td'); const edit = document.createElement('button'); edit.textContent = lang === 'fa' ? 'ویرایش' : 'Edit';edit.setAttribute('aria-label',edit.textContent+' '+(d.name||d.id)); edit.onclick = () => {const form = $('device'); for (const [key,value] of Object.entries(d)) {const field = form.elements.namedItem(key); if (!field) continue; if (typeof value === 'boolean') field.checked = value; else field.value = Array.isArray(value) ? JSON.stringify(value) : value;} form.scrollIntoView({behavior:'smooth'});}; cell.append(edit);tr.append(cell); }});
  $('clients').replaceChildren(); clients.clients.forEach(c => row($('clients'),[c.name,c.ip,c.mac,neighborLabel(c.neighbor_state)]));
  if(!clients.clients.length){const empty=row($('clients'),[wording('اطلاعات DHCP برای نمایش موجود نیست.','No DHCP observations available.')]);empty.firstChild.colSpan=4;empty.className='empty-row';}
}
async function refresh() {
  const me = await api('me');
  $('login').hidden = true; $('logout').hidden = false;
  $('user').hidden = false; viewState.me=me;renderMe();
  document.body.classList.add('signed-in');$('navigation').hidden=false;
  document.querySelectorAll('#navigation [data-roles]').forEach(a=>a.hidden=!a.dataset.roles.split(' ').includes(me.role));
  const staff = ['admin','operator'].includes(me.role);
  document.body.classList.toggle('staff-view',staff);
  await refreshBilling(me.role);
  await refreshReports(me.role);
  $('router-tools').hidden = me.role!=='admin';
  if(me.role==='admin'){viewState.tunnels=(await api('tunnels')).tunnels;const tunnels=viewState.tunnels.filter(t=>t.configuration_status==='confirmed');document.querySelectorAll('select.native-tunnels').forEach(select=>{const current=select.value;select.replaceChildren();const empty=document.createElement('option');empty.value='';empty.textContent='—';select.append(empty);for(const t of tunnels){const option=document.createElement('option');option.value=option.textContent=t.id;select.append(option);}select.value=current;});await refreshChanges();viewState.profiles=(await api('parental')).profiles;renderParentalViews();}
  $('dashboard').hidden = !staff;
  $('device').hidden = $('account').hidden = me.role !== 'admin';
  if (!staff) return;
  const [status, devices, clients] = await Promise.all([api('status'),api('devices'),api('clients')]);
  viewState.status=status;viewState.resources=await api('resources');renderOverview();
  viewState.devices=devices;viewState.clients=clients;renderDeviceViews();
  try {const nodes = await api('nodes'); $('nodes').replaceChildren(); nodes.nodes.forEach(n => { const option = document.createElement('option'); option.value = n;option.textContent=nodeName(n); $('nodes').append(option); });} catch (e) { message(e.message); }
}
$('login').onsubmit = async e => {e.preventDefault(); try {await api('login','POST',Object.fromEntries(new FormData(e.target))); e.target.reset(); await refresh(); message('');} catch(e) {message(e.message);} };
$('logout').onclick = async () => {try {await api('logout','POST',{}); location.reload();} catch(e) {message(e.message);} };
$('refresh').onclick = () => refresh().catch(e => message(e.message));
$('device').onsubmit = async e => { e.preventDefault(); try {const d = Object.fromEntries(new FormData(e.target)); for(const k of ['upload_kbps','download_kbps','quota_bytes']) d[k] = Number(d[k]); for(const k of ['internet','vpn','blocked_ips']) d[k] = JSON.parse(d[k]); if(!d.parental_profile)d.parental_profile=null;if(!d.tunnel)d.tunnel=null; d.enabled = e.target.elements.enabled.checked; d.hotspot = e.target.elements.hotspot.checked; await api('devices','PUT',d); await refresh(); message(lang === 'fa' ? 'ذخیره شد؛ وضعیت اعمال سیاست را بررسی کنید.' : 'Saved; inspect policy application status.');} catch(e) {message(e.message);} };
$('account').onsubmit = async e => {e.preventDefault(); try {await api('accounts','POST',Object.fromEntries(new FormData(e.target))); e.target.reset(); message(lang === 'fa' ? 'حساب ذخیره شد.' : 'Account saved.');} catch(e) {message(e.message);} };


let currentRole = '';
async function refreshBilling(role) {
  currentRole = role;
  const visible = ['admin','operator','accounting'].includes(role);
  $('billing').hidden = !visible;
  for (const id of ['plan-form','action-form','key-form','revoke-form']) $(id).hidden = role !== 'admin';
  $('issue-form').hidden = $('voucher-form').hidden = !['admin','accounting'].includes(role);
  if (!visible) return;
  const [plans,accounts] = await Promise.all([api('plans'),api('accounts')]);
  viewState.plans=plans.plans;viewState.accounts=accounts.accounts;renderBillingViews();
  document.querySelectorAll('select.plans').forEach(select => {const old=select.value;select.replaceChildren();plans.plans.forEach(p => {const option=document.createElement('option');option.value=p.id;option.textContent=p.name+' ('+p.id+')';select.append(option);}); if(plans.plans.some(p=>p.id===old))select.value=old;});
}
async function refreshReports(role=currentRole) {
  $('reports').hidden = !['admin','operator','accounting','user'].includes(role);
  if ($('reports').hidden) return;
  const [report,sessions] = await Promise.all([api('reports?period='+$('report-period').value),api('sessions')]);
  viewState.report=report;viewState.sessions=sessions.sessions;renderReportViews();
  $('audit-title').hidden=$('audit-data').hidden=role!=='admin';
  if(role==='admin'){viewState.audit=(await api('audit')).events;renderReportViews();}
}
function showVouchers(vouchers) {
  $('voucher-cards').replaceChildren();
  vouchers.forEach(v => {const card=document.createElement('article');card.className='voucher';for(const [key,value] of Object.entries(v)) {const line=document.createElement('p');line.textContent=key+': '+(value===null?'—':value);card.append(line);} $('voucher-cards').append(card);});
  $('print-vouchers').hidden=false;
}
$('plan-form').onsubmit=async e=>{e.preventDefault();try{const data=Object.fromEntries(new FormData(e.target));for(const key of ['quota_bytes','upload_kbps','download_kbps','valid_seconds','online_seconds','max_devices','max_sessions','reduced_upload_kbps','reduced_download_kbps'])data[key]=Number(data[key]);if(!data.tunnel)data.tunnel=null;await api('plans','PUT',data);await refreshBilling(currentRole);message(lang==='fa'?'طرح ذخیره شد.':'Plan saved.');}catch(e){message(e.message);}};
$('issue-form').onsubmit=async e=>{e.preventDefault();try{const data=Object.fromEntries(new FormData(e.target));if(!data.username)delete data.username;showVouchers([await api('issue','POST',data)]);await refreshBilling(currentRole);}catch(e){message(e.message);}};
$('voucher-form').onsubmit=async e=>{e.preventDefault();try{const data=Object.fromEntries(new FormData(e.target));data.count=Number(data.count);showVouchers((await api('vouchers','POST',data)).vouchers);await refreshBilling(currentRole);}catch(e){message(e.message);}};
$('action-form').onsubmit=async e=>{e.preventDefault();try{const data=Object.fromEntries(new FormData(e.target));if(data.action==='delete'&&!confirm(lang==='fa'?'حساب حذف شود؟':'Delete account?'))return;const result=await api('account-action','POST',data);if(result.password)showVouchers([{username:data.name,password:result.password}]);await refreshBilling(currentRole);message(lang==='fa'?'عملیات ثبت شد؛ وضعیت اعمال سیاست را بررسی کنید.':'Saved; inspect policy application status.');}catch(e){message(e.message);}};
$('key-form').onsubmit=async e=>{e.preventDefault();try{$('new-key').textContent=JSON.stringify(await api('api-keys','POST',{scopes:Array.from(e.target.elements.scopes.selectedOptions,o=>o.value),ttl_seconds:Number(e.target.elements.ttl_seconds.value)}),null,2);}catch(e){message(e.message);}};
$('revoke-form').onsubmit=async e=>{e.preventDefault();try{await api('api-keys/revoke','POST',Object.fromEntries(new FormData(e.target)));$('new-key').textContent='';message(lang==='fa'?'کلید باطل شد.':'Key revoked.');}catch(e){message(e.message);}};
$('print').onclick=()=>window.print();
$('clear-vouchers').onclick=()=>{$('voucher-cards').replaceChildren();$('print-vouchers').hidden=true;$('new-key').textContent='';message('');};
$('report-refresh').onclick=()=>refreshReports().catch(e=>message(e.message));
$('report-download').onclick=async()=>{try{const response=await fetch('/cgi-bin/rahawrt/wrt/api/v1/reports?format=csv&period='+$('report-period').value);if(!response.ok)throw new Error('Report unavailable');const url=URL.createObjectURL(await response.blob());const link=document.createElement('a');link.href=url;link.download='rahawrt-usage.csv';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(e){message(e.message);}};



const confirmations=new Map();
async function refreshChanges(){const data=await api('changes');$('changes-list').replaceChildren();for(const change of data.changes){const row=document.createElement('article');const text=document.createElement('pre');text.textContent=JSON.stringify(change,null,2);row.append(text);if(change.status==='awaiting'&&confirmations.has(change.id)){const button=document.createElement('button');button.textContent=lang==='fa'?'اتصال مدیریتی برقرار است؛ تأیید و نگهداری':'Management connection works; confirm and keep';button.onclick=async()=>{try{await api('changes/confirm','POST',{id:change.id,token:confirmations.get(change.id)});confirmations.delete(change.id);await refreshChanges();}catch(e){message(e.message);}};row.append(button);}if(['awaiting','rollback_failed'].includes(change.status)){const button=document.createElement('button');button.textContent=lang==='fa'?'بازگردانی تنظیمات':'Roll back';button.onclick=async()=>{try{await api('changes/rollback','POST',{id:change.id});confirmations.delete(change.id);await refreshChanges();}catch(e){message(e.message);}};row.append(button);}$('changes-list').append(row);}}
$('changes-refresh').onclick=()=>refreshChanges().catch(e=>message(e.message));
$('guest-form').onsubmit=async e=>{e.preventDefault();try{const data=Object.fromEntries(new FormData(e.target));data.open_wifi=e.target.elements.open_wifi.checked;if(!data.radio)delete data.radio;if(!data.portal_host)delete data.portal_host;const result=await api('guest','POST',data);confirmations.set(result.id,result.confirmation_token);e.target.elements.password.value='';await refreshChanges();message(lang==='fa'?'پس از برقراری اتصال، تغییر را پیش از مهلت تأیید کنید.':'After reconnecting, confirm before the deadline.');}catch(e){message(e.message);}};
$('parental-form').onsubmit=async e=>{e.preventDefault();try{const data=Object.fromEntries(new FormData(e.target));data.allow=JSON.parse(data.allow);data.block=JSON.parse(data.block);data.categories=e.target.elements.adult.checked?['adult']:[];delete data.adult;data.safe_search=e.target.elements.safe_search.checked;data.block_encrypted_dns=e.target.elements.block_encrypted_dns.checked;await api('parental','PUT',data);viewState.profiles=(await api('parental')).profiles;renderParentalViews();message(lang==='fa'?'پروفایل ذخیره شد؛ شناسه را در تنظیم دستگاه انتخاب کنید.':'Profile saved; select its ID in the device settings.');}catch(e){message(e.message);}};
$('category-form').onsubmit=async e=>{e.preventDefault();const button=e.target.querySelector('button');button.disabled=true;try{const data={category:'adult'};if(e.target.elements.sha256.value)data.sha256=e.target.elements.sha256.value;const result=await api('parental/refresh','POST',data);message(JSON.stringify(result));}catch(e){message(e.message);}finally{button.disabled=false;}};
async function downloadBackup(){const response=await fetch('/cgi-bin/rahawrt/wrt/api/v1/backup');if(!response.ok){let error;try{error=(await response.json()).error;}catch{}throw new Error(error||'Backup unavailable');}const url=URL.createObjectURL(await response.blob());const link=document.createElement('a');link.href=url;link.download='rahawrt-sensitive-backup.zip';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
$('backup-download').onclick=()=>downloadBackup().catch(e=>message(e.message));
$('diagnostics-form').onsubmit=async e=>{e.preventDefault();try{$('diagnostics-result').textContent=JSON.stringify(await api('diagnostics','POST',Object.fromEntries(new FormData(e.target))),null,2);}catch(e){message(e.message);}};
$('reservation-form').onsubmit=async e=>{e.preventDefault();try{const result=await api('reservations','POST',Object.fromEntries(new FormData(e.target)));confirmations.set(result.id,result.confirmation_token);await refreshChanges();}catch(e){message(e.message);}};
$('vpn-file').onchange=async e=>{try{const file=e.target.files[0];if(!file)return;if(file.size>65536)throw new Error('Profile exceeds 64 KiB');const field=$('vpn-form').elements.settings;const data=JSON.parse(field.value);data.profile=await file.text();field.value=JSON.stringify(data,null,2);}catch(e){message(e.message);}};
$('vpn-form').onsubmit=async e=>{e.preventDefault();try{const data=JSON.parse(e.target.elements.settings.value);const result=await api('tunnels','POST',data);confirmations.set(result.id,result.confirmation_token);e.target.elements.settings.value=JSON.stringify({kind:data.kind,id:data.id},null,2);$('vpn-file').value='';await refreshChanges();message(lang==='fa'?'پس از بررسی اتصال، تغییر را در مهلت مقرر تأیید کنید.':'Verify connectivity and confirm before the deadline.');}catch(e){message(e.message);}};
$('tunnels-refresh').onclick=async()=>{try{viewState.tunnels=(await api('tunnels')).tunnels;renderParentalViews();}catch(e){message(e.message);}};
$('tunnel-action').onsubmit=async e=>{e.preventDefault();try{await api('tunnels/action','POST',Object.fromEntries(new FormData(e.target)));$('tunnels-refresh').click();}catch(e){message(e.message);}};
translate();
(async()=>{try{const response=await fetch('/cgi-bin/rahawrt/wrt/api/v1/captive');const data=await response.json();if(data['https-required']&&location.protocol!=='https:'){if(data.guest){location.replace(data['user-portal-url']);}else{const url=new URL(location.href);url.protocol='https:';url.port='';location.replace(url.href);}return;}}catch{}await refresh().catch(()=>{});})();
