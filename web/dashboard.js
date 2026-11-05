'use strict';
// All displayed values come from API responses; DOM text nodes keep names safe.
const viewState = {};
function wording(fa, en) { return lang === 'fa' ? fa : en; }
function number(value, digits=0) { return new Intl.NumberFormat(lang==='fa'?'fa-IR':'en-US',{maximumFractionDigits:digits}).format(value); }
function bytes(value) {
  if (value === null || value === undefined) return '—';
  let amount=Math.max(0,Number(value)||0), unit=0;
  const units=['B','KiB','MiB','GiB','TiB'];
  while(amount>=1024 && unit<units.length-1){amount/=1024;unit++;}
  return number(amount,unit?1:0)+' '+units[unit];
}
function duration(value) {
  if (!value) return wording('نامحدود','Unlimited');
  if(value>=86400)return number(value/86400,1)+' '+wording('روز','days');
  if(value>=3600)return number(value/3600,1)+' '+wording('ساعت','hours');
  return number(value/60,1)+' '+wording('دقیقه','minutes');
}
function rate(value) { return value?number(value)+' kbps':wording('نامحدود','Unlimited'); }
function dateTime(value) { return value?new Date(value*1000).toLocaleString(lang==='fa'?'fa-IR':'en-GB',{dateStyle:'short',timeStyle:'short'}):'—'; }
function roleName(role) { return ({admin:wording('مدیر','Administrator'),operator:wording('اپراتور','Operator'),accounting:wording('حسابدار','Accounting'),user:wording('کاربر','User')})[role]||role; }
function nodeName(value,tunnel) { return tunnel||({direct:wording('اینترنت مستقیم','Direct internet'),default:wording('VPN پیش‌فرض','Default VPN')})[value]||value; }
function element(tag,text,className) { const item=document.createElement(tag);if(text!==undefined)item.textContent=text;if(className)item.className=className;return item; }
function badge(text,state='neutral') { return element('span',text,'badge '+state); }
function deviceLabel(d){const label=element('span',d.name||d.id,'device-label');if(d.name&&d.name!==d.id)label.append(element('small',d.id));return label;}
function tableView(id,headings,rows) {
  const target=$(id);target.replaceChildren();
  if(!rows.length){target.append(element('p',wording('هنوز موردی ثبت نشده است.','No records yet.'),'empty-state'));return;}
  const table=element('table'), head=element('thead'), line=element('tr'), body=element('tbody');
  for(const heading of headings){const cell=element('th',heading);cell.scope='col';line.append(cell);}
  head.append(line);
  for(const values of rows){const tr=element('tr');for(const value of values){const td=element('td');td.append(value instanceof Node?value:document.createTextNode(value??'—'));tr.append(td);}body.append(tr);}
  table.append(head,body);target.append(table);
}
function metric(title,value,detail,ratio) {
  const card=element('article',undefined,'metric');card.append(element('span',title,'metric-label'),element('strong',value,'metric-value'));
  if(ratio){const progress=element('progress');progress.max=1;progress.value=Math.min(1,Math.max(0,ratio[0]/(ratio[1]||1)));progress.setAttribute('aria-label',title);card.append(progress);}
  card.append(element('span',detail,'metric-detail'));return card;
}
function renderMe() {
  const me=viewState.me;if(!me)return;
  const target=$('me');target.replaceChildren();
  const greeting=element('div',undefined,'identity');greeting.append(element('span',me.name.slice(0,1).toUpperCase(),'avatar'),element('div',wording('خوش آمدی، ','Welcome, ')+me.name,'identity-name'),badge(roleName(me.role)));
  target.append(greeting);
  if(me.role==='user'){
    const state=me.account, grid=element('div',undefined,'metrics account-metrics');
    grid.append(metric(wording('مصرف این دستگاه','This device usage'),bytes((me.usage||[]).reduce((a,b)=>a+b,0)),wording('آپلود و دانلود ثبت‌شده','Recorded upload and download')));
    if(state){grid.append(metric(wording('حجم باقی‌ماندهٔ حساب','Account data remaining'),state.remaining_bytes===null?wording('نامحدود','Unlimited'):bytes(state.remaining_bytes),state.plan?.name||wording('بدون طرح محدود','No limited plan')));grid.append(metric(wording('اعتبار حساب','Account validity'),state.expires?dateTime(state.expires):wording('بدون انقضا','No expiry'),state.allowed?wording('حساب اجازهٔ دسترسی دارد','Account permits access'):wording('دسترسی طبق وضعیت حساب بسته است','Access restricted by account state')));}
    target.append(grid);
  }
}
function renderOverview() {
  const status=viewState.status, data=viewState.resources;if(!status||!data)return;
  const preview=status.mode!=='enforce', applied=Boolean(status.applied);
  const statusTitle=preview?wording('حالت پیش‌نمایش','Preview mode'):applied?wording('سیاست‌ها اعمال شده‌اند','Policies applied'):wording('سیاست‌ها اعمال نشده‌اند','Policies not applied');
  const target=$('status');target.replaceChildren();const notice=element('div',undefined,'status-notice '+(preview?'preview':applied?'success':'error'));
  notice.append(badge(statusTitle,preview?'neutral':applied?'good':'bad'),element('span',status.error|| (preview?wording('تغییری در شبکه اعمال نمی‌شود. منابع زیر مربوط به میزبان پیش‌نمایش‌اند.','Network changes are disabled. Resources below belong to the preview host.'):wording('وضعیت اجرای سیاست‌ها؛ این نشانگر تست اتصال اینترنت نیست.','Policy execution status; this is not an internet connectivity test.'))));target.append(notice);
  $('mode-badge').hidden=false;$('mode-badge').textContent=statusTitle;
  $('policy-debug').textContent=status.plan||wording('هنوز برنامه‌ای دریافت نشده است.','No policy plan received yet.');
  const memory=data.memory_bytes||{},storage=data.storage_bytes||{},used=Math.max(0,(memory.MemTotal||0)-(memory.MemAvailable??memory.MemFree??0));
  let total=0;for(const usage of Object.values(data.account_usage||{}))total+=(usage[0]||0)+(usage[1]||0);
  const grid=$('resources');grid.replaceChildren();
  grid.append(metric(wording('دستگاه‌های ثبت‌شده','Registered devices'),number(data.devices||0),wording('دارای سیاست در RahaWRT','With a RahaWRT policy')),
    metric(wording('دستگاه‌های واردشده','Authenticated devices'),number(data.authenticated_devices||0),wording('نشست مجاز حساب کاربری','Permitted account sessions')),
    metric(wording('مصرف ثبت‌شده','Recorded traffic'),bytes(total),wording('مجموع آپلود و دانلود دستگاه‌ها','All recorded device upload and download')),
    metric(wording('حافظهٔ در حال استفاده','Memory in use'),bytes(used)+' / '+bytes(memory.MemTotal),preview?wording('حافظهٔ میزبان پیش‌نمایش','Preview host memory'):wording('حافظهٔ روتر','Router memory'),[used,memory.MemTotal]),
    metric(wording('فضای ذخیره‌سازی آزاد','Free storage'),bytes(storage.free),wording('از مجموع ','Of ')+bytes(storage.total),[storage.total-storage.free,storage.total]),
    metric(wording('زمان روشن‌بودن','Uptime'),data.uptime_seconds===null?'—':duration(data.uptime_seconds),wording('بار یک دقیقه: ','1-minute load: ')+number(data.load?.[0]||0,2)));
}
function renderBillingViews() {
  if(viewState.plans)tableView('plans-list',[wording('طرح','Plan'),wording('حجم','Data allowance'),wording('آپلود / دانلود','Upload / download'),wording('اعتبار','Validity'),wording('مسیر','Route')],viewState.plans.map(p=>[p.name||p.id,p.quota_bytes?bytes(p.quota_bytes):wording('نامحدود','Unlimited'),rate(p.upload_kbps)+' / '+rate(p.download_kbps),duration(p.valid_seconds),nodeName(p.node,p.tunnel)]));
  if(viewState.accounts)tableView('accounts-list',[wording('نام کاربری','Username'),wording('نقش','Role'),wording('وضعیت حساب','Account state'),wording('باقی‌مانده','Data remaining'),wording('انقضا','Expiry')],viewState.accounts.map(a=>[a.name,roleName(a.role),a.account?badge(a.account.allowed?wording('مجاز','Permitted'):wording('محدود','Restricted'),a.account.allowed?'good':'bad'):'—',a.account?.remaining_bytes==null?wording('نامحدود','Unlimited'):bytes(a.account.remaining_bytes),a.account?.expires?dateTime(a.account.expires):'—']));
}
function renderReportViews() {
  if(viewState.report)tableView('report-data',[wording('بازه (UTC)','Period (UTC)'),wording('حساب','Account'),wording('دستگاه','Device'),wording('آپلود','Upload'),wording('دانلود','Download')],viewState.report.rows.map(r=>[r.period,r.account||'—',r.device,bytes(r.upload_bytes),bytes(r.download_bytes)]));
  if(viewState.sessions)tableView('session-data',[wording('حساب','Account'),wording('آدرس IP','IP address'),wording('ورود','Started'),wording('پایان','Ended')],viewState.sessions.map(s=>[s.name,s.ip,dateTime(s.started),s.ended?dateTime(s.ended):wording('نشست منقضی نشده','Session not expired')]));
  if(viewState.audit)tableView('audit-data',[wording('زمان','Time'),wording('عامل','Actor'),wording('عملیات','Action'),wording('موضوع','Subject')],viewState.audit.map(a=>[dateTime(a.time),a.actor,a.action,a.subject]));
}
function renderParentalViews() {
  if(viewState.profiles)tableView('parental-list',[wording('پروفایل','Profile'),wording('دامنهٔ مجاز','Allowed domains'),wording('دامنهٔ مسدود','Blocked domains'),wording('جست‌وجوی ایمن','SafeSearch')],viewState.profiles.map(p=>[p.name||p.id,number(p.allow.length),number(p.block.length),p.safe_search?wording('روشن','On'):wording('خاموش','Off')]));
  if(viewState.tunnels)tableView('tunnels-list',[wording('رابط','Interface'),wording('نوع','Type'),wording('تنظیمات','Configuration'),wording('وضعیت رابط','Interface state')],viewState.tunnels.map(t=>[t.id,t.kind,t.configuration_status,t.up?wording('بالا؛ سلامت مسیر تأیید نشده','Up; egress not verified'):wording('پایین یا نامشخص','Down or unknown')]));
}
function renderCachedViews() {if(typeof renderDeviceViews==='function')renderDeviceViews();document.querySelectorAll('#nodes option').forEach(o=>o.textContent=nodeName(o.value));renderMe();renderOverview();renderBillingViews();renderReportViews();renderParentalViews();}
