'use strict';
// Real Chromium UI integration. Test credentials stay in memory and a temporary DB.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawn,spawnSync}=require('node:child_process');
const crypto=require('node:crypto');
const root=path.resolve(__dirname,'..');
const {chromium}=require(path.join(root,'.local/browser/node_modules/playwright'));
const directory=fs.mkdtempSync(path.join(os.tmpdir(),'rahawrt-browser-'));
const db=path.join(directory,'state.db');
const password=crypto.randomBytes(24).toString('base64url');
const python=process.env.RAHAWRT_PYTHON || 'python3';
const seed=spawnSync(python,['-c',"import sys; from rahawrt.store import Store; s=Store(sys.argv[1]); s.account('owner',sys.stdin.read(),'admin'); s.db.close()",db],{cwd:root,input:password});
assert.equal(seed.status,0,'seed failed');
const server=spawn(python,['-m','rahawrt.server','--db',db,'--web',path.join(root,'web'),'--port','19081'],{cwd:root,stdio:'ignore'});
(async()=>{
  let browser;
  try {
    let ready=false;
    for(let i=0;i<100;i++){try{const r=await fetch('http://127.0.0.1:19081/wrt/');if(r.ok){ready=true;break;}}catch{} await new Promise(r=>setTimeout(r,50));}
    assert(ready,'server did not become ready');
    browser=await chromium.launch({headless:true,...(process.env.RAHAWRT_CHROMIUM==='bundled'?{}:{executablePath:process.env.RAHAWRT_CHROMIUM||'/usr/bin/chromium'})});
    const page=await browser.newPage({viewport:{width:1280,height:900}});
    const errors=[];page.on('pageerror',e=>errors.push(e.message));
    await page.goto('http://127.0.0.1:19081/wrt/');
    assert.equal(await page.locator('html').getAttribute('dir'),'rtl');
    await page.locator('#language').click();assert.equal(await page.locator('html').getAttribute('dir'),'ltr');
    await page.locator('#login [name=name]').fill('owner');await page.locator('#login [name=password]').fill(password);await page.locator('#login button').click();
    await page.locator('#dashboard').waitFor({state:'visible'});
    await page.locator('#plan-form [name=id]').fill('browser_plan');await page.locator('#plan-form [name=name]').fill('Daily guest');
    await page.locator('#plan-form [name=quota_bytes]').fill('1000');
    await Promise.all([page.waitForResponse(r=>r.url().endsWith('/plans')&&r.request().method()==='PUT'),page.locator('#plan-form button').click()]);
    await page.locator('#issue-form [name=plan_id] option[value=browser_plan]').waitFor({state:'attached'});
    await page.locator('#issue-form [name=invoice_id]').fill('browser_invoice');await page.locator('#issue-form [name=plan_id]').selectOption('browser_plan');
    let [response]=await Promise.all([page.waitForResponse(r=>r.url().endsWith('/issue')),page.locator('#issue-form button').click()]);
    const issued=await response.json();assert.equal(issued.created,true);assert(issued.password.length>=12);
    await page.locator('#print-vouchers').waitFor({state:'visible'});assert.equal(await page.locator('.voucher').count(),1);
    [response]=await Promise.all([page.waitForResponse(r=>r.url().endsWith('/issue')),page.locator('#issue-form button').click()]);
    const replay=await response.json();assert.equal(replay.created,false);assert.equal(replay.username,issued.username);assert.equal(replay.password,null);
    await page.locator('#clear-vouchers').click();await page.locator('#print-vouchers').waitFor({state:'hidden'});
    await page.locator('#account [name=name]').fill('operator');await page.locator('#account [name=password]').fill(password);await page.locator('#account [name=role]').selectOption('operator');
    await Promise.all([page.waitForResponse(r=>r.url().endsWith('/accounts')&&r.request().method()==='POST'),page.locator('#account button').click()]);
    await page.locator('#logout').click();await page.locator('#login').waitFor({state:'visible'});
    await page.locator('#login [name=name]').fill('operator');await page.locator('#login [name=password]').fill(password);await page.locator('#login button').click();
    await page.locator('#dashboard').waitFor({state:'visible'});
    assert.equal(await page.locator('#plan-form').isVisible(),false);assert.equal(await page.locator('#issue-form').isVisible(),false);assert.equal(await page.locator('#reports').isVisible(),true);
    await page.setViewportSize({width:390,height:844});
    await page.locator('#language').click();assert.equal(await page.locator('html').getAttribute('dir'),'rtl');
    fs.mkdirSync(path.join(root,'.local/screenshots'),{recursive:true});
    await page.screenshot({path:path.join(root,'.local/screenshots/operator-mobile.png'),fullPage:true});
    assert.deepEqual(errors,[],'browser runtime errors');
    console.log('PASS: Chromium RTL/LTR, real login, plan creation, invoice issuance/retry, secret clearing, operator permissions and mobile rendering.');
  } finally {
    if(browser)await browser.close();
    server.kill('SIGTERM');
    await new Promise(resolve=>{if(server.exitCode!==null)resolve();else server.once('exit',resolve);});
    fs.rmSync(directory,{recursive:true,force:true});
  }
})().catch(error=>{console.error(error.message);process.exitCode=1;});
