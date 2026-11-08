"""Optional real Chromium acceptance, isolated to synthetic route fixtures."""
import json
import os
import shutil
import subprocess

import pytest

from app.telemetry.dashboard import DASHBOARD_HTML
from test_network_dashboard import FIXTURE


BROWSER_RUNNER = r"""
const assert=require('node:assert/strict');
const {chromium}=require(process.env.RISKOPS_PLAYWRIGHT_MODULE);
(async()=>{
 const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);
 const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));
 const browser=await chromium.launch({executablePath:process.env.RISKOPS_BROWSER_EXECUTABLE,headless:true,args:['--no-sandbox','--disable-gpu','--disable-dev-shm-usage']});
 const reports=[];
 try{for(const [name,viewport] of [['desktop',{width:1440,height:1000}],['mobile',{width:390,height:844}]]){
  const context=await browser.newContext({viewport,timezoneId:'Europe/Berlin',serviceWorkers:'block'}),errors=[],calls=[],writes=[],external=[];
  const {networkRecord,networkFixture,networkEvent}=new Function(input.fixture+';return {networkRecord,networkFixture,networkEvent};')();
  networkFixture.sources.push({source_id:'net-b',hostname:'second.invalid',status:'current'});
  let disabled=false,failure=0,empty=false,latestSnapshot=77,releaseSlow=null,slowIP=null;
  await context.addInitScript(()=>sessionStorage.setItem('riskops-workspace','network'));
  const searchCalls=()=>calls.filter(call=>call.pathname==='/api/network/events/search');
  await context.route('**/*',async route=>{
   const req=route.request(),url=new URL(req.url()),path=url.pathname;calls.push(url);
   if(url.origin!=='http://network-search.invalid'){external.push(req.url());return route.abort();}
   if(req.method()!=='GET'){writes.push(req.method());return route.abort();}
   if(path==='/')return route.fulfill({contentType:'text/html',body:input.html});
   let data;
   if(path==='/api/console/bootstrap')data={state:'disabled'};
   else if(path==='/api/summary')data={sources:[],totals:{events:0,ssh_failures:0,ssh_successes:0,incidents:0}};
   else if(path==='/api/network/status')data=disabled?{enabled:false}:networkFixture;
   else if(path==='/api/network/incidents')data={items:[networkRecord],page:Number(url.searchParams.get('page')),total_pages:1,total:1};
   else if(path.endsWith('/evidence'))data={incident_id:networkRecord.incident_id,revision:Number(url.searchParams.get('revision')),items:[networkEvent],page:1,total_pages:1,total:1};
   else if(path==='/api/network/incidents/NET-example')data=networkRecord;
   else if(path==='/api/network/events/search'){
    if(failure)return route.fulfill({status:failure,contentType:'application/json',body:JSON.stringify({detail:'private schema budget',code:'internal'})});
    const q=url.searchParams,query={source_id:q.get('source_id'),ip:q.get('ip')==='2001:0db8:0:0::23'?'2001:db8::23':q.get('ip'),start:q.get('start'),end:q.get('end')},cursor=q.get('cursor'),snapshot=cursor?Number(cursor.split('-')[1]):latestSnapshot,second=cursor?.endsWith('-2');
    data={items:empty?[]:[{...networkEvent,...{source_id:query.source_id,src_ip:query.ip,journal_realtime_us:Date.parse(query.start)*1000,dst_port:second?444:443,ingress_interface:'<img src=x onerror=alert(1)>'}}],query,snapshot,page_cursor:`page-${snapshot}-${second?2:1}`,next_cursor:second||empty?null:`page-${snapshot}-2`,limitations:['retained_observations_only','late_receipts_excluded']};
    if(query.ip===slowIP)await new Promise(resolve=>{releaseSlow=resolve;});
   }else throw new Error('Unexpected '+path);
   return route.fulfill({contentType:'application/json',body:JSON.stringify(data)});
  });
  const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));
  await page.goto('http://network-search.invalid/');await page.locator('#network-rows').getByRole('button',{name:'查看详情',exact:true}).waitFor();
  assert.equal(searchCalls().length,0);assert.equal(await page.locator('#network-logs').isHidden(),true);
  await page.locator('#network-rows').getByRole('button',{name:'查看详情',exact:true}).click();await page.locator('#network-dialog[open]').waitFor();await page.waitForFunction(()=>document.getElementById('network-revision').textContent.includes('版本 2 / 2'));
  assert.equal(await page.locator('#network-ssh-search button').count(),2);await page.keyboard.press('Escape');
  await page.locator('#network-view-logs').click();assert.equal(await page.locator('#network-findings').isHidden(),true);assert.equal(searchCalls().length,0);
  await page.locator('#network-log-source').selectOption('net-a');await page.locator('#network-log-submit').click();assert.equal(searchCalls().length,0);assert.match(await page.locator('#network-log-status').textContent(),/空 IP/);
  await page.locator('#network-log-ip').fill('2001:0db8:0:0::23');assert.equal(searchCalls().length,0);await page.locator('#network-log-ip').press('Enter');
  await page.waitForFunction(()=>document.getElementById('network-log-page').textContent.includes('第 1 页'));
  const first=searchCalls()[0].searchParams;assert.equal(first.get('source_id'),'net-a');assert.equal(first.get('ip'),'2001:0db8:0:0::23');assert.equal(Date.parse(first.get('end'))-Date.parse(first.get('start')),86400000);
  assert.match(await page.locator('#network-log-scope').textContent(),/2001:db8::23/);assert.equal(await page.locator('#network-log-rows img').count(),0);assert.match(await page.locator('#network-log-rows').textContent(),/<img/);assert.match(await page.locator('#network-log-coverage').textContent(),/保留/);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await page.locator('#network-log-next').click();await page.waitForFunction(()=>document.getElementById('network-log-page').textContent.includes('第 2 页'));assert.equal(await page.locator('#network-log-next').isDisabled(),true);
  latestSnapshot=78;await page.locator('#network-log-prev').click();await page.waitForFunction(()=>document.getElementById('network-log-page').textContent.includes('第 1 页'));assert.equal(searchCalls().at(-1).searchParams.get('cursor'),'page-77-1');assert.doesNotMatch(await page.locator('#network-log-page').textContent(),/共|总/);
  await page.locator('#network-log-refresh').click();await page.waitForFunction(()=>document.getElementById('network-log-page').textContent.includes('第 1 页'));assert.equal(searchCalls().at(-1).searchParams.has('cursor'),false);
  await page.locator('#network-log-next').click();await page.waitForFunction(()=>document.getElementById('network-log-page').textContent.includes('第 2 页'));assert.equal(searchCalls().at(-1).searchParams.get('cursor'),'page-78-2');
  await page.locator('#network-log-window').selectOption('custom');assert.equal(await page.locator('#network-log-rows').textContent(),'');assert.equal(await page.locator('#network-log-prev').isDisabled(),true);
  await page.locator('#network-log-start').fill('2026-01-01T12:00');await page.locator('#network-log-end').fill('2026-01-01T13:00');await page.locator('#network-log-submit').click();await page.waitForFunction(()=>document.getElementById('network-log-page').textContent.includes('第 1 页'));
  assert.equal(searchCalls().at(-1).searchParams.get('start'),'2026-01-01T11:00:00.000Z');assert.equal(searchCalls().at(-1).searchParams.get('end'),'2026-01-01T12:00:00.000Z');
  const beforeInvalid=searchCalls().length;await page.locator('#network-log-end').fill('2026-01-09T13:00');await page.locator('#network-log-submit').click();assert.equal(searchCalls().length,beforeInvalid);assert.match(await page.locator('#network-log-status').textContent(),/最多 7 天/);
  await page.locator('#network-log-start').fill('2026-03-29T02:30');await page.locator('#network-log-end').fill('2026-03-29T04:00');await page.locator('#network-log-submit').click();assert.equal(searchCalls().length,beforeInvalid);assert.match(await page.locator('#network-log-status').textContent(),/夏令时/);
  await page.locator('#network-log-window').selectOption('1h');await page.locator('#network-log-source').selectOption('net-b');await page.locator('#network-log-submit').click();await page.waitForFunction(()=>document.getElementById('network-log-page').textContent.includes('第 1 页'));assert.equal(searchCalls().at(-1).searchParams.get('source_id'),'net-b');assert.equal(searchCalls().at(-1).searchParams.has('cursor'),false);assert.equal(Date.parse(searchCalls().at(-1).searchParams.get('end'))-Date.parse(searchCalls().at(-1).searchParams.get('start')),3600000);
  // Deliberately ignore cancellation to prove generation checks also reject late responses.
  await page.evaluate(()=>{const original=window.fetch;window.fetch=(url,options)=>original(url,{...options,signal:undefined});});
  slowIP='198.51.100.90';await page.locator('#network-log-ip').fill(slowIP);await page.locator('#network-log-submit').click();
  await page.waitForFunction(()=>document.getElementById('network-logs').getAttribute('aria-busy')==='true');
  assert.equal(await page.locator('#network-log-prev').isDisabled(),true);assert.equal(await page.locator('#network-log-next').isDisabled(),true);
  await page.locator('#network-log-ip').fill('198.51.100.91');assert.equal(await page.locator('#network-log-rows').textContent(),'');await page.locator('#network-log-submit').click();await page.waitForFunction(()=>document.getElementById('network-log-rows').textContent.includes('198.51.100.91'));
  assert(releaseSlow);releaseSlow();await page.waitForLoadState('networkidle');assert.doesNotMatch(await page.locator('#network-log-rows').textContent(),/198.51.100.90/);slowIP=null;
  failure=503;await page.locator('#network-log-refresh').click();await page.waitForFunction(()=>document.getElementById('network-log-status').textContent.includes('缩小时间范围或重试'));assert.doesNotMatch(await page.locator('#network-log-rows').textContent(),/198.51.100.91/);assert.doesNotMatch(await page.locator('#network-log-status').textContent(),/private|schema/);
  failure=422;await page.locator('#network-log-submit').click();await page.waitForFunction(()=>document.getElementById('network-log-status').textContent.includes('查询条件无效'));failure=404;await page.locator('#network-log-submit').click();await page.waitForFunction(()=>document.getElementById('network-log-status').textContent.includes('来源未配置或已移除'));assert.match(await page.locator('#network-log-rows').textContent(),/未展示结果/);failure=0;empty=true;await page.locator('#network-log-submit').click();await page.waitForFunction(()=>document.getElementById('network-log-rows').textContent.includes('没有匹配'));assert.match(await page.locator('#network-log-rows').textContent(),/不代表没有活动/);empty=false;
  await page.locator('#network-view-findings').click();await page.locator('#network-rows').getByRole('button',{name:'查网络日志：198.51.100.23',exact:true}).click();await page.waitForFunction(()=>document.getElementById('network-log-page').textContent.includes('第 1 页'));
  const pivot=searchCalls().at(-1).searchParams;assert.equal(pivot.get('source_id'),'net-a');assert.equal(pivot.get('start'),'2026-01-01T11:30:00.000Z');assert.equal(pivot.get('end'),'2026-01-01T12:31:00.000Z');
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  const beforeRefresh=searchCalls().length;disabled=true;await page.locator('#network-view-findings').click();await page.locator('#network-refresh').click();await page.waitForFunction(()=>document.getElementById('network-health').textContent.includes('尚未配置'));await page.locator('#network-view-logs').click();assert.equal(searchCalls().length,beforeRefresh);assert.equal(await page.locator('#network-log-submit').isDisabled(),true);assert.equal(await page.locator('#network-log-rows').textContent(),'');assert.match(await page.locator('#network-log-scope').textContent(),/不再可用/);
  assert(calls.every(url=>!url.pathname.includes('/ai/')&&!url.pathname.includes('/controls')&&!url.pathname.includes('ip-info')));assert.deepEqual(errors,[]);assert.deepEqual(writes,[]);assert.deepEqual(external,[]);
  reports.push({viewport:name,passed:true,page_errors:errors.length,writes:writes.length,external_requests:external.length});await context.close();
 }}finally{await browser.close();}
 console.log(JSON.stringify(reports));
})().catch(e=>{console.error(e.stack);process.exitCode=1;});
"""


def test_optional_real_browser_network_search():
    node = shutil.which('node')
    if not node or not os.environ.get('RISKOPS_PLAYWRIGHT_MODULE'):
        pytest.skip('Set RISKOPS_PLAYWRIGHT_MODULE for synthetic desktop/mobile acceptance')
    result = subprocess.run(
        [node, '-e', BROWSER_RUNNER],
        input=json.dumps({'html': DASHBOARD_HTML, 'fixture': FIXTURE.split('const dialog=')[0]}),
        text=True, encoding='utf-8', capture_output=True, timeout=150,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [
        {'viewport': name, 'passed': True, 'page_errors': 0, 'writes': 0, 'external_requests': 0}
        for name in ('desktop', 'mobile')
    ]
