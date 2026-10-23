"""Optional real-browser IP search acceptance against synthetic HTTP fixtures.

No production service, key, AI, geolocation or control endpoint is contacted.
"""
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
  const context=await browser.newContext({viewport,timezoneId:'Asia/Shanghai',serviceWorkers:'block',extraHTTPHeaders:{Authorization:'Basic c3ludGhldGljOmZpeHR1cmU='}});
  const errors=[],calls=[],writes=[],external=[],unexpected=[];
  const {networkRecord,networkFixture,networkEvent}=new Function(input.fixture+';return {networkRecord,networkFixture,networkEvent};')();
  let generation=1,releaseSlow=null,slowStarted=false;
  const source={source_id:'source-a',hostname:'synthetic-host',connection_status:'online',collection:{coverage_start:'2026-01-01T00:00:00Z',gaps_since_coverage:1,caught_up:true},last_seen:'2026-01-01T12:00:00Z'};
  const summary={sources:[source],totals:{events:102,ssh_failures:102,ssh_successes:0,incidents:102},triage_counts:{pending:100,acknowledged:1,resolved:1,total:102},retention_days:14};
  const incident=(ip,page)=>({incident_id:'SSH-'+page,source_id:'source-a',source_ids:['source-a'],hostname:'synthetic-host',src_ip:ip,first_seen:'2026-01-01T12:00:00Z',last_seen:'2026-01-01T12:01:00Z',failure_count:3,status:'open',triage_status:'resolved',rules:[]});
  const envelope=(items,page=1)=>({items,page,total_pages:3,total:102,triage_counts:{pending:100,acknowledged:1,resolved:1,total:102},score_counts:{attention:102,low:0,unscored:0,total:102}});
  const jsonReply=(route,data,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(data)});
  await context.route('**/*',async route=>{
   const req=route.request(),url=new URL(req.url()),path=url.pathname;calls.push({path,query:Object.fromEntries(url.searchParams),method:req.method()});
   if(url.origin!=='http://ip-search-ui.invalid'){external.push(req.url());return route.abort();}
   if(req.method()!=='GET'){writes.push(req.method()+' '+path);return route.abort();}
   if(req.headers().authorization!=='Basic c3ludGhldGljOmZpeHR1cmU='){unexpected.push('missing synthetic operator authentication');return route.abort();}
   if(path==='/')return route.fulfill({contentType:'text/html',body:input.html});
   if(path==='/favicon.ico')return route.fulfill({status:204,body:''});
   if(path==='/api/console/bootstrap')return jsonReply(route,{state:'ready',generation,generated_at:new Date().toISOString(),age_seconds:0,max_age_seconds:60,stale:false,data:{summary,events:{...envelope([],1),snapshot:'r1:999'},incidents:envelope([incident('192.0.2.200',1)])}});
   if(path==='/api/summary')return jsonReply(route,summary);
   if(path==='/api/controls')return jsonReply(route,{enabled:false,sources:[],blocks:[],source_checks:[],jobs:[]});
   if(path==='/api/incidents'||path==='/api/events'){
    const q=url.searchParams,ip=q.get('ip')||'192.0.2.200',page=Number(q.get('page')||1);
    if(ip.includes('/'))return jsonReply(route,{detail:'告警查询参数无效，请检查完整 IP 和带时区的时间范围'},422);
    if(ip==='203.0.113.99')return jsonReply(route,{detail:'synthetic unavailable'},503);
    if(ip==='192.0.2.88'){
     slowStarted=true;await new Promise(resolve=>{releaseSlow=resolve;});
     try{return await jsonReply(route,envelope([incident(ip,page)],page));}catch{return;}
    }
    const canonical=ip.startsWith('2001:0DB8')?'2001:db8::a':ip;
    if(path==='/api/incidents')return jsonReply(route,envelope([incident(canonical,page)],page));
    return jsonReply(route,{...envelope([{source_id:'source-a',event_id:'event-'+page,src_ip:canonical,event_type:'auth_failure',timestamp:'2026-01-01T12:00:00Z',message:'synthetic retained SSH evidence page '+page}],page),snapshot:q.get('snapshot')||'r1:77'});
   }
   if(path==='/api/network/status')return jsonReply(route,networkFixture);
   if(path==='/api/network/incidents')return jsonReply(route,{items:[networkRecord],page:1,total_pages:1,total:1});
   if(path==='/api/network/incidents/NET-example')return jsonReply(route,networkRecord);
   if(path==='/api/network/incidents/NET-example/evidence')return jsonReply(route,{incident_id:networkRecord.incident_id,revision:2,items:[networkEvent],page:1,total_pages:1,total:1});
   unexpected.push(path);return route.fulfill({status:500,body:'unexpected synthetic route'});
  });
  const page=await context.newPage();page.setDefaultTimeout(10000);page.on('pageerror',error=>errors.push(error.message));
  const last=(kind)=>calls.filter(call=>call.path==='/api/'+(kind==='event'?'events':'incidents')).at(-1)?.query;
  const act=async(kind,action)=>{
   const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/'+(kind==='event'?'events':'incidents'));
   await action();await response;await page.waitForFunction(kind=>document.getElementById(kind+'-section').getAttribute('aria-busy')==='false',kind);
   return last(kind);
  };
  const search=async(kind,ip)=>{const selector=kind==='event'?'#search-ip':'#incident-search-ip';return act(kind,async()=>{await page.locator(selector).fill(ip);await page.locator(selector).press('Enter');});};
  await page.goto('http://ip-search-ui.invalid/');await page.locator('#incidents tr.selectable').waitFor();
  assert.equal(await page.locator('#incident-search-ip').isVisible(),true);
  assert.equal(await page.locator('#incident-search-window').isVisible(),true,'time controls stay outside collapsed advanced options');
  assert.equal(await page.locator('#incident-options').evaluate(el=>el.open),false);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  let q=await search('incident','2001:0DB8:0000:0000:0000:0000:0000:000A');
  assert.equal(q.ip,'2001:0DB8:0000:0000:0000:0000:0000:000A');assert.equal(Date.parse(q.end)-Date.parse(q.start),86400000);
  assert.match(await page.locator('#incidents').textContent(),/2001:db8::a/);
  const bounds={start:q.start,end:q.end};q=await act('incident',()=>page.locator('#incident-next').click());
  assert.equal(q.page,'2');assert.equal(q.start,bounds.start);assert.equal(q.end,bounds.end);assert(q.ip);
  await page.locator('#incident-search-window').selectOption('custom');
  await page.locator('#incident-search-start').fill('2026-10-22T16:00');await page.locator('#incident-search-end').fill('2026-10-23T16:00');
  q=await act('incident',()=>page.locator('#incident-search-ip').press('Enter'));
  assert.equal(q.start,'2026-10-22T08:00:00.000Z');assert.equal(q.end,'2026-10-23T08:00:00.000Z');assert.equal(q.page,'1');
  q=await act('incident',()=>page.locator('#incident-search-all').click());assert.equal(q.start,undefined);assert.equal(q.end,undefined);assert(q.ip);
  assert.match(await page.locator('#incident-search-scope').textContent(),/全部保留时间/);
  assert.match(await page.locator('#incident-search-coverage').textContent(),/已知采集缺口/);
  generation++;q=await act('incident',()=>page.locator('#refresh').click());assert(q.ip);assert.equal(q.start,undefined);
  assert.doesNotMatch(await page.locator('#incidents').textContent(),/192\.0\.2\.200/);
  generation++;const bootstrap=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/console/bootstrap');
  await page.evaluate(()=>scheduleBootstrap(1));await bootstrap;await page.waitForTimeout(75);
  assert.doesNotMatch(await page.locator('#incidents').textContent(),/192\.0\.2\.200/,'background default cache must not replace search');
  await page.locator('#incident-search-ip').fill('192.0.2.88');await page.locator('#incident-search-ip').press('Enter');
  for(let i=0;i<100&&!slowStarted;i++)await page.waitForTimeout(10);assert(slowStarted);
  await search('incident','198.51.100.23');releaseSlow();await page.waitForTimeout(75);
  assert.match(await page.locator('#incidents').textContent(),/198\.51\.100\.23/);assert.doesNotMatch(await page.locator('#incidents').textContent(),/192\.0\.2\.88/);
  await search('incident','203.0.113.99');assert.match(await page.locator('#incidents').textContent(),/当前查询失败/);assert.doesNotMatch(await page.locator('#incidents').textContent(),/198\.51\.100\.23/);
  await search('incident','198.51.100.23/32');assert.match(await page.locator('#incident-status').textContent(),/IPv4|IPv6|完整/);
  await search('incident','198.51.100.23');
  // Deliberately establish unrelated previous filters through real controls.
  await act('incident',()=>page.locator('#source-filter').selectOption('source-a'));
  await page.locator('#incident-options summary').click();
  await act('incident',()=>page.locator('#incident-triage').selectOption('resolved'));
  await act('event',()=>page.locator('#workspace-tab-events').click());
  assert.equal(await page.locator('#search-ip').isVisible(),true);
  await page.locator('#event-search-options summary').click();await page.locator('#search-username').fill('previous-user');await page.locator('#search-q').fill('previous-keyword');
  await search('event','192.0.2.17');assert.equal(last('event').username,'previous-user');
  // Keyboard activation of a network list pivot clears unrelated filters.
  await page.locator('#workspace-tab-network').click();await page.locator('#network-rows').getByRole('button',{name:'查 SSH 告警：198.51.100.23',exact:true}).waitFor();
  q=await act('incident',async()=>{const pivot=page.locator('#network-rows').getByRole('button',{name:'查 SSH 告警：198.51.100.23',exact:true});await pivot.focus();await pivot.press('Enter');});
  assert.equal(q.source_id,undefined);assert.equal(q.triage,'all');assert.equal(q.focus,'all');assert.equal(q.ip,networkRecord.src_ip);
  assert.equal(Date.parse(q.start),Date.parse(networkRecord.first_seen)-1800000);assert.equal(Date.parse(q.end),Date.parse(networkRecord.last_seen)+1800000);
  assert.equal(await page.locator('#incident-search-ip').evaluate(el=>el===document.activeElement),true);
  assert.match(await page.locator('#incident-search-scope').textContent(),/全部 SSH 来源.*全部处置状态/);
  const pivotBounds={start:q.start,end:q.end};
  await page.locator('#workspace-tab-network').click();await page.locator('#network-rows').getByRole('button',{name:'查看详情',exact:true}).click();
  await page.locator('#network-dialog[open]').waitFor();await page.locator('#network-ssh-search button').first().waitFor();
  q=await act('event',()=>page.locator('#network-ssh-search').getByRole('button',{name:'查 SSH 日志：198.51.100.23',exact:true}).click());
  assert.equal(await page.locator('#network-dialog').isVisible(),false);assert.equal(q.source_id,undefined);assert.equal(q.ip,networkRecord.src_ip);
  for(const key of ['username','q','event_type','snapshot'])assert.equal(q[key],undefined,'pivot clears '+key);
  assert.equal(q.start,pivotBounds.start);assert.equal(q.end,pivotBounds.end);
  assert.equal(await page.locator('#search-ip').evaluate(el=>el===document.activeElement),true);
  q=await act('event',()=>page.locator('#event-next').click());assert.equal(q.page,'2');assert.equal(q.snapshot,'r1:77');assert.equal(q.ip,networkRecord.src_ip);
  q=await act('event',()=>page.locator('#event-latest').click());assert.equal(q.page,'1');assert.equal(q.snapshot,undefined);assert.equal(q.start,pivotBounds.start);
  q=await act('event',()=>page.reload());assert.equal(q.ip,networkRecord.src_ip);assert.equal(q.source_id,undefined);assert.equal(q.start,pivotBounds.start);assert.equal(q.end,pivotBounds.end);
  assert.equal(await page.locator('#event-search-window').inputValue(),'custom');
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  assert.deepEqual(errors,[]);assert.deepEqual(writes,[]);assert.deepEqual(external,[]);assert.deepEqual(unexpected,[]);
  assert(calls.every(call=>!call.path.includes('/ai')&&!call.path.includes('/ip-info')&&!call.path.includes('/abuseipdb')));
  reports.push({viewport:name,passed:true,page_errors:errors.length,writes:writes.length,external_requests:external.length});
  await context.close();
 }}finally{await browser.close();}
 console.log(JSON.stringify(reports));
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
"""


def test_optional_real_browser_ip_search_and_network_pivots():
    node = shutil.which("node")
    if not node or not os.environ.get("RISKOPS_PLAYWRIGHT_MODULE"):
        pytest.skip("Set RISKOPS_PLAYWRIGHT_MODULE for synthetic IP-search desktop/mobile acceptance")
    result = subprocess.run(
        [node, "-e", BROWSER_RUNNER],
        input=json.dumps({"html": DASHBOARD_HTML, "fixture": FIXTURE.split("const dialog=")[0]}),
        text=True, encoding="utf-8", capture_output=True, timeout=150,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [
        {"viewport": name, "passed": True, "page_errors": 0, "writes": 0, "external_requests": 0}
        for name in ("desktop", "mobile")
    ]
