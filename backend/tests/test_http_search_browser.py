"""Optional real-browser HTTP search acceptance with isolated synthetic routes."""
import json
import os
import shutil
import subprocess

import pytest

from app.telemetry.dashboard import DASHBOARD_HTML
from test_http_dashboard import FIXTURE


BROWSER_RUNNER = r"""
const assert=require('node:assert/strict'),{chromium}=require(process.env.RISKOPS_PLAYWRIGHT_MODULE);
(async()=>{
 const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);
 const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));
 const browser=await chromium.launch({executablePath:process.env.RISKOPS_BROWSER_EXECUTABLE,headless:true,args:['--no-sandbox','--disable-gpu','--disable-dev-shm-usage']}),reports=[];
 try{for(const [name,viewport] of [['desktop',{width:1440,height:1000}],['mobile',{width:390,height:844}]] ){
  const context=await browser.newContext({viewport,serviceWorkers:'block'}),calls=[],writes=[],external=[],errors=[];
  const {caseRecord,httpFixture}=new Function(input.fixture+';return {caseRecord,httpFixture};')();
  httpFixture.sources.push({id:'web-two',hostname:'second.invalid',services:['public','private']});
  let failure=0,empty=false,wrongScope=false,slowIP=null,releaseSlow=null,removed=false;
  const incidentCalls=()=>calls.filter(url=>url.pathname==='/api/http/incidents');
  await context.addInitScript(()=>sessionStorage.setItem('riskops-workspace','http'));
  await context.route('**/*',async route=>{
   const request=route.request(),url=new URL(request.url()),path=url.pathname;calls.push(url);
   if(url.origin!=='http://http-search.invalid'){external.push(request.url());return route.abort();}
   if(request.method()!=='GET'){writes.push(request.method());return route.abort();}
   if(path==='/')return route.fulfill({contentType:'text/html',body:input.html});
   let data;
   if(path==='/api/console/bootstrap')data={state:'disabled'};
   else if(path==='/api/summary')data={sources:[],totals:{events:0,ssh_failures:0,ssh_successes:0,incidents:0}};
   else if(path==='/api/http/status')data=removed?{...httpFixture,sources:[]}:httpFixture;
   else if(path==='/api/http/incidents'){
    const q=url.searchParams,ip=q.get('ip'),canonical=ip==='2001:0DB8:0:0::23'?'2001:db8::23':ip==='::ffff:198.51.100.23'?'198.51.100.23':ip;
    if(failure)return route.fulfill({status:failure,contentType:'application/json',body:JSON.stringify({detail:'private database exception'})});
    data={items:empty?[]:Array.from({length:ip&&q.get('page')!=='2'?50:1},()=>({...caseRecord,source_id:q.get('source_id')||'web',service_id:q.get('service_id')||'public',client_ip:canonical||caseRecord.client_ip,rules:[{label:'<img src=x onerror=alert(1)>'}]})),page:empty?1:Number(q.get('page')),total_pages:empty?1:2,total:empty?0:51};
    if(ip){data.query={ip:wrongScope?'198.51.100.99':canonical,source_id:q.get('source_id'),service_id:q.get('service_id'),focus:q.get('focus')};data.limitations=['retained_cases_only','connection_peer_only','analysis_coverage_limited','pages_may_change'];}
    if(ip&&ip===slowIP)await new Promise(resolve=>{releaseSlow=resolve;});
   }else if(path==='/api/http/incidents/HTTP-example')data=caseRecord;
   else if(path.endsWith('/evidence'))data={revision:Number(url.searchParams.get('revision')),items:[{timestamp:caseRecord.last_seen,method:'GET',path:'/<img src=x onerror=alert(1)>',status:404}],page:1,total_pages:1,total:1};
   else if(path==='/api/http/restores')data={items:[],page:1,total_pages:1,total:0};
   else throw new Error('Unexpected '+path);
   return route.fulfill({contentType:'application/json',body:JSON.stringify(data)});
  });
  const page=await context.newPage();page.on('pageerror',error=>errors.push(error.message));
  await page.goto('http://http-search.invalid/');await page.locator('#http-rows').getByRole('button',{name:'查看详情',exact:true}).waitFor();
  assert.equal(incidentCalls()[0].searchParams.has('ip'),false);
  const before=incidentCalls().length;await page.locator('#http-ip').fill('198.51.100.0/24');assert.equal(incidentCalls().length,before);assert.equal(await page.locator('#http-rows').textContent(),'');assert.equal(await page.locator('#http-next').isDisabled(),true);
  await page.locator('#http-ip').press('Enter');await page.waitForFunction(()=>document.getElementById('http-status').textContent.includes('完整 IPv4 / IPv6'));assert.equal(incidentCalls().length,before);
  await page.locator('#http-ip').fill('2001:0DB8:0:0::23');await page.locator('#http-source').selectOption('web');await page.locator('#http-service').selectOption('private');await page.locator('#http-focus').selectOption('attention');assert.equal(incidentCalls().length,before);
  await page.locator('#http-ip').press('Enter');await page.waitForFunction(()=>document.getElementById('http-page').textContent.includes('第 1 / 2 页'));
  let q=incidentCalls().at(-1).searchParams;assert.equal(q.get('ip'),'2001:0DB8:0:0::23');assert.equal(q.get('source_id'),'web');assert.equal(q.get('service_id'),'private');assert.equal(q.get('focus'),'attention');
  assert.match(await page.locator('#http-search-scope').textContent(),/2001:db8::23.*web.*private.*需关注/);assert.equal(await page.locator('#http-rows img').count(),0);assert.match(await page.locator('#http-rows').textContent(),/<img/);assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await page.locator('#http-next').click();await page.waitForFunction(()=>document.getElementById('http-page').textContent.includes('第 2 / 2 页'));assert.equal(incidentCalls().at(-1).searchParams.get('ip'),'2001:0DB8:0:0::23');assert.equal(await page.locator('#http-next').isDisabled(),true);
  await page.locator('#http-focus').selectOption('low');await page.waitForFunction(()=>document.getElementById('http-page').textContent.includes('第 1 / 2 页'));q=incidentCalls().at(-1).searchParams;assert.equal(q.get('focus'),'low');assert.equal(q.get('ip'),'2001:0DB8:0:0::23');
  await page.locator('#http-ip').fill('::ffff:198.51.100.23');await page.locator('#http-search').click();await page.waitForFunction(()=>document.getElementById('http-rows').textContent.includes('198.51.100.23'));assert.match(await page.locator('#http-search-scope').textContent(),/连接 IP 198.51.100.23/);
  await page.locator('#http-rows').getByRole('button',{name:'查看详情',exact:true}).first().click();await page.locator('#http-dialog[open]').waitFor();await page.waitForFunction(()=>document.getElementById('http-revision').textContent.includes('版本 2 / 2'));await page.locator('#http-tab-evidence').click();assert.equal(await page.locator('#http-evidence img').count(),0);assert.match(await page.locator('#http-evidence').textContent(),/<img/);await page.keyboard.press('Escape');
  await page.locator('#http-next').click();await page.waitForFunction(()=>document.getElementById('http-page').textContent.includes('第 2 / 2 页'));await page.locator('#http-search-clear').click();await page.waitForFunction(()=>document.getElementById('http-search-scope').textContent.includes('未限制连接 IP')&&document.getElementById('http-page').textContent.includes('第 1 / 2 页'));assert.equal(incidentCalls().at(-1).searchParams.has('ip'),false);assert.equal(await page.locator('#http-ip').inputValue(),'');
  // Ignore AbortSignal deliberately: generation checks must also reject stale replies.
  await page.evaluate(()=>{const fetchOriginal=window.fetch;window.fetch=(url,options)=>fetchOriginal(url,{...options,signal:undefined});});
  slowIP='198.51.100.90';await page.locator('#http-ip').fill(slowIP);await page.locator('#http-search').click();await page.waitForFunction(()=>document.getElementById('http-pane-incidents').getAttribute('aria-busy')==='true');
  await page.waitForTimeout(30);const slowCount=incidentCalls().length;await page.locator('#http-ip').fill('198.51.100.91');await page.locator('#http-source').selectOption('web-two');assert.equal(incidentCalls().length,slowCount);assert.equal(await page.locator('#http-rows').textContent(),'');assert.equal(await page.locator('#http-next').isDisabled(),true);
  await page.locator('#http-search').click();await page.waitForFunction(()=>document.getElementById('http-rows').textContent.includes('198.51.100.91'));assert(releaseSlow);releaseSlow();await page.waitForLoadState('networkidle');assert.doesNotMatch(await page.locator('#http-rows').textContent(),/198.51.100.90/);slowIP=null;
  failure=503;await page.locator('#http-refresh').click();await page.waitForFunction(()=>document.getElementById('http-status').textContent.includes('HTTP 搜索暂不可用'));assert.doesNotMatch(await page.locator('#http-rows').textContent(),/198.51.100.91/);assert.equal(await page.locator('#http-next').isDisabled(),true);assert.doesNotMatch(await page.locator('#http-status').textContent(),/private|database/);
  failure=422;await page.locator('#http-search').click();await page.waitForFunction(()=>document.getElementById('http-status').textContent.includes('查询条件无效'));failure=0;wrongScope=true;await page.locator('#http-search').click();await page.waitForFunction(()=>document.getElementById('http-status').textContent.includes('返回异常'));assert.doesNotMatch(await page.locator('#http-rows').textContent(),/198.51.100.91/);
  wrongScope=false;empty=true;await page.locator('#http-search').click();await page.waitForFunction(()=>document.getElementById('http-rows').textContent.includes('没有匹配'));assert.match(await page.locator('#http-rows').textContent(),/不代表没有请求或活动/);empty=false;
  await page.locator('#http-search').click();await page.waitForFunction(()=>document.getElementById('http-rows').textContent.includes('198.51.100.91'));removed=true;const beforeRemoval=incidentCalls().length;await page.locator('#http-refresh').click();await page.waitForFunction(()=>document.getElementById('http-search-scope').textContent.includes('原筛选条件已不可用'));assert.equal(incidentCalls().length,beforeRemoval);assert.equal(await page.locator('#http-rows').textContent(),'');
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);assert.deepEqual(errors,[]);assert.deepEqual(writes,[]);assert.deepEqual(external,[]);assert(calls.every(url=>!url.pathname.includes('/ai/')&&!url.pathname.includes('/controls')));
  reports.push({viewport:name,passed:true,page_errors:errors.length,writes:writes.length,external_requests:external.length});await context.close();
 }}finally{await browser.close();}
 console.log(JSON.stringify(reports));
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
"""


def test_optional_real_browser_http_search():
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
