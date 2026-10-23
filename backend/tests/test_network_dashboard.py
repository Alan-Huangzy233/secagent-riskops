"""Exercise shipped network UI with inert HTTP, revision races and literal text."""
from test_dashboard_control import ControlsHTML, run_dashboard
from app.telemetry.dashboard import DASHBOARD_HTML

FIXTURE = r"""
const networkRecord={incident_id:'NET-example',protocol:'network',source_id:'net-a',boot_id:'boot-a',source_profile_revision:'profile-a',src_ip:'198.51.100.23',dst_ip:'192.0.2.10',title:'TCP 多端口探测',revision:2,updated_at:'2026-01-01T12:30:00Z',first_seen:'2026-01-01T12:00:00Z',last_seen:'2026-01-01T12:01:00Z',window_start_monotonic_us:3600000000,window_end_monotonic_us:7200000000,correlation_version:'network-v1',evidence_count:26,evidence_sha256:'evidence-digest',coverage:['observations_are_lower_bounds'],stale:false,active:true,rules:[{label:'TCP 多端口探测',rule_id:'network_tcp_multi_port_probe',rule_version:1,window_seconds:300,evidence_count:26,distinct_dst_ports:[22,80,443]}],assessment:{version:'score-v1',score:35,priority:'P3',surfaced:true,reasons:[{reason:'多端口',criteria:'300 秒内',points:35}],note:'探测模式不证明入侵成功'}};
const networkFixture={enabled:true,analysis_enabled:true,coverage:[],expired_events:0,capacity_available:true,exhausted:[],storage_bytes:1048576,limits:{storage_bytes:268435456},sources:[{source_id:'net-a',hostname:'fixture.invalid',status:'current',accepted_total:26,rejected_total:0}],analysis:{last_run:new Date().toISOString(),pending:false,analyzed_input_records:26,missing_raw_records:0,coverage_issues:[],source_coverage:[]}};
const networkEvent={source_id:'net-a',boot_id:'boot-a',source_profile_revision:'profile-a',src_ip:'198.51.100.23',dst_ip:'192.0.2.10',journal_realtime_us:1767268800000000,journal_monotonic_us:3600000000,src_port:43210,dst_port:443,protocol:'TCP',tcp_flags:['SYN'],direction:'inbound',observation_point:'local_input',ingress_interface:'ens3',final_outcome:'unknown',coverage:['logging_limits_unknown']};
const dialog=$('network-dialog');dialog.showModal=()=>{dialog.open=true;};dialog.close=()=>{dialog.open=false;dialog.listeners.close();};
route=path=>{
 if(path==='/api/network/status')return response(networkFixture);
 if(path.startsWith('/api/network/incidents?')){const q=new URLSearchParams(path.split('?')[1]);return response({items:[{...networkRecord,title:'page-'+q.get('page'),dst_ip:q.get('page')==='2'?'192.0.2.20':networkRecord.dst_ip}],page:Number(q.get('page')),total_pages:2,total:51});}
 if(path.includes('/evidence?')){const q=new URLSearchParams(path.split('?')[1]);return response({incident_id:networkRecord.incident_id,revision:Number(q.get('revision')),items:[{...networkEvent,dst_port:q.get('page')==='2'?444:443}],page:Number(q.get('page')),total_pages:2,total:26});}
 if(path==='/api/network/incidents/NET-example')return response(networkRecord);
 if(path==='/api/network/incidents/NET-example?revision=1')return response({...networkRecord,revision:1});
 throw new Error('Unexpected path '+path);
};
$('network-focus').value='all';
"""


def test_network_has_independent_accessible_table_dialog_and_no_unsafe_claims():
    html = ControlsHTML()
    html.feed(DASHBOARD_HTML)
    assert not html.duplicates
    assert html.elements['workspace-tab-network'][1]['aria-controls'] == 'workspace-network'
    assert html.elements['workspace-network'][1]['role'] == 'tabpanel'
    assert html.elements['network-dialog'][0] == 'dialog'
    assert html.elements['network-evidence'][0] == 'tbody'
    assert html.elements['network-source'][0] == 'select'
    assert html.elements['network-tab-evidence'][1]['aria-controls'] == 'network-pane-evidence'
    assert 'hidden' in html.elements['network-pane-evidence'][1]
    assert '没有事件也不代表安全或完整覆盖' in DASHBOARD_HTML
    assert '拒绝相关日志标签不证明最终防火墙处置结果' in DASHBOARD_HTML
    assert '暂不纳入每日简报' in DASHBOARD_HTML


def test_network_pages_and_filters_are_independent_and_read_only():
    run_dashboard(FIXTURE + r"""
currentSource='ssh-only';await selectWorkspace('network');assert.equal($('source-filter').disabled,true);
assert.match($('network-rows').textContent,/192.0.2.10/);
await $('network-next').listeners.click();assert.match($('network-rows').textContent,/192.0.2.20/);assert.match($('network-page').textContent,/第 2 \/ 2 页/);
$('network-source').value='net-a';$('network-focus').value='stale';await $('network-focus').listeners.change();
assert.match(calls[calls.length-1].path,/page=1&limit=50&focus=stale&source_id=net-a/);
assert.equal(calls.every(c=>c.path.startsWith('/api/network/')&&(c.options.method||'GET')==='GET'),true);
setWorkspace('incidents');assert.equal($('source-filter').disabled,false);
""")


def test_failed_or_malformed_page_preserves_rows_and_confirmed_page():
    run_dashboard(FIXTURE + r"""
await loadNetwork(2);const normal=route;
route=path=>path.startsWith('/api/network/incidents?')?({ok:false,status:503,json:async()=>({})}):normal(path);
await loadNetwork(1);assert.match($('network-rows').textContent,/192.0.2.20/);assert.match($('network-page').textContent,/第 2 \/ 2 页/);assert.match($('network-status').textContent,/已保留.*可能不符合新筛选/);
route=path=>path.startsWith('/api/network/incidents?')?response({items:[networkRecord,{...networkRecord,assessment:null}],page:1,total_pages:1,total:2}):normal(path);
await loadNetwork(1);assert.match($('network-rows').textContent,/192.0.2.20/);assert.equal($('network-rows').children.length,1);
route=path=>path.startsWith('/api/network/incidents?')?response({items:[networkRecord],page:2,total_pages:2,total:51}):normal(path);
await loadNetwork(1);assert.match($('network-status').textContent,/返回异常/);
route=path=>path.startsWith('/api/network/incidents?')?response({items:[networkRecord],page:1,total_pages:1,total:1}):normal(path);
await loadNetwork(2);assert.match($('network-page').textContent,/第 1 \/ 1 页/);
""")


def test_older_responses_cannot_replace_latest_rows_or_disabled_state():
    run_dashboard(FIXTURE + r"""
let finish;const normal=route;
route=path=>path.startsWith('/api/network/incidents?')?new Promise(resolve=>{finish=()=>resolve(response({items:[],page:1,total_pages:1,total:0}));}):normal(path);
const pending=loadNetwork(1);for(let i=0;i<15;i++)await Promise.resolve();assert.equal($('network-next').disabled,true);
route=normal;await loadNetwork(2);finish();await pending;assert.match($('network-rows').textContent,/192.0.2.20/);
route=path=>path==='/api/network/status'?new Promise(resolve=>{finish=()=>resolve(response(networkFixture));}):normal(path);
const old=loadNetwork();for(let i=0;i<10;i++)await Promise.resolve();route=()=>response({enabled:false});await loadNetwork();finish();await old;
assert.match($('network-health').textContent,/没有在线网络检测覆盖/);assert.match($('network-rows').textContent,/尚未配置/);assert.equal($('network-prev').disabled,true);assert.equal($('network-next').disabled,true);
""")


def test_empty_findings_do_not_hide_source_quality_or_analysis_gaps():
    run_dashboard(FIXTURE + r"""
networkFixture.sources[0].status='degraded';networkFixture.analysis.pending=true;networkFixture.analysis.missing_raw_records=3;networkFixture.analysis.last_error='fixture failure';
networkFixture.analysis.source_coverage=[{source_id:'net-a',coverage:['journal_cursor_unavailable']}];networkFixture.analysis.coverage_issues=[{source_id:'net-a',coverage:['expired_context']}];
const normal=route;route=path=>path.startsWith('/api/network/incidents?')?response({items:[],page:1,total_pages:1,total:0}):normal(path);
await loadNetwork();assert.match($('network-rows').textContent,/没有命中不代表安全/);assert.match($('network-health').textContent,/有待分析记录.*3 条原始记录/s);assert.match($('network-health').textContent,/fixture failure/);
assert.match($('network-sources').textContent,/历史可能有缺口/);assert.match($('network-coverage').textContent,/关联上下文已过期/);assert.match($('network-quality-summary').textContent,/1 个采集异常.*1 个来源有覆盖限制.*1 个不完整窗口/);assert.notEqual($('network-source-quality').open,true);
assert.equal($('network-next').disabled,true);
""")


def test_drawer_pins_revision_and_evidence_renders_literal_fields_and_realtime_only():
    run_dashboard(FIXTURE + r"""
let restored=0;document.activeElement={isConnected:true,focus:()=>restored++};networkEvent.ingress_interface='<img src=x onerror=alert(1)>';
await showNetworkIncident('NET-example',1);assert.equal(dialog.open,true);assert.equal(networkDetail.revision,1);assert.match($('network-revision').textContent,/版本 1 \/ 2 · 历史快照/);
assert.match($('network-fields').textContent,/不是攻击概率/);assert.match($('network-provenance').textContent,/3600000000 — 7200000000（不是日历时间）/);
assert.match($('network-evidence').textContent,/<img src=x onerror=alert\(1\)>/);assert.equal($('network-evidence').children[0].children[4].children.length,0);
setNetworkDetailTab('evidence');assert.equal($('network-pane-overview').hidden,true);
await loadNetworkEvidence(2);assert.match(calls[calls.length-1].path,/revision=1&page=2/);assert.match($('network-evidence').textContent,/444/);
dialog.close();assert.equal(networkDetail,null);assert.equal(restored,1);
assert.equal(calls.every(c=>c.path.startsWith('/api/network/')&&(c.options.method||'GET')==='GET'),true);
""")


def test_cross_revision_or_wrong_source_evidence_cannot_replace_visible_page():
    run_dashboard(FIXTURE + r"""
await showNetworkIncident('NET-example',1);await loadNetworkEvidence(2);const normal=route;
route=path=>path.includes('/evidence?')?response({incident_id:'NET-other',revision:1,items:[networkEvent],page:1,total_pages:2,total:26}):normal(path);
await loadNetworkEvidence(1);assert.match($('network-evidence').textContent,/444/);assert.match($('network-evidence-page').textContent,/第 2 \/ 2 页/);assert.match($('network-evidence-status').textContent,/不匹配/);
route=path=>path.includes('/evidence?')?response({incident_id:'NET-example',revision:1,items:[networkEvent,{...networkEvent,source_profile_revision:'wrong'}],page:1,total_pages:2,total:26}):normal(path);
await loadNetworkEvidence(1);assert.equal($('network-evidence').children.length,1);assert.match($('network-evidence').textContent,/444/);assert.match($('network-evidence-status').textContent,/来源不匹配/);
""")


def test_late_evidence_or_detail_does_not_reopen_closed_drawer_or_mix_versions():
    run_dashboard(FIXTURE + r"""
let finish;const normal=route;route=path=>path.includes('/evidence?')?new Promise(resolve=>{finish=()=>resolve(normal(path));}):normal(path);
const pending=showNetworkIncident('NET-example',1);for(let i=0;i<20;i++)await Promise.resolve();dialog.close();route=normal;await showNetworkIncident('NET-example',2);finish();await pending;
assert.equal(networkDetail.revision,2);assert.match($('network-revision').textContent,/版本 2 \/ 2/);assert.equal($('network-evidence-retry').disabled,false);
route=path=>path==='/api/network/incidents/NET-example'?new Promise(resolve=>{finish=()=>resolve(normal(path));}):normal(path);
const detailPending=showNetworkIncident('NET-example',1);for(let i=0;i<10;i++)await Promise.resolve();dialog.close();finish();await detailPending;assert.equal(networkDetail,null);assert.equal(dialog.open,false);
""")


def test_notification_pins_event_revision_and_collection_is_not_an_attack():
    run_dashboard(FIXTURE + r"""
renderNotifications({items:[{id:1,kind:'network_incident',payload:{...networkRecord,revision:1},delivered_at:1800000000,read_at:null},{id:2,kind:'network_collection',payload:{title:'网络采集异常',source_id:'net-a',conditions:['stale','rejected_records'],note:'<img src=x onerror=alert(1)>',active:true},delivered_at:1800000001,read_at:1}],page:1,total_pages:1,total:2,unread:1,pending:0,retrying:0,health:[],enabled:true});
assert.match($('notification-rows').textContent,/网络事件.*版本 1/s);assert.match($('notification-rows').textContent,/网络采集.*采集心跳过期.*部分记录被拒收.*不代表发现攻击/s);
const content=$('notification-rows').children[1].children[2].children[1];assert.match(content.textContent,/<img src=x onerror=alert\(1\)>/);assert.equal(content.children.length,0);
await $('notification-rows').children[0].children[2].children[2].listeners.click();assert.equal(networkDetail.revision,1);
""")


def test_keyboard_tabs_update_focus_and_no_ai_or_response_controls_are_added():
    run_dashboard(FIXTURE + r"""
let focused='';for(const name of ['overview','evidence'])$('network-tab-'+name).focus=()=>{focused=name;};
$('network-tab-overview').listeners.keydown({key:'End',preventDefault(){}});assert.equal(focused,'evidence');assert.equal($('network-pane-overview').hidden,true);assert.equal($('network-tab-evidence').tabIndex,0);
$('network-tab-evidence').listeners.keydown({key:'Home',preventDefault(){}});assert.equal(focused,'overview');assert.equal($('network-pane-evidence').hidden,true);assert.equal(calls.length,0);
""")


def test_actual_storage_contract_shows_retention_capacity_and_bounded_quality_detail():
    run_dashboard(FIXTURE + r"""
networkFixture.coverage=['event_history_expired','event_retention_incomplete'];networkFixture.expired_events=12;networkFixture.capacity_available=false;networkFixture.exhausted=['receipts','storage'];
networkFixture.analysis.coverage_issues=Array.from({length:50},(_,i)=>({source_id:'source-'+i,coverage:['raw_history_expired_before_analysis']}));
networkFixture.analysis.source_coverage=[{source_id:'net-a',coverage:['collection_backlog_observed','monotonic_hour_review_bucket']}];
await loadNetwork();assert.match($('network-health').textContent,/已过期 12 条原始事件/);assert.match($('network-health').textContent,/1.0 \/ 256.0 MiB/);assert.match($('network-health').textContent,/容量已耗尽：去重凭据数、存储空间/);
assert.match($('network-coverage').textContent,/至少 50 个关联窗口/);assert.match($('network-coverage').textContent,/仅展示前 5 个窗口/);assert.doesNotMatch($('network-coverage').textContent,/source-5/);
assert.match($('network-sources').textContent,/曾观测到采集积压/);assert.notEqual($('network-source-quality').open,true);
""")


# Optional real-browser acceptance. The default suite needs only Node for the
# inert DOM tests above; set RISKOPS_PLAYWRIGHT_MODULE to run installed Playwright.
BROWSER_RUNNER = r"""
const assert=require('node:assert/strict');
const {chromium}=require(process.env.RISKOPS_PLAYWRIGHT_MODULE);
(async()=>{
 const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);
 const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));
 const browser=await chromium.launch({executablePath:process.env.RISKOPS_BROWSER_EXECUTABLE,headless:true,args:['--no-sandbox','--disable-gpu','--disable-dev-shm-usage']});
 const reports=[];
 try{for(const [name,viewport] of [['desktop',{width:1440,height:1000}],['mobile',{width:390,height:844}]]){
  const context=await browser.newContext({viewport,serviceWorkers:'block'}),errors=[],calls=[],writes=[],external=[];
  const {networkRecord,networkFixture,networkEvent}=new Function(input.fixture+';return {networkRecord,networkFixture,networkEvent};')();
  networkFixture.sources[0].status='degraded';networkFixture.analysis.missing_raw_records=1;
  networkFixture.analysis.coverage_issues=[{source_id:'net-a',coverage:['raw_history_expired_before_analysis']}];networkFixture.analysis.source_coverage=[{source_id:'net-a',coverage:['journal_cursor_unavailable']}];
  networkFixture.coverage=['event_history_expired'];networkFixture.expired_events=7;networkFixture.capacity_available=false;networkFixture.exhausted=['receipts'];
  networkEvent.ingress_interface='<img src=x onerror=alert(1)>';
  let disabled=false,failList=false;
  await context.addInitScript(()=>sessionStorage.setItem('riskops-workspace','network'));
  await context.route('**/*',async route=>{
   const req=route.request(),url=new URL(req.url()),path=url.pathname;calls.push(path+url.search);
   if(url.origin!=='http://network-ui.invalid'){external.push(req.url());return route.abort();}
   if(req.method()!=='GET'){writes.push(req.method());return route.abort();}
   if(path==='/')return route.fulfill({contentType:'text/html',body:input.html});
   let data;
   if(path==='/api/console/bootstrap')data={state:'disabled'};
   else if(path==='/api/summary')data={sources:[],totals:{events:0,ssh_failures:0,ssh_successes:0,incidents:0}};
   else if(path==='/api/network/status')data=disabled?{enabled:false}:networkFixture;
   else if(path==='/api/network/incidents'){
    if(failList)return route.fulfill({status:503,contentType:'application/json',body:'{}'});
    data={items:[networkRecord],page:Number(url.searchParams.get('page')),total_pages:2,total:51};
   }else if(path.endsWith('/evidence'))data={incident_id:networkRecord.incident_id,revision:Number(url.searchParams.get('revision')),items:[networkEvent],page:Number(url.searchParams.get('page')),total_pages:2,total:26};
   else if(path==='/api/network/incidents/NET-example')data={...networkRecord,revision:Number(url.searchParams.get('revision')||2)};
   else throw new Error('Unexpected '+path);
   return route.fulfill({contentType:'application/json',body:JSON.stringify(data)});
  });
  const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));
  await page.goto('http://network-ui.invalid/');await page.locator('#network-rows').getByRole('button',{name:'查看详情',exact:true}).waitFor();
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  assert.match(await page.locator('#network-health').textContent(),/检测覆盖不完整/);
  assert.match(await page.locator('#network-health').textContent(),/已过期 7 条原始事件/);
  assert.match(await page.locator('#network-health').textContent(),/容量已耗尽/);
  assert.equal(await page.locator('#network-source-quality').evaluate(el=>el.open),false);
  await page.locator('#network-quality-summary').click();
  assert.match(await page.locator('#network-sources').textContent(),/历史可能有缺口/);
  await page.locator('#network-quality-summary').click();
  await page.locator('#network-next').click();await page.waitForFunction(()=>document.getElementById('network-page').textContent.includes('第 2 / 2 页'));
  failList=true;await page.locator('#network-refresh').click();await page.waitForFunction(()=>document.getElementById('network-status').textContent.includes('已保留'));failList=false;
  await page.locator('#network-rows').getByRole('button',{name:'查看详情',exact:true}).click();await page.locator('#network-dialog[open]').waitFor();await page.waitForFunction(()=>document.getElementById('network-revision').textContent.includes('版本 2 / 2'));
  await page.locator('#network-revision-prev').click();await page.waitForFunction(()=>document.getElementById('network-revision').textContent.includes('版本 1 / 2'));
  await page.locator('#network-tab-evidence').click();await page.waitForFunction(()=>document.getElementById('network-evidence').textContent.includes('<img'));
  assert.equal(await page.locator('#network-evidence img').count(),0);
  await page.locator('#network-evidence-next').click();await page.waitForFunction(()=>document.getElementById('network-evidence-page').textContent.includes('第 2 / 2 页'));
  assert(calls.includes('/api/network/incidents/NET-example/evidence?revision=1&page=2&limit=25'));
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  const box=await page.locator('#network-dialog').boundingBox();assert(box.x>=0&&box.x+box.width<=viewport.width+1&&box.height<=viewport.height);
  await page.keyboard.press('Escape');await page.locator('#network-dialog').waitFor({state:'hidden'});
  assert.equal(await page.locator('#network-rows').getByRole('button',{name:'查看详情',exact:true}).evaluate(el=>el===document.activeElement),true);
  disabled=true;await page.locator('#network-refresh').click();await page.waitForFunction(()=>document.getElementById('network-health').textContent.includes('尚未配置'));
  assert.equal(await page.locator('#network-next').isDisabled(),true);assert.deepEqual(errors,[]);assert.deepEqual(writes,[]);assert.deepEqual(external,[]);
  reports.push({viewport:name,passed:true,page_errors:errors.length,writes:writes.length,external_requests:external.length});await context.close();
 }}finally{await browser.close();}
 console.log(JSON.stringify(reports));
})().catch(e=>{console.error(e.stack);process.exitCode=1;});
"""


def test_optional_real_browser_network_workspace():
    import json
    import os
    import shutil
    import subprocess

    import pytest

    node = shutil.which('node')
    if not node or not os.environ.get('RISKOPS_PLAYWRIGHT_MODULE'):
        pytest.skip('Set RISKOPS_PLAYWRIGHT_MODULE for synthetic desktop/mobile acceptance')
    result = subprocess.run(
        [node, '-e', BROWSER_RUNNER],
        input=json.dumps({'html': DASHBOARD_HTML, 'fixture': FIXTURE.split("const dialog=")[0]}),
        text=True, encoding='utf-8', capture_output=True, timeout=150,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [
        {'viewport': name, 'passed': True, 'page_errors': 0, 'writes': 0, 'external_requests': 0}
        for name in ('desktop', 'mobile')
    ]
