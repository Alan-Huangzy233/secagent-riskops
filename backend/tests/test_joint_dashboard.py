"""Shipped joint UI with inert HTTP, pinned revisions and real-browser acceptance."""
from app.telemetry.dashboard import DASHBOARD_HTML
from test_dashboard_control import ControlsHTML, run_dashboard

FIXTURE = r"""
const jointID='JOINT-'+'a'.repeat(32),jointNetID='NET-'+'b'.repeat(32);
const jointRow={case_id:jointID,revision:1,publish_generation:1,asset_id:'asset-a',peer_ip:'198.51.100.23',association_state:'linked',window_start_us:1767267000000000,window_end_us:1767270600000000,temporal_available:true,network_count:30,ssh_count:5,saved_count:26,observed_count:35,timeline_complete:false};
const jointStatus={enabled:true,state:'ready',store_id:'fixture',query_epoch:'one',generation:1,catalog_min_seq:7,assets:[{asset_id:'asset-a'}],discovery:{complete:true,scanned_count:2},cycle:{attempted_complete:true,all_items_refreshed:true,counts:{failed:0}},capacity:{},error:null};
const jointEvent={kind:'ssh',event_id:'ssh-event',event_ts_us:1767268800000000,source_id:'ssh-a',src_ip:'198.51.100.23',event_type:'auth_failure',account:'<img src=x onerror=alert(1)>',incident_refs:[{incident_id:'SSH-original',canonical_incident_id:'SSH-canonical'}]};
const jointProjection={case_id:jointID,state:'linked',asset_id:'asset-a',anchor:{incident_id:jointNetID,revision:3,source_id:'net-a',src_ip:'198.51.100.23',producer_id:'fixture'},window:{start_us:jointRow.window_start_us,end_us:jointRow.window_end_us},temporal_association_available:true,timeline:[jointEvent],timeline_complete:false,observed_evidence_count:35,reasons:['explicit_asset_mapping','same_observed_peer'],uncertainties:['timeline_truncated','shared_ip_does_not_establish_identity'],counts:{network:{'net-a':30},ssh:{'ssh-a':{evidence:5}}},mapping_sha256:'map',evidence_sha256:'evidence'};
const jointResult={case_id:jointID,revision:1,projection:jointProjection,first_read_metadata:{network_observation:{started_at:'2026-01-01T12:00:00Z',finished_at:'2026-01-01T12:00:01Z'},ssh_observation:{state:'read',started_at:'2026-01-01T12:00:01Z',finished_at:'2026-01-01T12:00:02Z'}},current:{revision:2,refresh_state:'unavailable',last_success:'2026-01-01T12:00:02Z',error:'source_busy'}};
const jointDialog=$('joint-dialog');jointDialog.showModal=()=>{jointDialog.open=true;};jointDialog.close=()=>{jointDialog.open=false;jointDialog.listeners.close();};
route=path=>{
 if(path==='/api/joint/status')return response(jointStatus);
 if(path.startsWith('/api/joint/cases?')){const q=new URLSearchParams(path.split('?')[1]);return response({items:[{...jointRow,asset_id:q.get('page')==='2'?'asset-page-two':jointRow.asset_id}],page:Number(q.get('page')),total_pages:2,total:21,snapshot:q.get('snapshot')||'snapshot-one',current_generation:jointStatus.generation});}
 if(path.includes('/timeline?')){const q=new URLSearchParams(path.split('?')[1]);return response({case_id:jointID,revision:Number(q.get('revision')),items:[{...jointEvent,event_type:q.get('page')==='2'?'auth_success':'auth_failure'}],page:Number(q.get('page')),total_pages:2,total_saved:26,observed_count:35,timeline_complete:false});}
 if(path.startsWith('/api/joint/cases/'+jointID+'?')){const q=new URLSearchParams(path.split('?')[1]);return response({...jointResult,revision:Number(q.get('revision'))});}
 throw new Error('Unexpected '+path);
};
"""


def test_joint_html_has_independent_accessible_table_and_default_off_boundary():
    html = ControlsHTML()
    html.feed(DASHBOARD_HTML)
    assert not html.duplicates
    assert html.elements['workspace-tab-joint'][1]['aria-controls'] == 'workspace-joint'
    assert html.elements['joint-dialog'][0] == 'dialog'
    for name in ('overview', 'timeline', 'sources'):
        assert html.elements['joint-tab-'+name][1]['aria-controls'] == 'joint-pane-'+name
    assert 'hidden' in html.elements['joint-pane-timeline'][1]
    assert '这里的刷新只读取已有结果' in DASHBOARD_HTML
    assert '不代表同一攻击者或入侵成功' in DASHBOARD_HTML


def test_pinned_pages_filters_are_independent_and_get_only():
    run_dashboard(FIXTURE + r"""
currentSource='ssh-other';await selectWorkspace('joint');assert.equal($('source-filter').disabled,true);
assert.equal(jointSnapshot,'snapshot-one');await $('joint-next').listeners.click();assert.match($('joint-rows').textContent,/asset-page-two/);
assert.match(calls[calls.length-1].path,/page=2&limit=20&snapshot=snapshot-one/);
jointStatus.generation=2;await loadJoint();assert.equal(jointPage,2);assert.match($('joint-new').textContent,/有新观察/);
$('joint-ip').value='198.51.100.23';$('joint-state').value='partial';$('joint-asset').value='asset-a';await $('joint-search').listeners.submit({preventDefault(){}});
const q=new URLSearchParams(calls[calls.length-1].path.split('?')[1]);assert.equal(q.get('page'),'1');assert.equal(q.get('snapshot'),null);assert.equal(q.get('ip'),'198.51.100.23');assert.equal(q.get('asset_id'),'asset-a');assert.equal(q.get('state'),'partial');assert.equal(q.get('source_id'),null);
setWorkspace('incidents');assert.equal($('source-filter').disabled,false);setWorkspace('joint');assert.equal(jointFilters.ip,'198.51.100.23');
assert.equal(calls.every(c=>c.path.startsWith('/api/joint/')&&(c.options.method||'GET')==='GET'),true);
""")


def test_disabled_does_not_fetch_cases_and_failures_preserve_only_same_query():
    run_dashboard(FIXTURE + r"""
route=()=>response({enabled:false});await loadJoint();assert.equal(calls.length,1);assert.match($('joint-rows').textContent,/尚未配置/);assert.equal($('joint-next').disabled,true);
""")
    run_dashboard(FIXTURE + r"""
await loadJoint(2);const normal=route;route=path=>path.startsWith('/api/joint/cases?')?({ok:false,status:503}):normal(path);
await loadJoint();assert.match($('joint-rows').textContent,/asset-page-two/);assert.match($('joint-page').textContent,/第 2/);assert.match($('joint-status').textContent,/已保留/);
$('joint-ip').value='198.51.100.0/24';route=path=>path.startsWith('/api/joint/cases?')?({ok:false,status:422}):normal(path);await submitJointSearch();
assert.doesNotMatch($('joint-rows').textContent,/asset-page-two/);assert.match($('joint-status').textContent,/查询条件无效/);assert.equal($('joint-next').disabled,true);
""")


def test_invalid_local_dates_cancel_old_queries_and_do_not_relabel_rows():
    run_dashboard(FIXTURE + r"""
await loadJoint();let finish;const normal=route;route=path=>path.startsWith('/api/joint/cases?')?new Promise(resolve=>{finish=()=>resolve(normal(path));}):normal(path);
const pending=loadJoint(2);for(let i=0;i<15;i++)await Promise.resolve();$('joint-start').value='2026-02-01T00:00:00';$('joint-end').value='2026-01-01T00:00:00';await submitJointSearch();finish();await pending;
assert.match($('joint-status').textContent,/开始时间/);assert.doesNotMatch($('joint-rows').textContent,/asset-a|asset-page-two/);assert.equal($('joint-next').disabled,true);
""")


def test_snapshot_mismatch_or_refresh_required_cannot_replace_confirmed_page():
    run_dashboard(FIXTURE + r"""
await loadJoint(2);const normal=route;
route=path=>path.startsWith('/api/joint/cases?')?response({items:[jointRow],page:1,total_pages:2,total:21,snapshot:'changed',current_generation:4}):normal(path);
await loadJoint(1);assert.match($('joint-status').textContent,/快照/);assert.match($('joint-rows').textContent,/asset-page-two/);
route=path=>path.startsWith('/api/joint/cases?')?({ok:false,status:409}):normal(path);await loadJoint();assert.match($('joint-status').textContent,/读取最新观察/);
route=normal;await $('joint-latest').listeners.click();assert.equal(jointPage,1);assert.equal(new URLSearchParams(calls[calls.length-1].path.split('?')[1]).get('snapshot'),null);
""")


def test_older_list_or_status_cannot_replace_new_query_or_disabled_state():
    run_dashboard(FIXTURE + r"""
let finish;const normal=route;route=path=>path.startsWith('/api/joint/cases?')?new Promise(resolve=>{finish=()=>resolve(normal(path));}):normal(path);
const pending=loadJoint(1);for(let i=0;i<15;i++)await Promise.resolve();route=normal;await loadJoint(2);finish();await pending;assert.match($('joint-rows').textContent,/asset-page-two/);
route=path=>path==='/api/joint/status'?new Promise(resolve=>{finish=()=>resolve(response(jointStatus));}):normal(path);
const old=loadJoint();for(let i=0;i<10;i++)await Promise.resolve();route=()=>response({enabled:false});await loadJoint();finish();await old;assert.match($('joint-health').textContent,/尚未配置/);assert.equal(jointSnapshot,null);
""")


def test_partial_recovery_and_failure_states_are_not_reported_complete():
    run_dashboard(FIXTURE + r"""
jointStatus.state='revalidation_pending';jointStatus.revalidation_pending=true;jointStatus.discovery={complete:false,scanned_count:4,error:'source_busy'};jointStatus.cycle={attempted_complete:true,all_items_refreshed:false,counts:{failed:1}};jointStatus.error='joint_capacity_exceeded';
const normal=route;route=path=>path.startsWith('/api/joint/cases?')?response({items:[],page:1,total_pages:1,total:0,snapshot:'empty',current_generation:1}):normal(path);
await loadJoint();assert.match($('joint-health').textContent,/来源待重新核验/);assert.match($('joint-health').textContent,/本轮未完成/);assert.match($('joint-health').textContent,/部分条目未成功/);assert.match($('joint-health').textContent,/达到容量上限/);assert.match($('joint-rows').textContent,/不能据此判断安全/);
""")


def test_details_pin_revision_lazy_timeline_and_escape_observed_strings():
    run_dashboard(FIXTURE + r"""
let restored=0;document.activeElement={isConnected:true,focus:()=>restored++};await showJointCase(jointID,1);
assert.equal(calls.length,1);assert.match(calls[0].path,/revision=1$/);assert.equal(jointDialog.open,true);assert.match($('joint-revision').textContent,/历史观察/);assert.match($('joint-freshness').textContent,/最近刷新失败/);assert.match($('joint-provenance').textContent,/无持久版本/);
await setJointTab('timeline');assert.match($('joint-timeline').textContent,/<img src=x onerror=alert\(1\)>/);assert.equal($('joint-timeline').children[0].children[2].children.length,0);
assert.match($('joint-timeline-page').textContent,/保存 26 \/ 观察 35.*截断/);await loadJointTimeline(2);assert.match(calls[calls.length-1].path,/revision=1&page=2&limit=25/);assert.match($('joint-timeline').textContent,/认证成功/);
jointDialog.close();assert.equal(jointDetail,null);assert.equal(restored,1);assert.equal(calls.every(c=>(c.options.method||'GET')==='GET'),true);
""")


def test_timeline_rejects_wrong_revision_source_or_identity_without_mixing_rows():
    run_dashboard(FIXTURE + r"""
await showJointCase(jointID,1);await loadJointTimeline(2);const normal=route;
for(const change of [{case_id:'wrong'},{revision:2},{items:[{...jointEvent,source_id:'wrong'}]}]){
 route=path=>path.includes('/timeline?')?response({case_id:jointID,revision:1,items:[jointEvent],page:1,total_pages:2,total_saved:26,observed_count:35,timeline_complete:false,...change}):normal(path);
 await loadJointTimeline(1);assert.match($('joint-timeline').textContent,/认证成功/);assert.match($('joint-timeline-status').textContent,/不匹配/);assert.equal(jointTimelinePage,2);
}
""")


def test_closed_or_new_revision_drawer_ignores_delayed_detail_and_timeline():
    run_dashboard(FIXTURE + r"""
let finish;const normal=route;route=()=>new Promise(resolve=>{finish=()=>resolve(response(jointResult));});
const old=showJointCase(jointID,1);for(let i=0;i<8;i++)await Promise.resolve();jointDialog.close();finish();await old;assert.equal(jointDetail,null);assert.equal(jointDialog.open,false);
route=normal;await showJointCase(jointID,1);route=path=>path.includes('/timeline?')?new Promise(resolve=>{finish=()=>resolve(normal(path));}):normal(path);
const timeline=loadJointTimeline(1);for(let i=0;i<8;i++)await Promise.resolve();route=normal;await showJointCase(jointID,2);finish();await timeline;assert.equal(jointDetail.revision,2);assert.equal($('joint-timeline').children.length,0);
""")


def test_detail_keyboard_tabs_and_current_ssh_pivot_are_read_only():
    run_dashboard(FIXTURE + r"""
let focused='';for(const name of ['overview','timeline','sources'])$('joint-tab-'+name).focus=()=>{focused=name;};
$('joint-tab-overview').listeners.keydown({key:'End',preventDefault(){}});assert.equal(focused,'sources');assert.equal($('joint-pane-overview').hidden,true);
$('joint-tab-sources').listeners.keydown({key:'Home',preventDefault(){}});assert.equal(focused,'overview');assert.equal(calls.length,0);
await showJointCase(jointID,1);const normal=route;route=path=>path.startsWith('/api/incidents?')?response({items:[],page:1,total_pages:1,total:0}):normal(path);
currentSource='wrong';incidentTriage='pending';await $('joint-source-actions').children[1].listeners.click();assert.equal(workspaceView,'incidents');assert.equal(jointDialog.open,false);assert.equal(currentSource,'');assert.equal(incidentTriage,'all');assert.equal(incidentFilters.ip,jointProjection.anchor.src_ip);assert.equal(calls.some(c=>c.path.includes('/ai/')||c.path.includes('/controls')),false);
""")


BROWSER_RUNNER = r"""
const assert=require('node:assert/strict');
const {chromium}=require(process.env.RISKOPS_PLAYWRIGHT_MODULE);
(async()=>{
 const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));
 const browser=await chromium.launch({executablePath:process.env.RISKOPS_BROWSER_EXECUTABLE,headless:true,args:['--no-sandbox','--disable-gpu','--disable-dev-shm-usage']});
 const reports=[];
 try{for(const [name,viewport] of [['desktop',{width:1440,height:1000}],['mobile',{width:390,height:844}]]){
  const context=await browser.newContext({viewport,serviceWorkers:'block'}),calls=[],writes=[],external=[],errors=[];
  const {jointID,jointRow,jointStatus,jointEvent,jointResult}=new Function(input.fixture+';return {jointID,jointRow,jointStatus,jointEvent,jointResult};')();
  let disabled=false,holdNext=false,release=null;
  await context.addInitScript(()=>sessionStorage.setItem('riskops-workspace','joint'));
  await context.route('**/*',async route=>{
   const req=route.request(),url=new URL(req.url()),path=url.pathname;calls.push(path+url.search);
   if(url.origin!=='http://joint-ui.invalid'){external.push(req.url());return route.abort();}
   if(req.method()!=='GET'){writes.push(req.method());return route.abort();}
   if(path==='/')return route.fulfill({contentType:'text/html',headers:{'Content-Security-Policy':input.csp},body:input.html});
   let data;
   if(path==='/api/console/bootstrap')data={state:'disabled'};
   else if(path==='/api/summary')data={sources:[],totals:{events:0,ssh_failures:0,ssh_successes:0,incidents:0}};
   else if(path==='/api/joint/status')data=disabled?{enabled:false}:jointStatus;
   else if(path==='/api/joint/cases'){
    const q=url.searchParams;data={items:[{...jointRow,peer_ip:q.get('ip')||jointRow.peer_ip,asset_id:'<img src=x onerror=alert(1)>'}],page:Number(q.get('page')),total_pages:2,total:21,snapshot:q.get('snapshot')||'snapshot-one',current_generation:jointStatus.generation};
    if(holdNext){holdNext=false;await new Promise(resolve=>{release=resolve;});}
   }else if(path.endsWith('/timeline'))data={case_id:jointID,revision:Number(url.searchParams.get('revision')),items:[{...jointEvent,event_type:url.searchParams.get('page')==='2'?'auth_success':'auth_failure'}],page:Number(url.searchParams.get('page')),total_pages:2,total_saved:26,observed_count:35,timeline_complete:false};
   else if(path==='/api/joint/cases/'+jointID)data={...jointResult,revision:Number(url.searchParams.get('revision'))};
   else throw new Error('Unexpected '+path);
   await route.fulfill({contentType:'application/json',body:JSON.stringify(data)}).catch(error=>{if(!/closed|canceled|cancelled|interception/i.test(error.message))throw error;});
  });
  const page=await context.newPage();page.on('pageerror',error=>errors.push(error.message));
  await page.goto('http://joint-ui.invalid/');await page.locator('#joint-rows').getByRole('button',{name:'查看详情',exact:true}).waitFor();
  assert.equal(await page.locator('#source-filter').isDisabled(),true);assert.equal(await page.locator('#joint-rows img').count(),0);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await page.locator('#joint-next').click();await page.waitForFunction(()=>document.getElementById('joint-page').textContent.includes('第 2 / 2 页'));
  assert(calls.some(path=>path.includes('page=2&limit=20&snapshot=snapshot-one')));
  jointStatus.generation=2;await page.locator('#joint-refresh').click();await page.waitForFunction(()=>document.getElementById('joint-new').textContent.includes('有新观察'));
  assert.match(await page.locator('#joint-page').textContent(),/第 2/);
  await page.locator('#joint-rows').getByRole('button',{name:'查看详情',exact:true}).click();await page.waitForFunction(()=>document.getElementById('joint-revision').textContent.includes('历史观察'));
  assert.match(await page.locator('#joint-freshness').textContent(),/最近刷新失败/);
  await page.locator('#joint-tab-overview').focus();await page.keyboard.press('End');assert.equal(await page.locator('#joint-tab-sources').evaluate(el=>el===document.activeElement),true);
  await page.keyboard.press('ArrowLeft');await page.waitForFunction(()=>document.getElementById('joint-timeline').textContent.includes('<img'));
  assert.equal(await page.locator('#joint-timeline img').count(),0);assert.match(await page.locator('#joint-timeline-page').textContent(),/保存 26 \/ 观察 35.*截断/);
  await page.locator('#joint-timeline-next').click();await page.waitForFunction(()=>document.getElementById('joint-timeline').textContent.includes('认证成功'));
  assert(calls.includes('/api/joint/cases/'+jointID+'/timeline?revision=1&page=2&limit=25'));
  const box=await page.locator('#joint-dialog').boundingBox();assert(box.x>=0&&box.x+box.width<=viewport.width+1&&box.height<=viewport.height);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await page.keyboard.press('Escape');await page.locator('#joint-dialog').waitFor({state:'hidden'});assert.equal(await page.locator('#joint-rows').getByRole('button',{name:'查看详情',exact:true}).evaluate(el=>el===document.activeElement),true);
  holdNext=true;await page.locator('#joint-refresh').click();for(let i=0;i<100&&!release;i++)await new Promise(resolve=>setTimeout(resolve,10));assert(release);
  await page.locator('#joint-ip').fill('203.0.113.9');await page.locator('#joint-search').getByRole('button',{name:'查询案件',exact:true}).click();await page.waitForFunction(()=>document.getElementById('joint-rows').textContent.includes('203.0.113.9'));
  release();await page.waitForTimeout(80);assert.match(await page.locator('#joint-rows').textContent(),/203.0.113.9/);assert.doesNotMatch(await page.locator('#joint-rows').textContent(),/198.51.100.23/);
  disabled=true;await page.locator('#joint-refresh').click();await page.waitForFunction(()=>document.getElementById('joint-health').textContent.includes('尚未配置'));assert.equal(await page.locator('#joint-next').isDisabled(),true);
  assert.deepEqual(errors,[]);assert.deepEqual(writes,[]);assert.deepEqual(external,[]);
  reports.push({viewport:name,passed:true,page_errors:errors.length,writes:writes.length,external_requests:external.length});await context.close();
 }}finally{await browser.close();}
 console.log(JSON.stringify(reports));
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
"""


def test_optional_real_browser_joint_workspace():
    import json
    import os
    import shutil
    import subprocess

    import pytest

    from app.telemetry.dashboard import CONTENT_SECURITY_POLICY

    node = shutil.which('node')
    if not node or not os.environ.get('RISKOPS_PLAYWRIGHT_MODULE'):
        pytest.skip('Set RISKOPS_PLAYWRIGHT_MODULE for synthetic desktop/mobile acceptance')
    result = subprocess.run(
        [node, '-e', BROWSER_RUNNER],
        input=json.dumps({'html': DASHBOARD_HTML, 'csp': CONTENT_SECURITY_POLICY,
                          'fixture': FIXTURE.split("const jointDialog=")[0]}),
        text=True, encoding='utf-8', capture_output=True, timeout=150,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [
        {'viewport': name, 'passed': True, 'page_errors': 0, 'writes': 0, 'external_requests': 0}
        for name in ('desktop', 'mobile')
    ]
