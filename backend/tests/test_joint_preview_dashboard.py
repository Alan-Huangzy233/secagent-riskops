"""Local joint preview rendering, stale request isolation and inert browser checks."""
import json
import os
import shutil
import subprocess

import pytest

from app.telemetry.dashboard import CONTENT_SECURITY_POLICY, DASHBOARD_HTML
from test_dashboard_control import ControlsHTML, run_dashboard
from test_joint_dashboard import FIXTURE

PREVIEW_FIXTURE = r"""
const alias=(p,i)=>p+'-'+i.toString(16).padStart(24,'0');
const previewEvidence=Array.from({length:12},(_,i)=>({event_id:alias('E',i+1),offset_us:i*1000000,source:alias('S',i%2+1),asset:alias('A',1),peer:alias('P',1),...(i%2?{kind:'ssh',event_type:'auth_failure',account:i===1?null:alias('U',i)}:{kind:'network_tcp',destination:alias('D',1),dst_port:22+i,protocol:'TCP',direction:'local_input'})}));
const previewRefs=Object.fromEntries(previewEvidence.map(row=>[row.event_id,{kind:row.kind==='ssh'?'ssh':'network',source_id:row.kind==='ssh'?'ssh-a':'net-a',event_id:'<img src=x onerror=alert(1)>',incident_refs:row.kind==='ssh'?[{incident_id:'SSH-original',canonical_incident_id:'SSH-canonical'}]:[{incident_id:jointNetID,revision:3}]}]));
const previewData={dossier_version:'joint-local-envelope-v1',case:{dossier_version:'joint-v1',case_id:alias('J',1),revision:alias('R',1),kind:'network_ssh',asset:alias('A',1),peer:alias('P',1),association_state:'partial',review_state:'historical',input_complete:false,timeline_complete:false,summary_complete:false,coverage_complete:null,temporal_association_available:true,window_duration_us:3600000000,counts:{network:{observed:8,retained:7,included:6},ssh:{observed:8,retained:7,included:6}},limitations:['source_coverage_unknown','cross_store_not_atomic','shared_ip_not_identity','clock_alignment_unknown','retained_incidents_only','observed_counts_lower_bounds','timeline_truncated','summary_truncated','projection_input_incomplete'],evidence:previewEvidence},local_refs:previewRefs,meta:{case_id:jointID,case_revision:1,current_revision:2,snapshot_context:{case_id:jointID,case_revision:1,current_revision:2,refresh_state:'fresh',refresh_error:false,freshness:'current',revalidation_pending:false}},preview:{version:'joint-preview-v1',mode:'local',external_calls:false,captured_at:'2026-01-01T12:01:02Z'}};
"""

PREVIEW_ROUTE = r"""
const detailRoute=route;
route=(path,options)=>path.includes('/ai/preview?')?response(previewData):detailRoute(path,options);
"""


def test_preview_tab_has_explicit_read_only_action_and_local_boundary():
    html = ControlsHTML()
    html.feed(DASHBOARD_HTML)
    assert not html.duplicates
    assert html.elements['joint-tab-ai'][1]['aria-controls'] == 'joint-pane-ai'
    assert 'hidden' in html.elements['joint-pane-ai'][1]
    assert html.elements['joint-ai-preview'][0] == 'button'
    assert 'disabled' in html.elements['joint-ai-preview'][1]
    assert '本地预览，未调用模型' in DASHBOARD_HTML
    assert '原始引用仅供本地核对' in DASHBOARD_HTML
    assert '#joint-ai-result .pager{position:static}' in DASHBOARD_HTML
    run_dashboard(FIXTURE + PREVIEW_FIXTURE + PREVIEW_ROUTE + r"""
await showJointCase(jointID,1);const before=calls.length;await setJointTab('ai');assert.equal(calls.length,before);assert.equal($('joint-ai-result').hidden,true);
await $('joint-ai-preview').listeners.click();assert.equal(calls.length,before+1);assert.equal(calls.at(-1).path,'/api/joint/cases/'+jointID+'/ai/preview?revision=1');assert.equal(calls.at(-1).options.cache,'no-store');assert.equal(calls.at(-1).options.credentials,'same-origin');
assert.equal(calls.every(c=>(c.options.method||'GET')==='GET'),true);assert.equal($('joint-ai-result').hidden,false);assert.match($('joint-ai-state').textContent,/历史观察.*不代表当前可用/);assert.doesNotMatch($('joint-ai-state').textContent,/捕获时版本可核验/);assert.match($('joint-ai-status').textContent,/未调用模型.*捕获时刻/);
assert.match($('joint-ai-counts').textContent,/网络：观察 8 \/ 保存 7 \/ 纳入摘要 6/);assert.match($('joint-ai-completeness').textContent,/输入不完整.*时间线已截断.*摘要已截断/);
assert.equal($('joint-ai-rows').children.length,10);assert.match($('joint-ai-rows').textContent,/未提供/);assert.match($('joint-ai-rows').textContent,/<img src=x onerror=alert\(1\)>/);assert.equal($('joint-ai-rows').children[0].children[3].children[0].children[1].children.length,0);
const requests=calls.length;await $('joint-ai-next').listeners.click();assert.equal(calls.length,requests);assert.equal($('joint-ai-rows').children.length,2);assert.match($('joint-ai-page').textContent,/第 2 \/ 2 页/);assert.equal($('joint-ai-next').disabled,true);
await $('joint-ai-prev').listeners.click();assert.equal($('joint-ai-rows').children.length,10);assert.equal($('joint-ai-prev').disabled,true);
""")


def test_python_summary_envelope_is_accepted_and_rendered_by_shipped_javascript(monkeypatch):
    from app.telemetry.ai_summary import Aliases
    from app.telemetry.joint_ai_summary import SnapshotContext, build
    from app.telemetry.joint_case_contract import validate_read
    from test_joint_case_contract import authored

    scope, request, read = authored(monkeypatch)
    observation = validate_read(scope, request, read)
    context = SnapshotContext(
        store_id='1' * 32, query_epoch='2' * 32, case_id=observation.case_id,
        case_revision=1, current_revision=1, refresh_state='fresh',
        refresh_error=False, freshness='current', revalidation_pending=False,
    )
    envelope = build(observation, scope, context, Aliases(b'synthetic-preview-ui-contract-key'))
    envelope['preview'] = {'version': 'joint-preview-v1', 'mode': 'local',
                           'external_calls': False, 'captured_at': '2026-01-01T12:01:02Z'}
    run_dashboard('const realPreview=' + json.dumps(envelope) + r""";
jointDetail={case_id:realPreview.meta.case_id,revision:1,current:{revision:1}};await setJointTab('ai');
route=path=>{assert.equal(path,'/api/joint/cases/'+realPreview.meta.case_id+'/ai/preview?revision=1');return response(realPreview);};
assert.equal(jointPreviewValid(realPreview,realPreview.meta.case_id,1),true);await loadJointPreview();
assert.equal($('joint-ai-result').hidden,false);assert.match($('joint-ai-state').textContent,/捕获时版本可核验/);assert.match($('joint-ai-status').textContent,/预览完成.*未调用模型/);
assert.match($('joint-ai-counts').textContent,/网络：观察 3 \/ 保存 3 \/ 纳入摘要 3/);assert.match($('joint-ai-counts').textContent,/SSH：观察 1 \/ 保存 1 \/ 纳入摘要 1/);
assert.equal($('joint-ai-rows').children.length,realPreview.case.evidence.length);
for(let i=0;i<realPreview.case.evidence.length;i++){
 const row=realPreview.case.evidence[i],ref=realPreview.local_refs[row.event_id],cells=$('joint-ai-rows').children[i].children;
 assert(cells[0].textContent.includes(row.event_id));assert(cells[1].textContent.includes(row.source));assert.equal(cells[1].textContent.includes(ref.source_id),false);
 assert(cells[3].textContent.includes(ref.source_id));assert(cells[3].textContent.includes(ref.event_id));for(const incident of ref.incident_refs)assert(cells[3].textContent.includes(incident.incident_id));
 if(row.kind==='ssh')assert(cells[2].textContent.includes(row.account));else assert(cells[2].textContent.includes(row.destination+':'+row.dst_port));
}
assert.equal(calls.length,1);assert.equal((calls[0].options.method||'GET'),'GET');
""")


def test_preview_never_promotes_uncertain_or_historical_state():
    run_dashboard(FIXTURE + PREVIEW_FIXTURE + PREVIEW_ROUTE + r"""
await showJointCase(jointID,1);await setJointTab('ai');
for(const [state,context,association] of [['current',{current_revision:1},'partial'],['historical',{},'partial'],['stale',{current_revision:1,freshness:'stale'},'partial'],['stale',{current_revision:1},'retracted'],['unknown',{current_revision:1,freshness:'unknown'},'partial'],['unavailable',{current_revision:1,refresh_state:'pending'},'partial'],['revalidation_required',{revalidation_pending:true},'partial']]){
 const base={case_id:jointID,case_revision:1,current_revision:2,refresh_state:'fresh',refresh_error:false,freshness:'current',revalidation_pending:false};previewData.meta.snapshot_context={...base,...context};previewData.meta.current_revision=previewData.meta.snapshot_context.current_revision;previewData.case.review_state=state;previewData.case.association_state=association;await loadJointPreview();assert.equal($('joint-ai-result').hidden,false);assert.equal($('joint-ai-state').textContent.includes('捕获时版本可核验'),state==='current');
}
previewData.case.review_state='current';await loadJointPreview();assert.equal($('joint-ai-result').hidden,true);assert.match($('joint-ai-status').textContent,/不匹配/);assert.equal($('joint-ai-rows').children.length,0);
""")


@pytest.mark.parametrize('mutation', [
    "bad.meta.case_id='JOINT-'+'c'.repeat(32)",
    'bad.meta.case_revision=2',
    'bad.meta.snapshot_context.current_revision=3',
    "bad.case.evidence[0].asset=alias('A',2)",
    'bad.case.evidence[1].event_id=bad.case.evidence[0].event_id',
    "bad.local_refs[alias('E',99)]=bad.local_refs[alias('E',1)]",
    "bad.local_refs[alias('E',1)].kind='ssh'",
    "delete bad.local_refs[alias('E',1)]",
    'bad.case.counts.ssh.included=5',
    'bad.case.timeline_complete=true',
    'bad.preview.external_calls=true',
    "bad.preview.captured_at='invalid'",
])
def test_malformed_preview_clears_prior_result_and_never_mixes_evidence(mutation):
    run_dashboard(FIXTURE + PREVIEW_FIXTURE + PREVIEW_ROUTE + r"""
await showJointCase(jointID,1);await setJointTab('ai');await loadJointPreview();assert.equal($('joint-ai-result').hidden,false);
const bad=JSON.parse(JSON.stringify(previewData));
""" + mutation + r""";
route=path=>path.includes('/ai/preview?')?response(bad):detailRoute(path);await loadJointPreview();assert.equal($('joint-ai-result').hidden,true);assert.equal($('joint-ai-rows').children.length,0);assert.match($('joint-ai-status').textContent,/不匹配/);assert.equal($('joint-ai-preview').disabled,false);
""")


@pytest.mark.parametrize(('status', 'code', 'message'), [
    (503, 'joint_ai_preview_unavailable', '脱敏配置'),
    (409, 'joint_preview_changed', '状态已变化'),
    (422, 'joint_ai_capacity_exceeded', '超出允许范围'),
    (401, '<img src=x>', '登录已失效'),
    (503, '<img src=x>', '本地预览暂不可用'),
])
def test_preview_fixed_errors_remove_old_result_without_echoing_server_text(status, code, message):
    run_dashboard(FIXTURE + PREVIEW_FIXTURE + PREVIEW_ROUTE + r"""
await showJointCase(jointID,1);await setJointTab('ai');await loadJointPreview();
route=()=>({ok:false,status:""" + str(status) + ',json:async()=>({detail:' + json.dumps(code) + r"""})});await loadJointPreview();
assert.equal($('joint-ai-result').hidden,true);assert.equal($('joint-ai-rows').children.length,0);assert.equal($('joint-ai-preview').disabled,false);assert.doesNotMatch($('joint-ai-status').textContent,/<img/);assert($('joint-ai-status').textContent.includes(""" + json.dumps(message) + r"""));
""")


@pytest.mark.parametrize('action', [
    "setJointTab('sources')", 'jointDialog.close()', 'await showJointCase(jointID,2)',
    "await showJointCase('JOINT-'+'c'.repeat(32),1)",
])
def test_departure_aborts_delayed_preview_and_discards_result(action):
    run_dashboard(FIXTURE + PREVIEW_FIXTURE + PREVIEW_ROUTE + r"""
await showJointCase(jointID,1);await setJointTab('ai');let finish;
route=path=>path.includes('/ai/preview?')?new Promise(resolve=>{finish=()=>resolve(response(previewData));}):detailRoute(path);
const pending=loadJointPreview();for(let i=0;i<8;i++)await Promise.resolve();const signal=calls.at(-1).options.signal;
""" + action + r""";
assert.equal(signal.aborted,true);finish();await pending;assert.equal($('joint-ai-result').hidden,true);assert.equal(jointPreview,null);assert.equal($('joint-ai-rows').children.length,0);assert.equal($('joint-ai-status').textContent,'');
""")


def test_preview_retry_discards_late_error_and_empty_evidence_warns():
    run_dashboard(FIXTURE + PREVIEW_FIXTURE + PREVIEW_ROUTE + r"""
await showJointCase(jointID,1);await setJointTab('ai');let finish;route=()=>new Promise(resolve=>{finish=()=>resolve({ok:false,status:503,json:async()=>({error:'joint_ai_preview_unavailable'})});});
const old=loadJointPreview();for(let i=0;i<8;i++)await Promise.resolve();route=()=>response(previewData);await loadJointPreview();finish();await old;assert.equal($('joint-ai-result').hidden,false);assert.match($('joint-ai-status').textContent,/预览完成/);
previewData.case.evidence=[];previewData.local_refs={};previewData.case.counts={network:{observed:0,retained:0,included:0},ssh:{observed:0,retained:0,included:0}};previewData.case.timeline_complete=previewData.case.summary_complete=true;previewData.case.temporal_association_available=false;previewData.case.window_duration_us=null;
await loadJointPreview();assert.equal($('joint-ai-result').hidden,false);assert.match($('joint-ai-rows').textContent,/不能据此判断安全/);assert.match($('joint-ai-completeness').textContent,/缺少 网络、SSH/);assert.equal($('joint-ai-next').disabled,true);
""")


def test_preview_transport_and_json_errors_do_not_echo_response_content():
    run_dashboard(FIXTURE + PREVIEW_FIXTURE + PREVIEW_ROUTE + r"""
await showJointCase(jointID,1);await setJointTab('ai');
for(const failure of [()=>{throw new Error('<private transport detail>');},()=>({ok:true,json:async()=>{throw new SyntaxError('<private response>');}})]){route=failure;await loadJointPreview();assert.equal($('joint-ai-result').hidden,true);assert.equal($('joint-ai-status').textContent,'本地预览读取失败，请重试。');}
""")


PREVIEW_BROWSER = r"""
const assert=require('node:assert/strict'),{chromium}=require(process.env.RISKOPS_PLAYWRIGHT_MODULE);
(async()=>{
 const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));
 const browser=await chromium.launch({executablePath:process.env.RISKOPS_BROWSER_EXECUTABLE,headless:true,args:['--no-sandbox','--disable-gpu','--disable-dev-shm-usage']});
 try{for(const viewport of [{width:1440,height:1000},{width:390,height:844}]){
  const context=await browser.newContext({viewport,serviceWorkers:'block'}),calls=[],errors=[];
  const fixtures=new Function(input.fixture+';return {jointID,jointRow,jointStatus,jointResult,previewData};')();
  await context.addInitScript(()=>sessionStorage.setItem('riskops-workspace','joint'));
  await context.route('**/*',async route=>{
   const request=route.request(),url=new URL(request.url());assert.equal(url.origin,'http://joint-preview.invalid');assert.equal(request.method(),'GET');calls.push(url.pathname+url.search);
   if(url.pathname==='/')return route.fulfill({contentType:'text/html',headers:{'Content-Security-Policy':input.csp},body:input.html});
   let data;if(url.pathname==='/api/console/bootstrap')data={state:'disabled'};
   else if(url.pathname==='/api/summary')data={sources:[],totals:{events:0,ssh_failures:0,ssh_successes:0,incidents:0}};
   else if(url.pathname==='/api/joint/status')data=fixtures.jointStatus;
   else if(url.pathname==='/api/joint/cases')data={items:[fixtures.jointRow],page:1,total_pages:1,total:1,snapshot:'fixture',current_generation:1};
   else if(url.pathname.endsWith('/ai/preview'))data=fixtures.previewData;
   else if(url.pathname==='/api/joint/cases/'+fixtures.jointID)data=fixtures.jointResult;
   else throw new Error('Unexpected '+url.pathname);
   await route.fulfill({contentType:'application/json',body:JSON.stringify(data)});
  });
  const page=await context.newPage();page.on('pageerror',error=>errors.push(error.message));await page.goto('http://joint-preview.invalid/');await page.locator('#joint-rows button').click();await page.locator('#joint-ai-preview').waitFor({state:'hidden'});await page.locator('#joint-tab-ai').click();assert.equal(calls.filter(x=>x.includes('/ai/')).length,0);
  await page.locator('#joint-ai-preview').click();await page.locator('#joint-ai-result').waitFor({state:'visible'});assert.equal(await page.locator('#joint-ai-rows tr').count(),10);assert.match(await page.locator('#joint-ai-state').textContent(),/历史观察/);
  await page.locator('#joint-ai-rows details').first().locator('summary').click();assert.equal(await page.locator('#joint-ai-result img').count(),0);assert.match(await page.locator('#joint-ai-rows').textContent(),/<img/);
  await page.locator('#joint-ai-next').click();assert.equal(await page.locator('#joint-ai-rows tr').count(),2);assert.equal(calls.filter(x=>x.includes('/ai/')).length,1);
  assert.equal(await page.locator('#joint-ai-result .pager').evaluate(el=>getComputedStyle(el).position),'static');
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);const box=await page.locator('#joint-dialog').boundingBox();assert(box.x>=0&&box.x+box.width<=viewport.width+1&&box.height<=viewport.height);
  await page.locator('#joint-tab-sources').click();await page.locator('#joint-tab-ai').click();assert.equal(await page.locator('#joint-ai-result').isVisible(),false);assert.equal(calls.filter(x=>x.includes('/ai/')).length,1);
  await page.locator('#joint-ai-preview').click();await page.locator('#joint-ai-result').waitFor({state:'visible'});await page.keyboard.press('Escape');assert.equal(await page.locator('#joint-dialog').isVisible(),false);assert.deepEqual(errors,[]);await context.close();
 }}finally{await browser.close();}console.log('passed');
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
"""


def test_optional_real_browser_joint_preview():
    node = shutil.which('node')
    if not node or not os.environ.get('RISKOPS_PLAYWRIGHT_MODULE'):
        pytest.skip('Set RISKOPS_PLAYWRIGHT_MODULE for synthetic desktop/mobile acceptance')
    result = subprocess.run(
        [node, '-e', PREVIEW_BROWSER],
        input=json.dumps({'html': DASHBOARD_HTML, 'csp': CONTENT_SECURITY_POLICY,
                          'fixture': FIXTURE.split('const jointDialog=')[0] + PREVIEW_FIXTURE}),
        text=True, encoding='utf-8', capture_output=True, timeout=150,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'passed'
