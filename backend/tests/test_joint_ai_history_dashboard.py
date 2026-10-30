"""Synthetic manual offline joint jobs: explicit actions and response isolation."""
import json
import os
import shutil
import subprocess

import pytest

from app.telemetry.dashboard import CONTENT_SECURITY_POLICY, DASHBOARD_HTML
from test_dashboard_control import ControlsHTML, run_dashboard
from test_joint_dashboard import FIXTURE
from test_joint_ai_service import (
    world as world, saved as saved, scheduled as scheduled, configured as configured,
    sources as sources, store_clock as store_clock,
)
from test_joint_preview_dashboard import PREVIEW_FIXTURE

HISTORY_FIXTURE = r"""
previewData.preview_key='a'.repeat(64);previewData.execution={enabled:true,mode:'offline',external_calls:false};
const offlineStatus={enabled:true,mode:'offline',external_calls:false,error:null,csrf_token:'synthetic-offline-csrf'};
function makeJointJob(index=1,revision=1){
 const caseData=JSON.parse(JSON.stringify(previewData.case)),meta=JSON.parse(JSON.stringify(previewData.meta));
 meta.case_revision=meta.snapshot_context.case_revision=revision;meta.current_revision=meta.snapshot_context.current_revision=Math.max(2,revision);caseData.review_state=revision<meta.current_revision?'historical':'current';
 return {id:index.toString(16).padStart(32,'0'),case_id:jointID,case_revision:revision,state:'review',created:1767268862,updated:1767268863,stale:revision<2,current_review_state:caseData.review_state,execution_mode:'offline',case:caseData,local:{meta,local_refs:JSON.parse(JSON.stringify(previewData.local_refs))},result:{verdict:'abstain',confidence:'low',rationale:'<img src=x onerror=alert(1)> synthetic rehearsal',evidence_ids:caseData.evidence.map(row=>row.event_id),attack_techniques:[],usd:0,metadata:{offline:true,evidence_validation:{status:'valid',reasons:[],revision:caseData.revision,proposal:null}}},error_code:null};
}
const offlineJob=makeJointJob();
const historyJobs=Array.from({length:12},(_,index)=>makeJointJob(index+1,index%2+1));
function historyRow(job){const {id,case_id,case_revision,state,created,updated,stale,current_review_state,execution_mode,error_code}=job;return {id,case_id,case_revision,state,created,updated,stale,current_review_state,execution_mode,error_code,result:job.result?{verdict:job.result.verdict,confidence:job.result.confidence}:null};}
const baseRoute=route;
route=(path,options={})=>{
 if(path.includes('/ai/preview?'))return response(previewData);
 if(path==='/api/joint/ai/status')return response(offlineStatus);
 if(path==='/api/joint/cases/'+jointID+'/ai'&&options.method==='POST')return response(offlineJob);
 if(path==='/api/joint/cases/'+jointID+'/ai/history')return response({case_id:jointID,items:historyJobs.map(historyRow)});
 if(path.startsWith('/api/joint/ai/jobs/'))return response(historyJobs.find(job=>job.id===path.split('/').at(-1)));
 return baseRoute(path,options);
};
"""


def run_history(scenario):
    return run_dashboard(FIXTURE + PREVIEW_FIXTURE + HISTORY_FIXTURE + scenario)


def test_offline_actions_are_explicit_and_success_does_not_poll_or_resubmit():
    html = ControlsHTML()
    html.feed(DASHBOARD_HTML)
    assert not html.duplicates
    assert 'disabled' in html.elements['joint-ai-submit'][1]
    assert 'hidden' in html.elements['joint-ai-submit'][1]
    assert 'disabled' in html.elements['joint-ai-history-load'][1]
    assert '#joint-ai-history .pager,#joint-ai-job .pager{position:static}' in DASHBOARD_HTML
    assert '演练建议不是真实模型判断' in DASHBOARD_HTML
    run_history(r"""
await showJointCase(jointID,1);await setJointTab('ai');assert.equal(calls.length,1);assert.equal($('joint-ai-submit').hidden,true);
await loadJointPreview();assert.equal(calls.filter(c=>c.path==='/api/joint/ai/status').length,0);assert.equal($('joint-ai-submit').hidden,false);assert.equal($('joint-ai-submit').disabled,false);
await $('joint-ai-submit').listeners.click();const status=calls.at(-2),submit=calls.at(-1);assert.equal(status.path,'/api/joint/ai/status');assert.equal(submit.path,'/api/joint/cases/'+jointID+'/ai');assert.equal(submit.options.method,'POST');assert.equal(submit.options.headers['Content-Type'],'application/json');assert.equal(submit.options.headers['X-RiskOps-CSRF'],offlineStatus.csrf_token);assert.deepEqual(JSON.parse(submit.options.body),{revision:1,preview_key:previewData.preview_key});
assert.equal($('joint-ai-job').hidden,false);assert.equal($('joint-ai-result').hidden,true);assert.equal($('joint-ai-submit').disabled,true);assert.match($('joint-ai-review-status').textContent,/未调用模型/);assert.match($('joint-ai-job-fields').textContent,/本地演练.*费用为 0/);assert.match($('joint-ai-job-rationale').textContent,/<img/);assert.equal($('joint-ai-job-rationale').children.length,0);
assert.equal($('joint-ai-job-refs').children.length,10);const count=calls.length;await $('joint-ai-job-next').listeners.click();assert.equal($('joint-ai-job-refs').children.length,2);assert.equal(calls.length,count);await submitJointReview();assert.equal(calls.length,count);assert.equal(jointSubmitLoading,false);assert.equal(calls.filter(c=>c.path.startsWith('/api/joint/ai/jobs/')).length,0);
""")


@pytest.mark.parametrize('mutation', [
    'delete previewData.execution', "previewData.execution.mode='api'",
    'previewData.execution.external_calls=true', 'previewData.execution.enabled=false',
    "previewData.preview_key='invalid'", 'delete previewData.preview_key',
])
def test_preview_without_enabled_offline_binding_cannot_submit(mutation):
    run_history(mutation + r""";
await showJointCase(jointID,1);await setJointTab('ai');await loadJointPreview();assert.equal($('joint-ai-submit').disabled,true);const count=calls.length;await submitJointReview();assert.equal(calls.length,count);
""")


@pytest.mark.parametrize('mutation', [
    'offlineStatus.enabled=false', "offlineStatus.mode='api'", 'offlineStatus.external_calls=true',
    "offlineStatus.error='private failure'", 'delete offlineStatus.csrf_token',
])
def test_status_must_reconfirm_offline_mode_before_post(mutation):
    run_history(mutation + r""";
await showJointCase(jointID,1);await setJointTab('ai');await loadJointPreview();await submitJointReview();assert.equal(calls.some(c=>c.options.method==='POST'),false);assert.equal($('joint-ai-result').hidden,true);assert.match($('joint-ai-review-status').textContent,/未提交任务/);assert.doesNotMatch($('joint-ai-review-status').textContent,/private failure/);
""")


@pytest.mark.parametrize('departure', [
    "setJointTab('sources')", 'jointDialog.close()', 'await showJointCase(jointID,2)',
    'await loadJointPreview()',
])
def test_delayed_status_cannot_submit_after_preview_or_drawer_departure(departure):
    run_history(r"""
await showJointCase(jointID,1);await setJointTab('ai');await loadJointPreview();const normal=route;let finish;
route=(path,options)=>path==='/api/joint/ai/status'?new Promise(resolve=>{finish=()=>resolve(response(offlineStatus));}):normal(path,options);
const pending=submitJointReview();for(let i=0;i<8;i++)await Promise.resolve();const signal=calls.at(-1).options.signal;
""" + departure + r""";
assert.equal(signal.aborted,true);finish();await pending;assert.equal(calls.some(c=>c.options.method==='POST'),false);assert.equal(jointReviewJob,null);assert.equal($('joint-ai-job').hidden,true);
""")


def test_duplicate_clicks_are_suppressed_during_status_post_and_after_saved_result():
    run_history(r"""
await showJointCase(jointID,1);await setJointTab('ai');await loadJointPreview();const normal=route;let statusDone,postDone;
route=(path,options)=>path==='/api/joint/ai/status'?new Promise(resolve=>{statusDone=()=>resolve(response(offlineStatus));}):options?.method==='POST'?new Promise(resolve=>{postDone=()=>resolve(response(offlineJob));}):normal(path,options);
const pending=submitJointReview();await submitJointReview();assert.equal(calls.filter(c=>c.path==='/api/joint/ai/status').length,1);statusDone();for(let i=0;i<12;i++)await Promise.resolve();await submitJointReview();assert.equal(calls.filter(c=>c.options.method==='POST').length,1);postDone();await pending;const count=calls.length;await submitJointReview();assert.equal(calls.length,count);
""")


@pytest.mark.parametrize('departure', ["setJointTab('sources')", 'jointDialog.close()', 'await showJointCase(jointID,2)'])
def test_late_post_response_never_populates_departed_or_replaced_case(departure):
    run_history(r"""
await showJointCase(jointID,1);await setJointTab('ai');await loadJointPreview();const normal=route;let finish;
route=(path,options)=>options?.method==='POST'?new Promise(resolve=>{finish=()=>resolve(response(offlineJob));}):normal(path,options);
const pending=submitJointReview();for(let i=0;i<16;i++)await Promise.resolve();assert.equal(calls.at(-1).options.method,'POST');const signal=calls.at(-1).options.signal;
""" + departure + r""";
assert.equal(signal.aborted,true);finish();await pending;assert.equal(jointReviewJob,null);assert.equal($('joint-ai-job').hidden,true);assert.equal($('joint-ai-review-status').textContent,'');
""")


def test_failed_or_ambiguous_post_clears_preview_and_requires_history_before_retry():
    run_history(r"""
await showJointCase(jointID,1);await setJointTab('ai');await loadJointPreview();const normal=route;
route=(path,options)=>{if(options?.method==='POST')throw new Error('private transport address');return normal(path,options);};await submitJointReview();assert.equal($('joint-ai-job').hidden,true);assert.equal($('joint-ai-result').hidden,true);assert.equal(jointPreview,null);assert.match($('joint-ai-review-status').textContent,/先查看研判历史/);assert.doesNotMatch($('joint-ai-review-status').textContent,/private/);const count=calls.length;await submitJointReview();assert.equal(calls.length,count);
""")


def test_history_pages_are_local_and_full_records_match_clicked_revision():
    run_history(r"""
await showJointCase(jointID,1);await setJointTab('ai');await $('joint-ai-history-load').listeners.click();assert.equal(calls.at(-1).path,'/api/joint/cases/'+jointID+'/ai/history');assert.equal(calls.some(c=>c.path==='/api/joint/ai/status'||c.options.method==='POST'),false);assert.equal($('joint-ai-history-rows').children.length,5);assert.match($('joint-ai-history-page').textContent,/最多 20/);
const count=calls.length;await $('joint-ai-history-next').listeners.click();assert.equal(calls.length,count);assert.match($('joint-ai-history-page').textContent,/第 2 \/ 3 页/);await $('joint-ai-history-rows').children[0].children[3].children[0].listeners.click();assert.equal(calls.at(-1).path,'/api/joint/ai/jobs/'+historyJobs[5].id);assert.equal(jointReviewJob.case_revision,2);assert.match($('joint-ai-job-state').textContent,/与当前所选版本不同的历史记录/);assert.equal($('joint-ai-job').hidden,false);
await $('joint-ai-job-refresh').listeners.click();assert.equal(calls.at(-1).path,'/api/joint/ai/jobs/'+historyJobs[5].id);assert.equal(calls.length,count+2);
""")


@pytest.mark.parametrize('replacement', [
    "{case_id:'wrong',items:historyJobs.map(historyRow)}",
    '{case_id:jointID,items:[historyRow(offlineJob),historyRow(offlineJob)]}',
    '{case_id:jointID,items:Array.from({length:21},()=>historyRow(offlineJob))}',
    "{case_id:jointID,items:[{...historyRow(offlineJob),execution_mode:'api'}]}",
    "{case_id:jointID,items:[{...historyRow(offlineJob),case_id:'wrong'}]}",
])
def test_invalid_history_replaces_no_old_rows(replacement):
    run_history(r"""
await showJointCase(jointID,1);await setJointTab('ai');await loadJointHistory();assert.equal($('joint-ai-history').hidden,false);route=()=>response(""" + replacement + r""");await loadJointHistory();assert.equal($('joint-ai-history').hidden,true);assert.equal($('joint-ai-history-rows').children.length,0);assert.match($('joint-ai-review-status').textContent,/不匹配/);
""")


@pytest.mark.parametrize(('status', 'code', 'label'), [
    (503, 'joint_ai_disabled', '尚未启用'), (404, 'joint_ai_record_not_found', '记录不可用'),
    (409, 'joint_ai_request_changed', '已变化'), (409, 'joint_preview_changed', '已变化'),
    (503, 'joint_ai_unavailable', '暂不可用'), (500, '<private>', '读取失败'),
])
def test_history_error_codes_use_fixed_local_labels(status, code, label):
    run_history(r"""
await showJointCase(jointID,1);await setJointTab('ai');route=()=>({ok:false,status:""" + str(status) + ',json:async()=>({detail:' + json.dumps(code) + r"""})});await loadJointHistory();assert.equal($('joint-ai-history').hidden,true);assert($('joint-ai-review-status').textContent.includes(""" + json.dumps(label) + r"""));assert.doesNotMatch($('joint-ai-review-status').textContent,/<private>/);
""")


def test_late_history_and_job_responses_cannot_replace_new_selection():
    run_history(r"""
await showJointCase(jointID,1);await setJointTab('ai');const normal=route;let finish;
route=path=>path.endsWith('/history')?new Promise(resolve=>{finish=()=>resolve(response({case_id:jointID,items:historyJobs.map(historyRow)}));}):normal(path);
const history=loadJointHistory();for(let i=0;i<8;i++)await Promise.resolve();setJointTab('sources');finish();await history;assert.equal(jointHistory,null);assert.equal($('joint-ai-history').hidden,true);
await setJointTab('ai');route=path=>path.endsWith(historyJobs[0].id)?new Promise(resolve=>{finish=()=>resolve(response(historyJobs[0]));}):normal(path);const old=loadJointJob(historyJobs[0].id,1);for(let i=0;i<8;i++)await Promise.resolve();await loadJointJob(historyJobs[1].id,2);finish();await old;assert.equal(jointReviewJob.id,historyJobs[1].id);
""")


@pytest.mark.parametrize('mutation', [
    "bad.id='f'.repeat(32)", "bad.case_id='JOINT-'+'f'.repeat(32)", 'bad.case_revision=2',
    'bad.local.meta.case_revision=2', "bad.execution_mode='api'", 'bad.result.metadata.offline=false',
    'bad.result.usd=0.01', "bad.result.evidence_ids.push(alias('E',99))",
    "bad.local.local_refs[bad.case.evidence[0].event_id].kind='ssh'",
    'bad.local.meta.snapshot_context.current_revision=99',
])
def test_full_job_identity_revision_mode_and_reference_mismatch_clear_old_result(mutation):
    run_history(r"""
await showJointCase(jointID,1);await setJointTab('ai');await loadJointJob(offlineJob.id,1);assert.equal($('joint-ai-job').hidden,false);const bad=JSON.parse(JSON.stringify(offlineJob));
""" + mutation + r""";
route=()=>response(bad);await loadJointJob(offlineJob.id,1);assert.equal($('joint-ai-job').hidden,true);assert.equal($('joint-ai-job-refs').children.length,0);assert.match($('joint-ai-review-status').textContent,/不匹配/);
""")


def test_queued_jobs_refresh_explicitly_and_invalid_claims_remain_review_only():
    run_history(r"""
await showJointCase(jointID,1);await setJointTab('ai');const queued={...offlineJob,state:'queued',result:null};route=()=>response(queued);await loadJointJob(offlineJob.id,1);assert.equal($('joint-ai-job-result').hidden,true);assert.equal($('joint-ai-job-refresh').disabled,false);const before=calls.length;
const review=JSON.parse(JSON.stringify(offlineJob));review.result.evidence_ids=[];review.result.metadata.evidence_validation={status:'requires_review',reasons:[{code:'unsupported_claim',private:'<private>'},{code:'<private>'}],proposal:null};route=()=>response(review);await $('joint-ai-job-refresh').listeners.click();assert.equal(calls.length,before+1);assert.match($('joint-ai-job-checks').textContent,/未通过.*不支持声明/);assert.doesNotMatch($('joint-ai-job-checks').textContent,/<private>/);assert.match($('joint-ai-job-refs').textContent,/不能据此判断安全/);assert.equal(calls.some(c=>c.options.method==='POST'),false);
""")


def test_python_offline_service_jobs_render_in_shipped_javascript(world):
    preview = world.service.preview(world.case_id, 1)
    queued = world.service.enqueue(world.case_id, 1, preview['preview_key'], 'operator')
    assert world.service.run_once()
    completed = world.service.job(queued['id'])
    wire = {'preview': preview, 'queued': queued, 'completed': completed,
            'status': world.service.status() | {'csrf_token': 'synthetic-service-csrf'},
            'history': {'case_id': world.case_id, 'items': world.service.history(world.case_id)}}
    run_dashboard('const wire=' + json.dumps(wire) + r""";
jointDetail={case_id:wire.queued.case_id,revision:1,current:{revision:1}};await setJointTab('ai');
route=(path,options)=>{
 if(path.endsWith('/ai/preview?revision=1'))return response(wire.preview);
 if(path==='/api/joint/ai/status')return response(wire.status);
 if(path==='/api/joint/cases/'+jointDetail.case_id+'/ai'){assert.equal(options.method,'POST');assert.deepEqual(JSON.parse(options.body),{revision:1,preview_key:wire.preview.preview_key});assert.equal(options.headers['X-RiskOps-CSRF'],wire.status.csrf_token);return response(wire.queued);}
 if(path==='/api/joint/ai/jobs/'+wire.queued.id)return response(wire.completed);
 if(path.endsWith('/ai/history'))return response(wire.history);
 throw new Error('Unexpected synthetic route');
};
await loadJointPreview();assert.equal(jointCanSubmit(),true);await submitJointReview();assert.equal(jointReviewJob.state,'queued');assert.equal($('joint-ai-job-result').hidden,true);assert.equal($('joint-ai-job-refresh').disabled,false);
await $('joint-ai-job-refresh').listeners.click();assert.equal(jointReviewJob.id,wire.completed.id);assert.equal(jointReviewJob.state,'review');assert.equal($('joint-ai-job-result').hidden,false);assert.match($('joint-ai-job-verdict').textContent,/保留人工复核/);assert.match($('joint-ai-job-fields').textContent,/未调用模型/);assert.match($('joint-ai-job-checks').textContent,/校验通过/);
await loadJointHistory();assert.equal($('joint-ai-history-rows').children.length,1);await $('joint-ai-history-rows').children[0].children[3].children[0].listeners.click();assert.equal(jointReviewJob.id,wire.completed.id);assert.equal(calls.filter(call=>call.options.method==='POST').length,1);
""")


BROWSER = r"""
const assert=require('node:assert/strict'),{chromium}=require(process.env.RISKOPS_PLAYWRIGHT_MODULE);
(async()=>{const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));
 const browser=await chromium.launch({executablePath:process.env.RISKOPS_BROWSER_EXECUTABLE,headless:true,args:['--no-sandbox','--disable-gpu','--disable-dev-shm-usage']});
 try{for(const viewport of [{width:1440,height:1000},{width:390,height:844}]){
  const context=await browser.newContext({viewport,serviceWorkers:'block'}),calls=[],errors=[];const data=new Function(input.fixture+';return {jointID,jointRow,jointStatus,jointResult,previewData,offlineStatus,offlineJob,historyJobs,historyRow};')();
  await context.addInitScript(()=>sessionStorage.setItem('riskops-workspace','joint'));
  await context.route('**/*',async route=>{const request=route.request(),url=new URL(request.url());assert.equal(url.origin,'http://joint-history.invalid');calls.push({path:url.pathname,method:request.method()});let body;
   if(request.method()==='POST'){assert.equal(url.pathname,'/api/joint/cases/'+data.jointID+'/ai');assert.equal(request.headers()['x-riskops-csrf'],data.offlineStatus.csrf_token);assert.deepEqual(request.postDataJSON(),{revision:1,preview_key:data.previewData.preview_key});body=data.offlineJob;}
   else{assert.equal(request.method(),'GET');if(url.pathname==='/')return route.fulfill({contentType:'text/html',headers:{'Content-Security-Policy':input.csp},body:input.html});
    if(url.pathname==='/api/console/bootstrap')body={state:'disabled'};else if(url.pathname==='/api/summary')body={sources:[],totals:{events:0,ssh_failures:0,ssh_successes:0,incidents:0}};
    else if(url.pathname==='/api/joint/status')body=data.jointStatus;else if(url.pathname==='/api/joint/cases')body={items:[data.jointRow],page:1,total_pages:1,total:1,snapshot:'fixture',current_generation:1};else if(url.pathname==='/api/joint/cases/'+data.jointID)body=data.jointResult;
    else if(url.pathname.endsWith('/ai/preview'))body=data.previewData;else if(url.pathname==='/api/joint/ai/status')body=data.offlineStatus;else if(url.pathname.endsWith('/ai/history'))body={case_id:data.jointID,items:data.historyJobs.map(data.historyRow)};else if(url.pathname.startsWith('/api/joint/ai/jobs/'))body=data.historyJobs.find(job=>job.id===url.pathname.split('/').at(-1));else throw new Error('Unexpected request');}
   await route.fulfill({contentType:'application/json',body:JSON.stringify(body)});
  });
  const page=await context.newPage();page.on('pageerror',error=>errors.push(error.message));await page.goto('http://joint-history.invalid/');await page.locator('#joint-rows button').click();await page.waitForFunction(()=>jointDetail!==null);await page.locator('#joint-tab-ai').click();assert.equal(calls.some(call=>call.path.startsWith('/api/joint/ai/')),false);
  await page.locator('#joint-ai-preview').click();await page.locator('#joint-ai-result').waitFor({state:'visible'});assert.equal(calls.some(call=>call.path==='/api/joint/ai/status'),false);await page.locator('#joint-ai-submit').click();await page.locator('#joint-ai-job').waitFor({state:'visible'});assert.equal(calls.filter(call=>call.method==='POST').length,1);assert.equal(await page.locator('#joint-ai-submit').isDisabled(),true);assert.equal(await page.locator('#joint-ai-job img').count(),0);assert.equal(await page.locator('#joint-ai-job-refs tr').count(),10);
  await page.locator('#joint-ai-job-refs details summary').first().click();await page.locator('#joint-ai-job-next').click();assert.equal(await page.locator('#joint-ai-job-refs tr').count(),2);await page.locator('#joint-ai-history-load').click();await page.locator('#joint-ai-history').waitFor({state:'visible'});assert.equal(await page.locator('#joint-ai-history-rows tr').count(),5);await page.locator('#joint-ai-history-next').click();await page.locator('#joint-ai-history-rows button').first().click();await page.locator('#joint-ai-job').waitFor({state:'visible'});assert.match(await page.locator('#joint-ai-job-state').textContent(),/与当前所选版本不同/);await page.locator('#joint-ai-job-refresh').click();await page.waitForFunction(()=>jointJobLoading===false);
  for(const selector of ['#joint-ai-history .pager','#joint-ai-job .pager'])assert.equal(await page.locator(selector).evaluate(el=>getComputedStyle(el).position),'static');assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);const box=await page.locator('#joint-dialog').boundingBox();assert(box.x>=0&&box.x+box.width<=viewport.width+1&&box.height<=viewport.height);
  await page.locator('#joint-tab-sources').click();await page.locator('#joint-tab-ai').click();assert.equal(await page.locator('#joint-ai-history').isVisible(),false);assert.equal(await page.locator('#joint-ai-job').isVisible(),false);assert.equal(calls.filter(call=>call.method==='POST').length,1);assert.deepEqual(errors,[]);await context.close();
 }}finally{await browser.close();}console.log('passed');})().catch(error=>{console.error(error.stack);process.exitCode=1;});
"""


def test_optional_real_browser_offline_history():
    node = shutil.which('node')
    if not node or not os.environ.get('RISKOPS_PLAYWRIGHT_MODULE'):
        pytest.skip('Set RISKOPS_PLAYWRIGHT_MODULE for synthetic desktop/mobile acceptance')
    # The browser installs its own routes; fixture extraction has no DOM access.
    fixture = (FIXTURE.split('const jointDialog=')[0] + PREVIEW_FIXTURE
               + HISTORY_FIXTURE.split('const baseRoute=route;')[0])
    result = subprocess.run(
        [node, '-e', BROWSER], input=json.dumps({'html': DASHBOARD_HTML,
        'csp': CONTENT_SECURITY_POLICY, 'fixture': fixture}),
        text=True, encoding='utf-8', capture_output=True, timeout=150,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'passed'
