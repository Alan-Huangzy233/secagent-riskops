"""Manual API UI uses synthetic wire objects and an inert Node DOM only."""
import json
import os
import shutil
import socket
import subprocess

import pytest

from app.telemetry.dashboard import CONTENT_SECURITY_POLICY, DASHBOARD_HTML
from test_dashboard_control import ControlsHTML, run_dashboard
from test_joint_ai_history_dashboard import BROWSER, HISTORY_FIXTURE, run_history
from test_joint_dashboard import FIXTURE
from test_joint_preview_dashboard import PREVIEW_FIXTURE
from test_joint_ai_live_service import world as world
from test_joint_ai_service import (
    saved as saved, scheduled as scheduled, configured as configured,
    sources as sources, store_clock as store_clock,
)


API_FIXTURE = r"""
previewData.case.review_state='current';previewData.meta.current_revision=1;previewData.meta.snapshot_context.current_revision=1;
previewData.execution={enabled:true,mode:'api',external_calls:true,error:null,model:'synthetic-model',provider:'synthetic',paused:false,pause_reason:null,approved_summary_version:'joint-summary-v1',execution_binding:'b'.repeat(64),budget:{total_usd:5,daily_usd:0.5,charged_usd:0.1,reserved_usd:0.02,today_committed_usd:0.12,unresolved_calls:1,halted:false}};
const apiStatus={...JSON.parse(JSON.stringify(previewData.execution)),csrf_token:'synthetic-api-csrf'};
const apiJob=JSON.parse(JSON.stringify(offlineJob));
Object.assign(apiJob,{execution_mode:'api',stale:false,current_review_state:'current',request_sha:'d'.repeat(64),config_sha:'b'.repeat(64),case:JSON.parse(JSON.stringify(previewData.case))});
apiJob.local.meta={...JSON.parse(JSON.stringify(previewData.meta)),execution_mode:'api',model:'synthetic-model',provider:'synthetic'};
apiJob.result.usd=0.002;
Object.assign(apiJob.result.metadata,{execution_mode:'api',offline:false,model:'synthetic-model',usage:{input_tokens:100,output_tokens:20,cache_read_input_tokens:0,cache_creation_input_tokens:0,reasoning_tokens:5},recovered:false,additional_usd:0.002,request_sha256:apiJob.request_sha,call_id:'e'.repeat(64),stale_at_completion:false});
apiJob.result.metadata.evidence_validation.free_text_requires_review=true;
const offlineRoute=route;
route=(path,options={})=>path==='/api/joint/ai/status'?response(apiStatus):path==='/api/joint/cases/'+jointID+'/ai'&&options.method==='POST'?response(apiJob):path==='/api/joint/ai/jobs/'+apiJob.id?response(apiJob):path.endsWith('/ai/history')?response({case_id:jointID,items:[historyRow(apiJob),historyRow({...offlineJob,id:'f'.repeat(32)})]}):offlineRoute(path,options);
function confirmAPI(){ $('joint-ai-confirm').checked=true;$('joint-ai-confirm').listeners.change(); }
"""


def run_live(scenario):
    return run_history(API_FIXTURE + scenario)


def test_online_confirmation_is_separate_unchecked_and_has_no_inline_code():
    html = ControlsHTML()
    html.feed(DASHBOARD_HTML)
    assert not html.duplicates
    assert html.elements['joint-ai-confirm'][0] == 'input'
    assert html.elements['joint-ai-confirm'][1]['type'] == 'checkbox'
    assert 'checked' not in html.elements['joint-ai-confirm'][1]
    assert 'disabled' in html.elements['joint-ai-confirm'][1]
    assert 'hidden' in html.elements['joint-ai-online'][1]
    assert '已核对摘要，确认发送至所选模型（可能计费）' in DASHBOARD_HTML
    assert '最多发送 40 条脱敏证据摘要' in DASHBOARD_HTML
    assert '不发送原始日志' in DASHBOARD_HTML
    assert "'unsafe-inline'" not in CONTENT_SECURITY_POLICY


def test_only_checked_explicit_submit_reconfirms_status_then_posts_once():
    run_live(r"""
await showJointCase(jointID,1);await setJointTab('ai');assert.equal(calls.length,1);
await loadJointPreview();assert.equal(calls.length,2);assert.equal($('joint-ai-online').hidden,false);assert.equal($('joint-ai-confirm').checked,false);assert.equal($('joint-ai-submit').disabled,true);assert.equal($('joint-ai-submit').textContent,'提交在线人工研判');
assert.match($('joint-ai-execution').textContent,/synthetic.*synthetic-model/);assert.match($('joint-ai-execution').textContent,/与 SSH 共用预算/);assert.match($('joint-ai-execution').textContent,/US\$ 5\.000000/);
await submitJointReview();assert.equal(calls.length,2);await $('joint-ai-next').listeners.click();assert.equal(calls.length,2);confirmAPI();assert.equal(calls.length,2);assert.equal($('joint-ai-submit').disabled,false);
await submitJointReview();assert.equal(calls.length,4);assert.equal(calls.at(-2).path,'/api/joint/ai/status');const post=calls.at(-1);assert.equal(post.options.method,'POST');assert.equal(post.options.headers['X-RiskOps-CSRF'],apiStatus.csrf_token);assert.deepEqual(JSON.parse(post.options.body),{revision:1,preview_key:previewData.preview_key});
assert.equal(jointReviewJob.execution_mode,'api');assert.equal($('joint-ai-online').hidden,true);assert.equal($('joint-ai-confirm').checked,false);assert.match($('joint-ai-review-status').textContent,/可能计费/);assert.doesNotMatch($('joint-ai-review-status').textContent,/本次未调用模型/);
assert.match($('joint-ai-job-title').textContent,/在线人工研判/);assert.match($('joint-ai-job-fields').textContent,/synthetic-model.*原调用费用US\$ 0\.002000/);assert.match($('joint-ai-job-verdict').textContent,/模型建议/);assert.match($('joint-ai-job-boundary').textContent,/人工核对/);
const count=calls.length;await $('joint-ai-job-next').listeners.click();await submitJointReview();assert.equal(calls.length,count);assert.equal(calls.filter(call=>call.options.method==='POST').length,1);
""")


@pytest.mark.parametrize('mutation', [
    "apiStatus.execution_binding='c'.repeat(64)", "apiStatus.model='other-model'",
    "apiStatus.provider='other-provider'", 'apiStatus.external_calls=false',
    'apiStatus.approved_summary_version=null', 'apiStatus.paused=true',
    "apiStatus.pause_reason='joint_ai_existing_api_changed'", 'apiStatus.budget.halted=true',
    'apiStatus.budget.today_committed_usd=apiStatus.budget.daily_usd',
    'apiStatus.budget=null', 'apiStatus.enabled=false', "apiStatus.mode='offline'",
    "apiStatus.error='<private>'", 'delete apiStatus.csrf_token',
])
def test_fresh_status_must_reconfirm_exact_permission_binding_before_post(mutation):
    run_live(r"""
await showJointCase(jointID,1);await setJointTab('ai');await loadJointPreview();confirmAPI();
""" + mutation + r""";
await submitJointReview();assert.equal(calls.some(call=>call.options.method==='POST'),false);assert.equal(jointReviewJob,null);assert.equal(jointPreview,null);assert.equal($('joint-ai-confirm').checked,false);assert.match($('joint-ai-review-status').textContent,/未提交任务/);assert.doesNotMatch($('joint-ai-review-status').textContent,/<private>/);
""")


@pytest.mark.parametrize('mutation', [
    'previewData.execution.paused=true', 'previewData.execution.external_calls=false',
    'previewData.execution.approved_summary_version=null',
    "previewData.execution.approved_summary_version='joint-summary-v999'",
    "previewData.execution.execution_binding='bad'", "previewData.execution.model='<img private>'",
    'previewData.execution.budget.halted=true', 'previewData.execution.budget=null',
    'previewData.execution.budget.charged_usd=5',
    "previewData.case.review_state='historical';previewData.meta.current_revision=2;previewData.meta.snapshot_context.current_revision=2",
    "previewData.case.review_state='stale';previewData.meta.snapshot_context.freshness='stale'",
])
def test_unapproved_paused_or_noncurrent_preview_cannot_submit_even_if_checkbox_forged(mutation):
    run_live(mutation + r""";
await showJointCase(jointID,1);await setJointTab('ai');await loadJointPreview();confirmAPI();assert.equal($('joint-ai-submit').disabled,true);const count=calls.length;await submitJointReview();assert.equal(calls.length,count);assert.equal(calls.some(call=>call.options.method==='POST'),false);assert.doesNotMatch($('joint-ai-execution').textContent,/<img private>/);
""")


@pytest.mark.parametrize('action', [
    "await setJointTab('sources')", 'jointDialog.close()', 'await showJointCase(jointID,2)',
    'await loadJointPreview()', 'await loadJointHistory()',
])
def test_confirmation_does_not_survive_case_preview_or_history_departure(action):
    run_live(r"""
await showJointCase(jointID,1);await setJointTab('ai');await loadJointPreview();confirmAPI();assert.equal($('joint-ai-confirm').checked,true);
""" + action + r""";
assert.equal($('joint-ai-confirm').checked,false);assert.equal(calls.some(call=>call.options.method==='POST'),false);
""")


def test_unchecking_during_delayed_status_prevents_post():
    run_live(r"""
await showJointCase(jointID,1);await setJointTab('ai');await loadJointPreview();confirmAPI();const normal=route;let finish;
route=(path,options)=>path==='/api/joint/ai/status'?new Promise(resolve=>{finish=()=>resolve(response(apiStatus));}):normal(path,options);
const pending=submitJointReview();for(let i=0;i<8;i++)await Promise.resolve();$('joint-ai-confirm').checked=false;finish();await pending;assert.equal(calls.some(call=>call.options.method==='POST'),false);assert.equal(jointReviewJob,null);
""")


def test_ssh_spending_can_change_budget_numbers_without_changing_consent_identity():
    run_live(r"""
await showJointCase(jointID,1);await setJointTab('ai');await loadJointPreview();confirmAPI();apiStatus.budget.charged_usd=0.15;apiStatus.budget.today_committed_usd=0.17;await submitJointReview();assert.equal(calls.filter(call=>call.options.method==='POST').length,1);
""")


@pytest.mark.parametrize('mutation', [
    "bad.execution_mode='offline'", "bad.local.meta.execution_mode='recorded'",
    'delete bad.config_sha', 'delete bad.local.meta.model', "bad.local.meta.provider='<private>'",
    "bad.result.metadata.execution_mode='offline'", 'bad.result.metadata.offline=true',
    "bad.result.metadata.model='unrelated-model'", "bad.result.metadata.model='synthetic-model-fallback'",
    "bad.result.metadata.request_sha256='f'.repeat(64)", "bad.result.metadata.call_id='invalid'",
    'bad.result.usd=-1', "bad.result.usd='0.002'", 'bad.result.usd=Infinity',
    'bad.result.metadata.additional_usd=0', 'bad.result.metadata.recovered=true',
    'delete bad.result.metadata.stale_at_completion',
    'bad.result.metadata.usage.reasoning_tokens=21', 'bad.result.metadata.usage.input_tokens=-1',
    'delete bad.result.metadata.usage.output_tokens',
    'delete bad.result.metadata.evidence_validation.revision',
    'bad.result.metadata.evidence_validation.free_text_requires_review=false',
    "bad.result.evidence_ids=['E-'+'f'.repeat(24)]",
])
def test_api_result_mode_model_cost_binding_and_references_must_match_saved_job(mutation):
    run_live(r"""
await showJointCase(jointID,1);await setJointTab('ai');await loadJointJob(apiJob.id,1,'api');assert.equal($('joint-ai-job').hidden,false);const bad=JSON.parse(JSON.stringify(apiJob));
""" + mutation + r""";
route=()=>response(bad);await loadJointJob(apiJob.id,1,'api');assert.equal(jointReviewJob,null);assert.equal($('joint-ai-job').hidden,true);assert.equal($('joint-ai-job-refs').children.length,0);assert.match($('joint-ai-review-status').textContent,/不匹配/);assert.doesNotMatch($('joint-ai-review-status').textContent,/<private>/);
""")


@pytest.mark.parametrize("model", ["synthetic-model-2026-01-01", "synthetic-model-20260101"])
def test_paid_receipt_recovery_has_original_cost_zero_additional_cost_and_no_post(model):
    run_live("apiJob.result.metadata.model=" + json.dumps(model) + r""";
apiJob.result.metadata.recovered=true;apiJob.result.metadata.additional_usd=0;apiJob.result.metadata.stale_at_completion=true;
await showJointCase(jointID,1);await setJointTab('ai');await loadJointJob(apiJob.id,1,'api');assert.equal($('joint-ai-job').hidden,false);assert.match($('joint-ai-job-fields').textContent,/原调用费用US\$ 0\.002000本次新增费用US\$ 0\.000000/);assert.match($('joint-ai-job-fields').textContent,/未再次发送请求/);assert.match($('joint-ai-job-state').textContent,/完成时摘要已变化/);assert.equal(calls.some(call=>call.options.method==='POST'),false);
""")


def test_paused_configuration_keeps_mixed_saved_history_readable_without_status_or_post():
    run_live(r"""
apiStatus.paused=true;apiStatus.external_calls=false;apiStatus.approved_summary_version=null;
await showJointCase(jointID,1);await setJointTab('ai');await loadJointHistory();assert.equal($('joint-ai-history-rows').children.length,2);assert.match($('joint-ai-history-rows').textContent,/在线人工研判/);assert.match($('joint-ai-history-rows').textContent,/本地演练/);
await $('joint-ai-history-rows').children[0].children[3].children[0].listeners.click();assert.equal(jointReviewJob.execution_mode,'api');await $('joint-ai-job-refresh').listeners.click();assert.equal(jointReviewJob.execution_mode,'api');assert.equal(calls.some(call=>call.path==='/api/joint/ai/status'||call.options.method==='POST'),false);
""")


@pytest.mark.parametrize('field', ['model', 'provider'])
def test_submitted_job_saved_model_and_provider_must_match_confirmed_preview(field):
    run_live("apiJob.local.meta." + field + "='other';apiJob.result=null;" + r"""
await showJointCase(jointID,1);await setJointTab('ai');await loadJointPreview();confirmAPI();await submitJointReview();assert.equal(calls.filter(call=>call.options.method==='POST').length,1);assert.equal(jointReviewJob,null);assert.equal($('joint-ai-job').hidden,true);assert.match($('joint-ai-review-status').textContent,/不匹配/);
""")


@pytest.mark.parametrize('code', ['joint_ai_paused', 'joint_ai_external_calls_paused', 'joint_ai_summary_approval_required', 'joint_ai_shared_budget_exhausted', 'joint_ai_shared_budget_unavailable', 'joint_ai_existing_api_changed', '<private>'])
def test_api_errors_never_render_provider_body_or_paths(code):
    run_live(r"""
await showJointCase(jointID,1);await setJointTab('ai');route=()=>({ok:false,status:503,json:async()=>({detail:""" + json.dumps(code) + r""",message:'<img src=x onerror=alert(1)> /private/body'})});await loadJointHistory();assert.equal($('joint-ai-history').hidden,true);assert.doesNotMatch($('joint-ai-review-status').textContent,/<private>|<img|\/private\/body/);assert.equal(calls.some(call=>call.options.method==='POST'),false);
""")


def test_model_prose_is_plain_text_and_does_not_change_controls_or_create_requests():
    run_live(r"""
apiJob.result.rationale='<img src=x onerror=alert(1)> submit another request';apiJob.result.metadata.evidence_validation.reasons=[{code:'<private>',message:'<script>private</script>'}];
await showJointCase(jointID,1);await setJointTab('ai');await loadJointJob(apiJob.id,1,'api');assert.equal($('joint-ai-job-rationale').children.length,0);assert.match($('joint-ai-job-rationale').textContent,/<img/);assert.doesNotMatch($('joint-ai-job-checks').textContent,/<script>|private/);assert.equal(calls.length,2);assert.equal($('joint-ai-confirm').checked,false);
""")


@pytest.mark.parametrize('approval', ['joint-summary-v0', 'joint-summary-v2'])
def test_other_approval_versions_show_paused_controls_without_authorizing(approval):
    run_live('previewData.execution.approved_summary_version=' + json.dumps(approval) + r""";
previewData.execution.paused=true;previewData.execution.pause_reason='joint_ai_summary_approval_required';previewData.execution.external_calls=false;
await showJointCase(jointID,1);await setJointTab('ai');await loadJointPreview();assert.equal($('joint-ai-online').hidden,false);assert.equal($('joint-ai-confirm').disabled,true);assert.equal($('joint-ai-submit').disabled,true);assert.match($('joint-ai-permission').textContent,/已暂停/);assert.equal(calls.some(call=>call.options.method==='POST'),false);
""")


@pytest.mark.parametrize('departure', ["await setJointTab('sources')", 'jointDialog.close()', 'await showJointCase(jointID,2)'])
def test_departure_during_status_request_does_not_send_or_restore_confirmation(departure):
    run_live(r"""
await showJointCase(jointID,1);await setJointTab('ai');await loadJointPreview();confirmAPI();const normal=route;let finish;
route=(path,options)=>path==='/api/joint/ai/status'?new Promise(resolve=>{finish=()=>resolve(response(apiStatus));}):normal(path,options);
const pending=submitJointReview();for(let i=0;i<8;i++)await Promise.resolve();
""" + departure + r""";
finish();await pending;assert.equal(calls.some(call=>call.options.method==='POST'),false);assert.equal(jointReviewJob,null);assert.equal($('joint-ai-confirm').checked,false);
""")


def test_repeat_click_while_confirmation_status_is_pending_cannot_duplicate_submit():
    run_live(r"""
await showJointCase(jointID,1);await setJointTab('ai');await loadJointPreview();confirmAPI();const normal=route;let finish;
route=(path,options)=>path==='/api/joint/ai/status'?new Promise(resolve=>{finish=()=>resolve(response(apiStatus));}):normal(path,options);
const pending=submitJointReview();for(let i=0;i<8;i++)await Promise.resolve();await submitJointReview();finish();await pending;assert.equal(calls.filter(call=>call.options.method==='POST').length,1);assert.equal(calls.filter(call=>call.path==='/api/joint/ai/status').length,1);
""")


def test_actual_api_service_wire_renders_queued_completed_and_paused_history(world, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('only authored httpx.MockTransport responses are allowed')
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    monkeypatch.setattr(socket.socket, 'connect_ex', forbidden)
    w = world
    preview = w.service.preview(w.case_id, 1)
    queued = w.service.enqueue(w.case_id, 1, preview['preview_key'], 'synthetic-operator')
    assert not w.requests
    assert w.service.run_once()
    completed = w.service.job(queued['id'])
    assert len(w.requests) == 1 and completed['result']['metadata']['offline'] is False
    wire = {'preview': preview, 'queued': queued, 'completed': completed,
            'status': w.service.status() | {'csrf_token': 'synthetic-api-csrf'},
            'history': {'case_id': w.case_id, 'items': w.service.history(w.case_id)}}
    run_dashboard('const wire=' + json.dumps(wire) + r""";
jointDetail={case_id:wire.queued.case_id,revision:1,current:{revision:1}};await setJointTab('ai');
route=(path,options)=>{
 if(path.endsWith('/ai/preview?revision=1'))return response(wire.preview);
 if(path==='/api/joint/ai/status')return response(wire.status);
 if(path==='/api/joint/cases/'+jointDetail.case_id+'/ai'){assert.equal(options.method,'POST');assert.deepEqual(JSON.parse(options.body),{revision:1,preview_key:wire.preview.preview_key});return response(wire.queued);}
 if(path==='/api/joint/ai/jobs/'+wire.queued.id)return response(wire.completed);
 if(path.endsWith('/ai/history'))return response(wire.history);
 throw new Error('Unexpected synthetic route');
};
await loadJointPreview();assert.equal(jointCanSubmit(),false);assert.equal($('joint-ai-online').hidden,false);$('joint-ai-confirm').checked=true;$('joint-ai-confirm').listeners.change();assert.equal(jointCanSubmit(),true);await submitJointReview();assert.equal(jointReviewJob.state,'queued');assert.equal($('joint-ai-job-result').hidden,true);
await $('joint-ai-job-refresh').listeners.click();assert.equal(jointReviewJob.state,'complete');assert.equal(jointReviewJob.execution_mode,'api');assert.equal($('joint-ai-job-result').hidden,false);assert.match($('joint-ai-job-verdict').textContent,/模型建议：优先人工核查/);assert.match($('joint-ai-job-fields').textContent,/原调用费用US\$ 0\.000160/);assert.match($('joint-ai-job-checks').textContent,/校验通过/);
wire.status.paused=true;wire.status.external_calls=false;wire.status.pause_reason='joint_ai_external_calls_paused';await loadJointHistory();assert.equal($('joint-ai-history-rows').children.length,1);await $('joint-ai-history-rows').children[0].children[3].children[0].listeners.click();assert.equal(jointReviewJob.id,wire.completed.id);assert.equal(calls.filter(call=>call.options.method==='POST').length,1);assert.equal(calls.filter(call=>call.path==='/api/joint/ai/status').length,1);
""")
    assert len(w.requests) == 1


def test_optional_real_browser_api_confirmation_and_paused_history():
    node = shutil.which('node')
    if not node or not os.environ.get('RISKOPS_PLAYWRIGHT_MODULE'):
        pytest.skip('Set RISKOPS_PLAYWRIGHT_MODULE for synthetic desktop/mobile acceptance')
    fixture = (FIXTURE.split('const jointDialog=')[0] + PREVIEW_FIXTURE
               + HISTORY_FIXTURE.split('const baseRoute=route;')[0]
               + API_FIXTURE.split('const offlineRoute=route;')[0])
    browser = BROWSER.replace('offlineStatus,offlineJob,historyJobs,historyRow',
                              'offlineStatus,offlineJob,historyJobs,historyRow,apiStatus,apiJob')
    browser = browser.replace('data.offlineStatus', 'data.apiStatus').replace('body=data.offlineJob;', 'body=data.apiJob;')
    browser = browser.replace('data.historyJobs.map(data.historyRow)', '[data.apiJob,...data.historyJobs.filter(job=>job.id!==data.apiJob.id)].map(data.historyRow)')
    browser = browser.replace("body=data.historyJobs.find(job=>job.id===url.pathname.split('/').at(-1))", "body=data.apiJob.id===url.pathname.split('/').at(-1)?data.apiJob:data.historyJobs.find(job=>job.id===url.pathname.split('/').at(-1))")
    browser = browser.replace("await page.locator('#joint-ai-submit').click();", r"""
assert.equal(await page.locator('#joint-ai-submit').textContent(),'提交在线人工研判');assert.equal(await page.locator('#joint-ai-submit').isDisabled(),true);assert.equal(await page.locator('#joint-ai-confirm').isChecked(),false);
assert.match(await page.locator('#joint-ai-execution').textContent(),/synthetic-model/);assert.match(await page.locator('#joint-ai-execution').textContent(),/与 SSH 共用预算/);
await page.locator('#joint-ai-next').click();assert.equal(calls.some(call=>call.method==='POST'),false);await page.locator('#joint-ai-confirm').check();assert.equal(calls.some(call=>call.path==='/api/joint/ai/status'),false);await page.locator('#joint-ai-submit').click();
""")
    browser = browser.replace("assert.equal(await page.locator('#joint-ai-job img').count(),0);", r"""
assert.equal(await page.locator('#joint-ai-job img').count(),0);assert.equal(await page.locator('#joint-ai-confirm').isChecked(),false);assert.match(await page.locator('#joint-ai-job-title').textContent(),/在线人工研判/);assert.match(await page.locator('#joint-ai-job-fields').textContent(),/原调用费用US\$ 0\.002000/);assert.match(await page.locator('#joint-ai-job-boundary').textContent(),/人工核对/);
Object.assign(data.apiStatus,{paused:true,external_calls:false,pause_reason:'joint_ai_external_calls_paused'});Object.assign(data.previewData.execution,data.apiStatus);
""")
    browser = browser.replace("assert.equal(await page.locator('#joint-ai-history-rows tr').count(),5);", r"""
assert.equal(await page.locator('#joint-ai-history-rows tr').count(),5);assert.match(await page.locator('#joint-ai-history-rows').textContent(),/在线人工研判/);assert.match(await page.locator('#joint-ai-history-rows').textContent(),/本地演练/);
await page.locator('#joint-ai-history-rows button').first().click();await page.locator('#joint-ai-job').waitFor({state:'visible'});assert.match(await page.locator('#joint-ai-job-title').textContent(),/在线人工研判/);await page.locator('#joint-ai-job-refresh').click();await page.waitForFunction(()=>jointJobLoading===false);assert.equal(calls.filter(call=>call.path==='/api/joint/ai/status').length,1);assert.equal(calls.filter(call=>call.method==='POST').length,1);
await page.locator('#joint-ai-history-load').click();await page.locator('#joint-ai-history').waitFor({state:'visible'});
""")
    browser = browser.replace("assert.deepEqual(errors,[]);", r"""
await page.locator('#joint-ai-preview').click();await page.locator('#joint-ai-result').waitFor({state:'visible'});assert.equal(await page.locator('#joint-ai-online').isVisible(),true);assert.equal(await page.locator('#joint-ai-confirm').isDisabled(),true);assert.equal(await page.locator('#joint-ai-confirm').isChecked(),false);assert.equal(await page.locator('#joint-ai-submit').isDisabled(),true);assert.match(await page.locator('#joint-ai-permission').textContent(),/已暂停/);assert.equal(calls.filter(call=>call.method==='POST').length,1);assert.deepEqual(errors,[]);
""")
    result = subprocess.run([node, '-e', browser], input=json.dumps({
        'html': DASHBOARD_HTML, 'csp': CONTENT_SECURITY_POLICY, 'fixture': fixture,
    }), text=True, encoding='utf-8', capture_output=True, timeout=150)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'passed'


def test_invalid_paid_receipt_never_implies_free_or_unsubmitted_call():
    run_live(r"""
apiJob.state='review';apiJob.result=null;apiJob.error_code='invalid_analysis_record';
await showJointCase(jointID,1);await setJointTab('ai');await loadJointJob(apiJob.id,1,'api');assert.equal($('joint-ai-job').hidden,false);assert.equal($('joint-ai-job-result').hidden,true);assert.match($('joint-ai-job-fields').textContent,/调用可能已计费.*已承诺预算不会自动释放/);assert.match($('joint-ai-review-status').textContent,/回执无法核验.*不会自动重新发送/);assert.equal(calls.some(call=>call.options.method==='POST'),false);
""")


def test_submitted_job_configuration_is_the_one_confirmed_in_preview():
    run_live(r"""
apiJob.config_sha='c'.repeat(64);
await showJointCase(jointID,1);await setJointTab('ai');await loadJointPreview();confirmAPI();await submitJointReview();assert.equal(calls.filter(call=>call.options.method==='POST').length,1);assert.equal(jointReviewJob,null);assert.equal($('joint-ai-job').hidden,true);assert.match($('joint-ai-review-status').textContent,/不匹配/);
""")
