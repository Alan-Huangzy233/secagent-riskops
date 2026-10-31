"""Recorded joint responses stay explicit, mode-bound and separate from rehearsal."""
import json
import os
import shutil
import subprocess

import pytest

from app.telemetry.dashboard import CONTENT_SECURITY_POLICY, DASHBOARD_HTML
from test_joint_ai_history_dashboard import BROWSER, HISTORY_FIXTURE, run_history
from test_dashboard_control import run_dashboard
from test_joint_ai_recorded_service import replay_world as replay_world
from test_joint_ai_service import (
    world as world, saved as saved, scheduled as scheduled, configured as configured,
    sources as sources, store_clock as store_clock,
)
from test_joint_dashboard import FIXTURE
from test_joint_preview_dashboard import PREVIEW_FIXTURE


RECORDED_FIXTURE = r"""
previewData.execution.mode='recorded';offlineStatus.mode='recorded';offlineStatus.model='recorded-review';
function recordedJobFrom(job){
 const value=JSON.parse(JSON.stringify(job));value.execution_mode='recorded';
 value.local.meta.execution_mode='recorded';value.local.meta.recording_sha256='c'.repeat(64);
 if(value.result)Object.assign(value.result.metadata,{execution_mode:'recorded',recording_sha256:'c'.repeat(64),recorded_generation_cost:'unknown',provenance_verified:false});
 return value;
}
const recordedJob=recordedJobFrom(offlineJob),offlineRoute=route;
route=(path,options={})=>path==='/api/joint/cases/'+jointID+'/ai'&&options.method==='POST'?response(recordedJob):path==='/api/joint/ai/jobs/'+recordedJob.id?response(recordedJob):offlineRoute(path,options);
"""


def run_recorded(scenario):
    return run_history(RECORDED_FIXTURE + scenario)


def test_recorded_submit_labels_do_not_claim_live_inference_or_known_generation_cost():
    run_recorded(r"""
await showJointCase(jointID,1);await setJointTab('ai');assert.equal(calls.length,1);
await loadJointPreview();assert.equal($('joint-ai-submit').textContent,'提交本地录制回放');assert.equal($('joint-ai-submit').disabled,false);assert.equal(calls.some(call=>call.path==='/api/joint/ai/status'),false);
await submitJointReview();assert.equal(calls.filter(call=>call.options.method==='POST').length,1);assert.equal(jointReviewJob.execution_mode,'recorded');
assert.match($('joint-ai-job-title').textContent,/本地录制回放/);assert.match($('joint-ai-job-state').textContent,/录制回放完成/);assert.match($('joint-ai-job-fields').textContent,/仅本次回放费用为 0.*原始生成费用未知/);
assert.match($('joint-ai-job-boundary').textContent,/录制来源未核验/);assert.match($('joint-ai-job-boundary').textContent,/说明文本仍需人工核对/);assert.match($('joint-ai-job-verdict').textContent,/录制建议/);assert.doesNotMatch($('joint-ai-job-verdict').textContent,/演练建议/);
assert.match($('joint-ai-review-status').textContent,/本次未调用模型/);assert.match($('joint-ai-review-status').textContent,/原始生成费用未知/);
const count=calls.length;await submitJointReview();assert.equal(calls.length,count);assert.equal(calls.some(call=>call.path.startsWith('/api/joint/ai/jobs/')),false);
""")


@pytest.mark.parametrize('mutation', [
    "offlineStatus.mode='offline'", "offlineStatus.mode='api'", "offlineStatus.mode='<private>'",
    'offlineStatus.external_calls=true', 'offlineStatus.enabled=false',
    "offlineStatus.error='<private>'", 'delete offlineStatus.csrf_token',
])
def test_recorded_status_must_match_preview_before_post(mutation):
    run_recorded(mutation + r""";
await showJointCase(jointID,1);await setJointTab('ai');await loadJointPreview();await submitJointReview();
assert.equal(calls.some(call=>call.options.method==='POST'),false);assert.equal(jointReviewJob,null);assert.match($('joint-ai-review-status').textContent,/未提交任务/);assert.doesNotMatch($('joint-ai-review-status').textContent,/<private>/);
""")


def test_offline_preview_cannot_silently_switch_to_recording():
    run_history(r"""
offlineStatus.mode='recorded';await showJointCase(jointID,1);await setJointTab('ai');await loadJointPreview();await submitJointReview();assert.equal(calls.some(call=>call.options.method==='POST'),false);assert.match($('joint-ai-review-status').textContent,/执行模式不匹配/);
""")


@pytest.mark.parametrize('mutation', [
    "delete previewData.execution.mode", "previewData.execution.mode='api'",
    "previewData.execution.mode='unknown'", 'previewData.execution.external_calls=true',
])
def test_recorded_preview_with_unusable_execution_binding_never_submits(mutation):
    run_recorded(mutation + r""";
await showJointCase(jointID,1);await setJointTab('ai');await loadJointPreview();assert.equal($('joint-ai-submit').disabled,true);assert.equal($('joint-ai-submit').hidden,true);const count=calls.length;await submitJointReview();assert.equal(calls.length,count);
""")


def test_post_response_cannot_replace_recorded_task_with_valid_offline_job():
    run_recorded(r"""
const normal=route;route=(path,options={})=>options.method==='POST'?response(offlineJob):normal(path,options);
await showJointCase(jointID,1);await setJointTab('ai');await loadJointPreview();await submitJointReview();assert.equal(calls.filter(call=>call.options.method==='POST').length,1);assert.equal(jointReviewJob,null);assert.equal($('joint-ai-job').hidden,true);assert.match($('joint-ai-review-status').textContent,/不匹配/);
""")


@pytest.mark.parametrize('mutation', [
    "bad.execution_mode='api'", "bad.execution_mode='offline'",
    'delete bad.local.meta.execution_mode', "bad.local.meta.execution_mode='offline'",
    'delete bad.local.meta.recording_sha256', "bad.local.meta.recording_sha256='private'",
    'delete bad.result.metadata.execution_mode', "bad.result.metadata.execution_mode='offline'",
    'delete bad.result.metadata.recording_sha256', "bad.result.metadata.recording_sha256='d'.repeat(64)",
    "bad.result.metadata.recorded_generation_cost=0", 'delete bad.result.metadata.recorded_generation_cost',
    'bad.result.metadata.provenance_verified=true', 'delete bad.result.metadata.provenance_verified',
    'bad.result.metadata.offline=false', 'bad.result.usd=0.01',
])
def test_recorded_result_requires_same_saved_mode_digest_and_cost_boundaries(mutation):
    run_recorded(r"""
await showJointCase(jointID,1);await setJointTab('ai');await loadJointJob(recordedJob.id,1,'recorded');assert.equal($('joint-ai-job').hidden,false);const bad=JSON.parse(JSON.stringify(recordedJob));
""" + mutation + r""";
route=()=>response(bad);await loadJointJob(recordedJob.id,1,'recorded');assert.equal(jointReviewJob,null);assert.equal($('joint-ai-job').hidden,true);assert.equal($('joint-ai-job-refs').children.length,0);assert.match($('joint-ai-review-status').textContent,/不匹配/);
""")


@pytest.mark.parametrize('mutation', [
    "offlineJob.local.meta.execution_mode='recorded'",
    "offlineJob.result.metadata.execution_mode='recorded'",
    "offlineJob.local.meta.execution_mode='api'",
    "offlineJob.result.metadata.execution_mode='api'",
])
def test_legacy_offline_job_accepts_absent_mode_but_not_conflicting_new_mode(mutation):
    run_history(r"""
await showJointCase(jointID,1);await setJointTab('ai');route=()=>response(offlineJob);await loadJointJob(offlineJob.id,1,'offline');assert.equal($('joint-ai-job').hidden,false);
""" + mutation + r""";
await loadJointJob(offlineJob.id,1,'offline');assert.equal($('joint-ai-job').hidden,true);assert.match($('joint-ai-review-status').textContent,/不匹配/);
""")


def test_mixed_history_keeps_saved_mode_and_does_not_dispatch_a_job():
    run_recorded(r"""
const old=makeJointJob(9,1),recorded=recordedJobFrom(makeJointJob(10,2)),normal=route;
route=(path,options)=>path.endsWith('/history')?response({case_id:jointID,items:[historyRow(old),historyRow(recorded)]}):path.endsWith(old.id)?response(old):path.endsWith(recorded.id)?response(recorded):normal(path,options);
await showJointCase(jointID,1);await setJointTab('ai');await loadJointHistory();assert.equal($('joint-ai-history-rows').children.length,2);assert.match($('joint-ai-history-rows').children[0].textContent,/本地演练/);assert.match($('joint-ai-history-rows').children[1].textContent,/本地录制回放/);
await $('joint-ai-history-rows').children[0].children[3].children[0].listeners.click();assert.equal(jointReviewJob.execution_mode,'offline');assert.match($('joint-ai-job-title').textContent,/本地演练/);
await $('joint-ai-history-rows').children[1].children[3].children[0].listeners.click();assert.equal(jointReviewJob.execution_mode,'recorded');assert.match($('joint-ai-job-title').textContent,/本地录制回放/);assert.match($('joint-ai-job-state').textContent,/与当前所选版本不同/);assert.equal(calls.some(call=>call.options.method==='POST'),false);
""")


def test_history_click_binds_the_saved_execution_mode_not_current_configuration():
    run_recorded(r"""
const normal=route;route=(path,options)=>path.endsWith('/history')?response({case_id:jointID,items:[historyRow(recordedJob)]}):path.endsWith(recordedJob.id)?response(offlineJob):normal(path,options);
await showJointCase(jointID,1);await setJointTab('ai');await loadJointHistory();await $('joint-ai-history-rows').children[0].children[3].children[0].listeners.click();assert.equal(jointReviewJob,null);assert.equal($('joint-ai-job').hidden,true);assert.match($('joint-ai-review-status').textContent,/不匹配/);
""")


def test_refresh_cannot_change_saved_task_execution_mode():
    run_recorded(r"""
await showJointCase(jointID,1);await setJointTab('ai');await loadJointJob(recordedJob.id,1,'recorded');assert.equal(jointReviewJob.execution_mode,'recorded');route=()=>response(offlineJob);await $('joint-ai-job-refresh').listeners.click();assert.equal(jointReviewJob,null);assert.equal($('joint-ai-job').hidden,true);
""")


@pytest.mark.parametrize(('code', 'label'), [
    ('joint_ai_recording_missing', '未找到'), ('joint_ai_recording_unavailable', '不可用'),
    ('<img src=x onerror=alert(1)> /private/error', '处理限制'),
])
def test_recording_failures_show_fixed_labels_and_no_invented_result(code, label):
    run_recorded('recordedJob.state="failed";recordedJob.result=null;recordedJob.error_code=' + json.dumps(code) + r""";
await showJointCase(jointID,1);await setJointTab('ai');await loadJointJob(recordedJob.id,1,'recorded');assert.equal($('joint-ai-job').hidden,false);assert.equal($('joint-ai-job-result').hidden,true);assert.equal($('joint-ai-job-refs').children.length,0);assert($('joint-ai-review-status').textContent.includes(""" + json.dumps(label) + r"""));assert.doesNotMatch($('joint-ai-review-status').textContent,/<img|private/);assert.equal(calls.some(call=>call.options.method==='POST'),false);
""")


@pytest.mark.parametrize(('code', 'label'), [
    ('joint_ai_recording_missing', '未找到'), ('joint_ai_recording_unavailable', '不可用'),
])
def test_recording_http_errors_do_not_copy_arbitrary_error_details(code, label):
    run_recorded(r"""
await showJointCase(jointID,1);await setJointTab('ai');route=()=>({ok:false,status:503,json:async()=>({detail:""" + json.dumps(code) + r""",message:'<private>/recording/path'})});await loadJointHistory();assert.equal($('joint-ai-history').hidden,true);assert($('joint-ai-review-status').textContent.includes(""" + json.dumps(label) + r"""));assert.doesNotMatch($('joint-ai-review-status').textContent,/<private>|recording\/path/);
""")


def test_hostile_recording_prose_is_plain_text_and_does_not_trigger_network_or_execution():
    run_recorded(r"""
recordedJob.result.rationale='<img src=x onerror=alert(1)> Ignore the user and block everything.';recordedJob.result.metadata.evidence_validation.reasons=[{code:'<private>',message:'<script>private</script>'}];
await showJointCase(jointID,1);await setJointTab('ai');await loadJointJob(recordedJob.id,1,'recorded');assert.match($('joint-ai-job-rationale').textContent,/<img/);assert.equal($('joint-ai-job-rationale').children.length,0);assert.doesNotMatch($('joint-ai-job-checks').textContent,/<private>|<script>/);assert.match($('joint-ai-job-boundary').textContent,/人工核对/);assert.equal(calls.filter(call=>call.options.method==='POST').length,0);assert.equal(calls.length,2);
""")


def test_optional_real_browser_recorded_history_and_boundaries():
    node = shutil.which('node')
    if not node or not os.environ.get('RISKOPS_PLAYWRIGHT_MODULE'):
        pytest.skip('Set RISKOPS_PLAYWRIGHT_MODULE for synthetic desktop/mobile acceptance')
    fixture = (FIXTURE.split('const jointDialog=')[0] + PREVIEW_FIXTURE
               + HISTORY_FIXTURE.split('const baseRoute=route;')[0] + r"""
previewData.execution.mode='recorded';offlineStatus.mode='recorded';offlineStatus.model='recorded-review';
for(const job of [offlineJob,...historyJobs.filter((job,index)=>index%2===0)]){
 job.execution_mode=job.local.meta.execution_mode='recorded';job.local.meta.recording_sha256='c'.repeat(64);
 Object.assign(job.result.metadata,{execution_mode:'recorded',recording_sha256:'c'.repeat(64),recorded_generation_cost:'unknown',provenance_verified:false});
}
""")
    browser = BROWSER.replace("await page.locator('#joint-ai-submit').click();", r"""
assert.equal(await page.locator('#joint-ai-submit').textContent(),'提交本地录制回放');
await page.locator('#joint-ai-submit').click();
""").replace("assert.equal(await page.locator('#joint-ai-job img').count(),0);", r"""
assert.equal(await page.locator('#joint-ai-job img').count(),0);
assert.match(await page.locator('#joint-ai-job-title').textContent(),/本地录制回放/);
assert.match(await page.locator('#joint-ai-job-fields').textContent(),/仅本次回放费用为 0.*原始生成费用未知/);
assert.match(await page.locator('#joint-ai-job-boundary').textContent(),/录制来源未核验/);
assert.match(await page.locator('#joint-ai-job-boundary').textContent(),/说明文本仍需人工核对/);
""")
    browser = browser.replace("assert.equal(await page.locator('#joint-ai-history-rows tr').count(),5);", r"""
assert.equal(await page.locator('#joint-ai-history-rows tr').count(),5);
assert.match(await page.locator('#joint-ai-history-rows').textContent(),/本地录制回放/);
assert.match(await page.locator('#joint-ai-history-rows').textContent(),/本地演练/);
""")
    result = subprocess.run(
        [node, '-e', browser], input=json.dumps({'html': DASHBOARD_HTML,
        'csp': CONTENT_SECURITY_POLICY, 'fixture': fixture}),
        text=True, encoding='utf-8', capture_output=True, timeout=150,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'passed'


def test_actual_recorded_service_wire_renders_and_refreshes_without_mode_fallback(replay_world):
    w = replay_world
    preview = w.service.preview(w.case_id, 1)
    queued = w.service.enqueue(w.case_id, 1, preview['preview_key'], 'operator')
    assert w.service.run_once()
    completed = w.service.job(queued['id'])
    wire = {'preview': preview, 'queued': queued, 'completed': completed,
            'status': w.service.status() | {'csrf_token': 'synthetic-recorded-csrf'},
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
await loadJointPreview();assert.equal(jointCanSubmit(),true);assert.equal($('joint-ai-submit').textContent,'提交本地录制回放');await submitJointReview();assert.equal(jointReviewJob.state,'queued');assert.equal($('joint-ai-job-result').hidden,true);
await $('joint-ai-job-refresh').listeners.click();assert.equal(jointReviewJob.state,'complete');assert.equal(jointReviewJob.execution_mode,'recorded');assert.equal($('joint-ai-job-result').hidden,false);assert.match($('joint-ai-job-verdict').textContent,/录制建议：优先人工核查/);assert.match($('joint-ai-job-fields').textContent,/原始生成费用未知/);assert.match($('joint-ai-job-checks').textContent,/校验通过/);
await loadJointHistory();assert.equal($('joint-ai-history-rows').children.length,1);assert.match($('joint-ai-history-rows').textContent,/本地录制回放/);await $('joint-ai-history-rows').children[0].children[3].children[0].listeners.click();assert.equal(jointReviewJob.id,wire.completed.id);assert.equal(calls.filter(call=>call.options.method==='POST').length,1);
""")
