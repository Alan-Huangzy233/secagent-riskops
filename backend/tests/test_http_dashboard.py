"""HTTP UI: async navigation, literal evidence, revision pinning and safe reads."""
from test_dashboard_control import ControlsHTML, run_dashboard
from app.telemetry.dashboard import DASHBOARD_HTML

FIXTURE = r"""
const caseRecord={incident_id:'HTTP-example',source_id:'web',service_id:'public',client_ip:'198.51.100.23',title:'HTTP 请求异常',revision:2,updated_at:'2026-01-01T12:30:00Z',last_seen:'2026-01-01T12:00:00Z',window_start:'2026-01-01T12:00:00Z',window_end:'2026-01-01T13:00:00Z',evidence_count:26,coverage:'complete',stale:false,active:true,rules:[{label:'扫描',evidence_count:26}],assessment:{score:30,priority:'P3',reasons:[{reason:'扫描',criteria:'300 秒内',points:30}],note:'请求模式不能证明入侵成功'}};
const httpFixture={enabled:true,sources:[{id:'web',hostname:'example.invalid',services:['public','private']}],last_run:new Date().toISOString(),pending:false,analyzed_input_records:26,missing_raw_records:0,coverage_issues:[],collection:[{source_id:'web',service_id:'public',status:'current',accepted_total:26,rejected_total:0}]};
const dialog=$('http-dialog');dialog.showModal=()=>{dialog.open=true;};dialog.close=()=>{dialog.open=false;dialog.listeners.close();};
route=path=>{
 if(path==='/api/http/status')return response(httpFixture);
 if(path.startsWith('/api/http/incidents?')){const q=new URLSearchParams(path.split('?')[1]);return response({items:[{...caseRecord,client_ip:q.get('page')==='2'?'192.0.2.9':caseRecord.client_ip}],page:Number(q.get('page')),total_pages:2,total:51});}
 if(path.includes('/evidence?')){const q=new URLSearchParams(path.split('?')[1]);return response({revision:Number(q.get('revision')),items:[{timestamp:caseRecord.last_seen,method:'GET',path:'/<img src=x onerror=alert(1)>',status:404}],page:Number(q.get('page')),total_pages:2,total:26});}
 if(path==='/api/http/incidents/HTTP-example')return response(caseRecord);
 if(path==='/api/http/incidents/HTTP-example?revision=1')return response({...caseRecord,revision:1});
 throw new Error('Unexpected path '+path);
};
$('http-focus').value='all';
"""


def test_http_has_independent_table_dialog_and_filters():
    html = ControlsHTML()
    html.feed(DASHBOARD_HTML)
    assert not html.duplicates
    assert html.elements['workspace-tab-http'][1]['aria-controls'] == 'workspace-http'
    assert html.elements['http-dialog'][0] == 'dialog'
    assert html.elements['http-evidence'][0] == 'tbody'
    assert html.elements['http-source'][0] == 'select'
    assert html.elements['http-tab-evidence'][1]['aria-controls'] == 'http-pane-evidence'
    assert 'HTTP 事件单独通知' in DASHBOARD_HTML


def test_http_table_pages_and_filters_do_not_use_ssh_or_action_endpoints():
    run_dashboard(FIXTURE + r"""
await selectWorkspace('http');assert.equal($('source-filter').disabled,true);assert.match($('http-rows').textContent,/198.51.100.23/);
await loadHttp(2);assert.match($('http-rows').textContent,/192.0.2.9/);assert.match($('http-page').textContent,/第 2 \/ 2 页/);
$('http-source').value='web';$('http-service').value='private';await loadHttp(1);
assert.match(calls[calls.length-1].path,/source_id=web&service_id=private/);
assert.equal(calls.every(c=>c.path.startsWith('/api/http/')&&(c.options.method||'GET')==='GET'),true);
setWorkspace('incidents');assert.equal($('source-filter').disabled,false);
""")


def test_older_table_response_and_failures_cannot_replace_visible_rows():
    run_dashboard(FIXTURE + r"""
await loadHttp();let finish;const normal=route;
route=path=>path.startsWith('/api/http/incidents?')?new Promise(resolve=>{finish=()=>resolve(response({items:[],page:1,total_pages:1,total:0}));}):normal(path);
const pending=loadHttp();for(let i=0;i<15;i++)await Promise.resolve();
route=normal;await loadHttp(2);finish();await pending;assert.match($('http-rows').textContent,/192.0.2.9/);
route=()=>({ok:false,status:503,json:async()=>({detail:'temporary'})});await loadHttp();
assert.match($('http-rows').textContent,/192.0.2.9/);assert.match($('http-status').textContent,/已保留/);
""")


def test_drawer_pins_revision_for_all_evidence_pages_and_renders_literal_paths():
    run_dashboard(FIXTURE + r"""
let restored=0;document.activeElement={isConnected:true,focus:()=>restored++};
await showHttpIncident('HTTP-example',1);assert.equal(dialog.open,true);assert.match($('http-revision').textContent,/版本 1 \/ 2 · 历史快照/);
assert.equal($('http-pane-evidence').hidden,true);setHttpDetailTab('evidence');assert.equal($('http-pane-overview').hidden,true);
assert.match($('http-evidence').textContent,/<img src=x onerror=alert\(1\)>/);
assert.equal($('http-evidence').children[0].children[2].children.length,0);
await loadHttpEvidence(2);assert.match(calls[calls.length-1].path,/revision=1&page=2/);
dialog.close();assert.equal(restored,1);assert.equal(httpDetail,null);
assert.equal(calls.every(c=>c.path.startsWith('/api/http/')&&(c.options.method||'GET')==='GET'),true);
""")


def test_closing_drawer_ignores_late_response_and_old_evidence_cannot_leak_into_new_revision():
    run_dashboard(FIXTURE + r"""
let finish;const normal=route;route=path=>path.includes('/evidence?')?new Promise(resolve=>{finish=()=>resolve(normal(path));}):normal(path);
const pending=showHttpIncident('HTTP-example',1);for(let i=0;i<20;i++)await Promise.resolve();
dialog.close();route=normal;await showHttpIncident('HTTP-example',2);finish();await pending;
assert.equal(httpDetail.revision,2);assert.match($('http-revision').textContent,/版本 2 \/ 2/);
assert.match($('http-evidence-page').textContent,/26 条证据/);
""")


def test_notification_opens_generation_time_revision_and_disabled_state_is_clear():
    run_dashboard(FIXTURE + r"""
renderNotifications({items:[{id:1,kind:'http_incident',payload:{...caseRecord,revision:1},delivered_at:1800000000,read_at:null}],page:1,total_pages:1,total:1,unread:1,pending:0,retrying:0,health:[],enabled:false});
assert.match($('notification-rows').textContent,/版本 1/);
await $('notification-rows').children[0].children[2].children[2].listeners.click();
assert.equal(httpDetail.revision,1);
route=()=>response({enabled:false});await loadHttp();assert.match($('http-health').textContent,/尚未配置/);assert.equal($('http-next').disabled,true);
""")


def test_http_briefing_is_distinct_from_ssh_and_renders_untrusted_text_literally():
    run_dashboard(FIXTURE + r"""
const payload={report_type:'http_daily',title:'2026-01-02 HTTP 每日简报（UTC）',cutoff:1800000000,counts:{requests:42,cases:3,attention:1,low:1,retracted:0,stale:1,batches:4,rejected:2,reported_batches:1,backlog_batches:1},analysis_pending:true,missing_raw_records_total:7,skipped_days:2,note:'<img src=x onerror=alert(1)>'};
renderNotifications({items:[{id:2,kind:'briefing',payload,delivered_at:1800000010,read_at:1}],page:1,total_pages:1,total:1,unread:0,pending:0,retrying:0,health:[],enabled:true});
const text=$('notification-rows').textContent;
assert.match(text,/HTTP 请求 42 条/);assert.match(text,/证据不完整 1/);assert.match(text,/检测尚未追平/);assert.match(text,/非当日计数/);assert.match(text,/2 天超出/);assert.match(text,/汇总截止/);
assert.match(text,/<img src=x onerror=alert\(1\)>/);assert.equal($('notification-rows').children[0].children[2].children[1].children.length,0);
assert.equal(calls.length,0);
assert.match(notificationText({kind:'briefing',payload:{log_count:10,new_incidents:1,attention:1,low:0,unscored:0,collection_gaps:0,note:'SSH'}}),/已采集日志 10 条/);
httpHealth({...httpFixture,briefing_in_progress:'2026-01-02',briefing_error:'HTTP 简报汇总暂时失败，将自动重试'});
assert.match($('http-health').textContent,/正在生成 2026-01-02 HTTP 简报/);assert.match($('http-health').textContent,/将自动重试/);
""")


RESTORE_FIXTURE = r"""
const restoreRecord={restore_id:'a'.repeat(64),backup_id:'rp-20261015-example',snapshot_at:'2026-10-15T01:00:00Z',marked_at:'2026-10-15T03:00:00Z',stream_count:2,verification_scope:'paired_database_snapshots'};
const eventRoute=route;
route=path=>{
 if(path.startsWith('/api/http/restores?')){const q=new URLSearchParams(path.split('?')[1]);return response({items:[{...restoreRecord,backup_id:'backup-page-'+q.get('page')}],page:Number(q.get('page')),limit:20,total_pages:2,total:21});}
 return eventRoute(path);
};
"""


def test_http_recovery_is_a_separate_accessible_tab_with_limited_claims():
    html = ControlsHTML()
    html.feed(DASHBOARD_HTML)
    assert html.elements['http-view-incidents'][1]['aria-selected'] == 'true'
    assert html.elements['http-view-restores'][1]['aria-controls'] == 'http-pane-restores'
    assert html.elements['http-view-restores'][1]['tabindex'] == '-1'
    assert html.elements['http-pane-restores'][1]['role'] == 'tabpanel'
    assert html.elements['http-pane-restores'][1]['aria-labelledby'] == 'http-view-restores'
    assert 'hidden' in html.elements['http-pane-restores'][1]
    assert 'disabled' in html.elements['http-restores-next'][1]
    assert '记录仅核对 HTTP 与控制台双库快照' in DASHBOARD_HTML
    assert '不代表日志未丢失或已补齐' in DASHBOARD_HTML
    assert '标记时间是登记这条记录的时间' in DASHBOARD_HTML


def test_restore_pages_refresh_independently_and_never_inherit_incident_filters():
    run_dashboard(FIXTURE + RESTORE_FIXTURE + r"""
await selectWorkspace('http');assert.equal(httpView,'incidents');
$('http-source').value='web';$('http-service').value='private';$('http-focus').value='attention';currentSource='ssh-source';
await $('http-view-restores').listeners.click();
assert.equal($('http-pane-incidents').hidden,true);assert.equal($('http-pane-restores').hidden,false);
assert.equal($('http-view-restores').attrs['aria-selected'],'true');assert.equal($('http-view-incidents').tabIndex,-1);
assert.match($('http-restores-rows').textContent,/backup-page-1/);
await $('http-restores-next').listeners.click();assert.match($('http-restores-page').textContent,/第 2 \/ 2 页/);
assert.equal($('http-restores-prev').disabled,false);assert.equal($('http-restores-next').disabled,true);
assert.match(calls[calls.length-1].path,/^\/api\/http\/restores\?page=2&limit=20$/);
const before=calls.length;await $('http-source').listeners.change();await $('http-service').listeners.change();await $('http-focus').listeners.change();assert.equal(calls.length,before);
await loadWorkspaceView(true);assert.equal(calls[calls.length-1].path,'/api/http/restores?page=2&limit=20');
await $('http-restores-prev').listeners.click();await $('http-restores-refresh').listeners.click();assert.match($('http-restores-rows').textContent,/backup-page-1/);
await $('http-view-incidents').listeners.click();assert.equal($('http-pane-restores').hidden,true);
assert.match(calls[calls.length-1].path,/focus=attention&source_id=web&service_id=private/);
assert.equal(calls.every(c=>c.path.startsWith('/api/http/')&&(c.options.method||'GET')==='GET'),true);
""")


def test_restore_tab_keyboard_navigation_updates_focus_and_aria():
    run_dashboard(FIXTURE + RESTORE_FIXTURE + r"""
let focused='',prevented=0;
for(const name of ['incidents','restores'])$('http-view-'+name).focus=()=>{focused=name;};
await $('http-view-incidents').listeners.keydown({key:'End',preventDefault:()=>prevented++});
assert.equal(httpView,'restores');assert.equal(focused,'restores');assert.equal($('http-view-restores').tabIndex,0);
await $('http-view-restores').listeners.keydown({key:'ArrowRight',preventDefault:()=>prevented++});
assert.equal(httpView,'incidents');assert.equal(focused,'incidents');
await $('http-view-incidents').listeners.keydown({key:'ArrowLeft',preventDefault:()=>prevented++});
assert.equal(httpView,'restores');
await $('http-view-restores').listeners.keydown({key:'Home',preventDefault:()=>prevented++});
assert.equal(httpView,'incidents');assert.equal(prevented,4);
""")


def test_restore_requests_ignore_late_pages_and_previous_tab_responses():
    run_dashboard(FIXTURE + RESTORE_FIXTURE + r"""
await selectHttpView('restores');const normal=route;let finish;
route=path=>path.startsWith('/api/http/restores?')?new Promise(resolve=>{finish=()=>resolve(response({items:[{...restoreRecord,backup_id:'obsolete'}],page:1,limit:20,total_pages:2,total:21}));}):normal(path);
const pending=loadHttpRestores(1);for(let i=0;i<15;i++)await Promise.resolve();
assert.equal($('http-restores-next').disabled,true);assert.equal($('http-pane-restores').attrs['aria-busy'],'true');
route=normal;await loadHttpRestores(2);finish();await pending;
assert.match($('http-restores-rows').textContent,/backup-page-2/);assert.doesNotMatch($('http-restores-rows').textContent,/obsolete/);
route=path=>path.startsWith('/api/http/restores?')?new Promise(resolve=>{finish=()=>resolve(response({items:[{...restoreRecord,backup_id:'wrong-tab'}],page:2,limit:20,total_pages:2,total:21}));}):normal(path);
const hidden=loadHttpRestores(2);for(let i=0;i<15;i++)await Promise.resolve();
route=normal;await selectHttpView('incidents');finish();await hidden;
assert.match($('http-rows').textContent,/198.51.100.23/);assert.doesNotMatch($('http-restores-rows').textContent,/wrong-tab/);
await selectHttpView('restores');assert.equal($('http-pane-restores').attrs['aria-busy'],'false');
route=path=>path==='/api/http/status'?new Promise(resolve=>{finish=()=>resolve(response({enabled:false}));}):normal(path);
const oldStatus=loadHttpRestores();for(let i=0;i<15;i++)await Promise.resolve();
route=normal;await loadHttpRestores(1);finish();await oldStatus;
assert.match($('http-restores-rows').textContent,/backup-page-1/);assert.equal($('http-restores-next').disabled,false);
""")


def test_restore_failure_keeps_rows_and_server_can_clamp_expired_page():
    run_dashboard(FIXTURE + RESTORE_FIXTURE + r"""
await selectHttpView('restores');await loadHttpRestores(2);const normal=route;
route=path=>path.startsWith('/api/http/restores?')?({ok:false,status:503,json:async()=>({})}):normal(path);
await loadHttpRestores(1);assert.match($('http-restores-rows').textContent,/backup-page-2/);assert.match($('http-restores-status').textContent,/503.*已保留/);
assert.match($('http-restores-page').textContent,/第 2 \/ 2 页/);assert.equal($('http-restores-prev').disabled,false);
route=path=>{
 if(path.startsWith('/api/http/restores?'))return response({items:[restoreRecord],page:1,limit:20,total_pages:1,total:1});
 return normal(path);
};
await loadHttpRestores(2);assert.equal(calls[calls.length-1].path,'/api/http/restores?page=2&limit=20');assert.match($('http-restores-page').textContent,/第 1 \/ 1 页/);
assert.match($('http-restores-rows').textContent,/rp-20261015-example/);assert.equal($('http-restores-prev').disabled,true);assert.equal($('http-restores-next').disabled,true);
route=path=>path.startsWith('/api/http/restores?')?response({items:[{...restoreRecord,backup_id:'unexpected-page'}],page:2,limit:20,total_pages:2,total:21}):normal(path);
await loadHttpRestores(1);assert.match($('http-restores-rows').textContent,/rp-20261015-example/);assert.match($('http-restores-status').textContent,/页码已变化/);
route=path=>path.startsWith('/api/http/restores?')?response({items:[restoreRecord,{...restoreRecord,backup_id:'partial-update',verification_scope:'unknown'}],page:1,limit:20,total_pages:1,total:2}):normal(path);
await loadHttpRestores(1);assert.equal($('http-restores-rows').children.length,1);assert.doesNotMatch($('http-restores-rows').textContent,/partial-update/);assert.match($('http-restores-status').textContent,/返回异常.*已保留/);
""")


def test_restore_empty_and_unconfigured_states_disable_both_page_buttons():
    run_dashboard(FIXTURE + RESTORE_FIXTURE + r"""
await selectHttpView('restores');await loadHttpRestores(2);const normal=route;
route=path=>path.startsWith('/api/http/restores?')?response({items:[],page:1,limit:20,total_pages:1,total:0}):normal(path);
await loadHttpRestores(1);assert.match($('http-restores-rows').textContent,/尚无 HTTP 恢复记录/);
assert.equal($('http-restores-prev').disabled,true);assert.equal($('http-restores-next').disabled,true);
route=normal;await loadHttpRestores(2);
route=path=>path==='/api/http/status'?response({enabled:false}):normal(path);
const before=calls.length;await loadHttpRestores();assert.equal(calls.length,before+1);
assert.match($('http-restores-rows').textContent,/HTTP 来源尚未配置/);assert.doesNotMatch($('http-restores-rows').textContent,/backup-page/);
assert.equal($('http-restores-prev').disabled,true);assert.equal($('http-restores-next').disabled,true);assert.equal($('http-restores-page').textContent,'');
assert.equal($('http-restores-status').textContent,'');assert.equal(httpRestorePage,1);
""")


def test_restore_rows_render_literal_text_without_internal_hashes_or_paths():
    run_dashboard(FIXTURE + RESTORE_FIXTURE + r"""
const normal=route,hostile='<img src=x onerror=alert(1)>';
route=path=>path.startsWith('/api/http/restores?')?response({items:[{...restoreRecord,backup_id:hostile,archive_path:'/private/backup',http_sha256:'secret-hash'}],page:1,limit:20,total_pages:1,total:1}):normal(path);
await selectHttpView('restores');const rows=$('http-restores-rows');
assert.match(rows.textContent,/<img src=x onerror=alert\(1\)>/);assert.equal(rows.children[0].children[1].children.length,0);
assert.doesNotMatch(rows.textContent,/private|secret-hash/);assert.doesNotMatch(rows.textContent,new RegExp('a'.repeat(64)));
assert.equal(rows.children[0].children.length,4);assert.equal(rows.children[0].children[3].textContent,'2');
""")
