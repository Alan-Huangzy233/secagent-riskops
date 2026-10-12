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
