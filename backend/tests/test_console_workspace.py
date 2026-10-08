"""User-facing tab, pagination and refresh semantics with inert HTTP fixtures."""
from test_dashboard_control import ControlsHTML, run_dashboard
from app.telemetry.dashboard import DASHBOARD_HTML


FIXTURE = r"""
const page=(items=[],extra={})=>({page:1,total_pages:1,total:items.length,items,...extra});
const fixture={state:'ready',age_seconds:1,max_age_seconds:120,generation:1,stale:false,generated_at:'2026-01-01T00:00:00Z',data:{
 summary:{sources:[],totals:{events:40,ssh_failures:20,ssh_successes:3,incidents:1}},
 events:page([{event_id:'cached-event',message:'cached log'}],{snapshot:'r1:40'}),
 incidents:page([{incident_id:'cached-incident',src_ip:'192.0.2.1'}])}};
route=path=>{
 if(path==='/api/console/bootstrap')return response(fixture);
 if(path==='/api/controls')return response({enabled:false,csrf_token:'fixture',sources:[],blocks:[],jobs:[]});
 throw new Error('Unexpected request '+path);
};
"""


def test_semantic_tabs_dialog_and_inline_content_have_unique_targets():
    html = ControlsHTML()
    html.feed(DASHBOARD_HTML)
    assert not html.duplicates
    for key in ("incidents", "events", "overview", "notifications", "collection", "ip", "controls"):
        panel = html.elements[f"workspace-{key}"][1]
        tab = html.elements[f"workspace-tab-{key}"][1]
        assert tab["role"] == "tab" and panel["role"] == "tabpanel"
        assert ("hidden" in panel) == (key != "incidents")
        assert tab["aria-controls"] == f"workspace-{key}"
    assert html.elements["detail-dialog"][0] == "dialog"
    for key in ("overview", "evidence", "ai"):
        assert html.elements[f"detail-tab-{key}"][1]["aria-controls"] == f"detail-pane-{key}"


def test_first_visit_renders_warm_data_before_control_state_without_eager_hidden_reads():
    run_dashboard(FIXTURE + r"""
let finishControls;
const normal=route;route=path=>path==='/api/controls'?new Promise(resolve=>{finishControls=()=>resolve(response({enabled:false}));}):normal(path);
const reading=refresh();
for(let i=0;i<12;i++)await Promise.resolve();
assert.match($('incidents').textContent,/192.0.2.1/);
assert.equal(JSON.stringify(calls.map(c=>c.path)),JSON.stringify(['/api/console/bootstrap','/api/controls']));
finishControls();await reading;
await selectWorkspace('events');assert.match($('events').textContent,/cached log/);
assert.equal(eventSnapshot,'r1:40');assert.equal(calls.length,2);
assert.equal($('workspace-incidents').hidden,true);assert.equal($('workspace-events').hidden,false);
assert.equal(calls.filter(c=>(c.options.method||'GET')!=='GET').length,0);
""")


def test_custom_queries_pages_and_frozen_log_snapshot_do_not_take_cached_first_page():
    run_dashboard(FIXTURE + r"""
await readBootstrap();
eventFilters={q:'filter'};assert.equal(cachedListAvailable('event'),false);
eventFilters={};pages.event.page=2;assert.equal(cachedListAvailable('event'),false);
pages.event.page=1;eventSnapshot='r1:39';assert.equal(cachedListAvailable('event'),false);
eventSnapshot=null;currentSource='source-a';assert.equal(cachedListAvailable('event'),false);
currentSource='';incidentTriage='resolved';assert.equal(cachedListAvailable('incident'),false);
incidentTriage='pending';assert.equal(cachedListAvailable('incident'),true);
fixture.stale=true;await readBootstrap();assert.equal(cachedListAvailable('incident'),false);
fixture.stale=false;fixture.age_seconds=121;await readBootstrap();assert.equal(cachedListAvailable('incident'),false);
""")


def test_local_disposition_blocks_old_bootstrap_until_a_new_clean_generation():
    run_dashboard(FIXTURE + r"""
await readBootstrap();invalidateBootstrap();
await readBootstrap();assert.equal(cachedListAvailable('incident'),false);
fixture.generation=2;fixture.stale=true;await readBootstrap();assert.equal(cachedListAvailable('incident'),false);
fixture.stale=false;await readBootstrap();assert.equal(cachedListAvailable('incident'),true);
""")


def test_new_logs_are_offered_without_replacing_a_frozen_page():
    run_dashboard(FIXTURE + r"""
await readBootstrap();await selectWorkspace('events');
fixture.generation=2;fixture.data.events.snapshot='r1:41';fixture.data.events.items=[{message:'new log'}];
scheduleBootstrap();await timers[timers.length-1].fn();
assert.equal(eventSnapshot,'r1:40');assert.match($('events').textContent,/cached log/);
assert.match($('event-latest').textContent,/有新日志/);
assert.equal(calls.filter(c=>c.path.startsWith('/api/events')).length,0);
""")


def test_source_switch_cancels_hidden_reads_and_fetches_only_visible_view():
    run_dashboard(FIXTURE + r"""
setWorkspace('events');controlsData={enabled:false,sources:[]};
const pending=beginList('incident',2);$('source-filter').value='source-a';
route=path=>{assert.match(path,/^\/api\/events\?/);assert.match(path,/source_id=source-a/);return response(page([],{snapshot:'r1:40'}));};
changeWorkspaceSource();for(let i=0;i<12;i++)await Promise.resolve();
assert.equal(pending.state.controller.signal.aborted,true);assert.equal(pages.incident.page,1);
assert.equal(calls.length,1);assert.equal(pages.event.displayed.source,'source-a');
""")


def test_drawer_keeps_untrusted_record_text_in_place_and_does_not_submit_ai():
    run_dashboard(r"""
const dialog=$('detail-dialog');dialog.showModal=()=>{dialog.open=true;};dialog.close=()=>{dialog.open=false;dialog.listeners.close();};
let restored=0;document.activeElement={isConnected:true,focus:()=>restored++};
details({message:'<img src=x onerror=alert(1)>',source_id:'fixture'},'日志详情');
assert.equal(dialog.open,true);assert.match($('detail-fields').textContent,/<img src=x onerror=alert\(1\)>/);
assert.equal($('detail-pane-overview').hidden,false);setDetailTab('evidence');assert.equal($('detail-pane-overview').hidden,true);
closeRecordDrawer();assert.equal(dialog.open,false);assert.equal(restored,1);assert.equal(calls.length,0);
""")


def test_background_overview_does_not_replace_source_scoped_disposition_counts():
    run_dashboard(FIXTURE + r"""
currentSource='source-a';
renderTriageCounts({pending:1,acknowledged:2,resolved:3,total:6},'list');
fixture.data.summary.triage_counts={pending:20,acknowledged:30,resolved:40,total:90};
await readBootstrap();
assert.equal($('incident-total').textContent,'20');
assert.match($('incident-triage-counts').textContent,/待处理 1 · 已知晓 2 · 已处理 3/);
""")
