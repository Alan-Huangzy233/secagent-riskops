"""IP investigation entrypoints: real shipped JS with inert API/DOM fixtures."""
from app.telemetry.dashboard import DASHBOARD_HTML
from test_console_workspace import FIXTURE as CACHE_FIXTURE
from test_dashboard_control import ControlsHTML, run_dashboard
from test_network_dashboard import FIXTURE as NETWORK_FIXTURE


SEARCH_FIXTURE = r"""
const searchPage=(ip='198.51.100.23',extra={})=>({page:1,total_pages:2,total:51,items:[{src_ip:ip,message:'retained SSH log',incident_id:'ssh-example',triage_status:'resolved'}],...extra});
controlsData={enabled:false,sources:[]};
route=path=>{const q=new URLSearchParams(path.split('?')[1]);return response(searchPage(q.get('ip'),{page:Number(q.get('page')),snapshot:q.get('snapshot')||'r1:51'}));};
const submit=kind=>$(kind+'-ip-form').listeners.submit({preventDefault(){}});
"""


def test_search_fields_are_labelled_unique_and_outside_collapsed_advanced_options():
    parsed = ControlsHTML()
    parsed.feed(DASHBOARD_HTML)
    assert not parsed.duplicates
    for kind, prefix in (("event", "search"), ("incident", "incident-search")):
        assert parsed.elements[f"{kind}-ip-form"][0] == "form"
        assert parsed.elements[f"{prefix}-ip"][1]["aria-describedby"] == f"{kind}-search-scope {kind}-search-coverage"
        assert parsed.elements[f"{prefix}-start"][1]["step"] == "1"
        assert parsed.elements[f"{kind}-search-scope"][1]["aria-live"] == "polite"
    assert DASHBOARD_HTML.index('id="search-ip"') < DASHBOARD_HTML.index('id="event-search-options"')
    assert DASHBOARD_HTML.index('id="incident-search-ip"') < DASHBOARD_HTML.index('id="incident-options"')
    incident_form = DASHBOARD_HTML.split('id="incident-ip-form"', 1)[1].split('</form>', 1)[0]
    assert '<details' not in incident_form
    assert 'id="incident-search-window"' in incident_form
    assert 'id="incident-search-end"' in incident_form


def test_manual_ip_search_uses_server_and_fixed_24_hours_through_pagination_refresh_and_save():
    run_dashboard(SEARCH_FIXTURE + r"""
currentSource='ssh-a';incidentTriage='all';$('incident-search-ip').value=' 2001:0db8:0:0::23 ';
const before=Date.now();await submit('incident');const after=Date.now();
const first=new URLSearchParams(calls[0].path.split('?')[1]);
assert.equal(first.get('ip'),'2001:0db8:0:0::23');assert.equal(first.get('source_id'),'ssh-a');assert.equal(first.get('triage'),'all');
assert.equal(new Date(first.get('end'))-new Date(first.get('start')),86400000);assert.ok(new Date(first.get('end'))>=before&&new Date(first.get('end'))<=after);
await loadList('incident',2);await loadList('incident');
for(const call of calls){const q=new URLSearchParams(call.path.split('?')[1]);assert.equal(q.get('ip'),first.get('ip'));assert.equal(q.get('start'),first.get('start'));assert.equal(q.get('end'),first.get('end'));}
const saved=JSON.parse(sessionStorage.getItem('riskops-view'));assert.equal(saved.incidentFilters.ip,first.get('ip'));assert.equal(saved.incidentPage,2);
assert.match($('incident-search-scope').textContent,/全部处置状态/);assert.match($('incident-search-scope').textContent,/按告警证据时段重叠匹配/);
assert.equal(calls.every(call=>(call.options.method||'GET')==='GET'&&call.path.startsWith('/api/incidents?')),true);
""")


def test_log_search_keeps_advanced_filters_and_snapshot_until_latest_or_conditions_change():
    run_dashboard(SEARCH_FIXTURE + r"""
$('search-ip').value='198.51.100.23';$('search-username').value='root';$('search-event_type').value='auth_failure';$('search-q').value='[preauth]';
await submit('event');const first=new URLSearchParams(calls[0].path.split('?')[1]);
assert.equal(first.get('username'),'root');assert.equal(first.get('q'),'[preauth]');assert.equal(first.get('event_type'),'auth_failure');assert.equal(eventSnapshot,'r1:51');
await loadList('event',2);assert.equal(new URLSearchParams(calls[1].path.split('?')[1]).get('snapshot'),'r1:51');
$('event-latest').listeners.click();for(let i=0;i<12;i++)await Promise.resolve();
const latest=new URLSearchParams(calls[2].path.split('?')[1]);assert.equal(latest.get('snapshot'),null);assert.equal(latest.get('page'),'1');assert.equal(latest.get('start'),first.get('start'));assert.equal(latest.get('ip'),first.get('ip'));
await $('event-search-all').listeners.click();const expanded=new URLSearchParams(calls[3].path.split('?')[1]);assert.equal(expanded.get('start'),null);assert.equal(expanded.get('end'),null);assert.equal(expanded.get('snapshot'),null);assert.equal(expanded.get('username'),'root');assert.match($('event-search-scope').textContent,/全部保留时间/);
await $('event-ip-clear').listeners.click();assert.equal(Object.keys(eventFilters).length,0);assert.equal($('search-username').value,'');assert.equal($('search-ip').value,'');
""")


def test_custom_window_validation_leaves_applied_query_explicit_and_can_expand_to_retained_history():
    run_dashboard(SEARCH_FIXTURE + r"""
$('incident-search-ip').value='198.51.100.23';await submit('incident');const old=JSON.stringify(incidentFilters);
$('incident-search-window').value='custom';$('incident-search-window').listeners.change();assert.equal($('incident-search-dates').hidden,false);
$('incident-search-start').value='2026-10-23T12:00:00';$('incident-search-end').value='2026-10-22T12:00:00';await submit('incident');
assert.equal(calls.length,1);assert.equal(JSON.stringify(incidentFilters),old);assert.match($('incident-status').textContent,/开始时间不能晚于结束时间/);
$('incident-search-start').value='2026-10-22T12:00:00';$('incident-search-end').value='2026-10-23T12:00:00';await submit('incident');
assert.equal(calls.length,2);assert.equal(incidentFilters.start,new Date('2026-10-22T12:00:00').toISOString());assert.equal(searchWindows.incident,'custom');
await $('incident-search-all').listeners.click();assert.equal(incidentFilters.start,undefined);assert.equal(incidentFilters.end,undefined);assert.equal(incidentFilters.ip,'198.51.100.23');assert.match($('incident-search-scope').textContent,/实际边界未知/);
""")


def test_filtered_incidents_never_take_prepared_default_page_or_replace_summary_counts():
    run_dashboard(CACHE_FIXTURE + SEARCH_FIXTURE + r"""
route=path=>path==='/api/console/bootstrap'?response(fixture):response(searchPage('198.51.100.23',{triage_counts:{pending:0,resolved:1,total:1}}));
await readBootstrap();assert.equal(cachedListAvailable('incident'),true);
$('incident-search-ip').value='198.51.100.23';await submit('incident');assert.equal(cachedListAvailable('incident'),false);
const previous=$('incident-total').textContent;await loadWorkspaceView();assert.equal(calls.filter(call=>call.path.startsWith('/api/incidents?')).length,2);assert.equal($('incident-total').textContent,previous);
fixture.generation=2;scheduleBootstrap();await timers[timers.length-1].fn();assert.match($('incidents').textContent,/198.51.100.23/);assert.doesNotMatch($('incidents').textContent,/192.0.2.1/);
""")


def test_old_request_and_failed_new_ip_cannot_label_previous_results_as_new_search():
    run_dashboard(SEARCH_FIXTURE + r"""
$('incident-search-ip').value='198.51.100.1';await submit('incident');
let finish;route=()=>new Promise(resolve=>{finish=()=>resolve(response(searchPage('198.51.100.2')));});
$('incident-search-ip').value='198.51.100.2';const pending=submit('incident');for(let i=0;i<8;i++)await Promise.resolve();
route=()=>({ok:false,status:422,json:async()=>({detail:'请输入完整的 IPv4 或 IPv6 地址，不支持 CIDR。'})});
$('incident-search-ip').value='198.51.100.0/24';await submit('incident');finish();await pending;
assert.match($('incident-status').textContent,/不支持 CIDR/);assert.match($('incidents').textContent,/当前查询失败/);assert.doesNotMatch($('incidents').textContent,/198.51.100.[12]/);
assert.equal(pages.incident.displayed,null);assert.equal(pages.incident.totalPages,null);assert.equal($('incident-triage-counts').textContent,'');
assert.match($('incident-search-scope').textContent,/198.51.100.0\/24/);
""")


def test_network_source_ip_actions_clear_unrelated_filters_and_use_exact_evidence_window():
    run_dashboard(NETWORK_FIXTURE + r"""
await loadNetwork();currentSource='ssh-wrong';eventFilters={ip:'192.0.2.99',username:'wrong',q:'wrong',start:'2020-01-01T00:00:00Z'};incidentFilters={ip:'192.0.2.99'};incidentTriage='pending';incidentFocus='attention';eventSnapshot='r1:9';pages.event.page=9;pages.incident.page=8;
const normal=route;route=path=>path.startsWith('/api/incidents?')||path.startsWith('/api/events?')?response({page:1,total_pages:1,total:0,items:[],snapshot:'r1:10'}):normal(path);
const buttons=$('network-rows').children[0].children[2].children[0].children;
assert.equal(JSON.stringify(buttons.map(button=>button.textContent)),JSON.stringify(['查 SSH 告警','查 SSH 日志']));
await buttons[0].listeners.click({stopPropagation(){}});
assert.equal(workspaceView,'incidents');assert.equal(currentSource,'');assert.equal(incidentTriage,'all');assert.equal(incidentFocus,'all');assert.equal(Object.keys(eventFilters).length,0);
const q=new URLSearchParams(calls[calls.length-1].path.split('?')[1]);assert.equal(q.get('ip'),networkRecord.src_ip);assert.equal(q.get('source_id'),null);assert.equal(q.get('triage'),'all');assert.equal(q.get('start'),'2026-01-01T11:30:00.000Z');assert.equal(q.get('end'),'2026-01-01T12:31:00.000Z');
assert.match($('incident-search-scope').textContent,/全部 SSH 来源.*全部处置状态/s);assert.match($('incidents').textContent,/无告警不等于无活动/);
await showNetworkIncident('NET-example');assert.equal(dialog.open,true);const before=calls.length;
await $('network-ssh-search').children[0].children[1].listeners.click({stopPropagation(){}});
assert.equal(dialog.open,false);assert.equal(workspaceView,'events');assert.equal(eventFilters.username,undefined);assert.equal(eventFilters.q,undefined);
const logQuery=new URLSearchParams(calls[before].path.split('?')[1]);assert.equal(logQuery.get('source_id'),null);assert.equal(logQuery.get('ip'),networkRecord.src_ip);assert.equal(logQuery.get('snapshot'),null);assert.equal(logQuery.get('start'),q.get('start'));
assert.equal(calls.every(call=>(call.options.method||'GET')==='GET'&&!call.path.includes('ip-info')&&!call.path.includes('/ai/')&&!call.path.includes('/controls')),true);
""")


def test_empty_search_explains_unknown_unconfigured_and_known_collection_gaps_separately():
    run_dashboard(SEARCH_FIXTURE + r"""
assert.match($('event-search-coverage').textContent,/采集与保留边界未知/);
searchSources=[];renderIPScopes();assert.match($('event-search-coverage').textContent,/未登记匹配的 SSH 来源/);
searchSources=[{source_id:'ssh-a',connection_status:'offline',collection:{coverage_start:'2026-01-01T00:00:00Z',gaps_since_coverage:2,caught_up:false}}];renderIPScopes();
assert.match($('event-search-coverage').textContent,/1 个来源有已知采集缺口/);assert.match($('event-search-coverage').textContent,/1 个来源离线或待追赶/);
route=()=>response({page:1,total_pages:1,total:0,items:[],snapshot:'r1:0'});$('search-ip').value='198.51.100.23';await submit('event');assert.match($('events').textContent,/没有匹配的 SSH 日志/);assert.match($('events').textContent,/不能据此判断安全/);
""")


def test_loading_another_network_revision_clears_previous_search_actions():
    run_dashboard(NETWORK_FIXTURE + r"""
await showNetworkIncident('NET-example');assert.equal($('network-ssh-search').children.length,1);
const normal=route;let finish;route=path=>path==='/api/network/incidents/NET-example'?new Promise(resolve=>{finish=()=>resolve(normal(path));}):normal(path);
const pending=showNetworkIncident('NET-example',1);for(let i=0;i<10;i++)await Promise.resolve();assert.equal($('network-ssh-search').children.length,0);
dialog.close();finish();await pending;assert.equal($('network-ssh-search').children.length,0);assert.equal(dialog.open,false);
""")


def test_search_budget_error_is_actionable_and_never_a_successful_empty_search():
    run_dashboard(SEARCH_FIXTURE + r"""
$('incident-search-ip').value='198.51.100.23';await submit('incident');
route=()=>({ok:false,status:503,json:async()=>({code:'search_temporarily_unavailable',detail:'查询耗时过长或数据库暂忙，请缩短时间范围或稍后重试；未返回部分结果。'})});
$('incident-search-ip').value='198.51.100.24';await submit('incident');
assert.match($('incident-status').textContent,/缩短时间范围/);assert.doesNotMatch($('incidents').textContent,/198\.51\.100\.23/);
$('search-ip').value='198.51.100.24';await submit('event');assert.match($('event-status').textContent,/未返回部分结果/);
route=()=>({ok:false,status:503,json:async()=>({code:'unknown',detail:'internal details must not be displayed'})});
await submit('event');assert.doesNotMatch($('event-status').textContent,/internal details/);
""")
