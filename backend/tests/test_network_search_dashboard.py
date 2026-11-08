"""Exercise shipped raw-network search controls, scopes and request races."""
from app.telemetry.dashboard import DASHBOARD_HTML
from test_dashboard_control import ControlsHTML, run_dashboard
from test_network_dashboard import FIXTURE


SEARCH_FIXTURE = FIXTURE + r"""
networkHealth(networkFixture);
const normalNetworkRoute=route;
const searchCalls=()=>calls.filter(call=>call.path.startsWith('/api/network/events/search?'));
const logPage=(path,extra={})=>{
 const q=new URLSearchParams(path.split('?')[1]),query={source_id:q.get('source_id'),ip:q.get('ip')==='2001:0db8:0:0::23'?'2001:db8::23':q.get('ip'),start:q.get('start'),end:q.get('end')};
 const second=q.get('cursor')==='page-2';
 return {items:[{...networkEvent,source_id:query.source_id,src_ip:query.ip,journal_realtime_us:Date.parse(query.start)*1000,dst_port:second?444:443}],query,snapshot:77,page_cursor:second?'page-2':'page-1',next_cursor:second?null:'page-2',limitations:['retained_observations_only','history_may_be_incomplete','late_receipts_excluded'],...extra};
};
route=path=>path.startsWith('/api/network/events/search?')?response(logPage(path)):normalNetworkRoute(path);
const submitLogs=()=>$('network-log-form').listeners.submit({preventDefault(){}});
$('network-log-ip').value='198.51.100.23';
"""


def test_network_search_is_a_labelled_compact_separate_pane():
    parsed = ControlsHTML()
    parsed.feed(DASHBOARD_HTML)
    assert not parsed.duplicates
    for name in ('findings', 'logs'):
        assert parsed.elements[f'network-view-{name}'][1]['aria-controls'] == f'network-{name}'
        assert parsed.elements[f'network-{name}'][1]['role'] == 'tabpanel'
    assert 'hidden' in parsed.elements['network-logs'][1]
    assert parsed.elements['network-log-form'][0] == 'form'
    assert 'required' in parsed.elements['network-log-source'][1]
    assert 'required' in parsed.elements['network-log-ip'][1]
    assert parsed.elements['network-log-start'][1]['step'] == '1'
    assert '相同 IP 不代表已确认关联' in DASHBOARD_HTML
    assert '结束时间（本地，含）' in DASHBOARD_HTML


def test_no_automatic_log_reads_and_empty_ip_cannot_scan():
    run_dashboard(SEARCH_FIXTURE + r"""
setNetworkView('logs');await loadNetwork();assert.equal(searchCalls().length,0);
$('network-log-ip').value='';await submitLogs();assert.equal(searchCalls().length,0);assert.match($('network-log-status').textContent,/不能进行空 IP/);
$('network-log-ip').value='198.51.100.23';$('network-log-ip').listeners.input();assert.equal(searchCalls().length,0);
await submitLogs();assert.equal(searchCalls().length,1);assert.equal(searchCalls()[0].options.credentials,'same-origin');assert.equal(searchCalls()[0].options.cache,'no-store');
const first=new URLSearchParams(searchCalls()[0].path.split('?')[1]);assert.equal(first.get('limit'),'50');assert.equal(first.get('source_id'),'net-a');assert.equal(Date.parse(first.get('end'))-Date.parse(first.get('start')),86400000);
await loadNetwork();assert.equal(searchCalls().length,1);assert.match($('network-log-rows').textContent,/198.51.100.23/);
""")


def test_time_presets_custom_local_conversion_and_seven_day_limit():
    run_dashboard(SEARCH_FIXTURE + r"""
for(const [mode,milliseconds] of [['1h',3600000],['7d',604800000]]){$('network-log-window').value=mode;await submitLogs();const q=new URLSearchParams(searchCalls().at(-1).path.split('?')[1]);assert.equal(Date.parse(q.get('end'))-Date.parse(q.get('start')),milliseconds);}
$('network-log-window').value='custom';$('network-log-window').listeners.change();assert.equal($('network-log-dates').hidden,false);
$('network-log-start').value='2026-01-01T12:00:00';$('network-log-end').value='2026-01-01T13:00:00';await submitLogs();const q=new URLSearchParams(searchCalls().at(-1).path.split('?')[1]);assert.equal(q.get('start'),new Date('2026-01-01T12:00:00').toISOString());assert.equal(q.get('end'),new Date('2026-01-01T13:00:00').toISOString());
const count=searchCalls().length;$('network-log-end').value='2026-01-09T13:00:00';await submitLogs();assert.equal(searchCalls().length,count);assert.match($('network-log-status').textContent,/最多 7 天/);assert.equal($('network-log-rows').children.length,0);
$('network-log-end').value='2026-01-01T12:00:00';await submitLogs();assert.equal(searchCalls().length,count);
""")


def test_back_uses_first_page_cursor_and_refresh_resets_snapshot():
    run_dashboard(SEARCH_FIXTURE + r"""
await submitLogs();const original={...networkLogQuery};assert.equal(networkLogPages[0].cursor,'page-1');
await $('network-log-next').listeners.click();assert.match($('network-log-page').textContent,/第 2 页/);assert.match($('network-log-rows').textContent,/444/);assert.equal($('network-log-next').disabled,true);
await $('network-log-prev').listeners.click();const previous=new URLSearchParams(searchCalls().at(-1).path.split('?')[1]);assert.equal(previous.get('cursor'),'page-1');assert.equal(previous.get('start'),original.start);assert.equal(previous.get('end'),original.end);
assert.doesNotMatch($('network-log-page').textContent,/共|总/);await $('network-log-refresh').listeners.click();assert.equal(new URLSearchParams(searchCalls().at(-1).path.split('?')[1]).has('cursor'),false);assert.equal(networkLogIndex,0);
""")


def test_filter_changes_invalidate_results_and_late_response_even_without_abort_support():
    run_dashboard(SEARCH_FIXTURE + r"""
await submitLogs();let finish;route=path=>new Promise(resolve=>{finish=()=>resolve(response(logPage(path)));});
const pending=$('network-log-next').listeners.click();for(let i=0;i<10;i++)await Promise.resolve();assert.equal($('network-log-prev').disabled,true);assert.equal($('network-log-next').disabled,true);
const oldSignal=searchCalls().at(-1).options.signal;$('network-log-ip').value='198.51.100.24';$('network-log-ip').listeners.input();assert.equal(oldSignal.aborted,true);assert.equal($('network-log-rows').children.length,0);assert.equal(networkLogPages.length,0);assert.match($('network-log-scope').textContent,/条件已修改/);
route=path=>response(logPage(path));await submitLogs();finish();await pending;assert.match($('network-log-rows').textContent,/198.51.100.24/);assert.doesNotMatch($('network-log-rows').textContent,/198.51.100.23/);assert.equal(networkLogIndex,0);
networkFixture.sources.push({source_id:'net-b',hostname:'second'});networkHealth(networkFixture);$('network-log-source').value='net-b';$('network-log-source').listeners.change();assert.equal($('network-log-rows').children.length,0);assert.equal(networkLogPages.length,0);await submitLogs();assert.equal(new URLSearchParams(searchCalls().at(-1).path.split('?')[1]).get('source_id'),'net-b');
""")


def test_disabled_removed_or_hidden_source_invalidates_pending_search():
    run_dashboard(SEARCH_FIXTURE + r"""
let finish;route=path=>new Promise(resolve=>{finish=()=>resolve(response(logPage(path)));});const pending=submitLogs();for(let i=0;i<10;i++)await Promise.resolve();
networkHealth({enabled:true,sources:[{source_id:'net-a',hidden:true}]});assert.equal(searchCalls()[0].options.signal.aborted,true);finish();await pending;assert.equal($('network-log-submit').disabled,true);assert.equal($('network-log-rows').children.length,0);assert.match($('network-log-scope').textContent,/不再可用/);
networkHealth(networkFixture);route=path=>response(logPage(path));await submitLogs();networkHealth({enabled:false});assert.equal($('network-log-source').disabled,true);assert.equal(networkLogQuery,null);assert.equal($('network-log-rows').children.length,0);
networkHealth({enabled:true,sources:[{source_id:'net-a',enabled:false}]});assert.equal($('network-log-submit').disabled,true);
""")


def test_failures_clear_rows_and_distinguish_empty_from_busy_and_invalid():
    run_dashboard(SEARCH_FIXTURE + r"""
await submitLogs();route=()=>({ok:false,status:503,json:async()=>({detail:'private SQL budget internals'})});await submitLogs();assert.match($('network-log-status').textContent,/缩小时间范围或重试/);assert.doesNotMatch($('network-log-status').textContent,/private|SQL/);assert.match($('network-log-rows').textContent,/未展示结果/);assert.equal(networkLogPages.length,0);
route=()=>({ok:false,status:422,json:async()=>({detail:'internal schema'})});await submitLogs();assert.match($('network-log-status').textContent,/查询条件无效/);assert.doesNotMatch($('network-log-status').textContent,/internal schema/);
route=()=>({ok:false,status:404});await submitLogs();assert.match($('network-log-status').textContent,/来源未配置或已移除/);assert.match($('network-log-rows').textContent,/未展示结果/);
route=path=>response(logPage(path,{items:[],next_cursor:null}));await submitLogs();assert.match($('network-log-rows').textContent,/没有匹配.*不代表没有活动/);assert.equal($('network-log-next').disabled,true);assert.equal($('network-log-status').textContent,'');
""")


def test_canonical_ipv6_scope_malformed_payloads_and_literal_text():
    run_dashboard(SEARCH_FIXTURE + r"""
$('network-log-ip').value='2001:0db8:0:0::23';networkEvent.ingress_interface='<img src=x onerror=alert(1)>';await submitLogs();assert.equal(networkLogQuery.ip,'2001:db8::23');assert.match($('network-log-rows').textContent,/<img/);assert.equal($('network-log-rows').children[0].children[4].children.length,0);
assert.equal(networkLogIPKey('::ffff:192.0.2.1'),networkLogIPKey('::ffff:c000:201'));assert.equal(networkLogIPKey('198.51.100.01'),null);
route=path=>{const data=logPage(path);data.query.ip='198.51.100.99';data.items[0].src_ip=data.query.ip;return response(data);};await submitLogs();assert.match($('network-log-status').textContent,/返回异常/);assert.doesNotMatch($('network-log-rows').textContent,/198.51.100.99/);
route=path=>{const data=logPage(path);data.items[0].journal_realtime_us=Date.parse(data.query.end)*1000+1;return response(data);};await submitLogs();assert.match($('network-log-status').textContent,/返回异常/);
route=path=>response(logPage(path));await submitLogs();route=path=>response(logPage(path,{snapshot:78}));await $('network-log-next').listeners.click();assert.match($('network-log-status').textContent,/返回异常/);assert.equal(networkLogPages.length,0);
""")


def test_explicit_finding_and_detail_pivots_use_source_and_evidence_window():
    run_dashboard(SEARCH_FIXTURE + r"""
await loadNetwork();const action=$('network-rows').children[0].children[2].children[1];assert.equal(action.textContent,'查网络日志');await action.listeners.click({stopPropagation(){}});
const q=new URLSearchParams(searchCalls().at(-1).path.split('?')[1]);assert.equal(q.get('source_id'),'net-a');assert.equal(q.get('ip'),networkRecord.src_ip);assert.equal(q.get('start'),'2026-01-01T11:30:00.000Z');assert.equal(q.get('end'),'2026-01-01T12:31:00.000Z');assert.equal($('network-findings').hidden,true);
await showNetworkIncident('NET-example');assert.equal(dialog.open,true);await $('network-log-search').children[0].listeners.click({stopPropagation(){}});assert.equal(dialog.open,false);assert.equal($('network-logs').hidden,false);
assert.equal(calls.every(call=>(call.options.method||'GET')==='GET'&&!call.path.includes('/ai/')&&!call.path.includes('/controls')&&!call.path.includes('ip-info')),true);
""")


def test_detail_pivot_loads_source_registry_on_first_visit_and_respects_newer_input():
    run_dashboard(SEARCH_FIXTURE + r"""
networkLogEnabled=false;networkLogSourceList=[];await showNetworkIncident('NET-example');const before=searchCalls().length;await $('network-log-search').children[0].listeners.click({stopPropagation(){}});assert.equal(searchCalls().length,before+1);assert.equal(networkLogQuery.source_id,'net-a');assert.equal(networkLogQuery.ip,networkRecord.src_ip);
networkLogEnabled=false;networkLogSourceList=[];let finish;const normal=route;route=path=>path==='/api/network/status'?new Promise(resolve=>{finish=()=>resolve(response(networkFixture));}):normal(path);
const pending=networkLogAction(networkRecord).listeners.click({stopPropagation(){}});for(let i=0;i<10;i++)await Promise.resolve();$('network-log-ip').value='198.51.100.99';$('network-log-ip').listeners.input();finish();await pending;assert.equal(searchCalls().length,before+1);assert.equal($('network-log-ip').value,'198.51.100.99');assert.equal($('network-log-rows').children.length,0);
""")
