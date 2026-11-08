"""Exercise the shipped HTTP connection-IP search with synthetic routes only."""
from app.telemetry.dashboard import DASHBOARD_HTML
from test_dashboard_control import ControlsHTML, run_dashboard
from test_http_dashboard import FIXTURE


SEARCH_FIXTURE = FIXTURE + r"""
const incidentCalls=()=>calls.filter(call=>call.path.startsWith('/api/http/incidents?'));
const originalHttpRoute=route;
const searchPage=(path,overrides={})=>{
 const q=new URLSearchParams(path.split('?')[1]);
 const ip=q.get('ip'),canonical=ip==='2001:0DB8:0:0::23'?'2001:db8::23':ip==='::ffff:198.51.100.23'?'198.51.100.23':ip;
 return {items:Array.from({length:q.get('page')==='2'?1:50},()=>({...caseRecord,client_ip:canonical,source_id:q.get('source_id')||'web',service_id:q.get('service_id')||'public',rules:[{label:'<img src=x onerror=alert(1)>'}]})),page:Number(q.get('page')),total_pages:2,total:51,query:{ip:canonical,source_id:q.get('source_id'),service_id:q.get('service_id'),focus:q.get('focus')},limitations:['retained_cases_only','connection_peer_only','analysis_coverage_limited','pages_may_change'],...overrides};
};
route=path=>path.startsWith('/api/http/incidents?')&&new URLSearchParams(path.split('?')[1]).has('ip')?response(searchPage(path)):originalHttpRoute(path);
const submitHTTP=()=>$('http-search-form').listeners.submit({preventDefault(){}});
const editHTTP=ip=>{$('http-ip').value=ip;$('http-ip').listeners.input();};
"""


def test_search_is_compact_labelled_and_explains_connection_scope():
    parsed = ControlsHTML()
    parsed.feed(DASHBOARD_HTML)
    assert not parsed.duplicates
    assert parsed.elements['http-search-form'][0] == 'form'
    assert parsed.elements['http-ip'][1]['maxlength'] == '45'
    assert parsed.elements['http-ip'][1]['aria-describedby'] == 'http-search-note'
    assert parsed.elements['http-search'][1]['type'] == 'submit'
    assert parsed.elements['http-search-clear'][1]['type'] == 'button'
    assert '已保留、已分析的 HTTP 事件' in DASHBOARD_HTML
    assert '代理后的连接 IP 不代表原始访客或攻击者' in DASHBOARD_HTML
    assert '不是原始日志搜索' in DASHBOARD_HTML
    assert '#http-search-form{display:flex;flex-wrap:wrap' in DASHBOARD_HTML


def test_ip_edits_do_not_request_and_clear_visible_rows_and_paging():
    run_dashboard(SEARCH_FIXTURE + r"""
await loadHttp(2);assert.equal($('http-prev').disabled,false);const before=calls.length;
editHTTP('198.51.100.23');assert.equal(calls.length,before);assert.equal($('http-rows').textContent,'');assert.equal($('http-page').textContent,'');
assert.equal($('http-prev').disabled,true);assert.equal($('http-next').disabled,true);assert.match($('http-search-scope').textContent,/条件已修改/);
await loadHttp();assert.equal(calls.length,before);
$('http-source').value='web';await $('http-source').listeners.change();$('http-service').value='private';await $('http-service').listeners.change();$('http-focus').value='attention';await $('http-focus').listeners.change();
assert.equal(calls.length,before);await submitHTTP();const q=new URLSearchParams(incidentCalls().at(-1).path.split('?')[1]);
assert.equal(q.get('ip'),'198.51.100.23');assert.equal(q.get('source_id'),'web');assert.equal(q.get('service_id'),'private');assert.equal(q.get('focus'),'attention');assert.equal(q.get('page'),'1');
assert.match($('http-search-scope').textContent,/198.51.100.23.*web.*private.*需关注/);assert.equal($('http-next').disabled,false);
assert.match($('http-rows').textContent,/<img/);assert.equal($('http-rows').children[0].children[3].children.length,0);
""")


def test_submit_and_clear_reset_page_while_pagination_and_filters_keep_submitted_ip():
    run_dashboard(SEARCH_FIXTURE + r"""
editHTTP('198.51.100.23');await submitHTTP();await $('http-next').listeners.click();
let q=new URLSearchParams(incidentCalls().at(-1).path.split('?')[1]);assert.equal(q.get('page'),'2');assert.equal(q.get('ip'),'198.51.100.23');
$('http-focus').value='low';await $('http-focus').listeners.change();q=new URLSearchParams(incidentCalls().at(-1).path.split('?')[1]);assert.equal(q.get('page'),'1');assert.equal(q.get('ip'),'198.51.100.23');assert.equal(q.get('focus'),'low');
await $('http-next').listeners.click();editHTTP('198.51.100.24');await submitHTTP();q=new URLSearchParams(incidentCalls().at(-1).path.split('?')[1]);assert.equal(q.get('page'),'1');assert.equal(q.get('ip'),'198.51.100.24');
await $('http-next').listeners.click();await $('http-search-clear').listeners.click();q=new URLSearchParams(incidentCalls().at(-1).path.split('?')[1]);assert.equal(q.has('ip'),false);assert.equal(q.get('page'),'1');assert.equal(q.get('focus'),'low');assert.equal($('http-ip').value,'');assert.match($('http-search-scope').textContent,/未限制连接 IP/);
assert(calls.every(call=>call.path.startsWith('/api/http/')&&(call.options.method||'GET')==='GET'));
""")


def test_address_equivalence_includes_compressed_ipv6_and_ipv4_mapped_forms():
    run_dashboard(SEARCH_FIXTURE + r"""
for(const [left,right] of [['2001:0DB8:0:0::23','2001:db8::23'],['::ffff:198.51.100.23','198.51.100.23'],['0:0:0:0:0:ffff:c633:6417','198.51.100.23'],['::','0:0:0:0:0:0:0:0'],['2001:db8::192.0.2.1','2001:db8::c000:201']])assert.equal(httpIPKey(left),httpIPKey(right));
assert.notEqual(httpIPKey('::198.51.100.23'),httpIPKey('198.51.100.23'));
for(const ip of ['2001:0DB8:0:0::23','::ffff:198.51.100.23']){editHTTP(ip);await submitHTTP();assert.equal($('http-status').textContent,'');assert.match($('http-page').textContent,/共 51/);}
assert.match($('http-search-scope').textContent,/连接 IP 198.51.100.23/);
""")


def test_invalid_ip_is_rejected_before_reading_and_whitespace_is_trimmed_explicitly():
    run_dashboard(SEARCH_FIXTURE + r"""
await loadHttp();const before=calls.length;
for(const ip of ['198.51.100.0/24','198.51.100.23:443','fe80::1%eth0','[2001:db8::1]','1.2.3','999.1.1.1','01.2.3.4','::ffff:01.2.3.4','2001:::1','1:2:3:4:5:6:7','1:2:3:4:5:6:7:8:9','::ffff:1.2.3.4:5','x'.repeat(46),'<img>']){
 editHTTP(ip);await submitHTTP();assert.equal(calls.length,before);assert.match($('http-status').textContent,/完整 IPv4 \/ IPv6/);assert.equal($('http-rows').textContent,'');assert.equal($('http-next').disabled,true);
}
editHTTP(' 198.51.100.23 ');await submitHTTP();assert.equal($('http-ip').value,'198.51.100.23');assert.equal(new URLSearchParams(incidentCalls().at(-1).path.split('?')[1]).get('ip'),'198.51.100.23');
""")


def test_changed_or_malformed_response_scope_cannot_render_as_search_results():
    run_dashboard(SEARCH_FIXTURE + r"""
await loadHttp();$('http-source').value='web';$('http-service').value='public';$('http-focus').value='attention';
const bad=[data=>({...data,query:{...data.query,ip:'198.51.100.99'}}),data=>({...data,query:{...data.query,source_id:null}}),data=>({...data,query:{...data.query,service_id:null}}),data=>({...data,query:{...data.query,focus:'all'}}),data=>({...data,query:null}),data=>({...data,limitations:[]}),data=>({...data,items:data.items.map((item,index)=>index?item:{...item,client_ip:'198.51.100.99'})}),data=>({...data,items:data.items.map((item,index)=>index?item:{...item,source_id:'other'})}),data=>({...data,items:data.items.map((item,index)=>index?item:{...item,service_id:'other'})}),data=>({...data,page:2}),data=>({...data,total:-1}),data=>({...data,total_pages:3}),data=>({...data,items:data.items.slice(0,49)}),data=>({...data,items:data.items.map((item,index)=>index===49?{...item,rules:null}:item)})];
for(const alter of bad){route=path=>path.startsWith('/api/http/incidents?')?response(alter(searchPage(path))):originalHttpRoute(path);editHTTP('198.51.100.23');await submitHTTP();assert.match($('http-status').textContent,/未展示结果/);assert.doesNotMatch($('http-rows').textContent,/198.51.100/);assert.equal($('http-page').textContent,'');assert.equal($('http-next').disabled,true);}
""")


def test_pending_old_response_cannot_repopulate_after_ip_or_selector_changes():
    run_dashboard(SEARCH_FIXTURE + r"""
await loadHttp();let finish;const normal=route;
route=path=>path.startsWith('/api/http/incidents?')?new Promise(resolve=>{finish=()=>resolve(response(searchPage(path)));}):normal(path);
editHTTP('198.51.100.23');const pending=submitHTTP();for(let i=0;i<20;i++)await Promise.resolve();assert.equal(typeof finish,'function');
editHTTP('198.51.100.24');assert.equal($('http-rows').textContent,'');assert.equal($('http-next').disabled,true);finish();await pending;assert.equal($('http-rows').textContent,'');
route=normal;await submitHTTP();assert.match($('http-rows').textContent,/198.51.100.24/);
route=path=>path.startsWith('/api/http/incidents?')?new Promise(resolve=>{finish=()=>resolve(response(searchPage(path)));}):normal(path);
const refresh=loadHttp();for(let i=0;i<20;i++)await Promise.resolve();route=normal;$('http-focus').value='low';await $('http-focus').listeners.change();finish();await refresh;
assert.match($('http-search-scope').textContent,/低分/);assert.equal($('http-status').textContent,'');assert.equal($('http-next').disabled,false);
""")


def test_pending_status_cannot_issue_old_search_after_filter_edit():
    run_dashboard(SEARCH_FIXTURE + r"""
await loadHttp();let finish;const normal=route;route=path=>path==='/api/http/status'?new Promise(resolve=>{finish=()=>resolve(response(httpFixture));}):normal(path);
editHTTP('198.51.100.23');const pending=submitHTTP();for(let i=0;i<15;i++)await Promise.resolve();const before=incidentCalls().length;
editHTTP('198.51.100.24');$('http-source').value='web';await $('http-source').listeners.change();finish();await pending;
assert.equal(incidentCalls().length,before);assert.equal($('http-rows').textContent,'');assert.match($('http-search-scope').textContent,/条件已修改/);
""")


def test_searched_errors_clear_previous_results_without_disclosing_error_details():
    run_dashboard(SEARCH_FIXTURE + r"""
editHTTP('198.51.100.23');await submitHTTP();const normal=route;
for(const status of [422,503,404,401,500]){
 route=path=>path.startsWith('/api/http/incidents?')?({ok:false,status,json:async()=>({detail:'private database path and secret'})}):normal(path);
 await loadHttp();assert.doesNotMatch($('http-rows').textContent,/198.51.100.23/);assert.equal($('http-page').textContent,'');assert.equal($('http-next').disabled,true);assert.doesNotMatch($('http-status').textContent,/private|secret|没有匹配/);assert.notEqual($('http-status').textContent,'');
}
route=path=>path.startsWith('/api/http/incidents?')?response(searchPage(path,{items:[],page:1,total_pages:1,total:0})):normal(path);
await loadHttp();assert.match($('http-rows').textContent,/没有匹配；不代表没有请求或活动/);assert.equal($('http-status').textContent,'');assert.match($('http-search-scope').textContent,/198.51.100.23/);
""")


def test_removed_source_and_tab_switch_cannot_accept_a_stale_search():
    run_dashboard(SEARCH_FIXTURE + r"""
await loadHttp();$('http-source').value='web';editHTTP('198.51.100.23');await submitHTTP();const normal=route;
route=path=>path==='/api/http/status'?response({...httpFixture,sources:[]}):normal(path);const before=incidentCalls().length;await loadHttp();
assert.equal(incidentCalls().length,before);assert.equal($('http-rows').textContent,'');assert.match($('http-search-scope').textContent,/原筛选条件已不可用/);assert.equal($('http-next').disabled,true);
route=normal;let finish;route=path=>path.startsWith('/api/http/incidents?')?new Promise(resolve=>{finish=()=>resolve(response(searchPage(path)));}):normal(path);
const pending=loadHttp();for(let i=0;i<20;i++)await Promise.resolve();setHttpView('restores');finish();await pending;assert.equal($('http-rows').textContent,'');
setHttpView('incidents');route=normal;await loadHttp();assert.match($('http-rows').textContent,/198.51.100.23/);
""")
