"""Self-contained read-only dashboard; no external assets or untrusted HTML."""
from __future__ import annotations

import base64
import hashlib

_STYLE = """
:root{color-scheme:dark;font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:#0b1422;color:#e7edf5}
*{box-sizing:border-box}body{max-width:1440px;margin:auto;padding:28px}h1{font-size:26px;margin:0 0 8px}h2{font-size:18px}
p,small{color:#a9bacd}button,select,input{background:#172941;color:#e7edf5;border:1px solid #37516d;border-radius:6px;padding:8px 12px}
button{cursor:pointer}button:disabled{opacity:.45;cursor:default}.toolbar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin:22px 0}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.card,section{background:#111e30;border:1px solid #263a53;border-radius:10px;padding:18px;margin-bottom:18px}.number{font-size:28px;font-weight:650;margin-top:8px}
.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;text-align:left;font-size:13px}th{color:#a9bacd;font-weight:500}td,th{border-bottom:1px solid #263a53;padding:11px 9px;vertical-align:top}td{max-width:480px;overflow-wrap:anywhere}tr.selectable{cursor:pointer}tr.selectable:hover{background:#1a2d46}
.online{color:#68dfa8}.offline,.error{color:#ffba85}.never_seen{color:#a9bacd}#error{color:#ffc49c;min-height:24px}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.7 ui-monospace,monospace;max-height:480px;overflow:auto}.pager{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-top:14px}.page-jump{display:flex;gap:8px;align-items:center}.page-jump input{width:86px}.list-status{min-height:20px;font-size:13px;margin-bottom:0}.muted{color:#a9bacd}
.ip-form{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.ip-form input{flex:1;min-width:220px;font:inherit}.ip-link{padding:0;border:0;background:none;color:#8ac7ff;text-align:left;font:inherit;overflow-wrap:anywhere}.ip-link:hover{text-decoration:underline}button:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid #8ac7ff;outline-offset:3px}a{color:#8ac7ff}.ip-fields{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:18px;margin:18px 0}.ip-fields dt{color:#a9bacd;font-size:13px;margin-bottom:6px}.ip-fields dd{margin:0;overflow-wrap:anywhere}#ip-status{min-height:24px;margin-bottom:0}
@media(max-width:800px){body{padding:16px}.cards,.ip-fields{grid-template-columns:repeat(2,minmax(0,1fr))}.ip-form input{min-width:0;flex-basis:100%}}
"""

_SCRIPT = """
'use strict';
const $=id=>document.getElementById(id);
let currentSource='', refreshRequestId=0, summaryController=null, summaryPending=false;
let sourceRowsKey=null, autoRefreshTimer=null, refreshRunning=false;
let ipRequestId=0, ipController=null, abuseRequestId=0, abuseController=null, abuseIP=null;
const pageSize=50;
const pages={event:{page:1,total:0,totalPages:null,requestId:0,controller:null,pending:false,displayed:null,visible:null},incident:{page:1,total:0,totalPages:null,requestId:0,controller:null,pending:false,displayed:null,visible:null}};
function text(id,value){const node=$(id),next=String(value??'—');if(node.textContent!==next)node.textContent=next;}
function when(value){if(!value)return '尚未收到'; const d=new Date(value);return Number.isNaN(d.valueOf())?value:d.toLocaleString('zh-CN',{hour12:false});}
function duration(started){const elapsed=Math.round(performance.now()-started);return elapsed<1000?`${elapsed} 毫秒`:`${(elapsed/1000).toFixed(1)} 秒`;}
function isBusy(){return refreshRunning||summaryPending||Object.values(pages).some(state=>state.pending);}
function updateRefreshButton(){const busy=isBusy();$('refresh').disabled=busy;text('refresh',busy?'正在更新…':'刷新数据');}
function clearDetails(){text('detail-title','记录详情');text('detail','选择上方记录查看详情。');}
function cell(row,value){const td=document.createElement('td');td.textContent=String(value??'—');row.append(td);return td;}
function empty(tbody,span,message){const tr=document.createElement('tr');const td=cell(tr,message);td.colSpan=span;tbody.append(tr);}
async function get(path,signal){const response=await fetch(path,{credentials:'same-origin',cache:'no-store',signal});if(!response.ok)throw new Error(response.status===401?'登录已失效，请刷新页面重新登录。':`读取失败（${response.status}）。请检查中控服务。`);return response.json();}
function details(record,title){text('detail-title',title);text('detail',JSON.stringify(record,null,2));$('detail-section').scrollIntoView({behavior:'smooth',block:'nearest'});}
function ipCell(row,value){
 const td=cell(row,null);if(!value)return td;
 const ip=String(value);const button=document.createElement('button');button.type='button';button.className='ip-link';button.textContent=ip;button.setAttribute('aria-label',`查询 ${ip} 的属地`);
 button.addEventListener('click',event=>{event.stopPropagation();$('ip-input').value=ip;lookupIp(ip);$('ip-query-section').scrollIntoView({behavior:'smooth',block:'nearest'});});
 button.addEventListener('keydown',event=>event.stopPropagation());td.replaceChildren(button);return td;
}
function renderIp(data){
 text('ip-address',data.ip);text('ip-type',[data.version?`IPv${data.version}`:null,data.address_type_label].filter(Boolean).join(' · ')||'—');
 text('ip-country',[data.country,data.country_code].filter(Boolean).join(' · ')||'—');text('ip-region',[data.region,data.city].filter(Boolean).join(' / ')||'—');
 text('ip-network',data.network_name||'—');text('ip-asn',data.asn===null||data.asn===undefined?'—':`AS${data.asn}`);
 text('ip-database-release',data.database_release||'—');text('ip-database-updated',data.database_updated_at?when(data.database_updated_at):'—');
 text('ip-database-status',data.status==='not_public'?'此类地址无需查询属地库':data.database_stale===true?'版本较旧，建议更新':data.database_stale===false?'可用':'未知');
 $('ip-database-status').className=data.database_stale===true?'error':'muted';$('ip-result').hidden=false;
}
function updateAbuseLink(data){
 const link=$('abuseipdb-link');link.hidden=true;link.removeAttribute('href');
 if(!data||data.address_type!=='public'||!data.ip)return;
 const ip=String(data.lookup_ip||data.ip);link.href='https://www.abuseipdb.com/check/'+encodeURIComponent(ip);
 link.textContent=`在 AbuseIPDB 查看 ${ip} 的风险评分 ↗`;link.hidden=false;
}
function resetAbuse(){
 ++abuseRequestId;if(abuseController)abuseController.abort();abuseIP=null;
 $('abuseipdb-check').disabled=true;$('abuseipdb-result').hidden=true;
 text('abuseipdb-status','先查询一个公网 IP，再点击风险查询。');text('abuseipdb-check','查询 AbuseIPDB 风险分');
}
function setAbuseIP(data){
 if(data&&data.address_type==='public'&&data.ip){abuseIP=String(data.lookup_ip||data.ip);$('abuseipdb-check').disabled=false;text('abuseipdb-status',`待查询 ${abuseIP}；点击后仅将此 IP 发送给 AbuseIPDB。`);}
}
async function lookupAbuse(){
 if(!abuseIP)return;const ip=abuseIP,requestId=++abuseRequestId;if(abuseController)abuseController.abort();abuseController=new AbortController();
 $('abuseipdb-check').disabled=true;text('abuseipdb-check','风险查询中…');text('abuseipdb-status',`正在查询 ${ip}…`);$('abuseipdb-result').hidden=true;
 try{
  const response=await fetch('/api/abuseipdb/check',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',cache:'no-store',body:JSON.stringify({ip}),signal:abuseController.signal});
  const data=await response.json().catch(()=>null);if(requestId!==abuseRequestId)return;
  if(!response.ok||!data||data.status!=='ok'){const errors={401:'登录已失效，请刷新页面重新登录。',422:'请输入有效的公网 IP。',429:'AbuseIPDB 查询额度或并发限制，请稍后重试。',503:'风险查询尚未配置 API Key，请先完成安全录入。',502:'AbuseIPDB 暂时无法连接，请稍后重试。'};throw new Error(data?.notice||errors[response.status]||'风险查询失败，请稍后重试。');}
  text('abuseipdb-score',`${data.score} / 100`);text('abuseipdb-reports',data.total_reports);text('abuseipdb-reporters',data.distinct_reporters);
  text('abuseipdb-last',data.last_reported_at?when(data.last_reported_at):'暂无举报');text('abuseipdb-checked',`${when(data.checked_at)}${data.cached?' · 5 分钟内缓存':''}`);
  $('abuseipdb-result').hidden=false;text('abuseipdb-status',data.notice||`已查询 ${ip}，举报统计窗口 ${data.max_age_days} 天。`);
 }catch(error){if(requestId!==abuseRequestId||error.name==='AbortError')return;text('abuseipdb-status',error instanceof TypeError?'网络连接失败，请稍后重试。':error.message);}
 finally{if(requestId===abuseRequestId){$('abuseipdb-check').disabled=false;text('abuseipdb-check','查询 AbuseIPDB 风险分');}}
}
async function lookupIp(value){
 const ip=String(value).trim();const requestId=++ipRequestId;if(ipController)ipController.abort();ipController=new AbortController();
 $('ip-result').hidden=true;$('ip-status').className='muted';updateAbuseLink(null);resetAbuse();
 if(!ip){text('ip-status','请输入要查询的 IPv4 或 IPv6 地址。');$('ip-query-section').setAttribute('aria-busy','false');text('ip-query-button','查询属地');return;}
 $('ip-query-section').setAttribute('aria-busy','true');text('ip-query-button','查询中…');text('ip-status',`正在查询 ${ip}…`);
 try{
  const response=await fetch('/api/ip-info?'+new URLSearchParams({ip}),{credentials:'same-origin',cache:'no-store',signal:ipController.signal});
  const data=await response.json().catch(()=>null);if(requestId!==ipRequestId)return;
  if(response.ok||response.status===503){updateAbuseLink(data);setAbuseIP(data);}
  if(!response.ok){const messages={401:'登录已失效，请刷新页面重新登录。',422:'IP 地址格式无效，请输入完整的 IPv4 或 IPv6 地址。',503:'IP 属地库暂不可用，请联系管理员安装或更新数据库。'};throw new Error(messages[response.status]||`查询失败（${response.status}），请稍后重试。`);}
  if(!data||typeof data!=='object'||!data.ip)throw new Error('属地查询返回异常，请稍后重试。');
  renderIp(data);const messages={ok:'查询完成。',not_public:'这是非公网地址，没有可查询的公网属地。',not_found:'属地库暂未收录此 IP。',unavailable:'IP 属地库暂不可用，请稍后重试。'};
  text('ip-status',data.notice||messages[data.status]||'查询完成。');$('ip-status').className=data.status==='unavailable'?'error':'muted';
 }catch(error){if(requestId!==ipRequestId||error.name==='AbortError')return;text('ip-status',error instanceof TypeError?'无法连接属地查询服务，请检查网络后重试。':error.message);$('ip-status').className='error';}
 finally{if(requestId===ipRequestId){$('ip-query-section').setAttribute('aria-busy','false');text('ip-query-button','查询属地');}}
}
function sourceQuery(page,source){const query=new URLSearchParams({limit:String(pageSize),page:String(page)});if(source)query.set('source_id',source);return query;}
function renderSummary(data){
 text('event-total',data.totals.events);text('incident-total',data.totals.incidents);text('failure-total',data.totals.ssh_failures);text('success-total',data.totals.ssh_successes);
 text('updated',`概览更新于 ${when(data.generated_at)} · 原始日志保留 ${data.retention_days} 天`);
 const rowsKey=JSON.stringify(data.sources);
 if(rowsKey!==sourceRowsKey){const rows=$('sources');rows.replaceChildren();
 const labels={online:'在线',offline:'心跳超时',error:'采集异常',never_seen:'未连接'};
 for(const source of data.sources){const tr=document.createElement('tr');cell(tr,source.hostname);cell(tr,source.source_id);const state=cell(tr,labels[source.connection_status]||'未知');state.className=source.connection_status;cell(tr,when(source.last_seen));cell(tr,when(source.last_event_at));cell(tr,source.last_error||'无');rows.append(tr);}
 if(!data.sources.length)empty(rows,6,'尚未配置来源。');sourceRowsKey=rowsKey;}
 const selector=$('source-filter');const ids=JSON.stringify(data.sources.map(s=>[s.source_id,s.hostname]));
 if(selector.dataset.ids!==ids){selector.replaceChildren();const all=document.createElement('option');all.value='';all.textContent='全部来源';selector.append(all);for(const s of data.sources){const option=document.createElement('option');option.value=s.source_id;option.textContent=`${s.hostname} (${s.source_id})`;selector.append(option);}selector.value=currentSource;selector.dataset.ids=ids;}
}
function renderEvents(data){
 const rows=$('events');rows.replaceChildren();
 for(const event of data){const tr=document.createElement('tr');tr.className='selectable';tr.tabIndex=0;cell(tr,when(event.timestamp));cell(tr,event.source_id);cell(tr,event.event_kind||event.event_type);ipCell(tr,event.src_ip||event.peer_ip);cell(tr,event.message);tr.addEventListener('click',()=>details(event,'日志详情'));tr.addEventListener('keydown',e=>{if(e.target===tr&&e.key==='Enter')details(event,'日志详情');});rows.append(tr);}
 if(!data.length)empty(rows,5,'此页没有已接收的日志。');
}
function renderIncidents(data){
 const rows=$('incidents');rows.replaceChildren();
 for(const incident of data){const tr=document.createElement('tr');tr.className='selectable';tr.tabIndex=0;cell(tr,when(incident.last_seen));cell(tr,incident.hostname||incident.source_id);ipCell(tr,incident.src_ip||incident.peer_ip);cell(tr,incident.failure_count);cell(tr,incident.status==='open'?'待人工核查':incident.status);tr.addEventListener('click',()=>details(incident,'SSH 失败事件与原始证据'));tr.addEventListener('keydown',e=>{if(e.target===tr&&e.key==='Enter')details(incident,'SSH 失败事件与原始证据');});rows.append(tr);}
 if(!data.length)empty(rows,5,'尚未发现达到阈值的 SSH 登录失败事件。');
}
function updatePager(kind){
 const state=pages[kind];$(kind+'-prev').disabled=state.page<=1;$(kind+'-next').disabled=state.totalPages===null||state.page>=state.totalPages;
 const jump=$(kind+'-jump');jump.value=String(state.page);jump.disabled=state.totalPages===0;$(kind+'-jump-button').disabled=state.totalPages===0;
 if(state.totalPages===null)jump.removeAttribute('max');else jump.max=String(Math.max(1,state.totalPages));
 text(kind+'-page',state.totalPages===null?`第 ${state.page} 页 · 总页数待加载`:state.totalPages===0?'共 0 页 · 0 条':`第 ${state.page} 页 / 共 ${state.totalPages} 页 · ${state.total} 条`);
}
function beginList(kind,page){
 const state=pages[kind],source=currentSource,started=performance.now();const requestId=++state.requestId;if(state.controller)state.controller.abort();state.controller=new AbortController();
 const previous=state.displayed,sameView=state.visible&&state.visible.source===source&&state.visible.page===page;
 state.page=page;state.pending=true;updatePager(kind);updateRefreshButton();
 const rows=$(kind==='event'?'events':'incidents');
 if(!sameView){state.visible=null;rows.replaceChildren();empty(rows,5,`正在读取第 ${page} 页…`);text(kind+'-updated','');clearDetails();}
 $(kind+'-section').setAttribute('aria-busy','true');$(kind+'-status').className='list-status muted';
 text(kind+'-status',sameView?`正在更新第 ${page} 页，保留当前显示…`:`正在读取第 ${page} 页…`);$(kind+'-jump').removeAttribute('aria-invalid');
 return {kind,state,source,page,started,requestId,previous,sameView,rows};
}
function isCurrent(view){return view.requestId===view.state.requestId&&view.source===currentSource;}
async function acceptList(view,data){
  if(!isCurrent(view))return;const {kind,state,source,started,previous,sameView}=view;
  if(!data||!Array.isArray(data.items)||!Number.isInteger(data.total_pages)||data.total_pages<0||!Number.isInteger(data.total)||data.total<0||!Number.isInteger(data.page)||data.page<1)throw new Error('分页数据返回异常，请刷新重试。');
  state.total=data.total;state.totalPages=data.total_pages;const lastPage=Math.max(1,state.totalPages);
  if(data.page>lastPage){await loadList(kind,lastPage);return;}
  const itemsKey=JSON.stringify(data.items),unchanged=sameView&&previous.page===data.page&&previous.itemsKey===itemsKey;
  state.page=data.page;if(!unchanged){if(kind==='event')renderEvents(data.items);else renderIncidents(data.items);}
  state.displayed={source,page:state.page,total:state.total,totalPages:state.totalPages,items:data.items,itemsKey,updatedAt:new Date().toISOString(),elapsed:duration(started)};state.visible=state.displayed;
  updatePager(kind);text(kind+'-updated',`更新于 ${when(state.displayed.updatedAt)} · 用时 ${state.displayed.elapsed}`);text(kind+'-status',unchanged?'已是最新，内容无变化。':'');
}
function failList(view,error){
  if(!isCurrent(view)||error.name==='AbortError')return;const {kind,state,source,previous,sameView,rows}=view;
  let retained=false;
  if(previous&&previous.source===source){
   state.page=previous.page;state.total=previous.total;state.totalPages=previous.totalPages;state.displayed=previous;state.visible=previous;retained=true;
   if(!sameView){if(kind==='event')renderEvents(previous.items);else renderIncidents(previous.items);}
   text(kind+'-updated',`更新于 ${when(previous.updatedAt)} · 用时 ${previous.elapsed}`);
  }else{state.displayed=null;state.visible=null;rows.replaceChildren();empty(rows,5,'此来源暂时无法读取，请刷新重试。');}
  updatePager(kind);const message=error instanceof TypeError?'网络连接失败，请刷新重试。':error.message;
  text(kind+'-status',message+(retained?` 已保留第 ${state.page} 页上次成功读取的数据。`:''));$(kind+'-status').className='list-status error';
}
function finishList(view){if(view.requestId===view.state.requestId){view.state.pending=false;$(view.kind+'-section').setAttribute('aria-busy','false');updateRefreshButton();}}
async function loadList(kind,page=pages[kind].page){
 const view=beginList(kind,page);
 try{const data=await get((kind==='event'?'/api/events?':'/api/incidents?')+sourceQuery(page,view.source),view.state.controller.signal);await acceptList(view,data);}
 catch(error){failList(view,error);}
 finally{finishList(view);}
}
function navigate(kind,value){
 const state=pages[kind];const raw=String(value).trim();const page=Number(raw);const lastPage=state.totalPages===null?null:Math.max(1,state.totalPages);
 if(!/^[0-9]+$/.test(raw)||!Number.isSafeInteger(page)||page<1||(lastPage!==null&&page>lastPage)){$(kind+'-jump').setAttribute('aria-invalid','true');text(kind+'-status',lastPage===null?'请输入大于等于 1 的整数页码。':`请输入 1 至 ${lastPage} 之间的整数页码。`);$(kind+'-status').className='list-status error';return;}
 loadList(kind,page);
}
function scheduleAutoRefresh(){
 if(autoRefreshTimer!==null)clearTimeout(autoRefreshTimer);autoRefreshTimer=null;
 const minutes=Number($('refresh-interval').value);if(!minutes)return;
 autoRefreshTimer=setTimeout(()=>{autoRefreshTimer=null;if(document.hidden||isBusy()){scheduleAutoRefresh();return;}refresh();},minutes*60000);
}
async function refresh(){
 const requestId=++refreshRequestId;if(summaryController)summaryController.abort();summaryController=new AbortController();
 const controller=summaryController,source=currentSource;refreshRunning=true;summaryPending=true;updateRefreshButton();text('error','');
 const views=[beginList('event',pages.event.page),beginList('incident',pages.incident.page)];
 const query=new URLSearchParams({limit:String(pageSize),event_page:String(views[0].page),incident_page:String(views[1].page)});if(source)query.set('source_id',source);
 try{
  const data=await get('/api/dashboard?'+query,controller.signal);if(requestId!==refreshRequestId||source!==currentSource)return;
  if(!data||!data.summary||!data.events||!data.incidents)throw new Error('概览数据返回异常，请刷新重试。');
  renderSummary(data.summary);
  await Promise.all(views.map(async(view,index)=>{try{await acceptList(view,index===0?data.events:data.incidents);}catch(error){failList(view,error);}}));
 }catch(error){if(requestId===refreshRequestId&&error.name!=='AbortError'){text('error',`${error.message} 已保留上次成功读取的数据。`);for(const view of views)failList(view,error);}}
 finally{for(const view of views)finishList(view);if(requestId===refreshRequestId){refreshRunning=false;summaryPending=false;updateRefreshButton();scheduleAutoRefresh();}}
}
$('refresh').addEventListener('click',refresh);
$('refresh-interval').addEventListener('change',()=>{try{localStorage.setItem('riskops-refresh-minutes',$('refresh-interval').value);}catch{}scheduleAutoRefresh();});
$('ip-form').addEventListener('submit',event=>{event.preventDefault();lookupIp($('ip-input').value);});
$('abuseipdb-check').addEventListener('click',lookupAbuse);
$('source-filter').addEventListener('change',()=>{currentSource=$('source-filter').value;if(summaryController)summaryController.abort();++refreshRequestId;refreshRunning=false;summaryPending=false;clearDetails();for(const kind of ['event','incident']){pages[kind].totalPages=null;pages[kind].total=0;text(kind+'-updated','');loadList(kind,1);}scheduleAutoRefresh();});
for(const kind of ['event','incident']){
 $(kind+'-prev').addEventListener('click',()=>navigate(kind,pages[kind].page-1));
 $(kind+'-next').addEventListener('click',()=>navigate(kind,pages[kind].page+1));
 $(kind+'-jump-form').addEventListener('submit',event=>{event.preventDefault();navigate(kind,$(kind+'-jump').value);});
}
try{const saved=localStorage.getItem('riskops-refresh-minutes');if(['0','1','5','15'].includes(saved))$('refresh-interval').value=saved;}catch{}
refresh();
"""

DASHBOARD_HTML = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SecAgent RiskOps · 实时日志</title><style>__STYLE__</style></head>
<body><h1>SecAgent RiskOps · 实时日志</h1><p>查看已接入服务器的心跳、系统日志和 SSH 登录失败事件。所有内容来自采集器实际上传的数据；本页只读。</p>
<div class="toolbar"><label for="source-filter">日志来源</label><select id="source-filter"><option value="">全部来源</option></select><button id="refresh" type="button">刷新数据</button><label for="refresh-interval">自动刷新</label><select id="refresh-interval" aria-describedby="refresh-help"><option value="0">关闭（手动刷新）</option><option value="1">每 1 分钟</option><option value="5">每 5 分钟</option><option value="15">每 15 分钟</option></select><small id="updated">正在读取</small></div><p id="refresh-help">默认保留当前列表，点击“刷新数据”获取最新内容；刷新保留当前来源、页码与已打开的详情。自动刷新仅在页面可见且没有读取任务时运行。</p><div id="error" role="status"></div>
<div class="cards"><div class="card">保留期内日志<div class="number" id="event-total">—</div></div><div class="card">SSH 失败事件<div class="number" id="incident-total">—</div></div><div class="card">SSH 认证异常日志<div class="number" id="failure-total">—</div></div><div class="card">SSH 成功日志<div class="number" id="success-total">—</div></div></div>
<section><h2>来源状态</h2><p>来源 ID（source_id）是跨日志关联使用的稳定资产 ID，服务器一栏显示配置名称。在线表示近期收到采集器心跳；心跳超时不代表已确认入侵。</p><div class="table-wrap"><table><thead><tr><th>服务器</th><th>来源 ID</th><th>状态</th><th>最后心跳</th><th>最新日志时间</th><th>采集异常</th></tr></thead><tbody id="sources"></tbody></table></div></section>
<section id="ip-query-section" aria-busy="false"><h2>IP 属地查询</h2><p id="ip-help">输入 IPv4 / IPv6 地址，或点击下方日志中的来源 IP。属地查询使用离线库，不会自动发送 IP 给第三方；属地仅供参考，不能确定实际使用者位置。</p>
<form id="ip-form" class="ip-form"><label for="ip-input">IP 地址</label><input id="ip-input" name="ip" type="text" required maxlength="128" autocomplete="off" autocapitalize="off" spellcheck="false" aria-describedby="ip-help" placeholder="例如 8.8.8.8 或 2001:4860:4860::8888"><button id="ip-query-button" type="submit">查询属地</button></form>
<p id="ip-status" class="muted" role="status" aria-live="polite">等待输入 IP 地址。</p>
<p><button id="abuseipdb-check" type="button" disabled>查询 AbuseIPDB 风险分</button></p><p id="abuseipdb-status" role="status" aria-live="polite">先查询一个公网 IP，再点击风险查询。</p>
<div id="abuseipdb-result" hidden><dl class="ip-fields"><div><dt>风险评分（举报置信度）</dt><dd id="abuseipdb-score">—</dd></div><div><dt>近 90 天举报条数</dt><dd id="abuseipdb-reports">—</dd></div><div><dt>独立举报者</dt><dd id="abuseipdb-reporters">—</dd></div><div><dt>最近举报时间</dt><dd id="abuseipdb-last">—</dd></div></dl><p><small id="abuseipdb-checked"></small></p></div>
<p><a id="abuseipdb-link" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer" hidden>在 AbuseIPDB 查看完整报告 ↗</a></p><p><small>外部风险查询：仅在点击按钮或报告入口时向 AbuseIPDB 发送所选公网 IP，不发送 SSH 原始日志或账号。评分仅供核查，0 分不代表确认安全。</small></p>
<div id="ip-result" hidden><dl class="ip-fields"><div><dt>IP 地址</dt><dd id="ip-address">—</dd></div><div><dt>地址类型</dt><dd id="ip-type">—</dd></div><div><dt>国家 / 地区</dt><dd id="ip-country">—</dd></div><div><dt>省份 / 城市</dt><dd id="ip-region">—</dd></div><div><dt>网络组织</dt><dd id="ip-network">—</dd></div><div><dt>ASN</dt><dd id="ip-asn">—</dd></div><div><dt>属地库版本</dt><dd id="ip-database-release">—</dd></div><div><dt>数据库更新时间</dt><dd id="ip-database-updated">—</dd></div></dl><p>数据库状态：<span id="ip-database-status" class="muted">—</span></p></div>
<p><small>属地数据：<a href="https://db-ip.com" target="_blank" rel="noopener noreferrer">DB-IP Lite</a>（CC BY 4.0）。部分地址可能缺少城市或网络组织信息。</small></p></section>
<section id="incident-section" aria-busy="false"><h2>SSH 登录失败事件</h2><p>统计认证失败、无效账号和认证前断开的日志条数，不等于独立连接或攻击次数。事件保存在中控，刷新不会删除；点击查看证据或查询来源 IP。</p><p><small id="incident-updated"></small></p><div class="table-wrap"><table><thead><tr><th>最近发生</th><th>服务器</th><th>来源 IP</th><th>异常日志条数</th><th>状态</th></tr></thead><tbody id="incidents"></tbody></table></div><div class="pager"><button id="incident-prev" type="button">上一页</button><span id="incident-page"></span><button id="incident-next" type="button">下一页</button><form id="incident-jump-form" class="page-jump" novalidate><label for="incident-jump">跳至</label><input id="incident-jump" type="number" min="1" step="1" value="1" aria-label="SSH 失败事件页码" aria-describedby="incident-status"><span>页</span><button id="incident-jump-button" type="submit">跳转</button></form></div><p id="incident-status" class="list-status muted" role="status" aria-live="polite"></p></section>
<section id="event-section" aria-busy="false"><h2>已接收日志</h2><p>点击一行查看完整记录，点击来源 IP 查询属地。系统当前采集 SSH 相关日志；这里不代表服务器的全部网络流量。</p><p><small id="event-updated"></small></p><div class="table-wrap"><table><thead><tr><th>日志时间</th><th>来源</th><th>类型</th><th>来源 IP</th><th>原始消息</th></tr></thead><tbody id="events"></tbody></table></div><div class="pager"><button id="event-prev" type="button">上一页</button><span id="event-page"></span><button id="event-next" type="button">下一页</button><form id="event-jump-form" class="page-jump" novalidate><label for="event-jump">跳至</label><input id="event-jump" type="number" min="1" step="1" value="1" aria-label="日志页码" aria-describedby="event-status"><span>页</span><button id="event-jump-button" type="submit">跳转</button></form></div><p id="event-status" class="list-status muted" role="status" aria-live="polite"></p></section>
<section id="detail-section"><h2 id="detail-title">记录详情</h2><pre id="detail">选择上方记录查看详情。</pre></section><script>__SCRIPT__</script></body></html>""".replace("__STYLE__", _STYLE).replace("__SCRIPT__", _SCRIPT)


def _csp_hash(value: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(value.encode("utf-8")).digest()).decode("ascii") + "'"


CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src " + _csp_hash(_SCRIPT) + "; style-src " + _csp_hash(_STYLE)
    + "; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)
