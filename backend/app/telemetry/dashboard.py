"""Self-contained telemetry dashboard; no external assets or untrusted HTML."""
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
.incident-value{white-space:pre-line}
.triage{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}.triage-pending{background:#7a2e1d;color:#ffd9c7}.triage-acknowledged{background:#6b5314;color:#ffe9a8}.triage-resolved{background:#1d4d37;color:#b3f0d2}.row-actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}.row-actions button{padding:4px 8px;font-size:12px}#triage-note{min-width:220px;flex:1}.card small{display:block;margin-top:6px}.triage-time{display:block;font-size:12px;margin-top:4px}
.search-fields{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.search-fields label{display:flex;flex-direction:column;gap:6px;font-size:13px;color:#a9bacd}.search-fields input,.search-fields select{min-width:0;width:100%}.actions{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:14px}.selection{display:flex;gap:8px;align-items:center}.selection input{width:18px;height:18px}.danger{border-color:#d69673;color:#ffd2b6}.control-targets{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0}.control-targets label{display:flex;gap:6px;align-items:center}.control-targets input{width:18px;height:18px}fieldset{border:1px solid #37516d;border-radius:6px;margin:14px 0}textarea{background:#172941;color:#e7edf5;border:1px solid #37516d;border-radius:6px;width:100%;padding:10px;font:inherit}#control-plan{border-left:3px solid #d69673;padding-left:14px}#evidence-view table{font-size:12px}
@media(max-width:800px){body{padding:16px}.cards,.ip-fields,.search-fields{grid-template-columns:repeat(2,minmax(0,1fr))}.ip-form input{min-width:0;flex-basis:100%}}@media(max-width:480px){.search-fields{grid-template-columns:1fr}}
"""

_SCRIPT = """
'use strict';
const $=id=>document.getElementById(id);
let currentSource='', refreshRequestId=0, summaryController=null, summaryPending=false;
let sourceRowsKey=null, autoRefreshTimer=null, refreshRunning=false;
let ipRequestId=0, ipController=null, abuseRequestId=0, abuseController=null, abuseIP=null;
let eventFilters={},eventSnapshot=null,detailRequestId=0,detailController=null,detailIncident=null,evidencePage=1,evidenceTotalPages=1;
let controlsData=null,controlBusy=false,controlPlan=null,controlRevision=0,controlPollTimer=null,controlPollId=0,controlReadId=0;
let incidentTriage='pending',incidentFocus='all',incidentSort='score',triageBusy=false;
const scoreFilters=['all','attention','low','unscored'],scoreSorts=['score','recent'];
const triageLabels={pending:'待处理',acknowledged:'已知晓',resolved:'已处理'},triageFilters=['pending','acknowledged','resolved','all'];
const triageActions={pending:[['acknowledged','标为已知晓'],['resolved','标为已处理']],acknowledged:[['resolved','标为已处理'],['pending','退回待处理']],resolved:[['pending','重新打开']]};
const selectedTargets=new Map(),channelLabels={ssh:'SSH 端口',tcp:'全部 TCP（包含 SSH）',udp:'全部 UDP'};
const pageSize=50;
const pages={event:{page:1,total:0,totalPages:null,requestId:0,controller:null,pending:false,displayed:null,visible:null},incident:{page:1,total:0,totalPages:null,requestId:0,controller:null,pending:false,displayed:null,visible:null}};
function text(id,value){const node=$(id),next=String(value??'—');if(node.textContent!==next)node.textContent=next;}
function when(value){if(!value)return '尚未收到'; const d=new Date(value);return Number.isNaN(d.valueOf())?value:d.toLocaleString('zh-CN',{hour12:false});}
function duration(started){const elapsed=Math.round(performance.now()-started);return elapsed<1000?`${elapsed} 毫秒`:`${(elapsed/1000).toFixed(1)} 秒`;}
function isBusy(){return refreshRunning||summaryPending||Object.values(pages).some(state=>state.pending);}
function updateRefreshButton(){const busy=isBusy();$('refresh').disabled=busy;text('refresh',busy?'正在更新…':'刷新数据');}
function clearDetails(){++detailRequestId;if(detailController)detailController.abort();detailIncident=null;$('evidence-view').hidden=true;text('detail-title','记录详情');text('detail','选择上方记录查看详情。');}
function cell(row,value){const td=document.createElement('td');td.textContent=String(value??'—');row.append(td);return td;}
function empty(tbody,span,message){const tr=document.createElement('tr');const td=cell(tr,message);td.colSpan=span;tbody.append(tr);}
async function get(path,signal){const response=await fetch(path,{credentials:'same-origin',cache:'no-store',signal});if(!response.ok)throw new Error(response.status===401?'登录已失效，请刷新页面重新登录。':`读取失败（${response.status}）。请检查中控服务。`);return response.json();}
function details(record,title){clearDetails();text('detail-title',title);text('detail',JSON.stringify(record,null,2));$('detail-section').scrollIntoView({behavior:'smooth',block:'nearest'});}
function filterKey(){return JSON.stringify({filters:eventFilters,snapshot:eventSnapshot});}
function listKey(kind){return kind==='event'?filterKey():JSON.stringify([incidentTriage,incidentFocus,incidentSort]);}
function saveView(){try{sessionStorage.setItem('riskops-view',JSON.stringify({source:currentSource,filters:eventFilters,snapshot:eventSnapshot,eventPage:pages.event.page,incidentPage:pages.incident.page,incidentTriage,incidentFocus,incidentSort}));}catch{}}
function setFilterInputs(){for(const key of ['ip','username','event_type','q','start','end']){let value=eventFilters[key]||'';if(value&&(key==='start'||key==='end')){const d=new Date(value);if(!Number.isNaN(d.valueOf())){const local=new Date(d.valueOf()-d.getTimezoneOffset()*60000);value=local.toISOString().slice(0,16);}}$('search-'+key).value=value;}}
function queryLogsForIP(ip){eventFilters={...eventFilters,ip:String(ip)};eventSnapshot=null;setFilterInputs();saveView();loadList('event',1);$('event-section').scrollIntoView({behavior:'smooth',block:'start'});}
async function showIncident(incident){
 clearDetails();const id=incident.incident_id;if(!id){details(incident,'SSH 认证告警与原始证据');return;}
 detailIncident=String(id);const requestId=++detailRequestId;detailController=new AbortController();text('detail-title','SSH 认证告警与原始证据');text('detail','正在读取事件详情…');$('detail-section').scrollIntoView({behavior:'smooth',block:'nearest'});
 try{const data=await get('/api/incidents/'+encodeURIComponent(id),detailController.signal);if(requestId!==detailRequestId)return;const summary={...data};delete summary.evidence_snapshots;text('detail',JSON.stringify(summary,null,2));await loadEvidence(1);}
 catch(error){if(requestId===detailRequestId&&error.name!=='AbortError')text('detail',error.message);}
}
async function loadEvidence(page){
 if(!detailIncident)return;const id=detailIncident,requestId=++detailRequestId;if(detailController)detailController.abort();detailController=new AbortController();$('evidence-view').hidden=false;text('evidence-status','正在读取原始证据…');
 try{const data=await get('/api/incidents/'+encodeURIComponent(id)+'/evidence?'+new URLSearchParams({page:String(page),limit:String(pageSize)}),detailController.signal);if(requestId!==detailRequestId||id!==detailIncident)return;
  if(!Array.isArray(data.items)||!Number.isInteger(data.page)||!Number.isInteger(data.total_pages))throw new Error('证据分页返回异常，请重试。');
  evidencePage=data.page;evidenceTotalPages=Math.max(1,data.total_pages);const rows=$('evidence-rows');rows.replaceChildren();
  for(const record of data.items){const tr=document.createElement('tr');cell(tr,when(record.timestamp));cell(tr,record.source_id);cell(tr,record.event_kind||record.event_type);ipCell(tr,record.peer_ip||record.src_ip);cell(tr,record.username||record.ssh_user);cell(tr,record.message);rows.append(tr);}if(!data.items.length)empty(rows,6,'没有可显示的证据。');
  text('evidence-page',`第 ${evidencePage} 页 / 共 ${evidenceTotalPages} 页 · ${data.total} 条证据`);$('evidence-jump').value=String(evidencePage);$('evidence-jump').max=String(evidenceTotalPages);$('evidence-prev').disabled=evidencePage<=1;$('evidence-next').disabled=evidencePage>=evidenceTotalPages;text('evidence-status','证据按时间顺序展示，跨服务器记录在同一时间线中。');
 }catch(error){if(requestId===detailRequestId&&error.name!=='AbortError')text('evidence-status',error.message+' 已保留上次成功读取的证据。');}
}
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
function sourceQuery(page,source,kind='incident'){const query=new URLSearchParams({limit:String(pageSize),page:String(page)});if(source)query.set('source_id',source);if(kind==='event')appendEventQuery(query);else{query.set('include_evidence','false');query.set('triage',incidentTriage);query.set('focus',incidentFocus);query.set('sort',incidentSort);}return query;}
function appendEventQuery(query){for(const [key,value] of Object.entries(eventFilters))if(value)query.set(key,value);if(eventSnapshot!==null)query.set('snapshot',String(eventSnapshot));}
function targetKey(target){return JSON.stringify([target.source_id,target.ip]);}
function incidentTargets(incident){const ip=incident.src_ip||incident.peer_ip;if(!ip)return [];const sources=currentSource?[currentSource]:(Array.isArray(incident.source_ids)&&incident.source_ids.length?incident.source_ids:[incident.source_id]);return [...new Set(sources.filter(Boolean))].map(source_id=>({source_id,ip:String(ip)}));}
function appendIncidentSelection(td,incident){
 const targets=incidentTargets(incident);if(!targets.length)return;const label=document.createElement('label');label.className='selection';const input=document.createElement('input');input.type='checkbox';input.checked=targets.every(target=>selectedTargets.has(targetKey(target)));input.setAttribute('aria-label',`选择 ${targets[0].ip}，涉及 ${targets.length} 个来源`);
 input.addEventListener('change',()=>{for(const target of targets){if(input.checked)selectedTargets.set(targetKey(target),target);else selectedTargets.delete(targetKey(target));}invalidatePlan();renderSelectedTargets();});label.addEventListener('click',event=>event.stopPropagation());label.addEventListener('keydown',event=>event.stopPropagation());const caption=document.createElement('span');caption.textContent=`选择 IP（${targets.length} 个来源）`;label.append(input,caption);td.append(label);
}
function invalidatePlan(){++controlRevision;controlPlan=null;$('control-plan').hidden=true;$('control-confirm').checked=false;$('control-execute').disabled=true;}
function controlState(){const enabled=controlsData?.enabled===true&&!controlBusy;$('control-preview').disabled=!enabled||!selectedTargets.size;$('control-execute').disabled=!enabled||!controlPlan||!$('control-confirm').checked;}
function durationLabel(value){return value===null?'永久（需要手动解封）':value===86400?'24 小时':value===3600?'1 小时':`${value/60} 分钟`;}
function renderSelectedTargets(){
 const rows=$('control-selected');rows.replaceChildren();for(const [key,target] of selectedTargets){const row=document.createElement('tr');cell(row,target.source_id);cell(row,target.ip);const td=cell(row,'');const remove=document.createElement('button');remove.type='button';remove.textContent='移除';remove.addEventListener('click',()=>{selectedTargets.delete(key);invalidatePlan();renderSelectedTargets();if(pages.incident.displayed)renderIncidents(pages.incident.displayed.items);});td.append(remove);rows.append(row);}if(!selectedTargets.size)empty(rows,3,'尚未选择目标。请勾选告警，或输入单个 IP 并勾选目标来源。');text('control-selection-count',`已选 ${selectedTargets.size} 个 IP / 来源组合；仅这些目标会进入预览。`);text('incident-control-open',`查看已选目标与封禁预览（${selectedTargets.size}）`);controlState();
}
function renderControlSources(sources){
 const wrap=$('control-sources'),key=JSON.stringify(sources);if(wrap.dataset.key===key)return;wrap.dataset.key=key;wrap.replaceChildren();
 for(const source of sources){const label=document.createElement('label'),input=document.createElement('input'),caption=document.createElement('span');input.type='checkbox';input.value=source.source_id;input.checked=!!currentSource&&source.source_id===currentSource;caption.textContent=`${source.hostname||source.source_id} (${source.source_id}) · SSH ${(source.ssh_ports||[]).join('、')}`;label.append(input,caption);wrap.append(label);}
}
function renderBlocks(blocks){
 const checks=controlsData?.source_checks||[],rows=$('control-blocks');rows.replaceChildren();for(const block of blocks){const check=checks.find(item=>item.source_id===block.source_id),tr=document.createElement('tr');cell(tr,block.source_id);cell(tr,block.ip);cell(tr,channelLabels[block.channel]||block.channel);cell(tr,block.expires_at?when(typeof block.expires_at==='number'?block.expires_at*1000:block.expires_at):'永久');cell(tr,`${block.verified_at?when(block.verified_at*1000):'尚未确认'}${!check||check.error?' · 当前待核实':''}`);const td=cell(tr,'');const button=document.createElement('button');button.type='button';button.textContent='预览解封';button.disabled=!controlsData?.enabled;button.addEventListener('click',()=>previewUnban(block));td.append(button);rows.append(tr);}if(!blocks.length)empty(rows,6,'暂无封禁记录；请结合下方各来源核实状态判断。');
 text('control-source-checks',checks.length?checks.map(check=>`${check.source_id} · ${when(check.checked_at*1000)} · ${check.error?'无法核实：'+check.error:'已核实'}`).join('\\n'):'尚未收到来源核实结果。');
}
async function loadControls(){
 const readId=++controlReadId;try{const data=await get('/api/controls');if(readId!==controlReadId)return;controlsData=data;renderControlSources(Array.isArray(data.sources)?data.sources:[]);renderBlocks(Array.isArray(data.blocks)?data.blocks:[]);text('control-availability',data.enabled?'手动控制已启用。先选择目标、范围和时长，再预览确认。':'此中控尚未配置受限执行通道，仍可查看告警；封禁暂不可用。');controlState();renderJobHistory(Array.isArray(data.jobs)?data.jobs:[]);}
 catch(error){if(readId!==controlReadId)return;text('control-availability',error.message+' 下方仅保留上次读取的状态，当前情况待核实。');controlsData=null;controlState();}
}
async function csrfPost(path,payload){
 if(!controlsData?.csrf_token)throw new Error('操作校验尚未准备好，请点击“刷新封禁状态与操作记录”后重试。');
 const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-RiskOps-CSRF':controlsData.csrf_token},credentials:'same-origin',cache:'no-store',body:JSON.stringify(payload)});const data=await response.json().catch(()=>null);
 if(!response.ok){const errors={401:'登录已失效，请重新登录。',403:'操作校验失效，请刷新封禁状态后重新预览。',409:'计划已过期或状态冲突，请重新预览。',422:'目标、范围或时长不符合控制策略。',503:'受限执行通道尚不可用。'};const detail=typeof data?.detail==='string'?data.detail:null;throw new Error(detail||errors[response.status]||`操作失败（${response.status}）。`);}if(!data||typeof data!=='object')throw new Error('操作接口返回异常。');return data;
}
async function controlPost(path,payload){if(!controlsData?.enabled)throw new Error('执行通道尚未准备好，请刷新封禁状态。');return csrfPost(path,payload);}
function renderTriageCounts(counts){
 if(!counts||typeof counts!=='object')return;const n=key=>Number.isInteger(counts[key])?counts[key]:0;
 text('incident-total',n('pending'));text('incident-triage-summary',`已知晓 ${n('acknowledged')} · 已处理 ${n('resolved')} · 合计 ${n('total')}`);
 text('incident-triage-counts',`待处理 ${n('pending')} · 已知晓 ${n('acknowledged')} · 已处理 ${n('resolved')}`);
}
function appendTriageActions(td,incident,state){
 const id=incident.incident_id;if(!id)return;const options=triageActions[state]||[];if(!options.length)return;const wrap=document.createElement('div');wrap.className='row-actions';
 for(const [target,label] of options){const button=document.createElement('button');button.type='button';button.textContent=label;button.disabled=triageBusy;button.setAttribute('aria-label',`${label}：${incident.src_ip||incident.peer_ip||id}`);button.addEventListener('click',event=>{event.stopPropagation();triageIncident(String(id),target);});button.addEventListener('keydown',event=>event.stopPropagation());wrap.append(button);}
 td.append(wrap);
}
async function triageIncident(id,state){
 if(triageBusy)return;triageBusy=true;$('triage-status').className='list-status muted';text('triage-status',`正在将告警标为${triageLabels[state]||state}…`);
 try{
  const note=$('triage-note').value.trim();const data=await csrfPost('/api/incidents/triage',{incident_ids:[id],state,...(note?{note}:{})});
  const outcome=Array.isArray(data.results)&&data.results[0]?data.results[0].result:null;
  const messages={changed:`已将告警标为${triageLabels[state]}。`,unchanged:'告警已是该状态，未做更改。',invalid:`当前状态不允许直接改为${triageLabels[state]}。`,missing:'告警不存在或已合并，请刷新列表。'};
  text('triage-status',messages[outcome]||'处置结果未知，请刷新列表核对。');if(data.triage_counts)renderTriageCounts(data.triage_counts);
 }catch(error){text('triage-status',error instanceof TypeError?'网络连接失败，请稍后重试。':error.message);$('triage-status').className='list-status error';}
 finally{triageBusy=false;}
 await loadList('incident',pages.incident.page);
}
function controlPayload(){const channels=['ssh','tcp','udp'].filter(channel=>$('control-channel-'+channel).checked),durationValue=$('control-duration').value;return {action:'ban',targets:[...selectedTargets.values()],channels,duration_seconds:durationValue==='permanent'?null:Number(durationValue),reason:$('control-reason').value.trim()};}
async function previewControl(payload=controlPayload()){
 if(controlBusy)return;invalidatePlan();const revision=controlRevision;controlBusy=true;controlState();text('control-status','正在核对目标与保护规则，尚未执行…');
 try{if(!payload.targets.length)throw new Error('请先选择至少一个 IP / 来源组合。');if(!payload.channels.length)throw new Error('请至少选择一个封禁范围。');if(!payload.reason)throw new Error('请填写操作原因，便于审计。');const plan=await controlPost('/api/controls/preview',payload);if(revision!==controlRevision)return;
  if(!plan.plan_id||!Array.isArray(plan.items)||!plan.items.length)throw new Error('操作计划返回异常，请重试。');controlPlan={...plan,action:payload.action};const rows=$('control-plan-items');rows.replaceChildren();for(const item of plan.items){const tr=document.createElement('tr');cell(tr,item.source_id);cell(tr,item.ip);cell(tr,channelLabels[item.channel]||item.channel);cell(tr,item.action==='unban'?'解封':durationLabel(item.duration_seconds));rows.append(tr);}text('control-plan-title',payload.action==='unban'?'请核对解封计划':'请核对封禁计划');text('control-plan-expiry',`共 ${plan.items.length} 项；计划有效至 ${when(typeof plan.expires_at==='number'?plan.expires_at*1000:plan.expires_at)}。修改选择后需要重新预览。`);$('control-plan').hidden=false;text('control-status','预览已生成，尚未执行。请核对所有目标和范围。');$('control-plan').scrollIntoView({behavior:'smooth',block:'nearest'});
 }catch(error){text('control-status',error.message);}finally{controlBusy=false;controlState();}
}
async function previewUnban(block){
 $('control-section').scrollIntoView({behavior:'smooth',block:'start'});await previewControl({action:'unban',targets:[{source_id:block.source_id,ip:block.ip}],channels:[block.channel],duration_seconds:3600,reason:$('control-reason').value.trim()||'操作员手动解封'});
}
const jobStatusLabels={queued:'等待执行',running:'正在执行',done:'已完成',partial:'部分完成',failed:'失败',succeeded:'成功',success:'成功',ok:'成功',pending:'等待执行',blocked:'拒绝执行',unknown:'结果待核实'};
function renderJob(job){
 text('control-job-title',`操作 ${job.id||job.job_id||''} · ${jobStatusLabels[job.status]||job.status}`);const rows=$('control-job-items');rows.replaceChildren();for(const item of job.items||[]){const tr=document.createElement('tr');cell(tr,item.source_id);cell(tr,item.ip);cell(tr,channelLabels[item.channel]||item.channel);cell(tr,jobStatusLabels[item.status]||item.status);cell(tr,item.error||item.message||'—');rows.append(tr);}if(!(job.items||[]).length)empty(rows,5,'任务已建立，等待执行结果。');$('control-job').hidden=false;
}
function renderJobHistory(jobs){const list=$('control-history');list.replaceChildren();for(const job of jobs){const button=document.createElement('button');button.type='button';button.textContent=`${when(typeof job.created_at==='number'?job.created_at*1000:job.created_at)} · ${jobStatusLabels[job.status]||job.status}`;button.addEventListener('click',()=>watchJob(job.id||job.job_id));list.append(button);}if(!jobs.length)list.textContent='暂无操作记录。';}
async function watchJob(id,attempt=0,pollId=null){
 if(!id)return;if(pollId===null){pollId=++controlPollId;if(controlPollTimer!==null)clearTimeout(controlPollTimer);}try{const job=await get('/api/controls/jobs/'+encodeURIComponent(id));if(pollId!==controlPollId)return;renderJob(job);if(['done','partial','failed','succeeded'].includes(job.status)){text('control-status',job.status==='done'||job.status==='succeeded'?'操作完成，请查看逐项结果；已核实封禁的告警会自动标为已处理。':'操作已结束，请检查失败项目。');await loadControls();await loadList('incident',pages.incident.page);return;}const delay=Math.min(15000,3000*(1+Math.floor(attempt/5)));controlPollTimer=setTimeout(()=>watchJob(id,attempt+1,pollId),delay);}
 catch(error){if(pollId!==controlPollId)return;text('control-status',error.message+' 执行任务可能仍在运行，请从操作记录重新查看；不要重复提交。');}
}
async function executeControl(){
 if(controlBusy||!controlPlan||!$('control-confirm').checked)return;const plan=controlPlan;if(plan.expires_at&&Date.now()/1000>=Number(plan.expires_at)){invalidatePlan();text('control-status','计划已过期，请重新预览。');return;}controlBusy=true;controlState();text('control-status','正在提交已确认的计划…');
 try{const job=await controlPost('/api/controls/execute',{plan_id:plan.plan_id});invalidatePlan();renderJob(job);text('control-status','任务已提交，正在读取执行结果…');await watchJob(job.id||job.job_id);}
 catch(error){invalidatePlan();text('control-status',error.message+' 请先刷新操作记录核实是否已建立任务，再决定是否重新预览。');await loadControls();}finally{controlBusy=false;controlState();}
}
const issueKinds={coverage_start:'覆盖起点：更早的日志不在采集范围',cursor_lost:'采集游标丢失，从近期窗口重新开始',retention_gap:'来源日志已轮转，旧游标失效',cursor_reset:'游标重置，但恢复窗口覆盖了已收日志，没有缺失',silence:'一段时间没有批次到达（采集器或中控 API 未运行）',source_error:'来源读取失败，等待重试',catching_up:'积压追赶中',delivery_delay:'批次在采集器本地排队后才送达',message_truncated:'超长日志消息被截断',restore:'从恢复包还原的时间点'};
const issueCategories={gap:'缺口',delay:'延迟',notice:'提示'};
function completeness(c){if(!c)return ['尚无记录','muted'];
 // A source collected before tracking began: only the time since tracking is known to be complete.
 const since=c.coverage_note?`自 ${when(c.tracking_since)} 开始记录以来`:c.coverage_start?`自覆盖起点 ${when(c.coverage_start)} 以来`:'覆盖起点未知，';
 const earlier=c.coverage_note&&c.coverage_start?`；覆盖起点约 ${when(c.coverage_start)}，此前未记录缺口`:'';
 if(!c.gaps_since_coverage)return [`完整：${since}无缺口${earlier}`,'online'];const g=c.last_gap;return [`${since}有 ${c.gaps_since_coverage} 处缺口；最近一处 ${g?when(g.started_at)+' 至 '+when(g.ended_at):''}${earlier}`,'error'];}
function lateness(c){if(!c)return ['—','muted'];const open=c.open||[];if(open.includes('source_error'))return ['来源读取失败，日志留在来源等待重试','error'];if(open.includes('catching_up')||!c.caught_up)return ['追赶中：还有积压','offline'];const lag=Number(c.last_delivery_lag_seconds);return [`已追上${Number.isFinite(lag)&&lag>=60?`（最近一批晚到 ${Math.round(lag)} 秒）`:''}`,'online'];}
let collectionPage=1,collectionPages=1,collectionRequestId=0;
async function loadCollection(page=collectionPage){const requestId=++collectionRequestId;const query=new URLSearchParams({limit:'20',page:String(page)});if(currentSource)query.set('source_id',currentSource);
 try{const data=await get('/api/collection-issues?'+query);if(requestId!==collectionRequestId)return;collectionPage=data.page;collectionPages=data.total_pages;const rows=$('collection-rows');rows.replaceChildren();
  for(const issue of data.items){const tr=document.createElement('tr');cell(tr,when(issue.opened_at));cell(tr,issue.source_id);cell(tr,issueCategories[issue.category]||issue.category).className=issue.category==='gap'?'error':issue.category==='delay'?'offline':'muted';const kind=cell(tr,issueKinds[issue.kind]||issue.kind);kind.title=issue.detail||'';cell(tr,issue.started_at||issue.ended_at?`${issue.started_at?when(issue.started_at):'此前'} 至 ${issue.ended_at?when(issue.ended_at):'现在'}`:'—');cell(tr,issue.batches);cell(tr,issue.ended_at||issue.category!=='delay'?'已结束':'进行中');rows.append(tr);}
  if(!data.items.length)empty(rows,7,'没有缺口或延迟记录。');text('collection-page',`第 ${collectionPage} / ${collectionPages} 页，共 ${data.total} 条`);text('collection-status','');$('collection-prev').disabled=collectionPage<=1;$('collection-next').disabled=collectionPage>=collectionPages;}
 catch(error){if(requestId===collectionRequestId)text('collection-status',`${error.message} 已保留上次读取的采集记录。`);}}
function renderSummary(data){
 text('event-total',data.totals.events);text('failure-total',data.totals.ssh_failures);text('success-total',data.totals.ssh_successes);
 if(data.triage_counts)renderTriageCounts(data.triage_counts);else text('incident-total',data.totals.incidents);
 text('updated',`概览更新于 ${when(data.generated_at)} · 原始日志保留 ${data.retention_days} 天`);
 const rowsKey=JSON.stringify(data.sources);
 if(rowsKey!==sourceRowsKey){const rows=$('sources');rows.replaceChildren();
 const labels={online:'在线',offline:'心跳超时',error:'采集异常',never_seen:'未连接'};
 for(const source of data.sources){const tr=document.createElement('tr');cell(tr,source.hostname);cell(tr,source.source_id);const state=cell(tr,labels[source.connection_status]||'未知');state.className=source.connection_status;const [integrity,integrityClass]=completeness(source.collection);cell(tr,integrity).className=integrityClass;const [delay,delayClass]=lateness(source.collection);cell(tr,delay).className=delayClass;cell(tr,when(source.last_seen));cell(tr,when(source.last_event_at));rows.append(tr);}
 if(!data.sources.length)empty(rows,7,'尚未配置来源。');sourceRowsKey=rowsKey;}
 const selector=$('source-filter');const ids=JSON.stringify(data.sources.map(s=>[s.source_id,s.hostname]));
 if(selector.dataset.ids!==ids){selector.replaceChildren();const all=document.createElement('option');all.value='';all.textContent='全部来源';selector.append(all);for(const s of data.sources){const option=document.createElement('option');option.value=s.source_id;option.textContent=`${s.hostname} (${s.source_id})`;selector.append(option);}selector.value=currentSource;selector.dataset.ids=ids;}
}
function renderEvents(data){
 const rows=$('events');rows.replaceChildren();
 for(const event of data){const tr=document.createElement('tr');tr.className='selectable';tr.tabIndex=0;cell(tr,when(event.timestamp));cell(tr,event.source_id);cell(tr,event.event_kind||event.event_type);ipCell(tr,event.src_ip||event.peer_ip);cell(tr,event.message);tr.addEventListener('click',()=>details(event,'日志详情'));tr.addEventListener('keydown',e=>{if(e.target===tr&&e.key==='Enter')details(event,'日志详情');});rows.append(tr);}
 if(!data.length)empty(rows,5,'此页没有已接收的日志。');
}
const detectionRuleLabels={burst:'短时密集失败',slow_scan:'慢速扫描',multi_account:'多账号尝试',cross_source:'跨服务器尝试',success_after_failures:'多次失败后成功'};
function incidentSources(incident){
 const sourceIds=Array.isArray(incident.source_ids)&&incident.source_ids.length?incident.source_ids:[incident.source_id].filter(Boolean);
 const hostnames=Array.isArray(incident.hostnames)&&incident.hostnames.length?incident.hostnames:[incident.hostname].filter(Boolean);
 return [hostnames.join('、'),sourceIds.length?`来源 ID：${sourceIds.join('、')}`:''].filter(Boolean).join('\\n')||'—';
}
function incidentRules(incident){
 return Array.isArray(incident.rules)?incident.rules.filter(rule=>rule&&typeof rule==='object'):[];
}
function scoreReason(reason){
 return String(reason)
  .replace(/login succeeded after failed attempts/,'多次失败后登录成功')
  .replace(/attempts against (\\d+) existing non-root account\\(s\\)/,'尝试 $1 个非 root 有效账号')
  .replace(/activity on (\\d+) hosts/,'涉及 $1 台服务器')
  .replace(/persisted for ([\\d.]+) h/,'持续 $1 小时')
  .replace(/(\\d+) failed-authentication records/,'$1 条认证失败日志');
}
function renderAssessment(parent,assessment){
 const box=document.createElement('div');box.className='incident-value';
 if(!assessment||assessment.status!=='scored'||!Number.isFinite(assessment.score)){
  box.textContent='尚未评分 · 保留待核查';parent.append(box);return;
 }
 const title=document.createElement('strong');title.textContent=`${assessment.score} 分 · ${assessment.priority||'低分'} · ${assessment.surfaced?'优先核查':'低于关注线'}`;box.append(title);
 const reasons=Array.isArray(assessment.reasons)?assessment.reasons:[];
 const detail=document.createElement('details'),summary=document.createElement('summary');summary.textContent='评分原因';detail.addEventListener('click',event=>event.stopPropagation());detail.addEventListener('keydown',event=>event.stopPropagation());detail.append(summary);
 const body=document.createElement('div');body.textContent=reasons.length?reasons.map(scoreReason).join('\\n'):'未命中加分项；低分不代表安全。';detail.append(body);box.append(detail);parent.append(box);
}
function renderScoreCounts(counts){
 if(!counts){text('incident-score-counts','');return;}
 text('incident-score-counts',`当前来源 / 处置状态：优先核查 ${counts.attention??0} · 低分 ${counts.low??0} · 未评分 ${counts.unscored??0} · 合计 ${counts.total??0}`);
}
function renderIncidents(data){
 const rows=$('incidents');rows.replaceChildren();
 for(const incident of data){
  const tr=document.createElement('tr');tr.className='selectable';tr.tabIndex=0;cell(tr,when(incident.last_seen));
  const sources=cell(tr,incidentSources(incident));sources.className='incident-value';ipCell(tr,incident.src_ip||incident.peer_ip);
  const counts=[`失败日志：${incident.failure_count??0} 条`];
  if(incident.success_count!==undefined&&incident.success_count!==null)counts.push(`成功日志：${incident.success_count} 条`);
  if(incident.username_count!==undefined&&incident.username_count!==null)counts.push(`非空账号：${incident.username_count} 个`);
  const countCell=cell(tr,counts.join('\\n'));countCell.className='incident-value';
  if(Array.isArray(incident.usernames)&&incident.usernames.length)countCell.title=`涉及账号：${incident.usernames.join('、')}`;
  const rules=incidentRules(incident),ruleCell=cell(tr,rules.length?rules.map(rule=>detectionRuleLabels[rule.rule_id]||rule.rule_id||'未知规则').join('、'):'登录失败（旧版记录）');
  ruleCell.title=rules.map(rule=>[rule.reason,rule.window_seconds?`窗口 ${rule.window_seconds} 秒`:null,rule.rule_version?`版本 ${rule.rule_version}`:null].filter(Boolean).join(' · ')).join('\\n');
  renderAssessment(ruleCell,incident.assessment);
  const state=triageLabels[incident.triage_status]?incident.triage_status:'pending',statusCell=cell(tr,''),badge=document.createElement('span');badge.className='triage triage-'+state;badge.textContent=triageLabels[state];statusCell.append(badge);
  if(incident.triage_updated_at){const stamp=document.createElement('small');stamp.className='muted triage-time';stamp.textContent=`更新于 ${when(incident.triage_updated_at)}`;statusCell.append(stamp);}
  appendIncidentSelection(statusCell,incident);appendTriageActions(statusCell,incident,state);tr.addEventListener('click',()=>showIncident(incident));tr.addEventListener('keydown',e=>{if(e.target===tr&&e.key==='Enter')showIncident(incident);});rows.append(tr);
 }
 if(!data.length)empty(rows,6,incidentFocus!=='all'?'当前评分筛选没有匹配事件；可切换全部查看。':incidentTriage==='all'?'尚未发现达到阈值的 SSH 认证告警。':`没有${triageLabels[incidentTriage]||''}状态的告警；可切换处置状态查看其他告警。`);
}
function updatePager(kind){
 const state=pages[kind];$(kind+'-prev').disabled=state.page<=1;$(kind+'-next').disabled=state.totalPages===null||state.page>=state.totalPages;
 const jump=$(kind+'-jump');jump.value=String(state.page);jump.disabled=state.totalPages===0;$(kind+'-jump-button').disabled=state.totalPages===0;
 if(state.totalPages===null)jump.removeAttribute('max');else jump.max=String(Math.max(1,state.totalPages));
 text(kind+'-page',state.totalPages===null?`第 ${state.page} 页 · 总页数待加载`:state.totalPages===0?'共 0 页 · 0 条':`第 ${state.page} 页 / 共 ${state.totalPages} 页 · ${state.total} 条`);
}
function beginList(kind,page){
 const state=pages[kind],source=currentSource,started=performance.now();const requestId=++state.requestId;if(state.controller)state.controller.abort();state.controller=new AbortController();
 const queryKey=listKey(kind),previous=state.displayed,sameView=state.visible&&state.visible.source===source&&state.visible.page===page&&state.visible.queryKey===queryKey;
 state.page=page;state.pending=true;updatePager(kind);updateRefreshButton();
 const rows=$(kind==='event'?'events':'incidents');
 if(!sameView){state.visible=null;rows.replaceChildren();empty(rows,kind==='incident'?6:5,`正在读取第 ${page} 页…`);text(kind+'-updated','');clearDetails();}
 $(kind+'-section').setAttribute('aria-busy','true');$(kind+'-status').className='list-status muted';
 text(kind+'-status',sameView?`正在更新第 ${page} 页，保留当前显示…`:`正在读取第 ${page} 页…`);$(kind+'-jump').removeAttribute('aria-invalid');
 return {kind,state,source,page,started,requestId,previous,sameView,rows,queryKey};
}
function isCurrent(view){return view.requestId===view.state.requestId&&view.source===currentSource;}
async function acceptList(view,data){
  if(!isCurrent(view))return;const {kind,state,source,started,previous,sameView}=view;
  if(!data||!Array.isArray(data.items)||!Number.isInteger(data.total_pages)||data.total_pages<0||!Number.isInteger(data.total)||data.total<0||!Number.isInteger(data.page)||data.page<1)throw new Error('分页数据返回异常，请刷新重试。');
  state.total=data.total;state.totalPages=data.total_pages;const lastPage=Math.max(1,state.totalPages);
  if(data.page>lastPage){await loadList(kind,lastPage);return;}
  const itemsKey=JSON.stringify(data.items),unchanged=sameView&&previous.page===data.page&&previous.itemsKey===itemsKey;
  state.page=data.page;if(!unchanged){if(kind==='event')renderEvents(data.items);else renderIncidents(data.items);}
  if(kind==='event'&&data.snapshot!==undefined)eventSnapshot=data.snapshot;
  if(kind==='incident'){if(data.triage_counts)renderTriageCounts(data.triage_counts);renderScoreCounts(data.score_counts);}
  state.displayed={source,page:state.page,queryKey:listKey(kind),total:state.total,totalPages:state.totalPages,items:data.items,itemsKey,updatedAt:new Date().toISOString(),elapsed:duration(started)};state.visible=state.displayed;saveView();
  updatePager(kind);text(kind+'-updated',`更新于 ${when(state.displayed.updatedAt)} · 用时 ${state.displayed.elapsed}`);text(kind+'-status',unchanged?'已是最新，内容无变化。':'');
}
function failList(view,error){
  if(!isCurrent(view)||error.name==='AbortError')return;const {kind,state,source,previous,sameView,rows}=view;
  let retained=false;
  if(previous&&previous.source===source&&previous.queryKey===listKey(kind)){
   state.page=previous.page;state.total=previous.total;state.totalPages=previous.totalPages;state.displayed=previous;state.visible=previous;retained=true;
   if(!sameView){if(kind==='event')renderEvents(previous.items);else renderIncidents(previous.items);}
   text(kind+'-updated',`更新于 ${when(previous.updatedAt)} · 用时 ${previous.elapsed}`);
  }else{state.displayed=null;state.visible=null;rows.replaceChildren();empty(rows,kind==='incident'?6:5,'此来源暂时无法读取，请刷新重试。');}
  updatePager(kind);const message=error instanceof TypeError?'网络连接失败，请刷新重试。':error.message;
  text(kind+'-status',message+(retained?` 已保留第 ${state.page} 页上次成功读取的数据。`:''));$(kind+'-status').className='list-status error';
}
function finishList(view){if(view.requestId===view.state.requestId){view.state.pending=false;$(view.kind+'-section').setAttribute('aria-busy','false');updateRefreshButton();}}
async function loadList(kind,page=pages[kind].page){
 const view=beginList(kind,page);
 try{const data=await get((kind==='event'?'/api/events?':'/api/incidents?')+sourceQuery(page,view.source,kind),view.state.controller.signal);await acceptList(view,data);}
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
 loadControls();loadCollection();
 const requestId=++refreshRequestId;if(summaryController)summaryController.abort();summaryController=new AbortController();
 const controller=summaryController,source=currentSource;refreshRunning=true;summaryPending=true;updateRefreshButton();text('error','');
 const views=[beginList('event',pages.event.page),beginList('incident',pages.incident.page)];
 const query=new URLSearchParams({limit:String(pageSize),event_page:String(views[0].page),incident_page:String(views[1].page),incident_triage:incidentTriage,incident_focus:incidentFocus,incident_sort:incidentSort});if(source)query.set('source_id',source);appendEventQuery(query);
 try{
  const data=await get('/api/dashboard?'+query,controller.signal);if(requestId!==refreshRequestId||source!==currentSource)return;
  if(!data||!data.summary||!data.events||!data.incidents)throw new Error('概览数据返回异常，请刷新重试。');
  renderSummary(data.summary);
  await Promise.all(views.map(async(view,index)=>{try{await acceptList(view,index===0?data.events:data.incidents);}catch(error){failList(view,error);}}));
 }catch(error){if(requestId===refreshRequestId&&error.name!=='AbortError'){text('error',`${error.message} 已保留上次成功读取的数据。`);for(const view of views)failList(view,error);}}
 finally{for(const view of views)finishList(view);if(requestId===refreshRequestId){refreshRunning=false;summaryPending=false;updateRefreshButton();scheduleAutoRefresh();}}
}
$('refresh').addEventListener('click',refresh);
$('collection-prev').addEventListener('click',()=>loadCollection(Math.max(1,collectionPage-1)));
$('collection-next').addEventListener('click',()=>loadCollection(Math.min(collectionPages,collectionPage+1)));
$('refresh-interval').addEventListener('change',()=>{try{localStorage.setItem('riskops-refresh-minutes',$('refresh-interval').value);}catch{}scheduleAutoRefresh();});
$('ip-form').addEventListener('submit',event=>{event.preventDefault();lookupIp($('ip-input').value);});
$('abuseipdb-check').addEventListener('click',lookupAbuse);
$('incident-control-open').addEventListener('click',()=>$('control-section').scrollIntoView({behavior:'smooth',block:'start'}));
for(const [id,values,apply] of [['incident-focus',scoreFilters,v=>incidentFocus=v],['incident-sort',scoreSorts,v=>incidentSort=v]])$(id).addEventListener('change',()=>{const value=$(id).value;if(!values.includes(value))return;apply(value);saveView();loadList('incident',1);});
$('incident-triage').addEventListener('change',()=>{const value=$('incident-triage').value;incidentTriage=triageFilters.includes(value)?value:'pending';saveView();loadList('incident',1);});
$('ip-show-events').addEventListener('click',()=>{const ip=$('ip-input').value.trim();if(ip)queryLogsForIP(ip);else text('ip-status','请先输入要查日志的 IP。');});
$('ip-add-control').addEventListener('click',()=>{$('control-ip').value=$('ip-input').value.trim();$('control-section').scrollIntoView({behavior:'smooth',block:'start'});});
$('source-filter').addEventListener('change',()=>{currentSource=$('source-filter').value;eventSnapshot=null;if(summaryController)summaryController.abort();++refreshRequestId;refreshRunning=false;summaryPending=false;clearDetails();for(const kind of ['event','incident']){pages[kind].totalPages=null;pages[kind].total=0;text(kind+'-updated','');loadList(kind,1);}if(controlsData){$('control-sources').dataset.key='';renderControlSources(controlsData.sources||[]);}loadCollection(1);saveView();scheduleAutoRefresh();});
$('search-form').addEventListener('submit',event=>{event.preventDefault();const next={};for(const key of ['ip','username','event_type','q','start','end']){const value=$('search-'+key).value.trim();if(!value)continue;if(key==='start'||key==='end'){const date=new Date(value);if(Number.isNaN(date.valueOf())){text('event-status','请输入有效的起止时间。');return;}next[key]=date.toISOString();}else next[key]=value;}if(next.start&&next.end&&next.start>next.end){text('event-status','开始时间不能晚于结束时间。');return;}eventFilters=next;eventSnapshot=null;saveView();loadList('event',1);});
$('search-clear').addEventListener('click',()=>{eventFilters={};eventSnapshot=null;setFilterInputs();saveView();loadList('event',1);});
$('event-latest').addEventListener('click',()=>{eventSnapshot=null;saveView();loadList('event',1);});
$('evidence-prev').addEventListener('click',()=>loadEvidence(Math.max(1,evidencePage-1)));
$('evidence-next').addEventListener('click',()=>loadEvidence(Math.min(evidenceTotalPages,evidencePage+1)));
$('evidence-jump-form').addEventListener('submit',event=>{event.preventDefault();const value=Number($('evidence-jump').value);if(!Number.isInteger(value)||value<1||value>evidenceTotalPages){text('evidence-status',`请输入 1 至 ${evidenceTotalPages} 之间的整数页码。`);return;}loadEvidence(value);});
$('control-add-form').addEventListener('submit',event=>{event.preventDefault();const ip=$('control-ip').value.trim(),sources=Array.from($('control-sources').querySelectorAll('input:checked')).map(input=>input.value);if(!ip||!sources.length){text('control-status','请输入一个 IP，并勾选至少一个目标来源。');return;}for(const source_id of sources)selectedTargets.set(targetKey({source_id,ip}),{source_id,ip});invalidatePlan();renderSelectedTargets();if(pages.incident.displayed)renderIncidents(pages.incident.displayed.items);text('control-status','目标已加入待预览列表，尚未执行。');});
$('control-clear').addEventListener('click',()=>{selectedTargets.clear();invalidatePlan();renderSelectedTargets();if(pages.incident.displayed)renderIncidents(pages.incident.displayed.items);});
for(const id of ['control-channel-ssh','control-channel-tcp','control-channel-udp','control-duration','control-reason'])$(id).addEventListener('input',()=>{invalidatePlan();controlState();});
$('control-preview').addEventListener('click',()=>previewControl());$('control-cancel').addEventListener('click',()=>{invalidatePlan();controlState();text('control-status','已取消预览，没有执行。');});$('control-confirm').addEventListener('change',controlState);$('control-execute').addEventListener('click',executeControl);$('control-refresh').addEventListener('click',loadControls);
for(const kind of ['event','incident']){
 $(kind+'-prev').addEventListener('click',()=>navigate(kind,pages[kind].page-1));
 $(kind+'-next').addEventListener('click',()=>navigate(kind,pages[kind].page+1));
 $(kind+'-jump-form').addEventListener('submit',event=>{event.preventDefault();navigate(kind,$(kind+'-jump').value);});
}
try{const saved=localStorage.getItem('riskops-refresh-minutes');if(['0','1','5','15'].includes(saved))$('refresh-interval').value=saved;}catch{}
try{const saved=JSON.parse(sessionStorage.getItem('riskops-view')||'null');if(saved&&typeof saved==='object'){currentSource=typeof saved.source==='string'?saved.source:'';if(saved.filters&&typeof saved.filters==='object')for(const key of ['ip','username','event_type','q','start','end'])if(typeof saved.filters[key]==='string')eventFilters[key]=saved.filters[key];eventSnapshot=typeof saved.snapshot==='string'?saved.snapshot:null;if(triageFilters.includes(saved.incidentTriage))incidentTriage=saved.incidentTriage;if(scoreFilters.includes(saved.incidentFocus))incidentFocus=saved.incidentFocus;if(scoreSorts.includes(saved.incidentSort))incidentSort=saved.incidentSort;for(const kind of ['event','incident'])if(Number.isSafeInteger(saved[kind+'Page'])&&saved[kind+'Page']>0)pages[kind].page=saved[kind+'Page'];setFilterInputs();}}catch{}
$('incident-triage').value=incidentTriage;$('incident-focus').value=incidentFocus;$('incident-sort').value=incidentSort;
refresh();
"""

DASHBOARD_HTML = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SecAgent RiskOps · 实时日志</title><style>__STYLE__</style></head>
<body><h1>SecAgent RiskOps · 实时日志</h1><p>查看已接入服务器的心跳、系统日志和 SSH 认证告警，核对证据后手动执行封禁或解封。</p>
<div class="toolbar"><label for="source-filter">日志来源</label><select id="source-filter"><option value="">全部来源</option></select><button id="refresh" type="button">刷新数据</button><label for="refresh-interval">自动刷新</label><select id="refresh-interval" aria-describedby="refresh-help"><option value="0">关闭（手动刷新）</option><option value="1">每 1 分钟</option><option value="5">每 5 分钟</option><option value="15">每 15 分钟</option></select><small id="updated">正在读取</small></div><p id="refresh-help">默认手动刷新，保留当前来源、筛选、页码与已打开的详情。日志查询固定在本次快照；点击“获取最新日志”重新查询并回到第一页。自动刷新仅在页面可见且没有读取任务时运行。</p><div id="error" role="status"></div>
<div class="cards"><div class="card">保留期内日志<div class="number" id="event-total">—</div></div><div class="card">待处理告警<div class="number" id="incident-total">—</div><small id="incident-triage-summary"></small></div><div class="card">SSH 认证异常日志<div class="number" id="failure-total">—</div></div><div class="card">SSH 成功日志<div class="number" id="success-total">—</div></div></div>
<section><h2>来源状态</h2><p>来源 ID（source_id）是跨日志关联使用的稳定资产 ID，服务器一栏显示配置名称。三件事分开看：<b>在线</b>只表示近期收到采集器心跳；<b>采集完整性</b>表示自覆盖起点以来有没有可能丢失日志的缺口；<b>延迟 / 追赶</b>表示日志是否已经全部收到，晚到的日志仍在来源上，不算丢失。心跳超时不代表已确认入侵；原始日志保留期到期删除是保留策略，不算缺口。</p><div class="table-wrap"><table><thead><tr><th>服务器</th><th>来源 ID</th><th>在线</th><th>采集完整性</th><th>延迟 / 追赶</th><th>最后心跳</th><th>最新日志时间</th></tr></thead><tbody id="sources"></tbody></table></div></section>
<section id="collection-section"><h2>采集记录</h2><p>每一次缺口（日志可能已丢失）和延迟（日志晚到）都单独记录，恢复正常后不会被覆盖或删除。缺口的时间区间内可能缺少日志；延迟只说明当时日志晚到了。</p><div class="table-wrap"><table><thead><tr><th>记录时间</th><th>来源 ID</th><th>类别</th><th>类型</th><th>区间</th><th>批次</th><th>状态</th></tr></thead><tbody id="collection-rows"></tbody></table></div><div class="pager"><button id="collection-prev" type="button">上一页</button><span id="collection-page"></span><button id="collection-next" type="button">下一页</button></div><p id="collection-status" class="list-status muted" role="status" aria-live="polite"></p></section>
<section id="ip-query-section" aria-busy="false"><h2>IP 属地查询</h2><p id="ip-help">输入 IPv4 / IPv6 地址，或点击下方日志中的来源 IP。属地查询使用离线库，不会自动发送 IP 给第三方；属地仅供参考，不能确定实际使用者位置。</p>
<form id="ip-form" class="ip-form"><label for="ip-input">IP 地址</label><input id="ip-input" name="ip" type="text" required maxlength="128" autocomplete="off" autocapitalize="off" spellcheck="false" aria-describedby="ip-help" placeholder="例如 8.8.8.8 或 2001:4860:4860::8888"><button id="ip-query-button" type="submit">查询属地</button></form>
<div class="actions"><button id="ip-show-events" type="button">查看此 IP 的日志</button><button id="ip-add-control" type="button">为此 IP 选择封禁来源</button></div>
<p id="ip-status" class="muted" role="status" aria-live="polite">等待输入 IP 地址。</p>
<p><button id="abuseipdb-check" type="button" disabled>查询 AbuseIPDB 风险分</button></p><p id="abuseipdb-status" role="status" aria-live="polite">先查询一个公网 IP，再点击风险查询。</p>
<div id="abuseipdb-result" hidden><dl class="ip-fields"><div><dt>风险评分（举报置信度）</dt><dd id="abuseipdb-score">—</dd></div><div><dt>近 90 天举报条数</dt><dd id="abuseipdb-reports">—</dd></div><div><dt>独立举报者</dt><dd id="abuseipdb-reporters">—</dd></div><div><dt>最近举报时间</dt><dd id="abuseipdb-last">—</dd></div></dl><p><small id="abuseipdb-checked"></small></p></div>
<p><a id="abuseipdb-link" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer" hidden>在 AbuseIPDB 查看完整报告 ↗</a></p><p><small>外部风险查询：仅在点击按钮或报告入口时向 AbuseIPDB 发送所选公网 IP，不发送 SSH 原始日志或账号。评分仅供核查，0 分不代表确认安全。</small></p>
<div id="ip-result" hidden><dl class="ip-fields"><div><dt>IP 地址</dt><dd id="ip-address">—</dd></div><div><dt>地址类型</dt><dd id="ip-type">—</dd></div><div><dt>国家 / 地区</dt><dd id="ip-country">—</dd></div><div><dt>省份 / 城市</dt><dd id="ip-region">—</dd></div><div><dt>网络组织</dt><dd id="ip-network">—</dd></div><div><dt>ASN</dt><dd id="ip-asn">—</dd></div><div><dt>属地库版本</dt><dd id="ip-database-release">—</dd></div><div><dt>数据库更新时间</dt><dd id="ip-database-updated">—</dd></div></dl><p>数据库状态：<span id="ip-database-status" class="muted">—</span></p></div>
<p><small>属地数据：<a href="https://db-ip.com" target="_blank" rel="noopener noreferrer">DB-IP Lite</a>（CC BY 4.0）。部分地址可能缺少城市或网络组织信息。</small></p></section>
<section id="incident-section" aria-busy="false"><h2>SSH 认证告警</h2><p>检测短时密集失败、慢速扫描、多账号尝试、跨服务器尝试及多次失败后成功。失败日志包括认证失败、无效账号和认证前断开，不等于独立连接或攻击次数。相同来源 IP 可能由不同使用者共享，命中规则需要人工核查，不会自动封禁。</p><p>告警保存在中控，刷新不会删除；来源一栏列出全部关联服务器与来源 ID。点击查看命中原因、账号和原始证据，或点击来源 IP 查询属地。</p><p>处置状态：待处理表示尚未处理；已知晓表示已有人知悉但未采取措施；已处理表示已封禁或人工确认处理完毕。封禁在全部关联来源核实生效后会自动标为已处理；已处理的 IP 若再次出现新证据会自动回到待处理。每次变更都写入处置记录，可在详情中查看。</p><div class="actions"><label for="incident-triage">处置状态</label><select id="incident-triage"><option value="pending" selected>待处理</option><option value="acknowledged">已知晓</option><option value="resolved">已处理</option><option value="all">全部</option></select><span id="incident-triage-counts" class="muted"></span><label for="incident-focus">评分筛选</label><select id="incident-focus"><option value="all" selected>全部事件</option><option value="attention">优先核查 + 未评分</option><option value="low">低分事件</option><option value="unscored">尚未评分</option></select><label for="incident-sort">排序</label><select id="incident-sort"><option value="score" selected>分数从高到低（未评分在前）</option><option value="recent">最近发生</option></select><label for="triage-note">处置备注（可选）</label><input id="triage-note" type="text" maxlength="300" placeholder="写入处置记录，例如：已确认为内部扫描" autocomplete="off"><button id="incident-control-open" type="button">查看已选目标与封禁预览（0）</button></div><p>评分由日志证据计算，25 分起建议优先核查；P1 ≥ 60、P2 ≥ 40、P3 ≥ 25。默认显示全部待处理事件，低分仍保留且不自动结案。未评分事件优先显示；既往登录不自动减分。评分不代表攻击概率。</p><p id="incident-score-counts" class="muted" role="status"></p><p id="triage-status" class="list-status muted" role="status" aria-live="polite"></p><p><small id="incident-updated"></small></p><div class="table-wrap"><table><thead><tr><th>最近发生</th><th>关联服务器 / 来源</th><th>来源 IP</th><th>日志 / 账号统计</th><th>评分 / 命中规则</th><th>状态</th></tr></thead><tbody id="incidents"></tbody></table></div><div class="pager"><button id="incident-prev" type="button">上一页</button><span id="incident-page"></span><button id="incident-next" type="button">下一页</button><form id="incident-jump-form" class="page-jump" novalidate><label for="incident-jump">跳至</label><input id="incident-jump" type="number" min="1" step="1" value="1" aria-label="SSH 认证告警页码" aria-describedby="incident-status"><span>页</span><button id="incident-jump-button" type="submit">跳转</button></form></div><p id="incident-status" class="list-status muted" role="status" aria-live="polite"></p></section>
<section id="event-section" aria-busy="false"><h2>已接收日志</h2><p>点击一行查看完整记录，点击来源 IP 查询属地。系统当前采集 SSH 相关日志；这里不代表服务器的全部网络流量。以下条件组合生效，仅筛选日志，不影响上方告警和概览。</p>
<form id="search-form"><div class="search-fields"><label>来源 IP<input id="search-ip" type="text" maxlength="128" placeholder="完整 IPv4 / IPv6" autocomplete="off"></label><label>账号<input id="search-username" type="text" maxlength="256" placeholder="完整账号名" autocomplete="off"></label><label>事件类型<select id="search-event_type"><option value="">全部类型</option><option value="auth_failure">认证失败</option><option value="invalid_user">无效账号</option><option value="preauth_abort">认证前断开</option><option value="auth_success">认证成功</option><option value="probe">协议探测</option><option value="disconnect">断开连接</option><option value="session_open">会话打开</option><option value="session_close">会话关闭</option><option value="daemon">服务状态</option><option value="other">其他</option></select></label><label>开始时间（本地）<input id="search-start" type="datetime-local"></label><label>结束时间（本地）<input id="search-end" type="datetime-local"></label><label>消息关键字<input id="search-q" type="text" maxlength="256" placeholder="原始消息包含" autocomplete="off"></label></div><div class="actions"><button type="submit">查询日志</button><button id="search-clear" type="button">清空条件</button><button id="event-latest" type="button">获取最新日志</button></div></form><p><small id="event-updated"></small></p><div class="table-wrap"><table><thead><tr><th>日志时间</th><th>来源</th><th>类型</th><th>来源 IP</th><th>原始消息</th></tr></thead><tbody id="events"></tbody></table></div><div class="pager"><button id="event-prev" type="button">上一页</button><span id="event-page"></span><button id="event-next" type="button">下一页</button><form id="event-jump-form" class="page-jump" novalidate><label for="event-jump">跳至</label><input id="event-jump" type="number" min="1" step="1" value="1" aria-label="日志页码" aria-describedby="event-status"><span>页</span><button id="event-jump-button" type="submit">跳转</button></form></div><p id="event-status" class="list-status muted" role="status" aria-live="polite"></p></section>
<section id="detail-section"><h2 id="detail-title">记录详情</h2><pre id="detail">选择上方记录查看详情。</pre><div id="evidence-view" hidden><h3>原始证据时间线</h3><div class="table-wrap"><table><thead><tr><th>时间</th><th>来源</th><th>类型</th><th>IP</th><th>账号</th><th>原始消息</th></tr></thead><tbody id="evidence-rows"></tbody></table></div><div class="pager"><button id="evidence-prev" type="button">上一页证据</button><span id="evidence-page"></span><button id="evidence-next" type="button">下一页证据</button><form id="evidence-jump-form" class="page-jump" novalidate><label for="evidence-jump">跳至</label><input id="evidence-jump" type="number" min="1" step="1" value="1"><span>页</span><button type="submit">跳转</button></form></div><p id="evidence-status" role="status" aria-live="polite"></p></div></section>
<section id="control-section"><h2>手动封禁与解封</h2><p id="control-availability" role="status">正在读取执行通道状态…</p><p>勾选告警可选择该 IP 在关联来源上的目标；指定日志来源时，仅选择该来源。翻页保留已选目标，不会自动选择全部历史告警。也可以在下面输入单个 IP 并明确选择来源。</p>
<form id="control-add-form"><div class="ip-form"><label for="control-ip">目标 IP</label><input id="control-ip" type="text" maxlength="128" required autocomplete="off" placeholder="输入要封禁的完整公网 IP"></div><fieldset><legend>选择目标服务器</legend><div id="control-sources" class="control-targets"></div></fieldset><button type="submit">加入待预览目标</button></form>
<p id="control-selection-count">已选 0 个 IP / 来源组合。</p><div class="table-wrap"><table><thead><tr><th>目标来源</th><th>目标 IP</th><th>选择</th></tr></thead><tbody id="control-selected"><tr><td colspan="3">尚未选择目标。请勾选告警，或输入单个 IP 并勾选目标来源。</td></tr></tbody></table></div><div class="actions"><button id="control-clear" type="button">清空已选目标</button></div>
<fieldset><legend>封禁范围（可多选）</legend><div class="control-targets"><label><input id="control-channel-ssh" type="checkbox" checked>SSH 端口</label><label><input id="control-channel-tcp" type="checkbox">全部 TCP（包含 SSH）</label><label><input id="control-channel-udp" type="checkbox">全部 UDP</label></div><p>限制所选 IP 进入目标服务器本机的对应流量。全部 TCP／UDP 会影响现有连接，也会拦截服务器主动访问该 IP 时的回包；不会过滤经服务器转发的流量。</p></fieldset>
<div class="actions"><label for="control-duration">有效时长</label><select id="control-duration"><option value="300">5 分钟</option><option value="900">15 分钟</option><option value="1800">30 分钟</option><option value="3600" selected>1 小时</option><option value="86400">24 小时</option><option value="permanent">永久（需要手动解封）</option></select></div><p><label for="control-reason">操作原因（写入审计记录）</label></p><textarea id="control-reason" rows="2" maxlength="300" placeholder="例如：已核对跨服务器扫描证据，临时限制来源"></textarea><div class="actions"><button id="control-preview" type="button" class="danger" disabled>预览封禁计划</button><button id="control-refresh" type="button">刷新封禁状态与操作记录</button></div><p id="control-status" role="status" aria-live="polite">尚未提交操作。</p>
<div id="control-plan" hidden><h3 id="control-plan-title">请核对封禁计划</h3><div class="table-wrap"><table><thead><tr><th>目标来源</th><th>目标 IP</th><th>影响范围</th><th>动作 / 有效时长</th></tr></thead><tbody id="control-plan-items"></tbody></table></div><p id="control-plan-expiry"></p><label class="selection"><input id="control-confirm" type="checkbox">我已核对上方全部目标、范围和有效时长</label><div class="actions"><button id="control-execute" type="button" class="danger" disabled>确认执行此计划</button><button id="control-cancel" type="button">取消</button></div></div>
<div id="control-job" hidden><h3 id="control-job-title">操作结果</h3><div class="table-wrap"><table><thead><tr><th>来源</th><th>IP</th><th>范围</th><th>状态</th><th>说明</th></tr></thead><tbody id="control-job-items"></tbody></table></div></div><h3>封禁状态与最近核实记录</h3><p>到期封禁由目标服务器自动解除；永久封禁需要手动解封。表格是最近一次核实的快照，核实失败时不代表当前仍然生效；解封同样需要核对预览。</p><div class="table-wrap"><table><thead><tr><th>来源</th><th>IP</th><th>范围</th><th>到期时间</th><th>最近确认时间</th><th>操作</th></tr></thead><tbody id="control-blocks"></tbody></table></div><p id="control-source-checks" class="incident-value" role="status"></p><h3>最近操作记录</h3><div id="control-history" class="actions"></div></section><script>__SCRIPT__</script></body></html>""".replace("__STYLE__", _STYLE).replace("__SCRIPT__", _SCRIPT)


def _csp_hash(value: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(value.encode("utf-8")).digest()).decode("ascii") + "'"


CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src " + _csp_hash(_SCRIPT) + "; style-src " + _csp_hash(_STYLE)
    + "; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)
