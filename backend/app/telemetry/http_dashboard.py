"""HTTP review table and version-pinned evidence drawer, without response actions."""
SECTION = """<section id="http-section"><h2>HTTP 检测</h2>
<p>按来源、服务、连接 IP 和 UTC 小时关联请求。跨小时模式可能在相邻事件中共用证据；分数表示探测迹象，不能证明入侵成功。</p>
<p id="http-health" role="status">正在读取 HTTP 检测状态…</p>
<div class="actions"><label for="http-source">HTTP 来源</label><select id="http-source"><option value="">全部</option></select><label for="http-service">服务</label><select id="http-service"><option value="">全部</option></select><label for="http-focus">事件</label><select id="http-focus"><option value="all">全部</option><option value="attention">需关注（≥30 分）</option><option value="low">低分</option><option value="retracted">已撤回</option></select><button id="http-refresh" type="button">刷新 HTTP</button></div>
<div class="table-wrap"><table><thead><tr><th>最近证据</th><th>来源 / 服务</th><th>连接 IP</th><th>模式</th><th>评分 / 状态</th><th>详情</th></tr></thead><tbody id="http-rows"></tbody></table></div>
<div class="pager"><button id="http-prev" type="button" disabled>上一页</button><span id="http-page"></span><button id="http-next" type="button" disabled>下一页</button></div><p id="http-status" role="status"></p></section>"""

DIALOG = """<dialog id="http-dialog" aria-labelledby="http-detail-title"><div class="http-detail-body"><div class="drawer-heading"><h2 id="http-detail-title">HTTP 事件详情</h2><button id="http-close" type="button" aria-label="关闭 HTTP 详情">关闭 ✕</button></div>
<p id="http-detail-status" role="status"></p><div class="actions"><button id="http-revision-prev" type="button" disabled>上一版本</button><span id="http-revision"></span><button id="http-revision-next" type="button" disabled>下一版本</button><button id="http-current" type="button">读取当前版本</button></div>
<div class="detail-tabs" role="tablist" aria-label="HTTP 详情内容"><button id="http-tab-overview" type="button" role="tab" aria-controls="http-pane-overview" aria-selected="true">概览</button><button id="http-tab-evidence" type="button" role="tab" aria-controls="http-pane-evidence" aria-selected="false" tabindex="-1">证据</button></div>
<div id="http-pane-overview" class="http-detail-scroll" role="tabpanel" aria-labelledby="http-tab-overview"><dl id="http-fields" class="detail-fields"></dl></div><div id="http-pane-evidence" class="http-detail-scroll" role="tabpanel" aria-labelledby="http-tab-evidence" hidden><h3>该版本的证据</h3><p>路径已移除查询串。响应状态码只描述 HTTP 响应。</p><div class="table-wrap"><table><thead><tr><th>时间</th><th>方法</th><th>路径</th><th>状态码</th></tr></thead><tbody id="http-evidence"></tbody></table></div><div class="pager"><button id="http-evidence-prev" type="button" disabled>上一页</button><span id="http-evidence-page"></span><button id="http-evidence-next" type="button" disabled>下一页</button></div></div></div></dialog>"""

STYLE = """
#http-dialog{position:fixed;inset:0 0 0 auto;margin:0;width:min(900px,100vw);max-width:100vw;height:100dvh;max-height:100dvh;box-sizing:border-box;border:0;border-left:1px solid #385475;background:#101d2e;color:#e7edf5;padding:22px}#http-dialog::backdrop{background:#030b17a6}.http-detail-body{height:100%;display:flex;flex-direction:column;gap:12px;min-width:0}.http-detail-scroll{overflow:auto;min-height:0;flex:1}#http-pane-evidence{display:flex;flex-direction:column;overflow:hidden}.http-detail-scroll .table-wrap{overflow:auto;min-height:0;flex:1}.http-detail-scroll .pager{flex-shrink:0}.http-detail-scroll td{overflow-wrap:anywhere;max-width:430px}.http-detail-scroll .pager{display:flex;align-items:center;gap:12px;margin:14px 0}#http-dialog .actions{flex-wrap:wrap}#http-dialog .detail-tabs{margin:0;padding:0 0 10px}#http-detail-status:empty{display:none}#http-health{white-space:pre-line}.http-detail-scroll h3{font-size:16px}@media(max-width:850px){#http-dialog{padding:16px}.http-detail-scroll .table-wrap table{min-width:580px}}
"""

SCRIPT = r"""
let httpSources=[],httpPage=1,httpPages=1,httpRequest=0,httpDetailRequest=0,httpEvidenceRequest=0;
let httpDetail=null,httpLatest=0,httpEvidencePage=1,httpEvidencePages=1,httpReturnFocus=null;
const httpCollection={never_seen:'尚未收到日志',stale:'采集心跳过期',delayed:'采集延迟',degraded:'采集有缺口或拒收',current:'采集正常'};
const httpCoverage={complete:'已核算',context_limit:'上下文超过处理上限',expired_context:'关联上下文已过期'};
function httpOptions(id,values){const select=$(id),previous=select.value;select.replaceChildren();for(const [value,label] of [['','全部'],...values]){const option=document.createElement('option');option.value=value;option.textContent=label;select.append(option);}select.value=values.some(v=>v[0]===previous)?previous:'';}
function httpServices(){const source=$('http-source').value,services=[...new Set(httpSources.filter(s=>!source||s.id===source).flatMap(s=>s.services))].sort();httpOptions('http-service',services.map(s=>[s,s]));}
function httpHealth(status){
 if(!status.enabled){text('http-health','HTTP 来源尚未配置。接入访问日志后，这里将展示检测结果。');return;}
 httpSources=status.sources;httpOptions('http-source',httpSources.map(s=>[s.id,s.hostname+' · '+s.id]));httpServices();
 const delayed=!status.last_run||Date.now()-Date.parse(status.last_run)>120000;
 const notes=[`最近检测：${status.last_run?when(status.last_run):'尚未运行'} · ${status.pending?'有待处理日志':'已处理当前收到的日志'} · 累计读取 ${status.analyzed_input_records} 条`];
 for(const row of status.collection||[])notes.push(`${row.source_id} / ${row.service_id}：${httpCollection[row.status]||row.status} · 累计接收 ${row.accepted_total}，拒收 ${row.rejected_total}`);
 if(delayed)notes.push('检测任务尚未更新，请检查后台服务。');
 if(status.last_error)notes.push(status.last_error);
 if(status.missing_raw_records)notes.push(`有 ${status.missing_raw_records} 条日志在分析前已过期；检测覆盖不完整。`);
 if(status.coverage_issues.length)notes.push(`近期有 ${status.coverage_issues.length===50?'至少 50':status.coverage_issues.length} 个关联窗口不完整；相关事件保留上次可核验的结果。`);
 text('http-health',notes.join('\n'));
}
async function loadHttp(page=httpPage){
 const request=++httpRequest,source=$('http-source').value,service=$('http-service').value,focus=$('http-focus').value;
 text('http-status','正在读取 HTTP 事件…');
 try{
  const status=await get('/api/http/status');if(request!==httpRequest)return;httpHealth(status);
  if(!status.enabled){empty($('http-rows'),6,'暂无 HTTP 来源。');text('http-page','');httpPage=httpPages=1;$('http-prev').disabled=$('http-next').disabled=true;text('http-status','');return;}
  const query=new URLSearchParams({page:String(page),limit:'50',focus});if(source)query.set('source_id',source);if(service)query.set('service_id',service);
  const data=await get('/api/http/incidents?'+query);if(request!==httpRequest)return;
  if(!Array.isArray(data.items)||!Number.isInteger(data.page)||!Number.isInteger(data.total_pages))throw new Error('HTTP 事件返回异常');
  httpPage=data.page;httpPages=data.total_pages;const rows=$('http-rows');rows.replaceChildren();
  for(const item of data.items){const tr=document.createElement('tr');cell(tr,when(item.last_seen));cell(tr,item.source_id+' / '+item.service_id);cell(tr,item.client_ip);cell(tr,item.rules.map(r=>r.label).join('、')||'模式已撤回');cell(tr,`${item.assessment.score} 分 · ${item.stale?'待重新核验':item.active?(item.assessment.priority||'低分'):'已撤回'}`);const button=document.createElement('button');button.type='button';button.textContent='查看详情';button.addEventListener('click',()=>showHttpIncident(item.incident_id));cell(tr,'').append(button);rows.append(tr);}
  if(!data.items.length)empty(rows,6,'暂无符合条件的 HTTP 事件。');
  text('http-page',`第 ${data.page} / ${data.total_pages} 页 · 共 ${data.total} 个事件`);$('http-prev').disabled=data.page<=1;$('http-next').disabled=data.page>=data.total_pages;text('http-status','');
 }catch(error){if(request===httpRequest)text('http-status',error.message+' 已保留上次读取的 HTTP 事件。');}
}
function renderHttpDetail(item){
 httpDetail=item;const fields=$('http-fields');fields.replaceChildren();
 const values=[['标题',item.title],['来源 / 服务',item.source_id+' / '+item.service_id],['连接 IP',item.client_ip],['关联时段',when(item.window_start)+' — '+when(item.window_end)],['版本',item.revision+' · '+when(item.updated_at)],['评分',item.assessment.score+' 分 · '+(item.assessment.priority||'低分')],['检测状态',(httpCoverage[item.coverage]||item.coverage)+(item.stale?'；保留上次可核验评分与证据':'')],['规则',item.rules.map(r=>r.label+'（'+r.evidence_count+' 条证据）').join('、')||'原模式已撤回'],['计分依据',item.assessment.reasons.map(r=>r.reason+' +'+r.points+'：'+r.criteria).join('；')||'当前无命中'],['证据数量',item.evidence_count],['判断边界',item.assessment.note]];
 for(const [label,value] of values){const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=label;dd.textContent=String(value);fields.append(dt,dd);}
 text('http-revision',`版本 ${item.revision} / ${httpLatest}${item.revision<httpLatest?' · 历史快照':''}`);$('http-revision-prev').disabled=item.revision<=1;$('http-revision-next').disabled=item.revision>=httpLatest;
}
async function loadHttpEvidence(page=1){
 if(!httpDetail)return;const request=++httpEvidenceRequest,identity=httpDetail.incident_id,revision=httpDetail.revision;
 try{const data=await get('/api/http/incidents/'+encodeURIComponent(identity)+'/evidence?'+new URLSearchParams({revision:String(revision),page:String(page),limit:'25'}));if(request!==httpEvidenceRequest||!httpDetail||httpDetail.incident_id!==identity||httpDetail.revision!==revision)return;
  if(data.revision!==revision||!Array.isArray(data.items))throw new Error('HTTP 证据版本不匹配');
  httpEvidencePage=data.page;httpEvidencePages=data.total_pages;const rows=$('http-evidence');rows.replaceChildren();
  for(const item of data.items){const tr=document.createElement('tr');cell(tr,when(item.timestamp));cell(tr,item.method);cell(tr,item.path);cell(tr,item.status);rows.append(tr);}if(!data.items.length)empty(rows,4,'该版本没有命中证据。');
  text('http-evidence-page',`第 ${data.page} / ${data.total_pages} 页 · ${data.total} 条证据`);$('http-evidence-prev').disabled=data.page<=1;$('http-evidence-next').disabled=data.page>=data.total_pages;text('http-detail-status','');
 }catch(error){if(request===httpEvidenceRequest)text('http-detail-status',error.message+' 证据读取失败，请重试当前版本。');}
}
async function showHttpIncident(identity,revision=null){
 const dialog=$('http-dialog');if(!dialog.open){setHttpDetailTab('overview');httpReturnFocus=document.activeElement;if(typeof dialog.showModal==='function')dialog.showModal();else dialog.setAttribute('open','');}
 const request=++httpDetailRequest;++httpEvidenceRequest;httpDetail=null;$('http-fields').replaceChildren();$('http-evidence').replaceChildren();text('http-revision','');text('http-evidence-page','');
 for(const id of ['http-revision-prev','http-revision-next','http-evidence-prev','http-evidence-next','http-current'])$(id).disabled=true;
 text('http-detail-status','正在读取 HTTP 事件版本…');
 try{const path='/api/http/incidents/'+encodeURIComponent(identity),latest=await get(path);if(request!==httpDetailRequest)return;httpLatest=latest.revision;const item=revision===null||revision===latest.revision?latest:await get(path+'?revision='+revision);if(request!==httpDetailRequest)return;renderHttpDetail(item);$('http-current').disabled=false;await loadHttpEvidence();}
 catch(error){if(request===httpDetailRequest)text('http-detail-status',error.message+' 请关闭后重新打开事件。');}
}
function clearHttpDetail(){++httpDetailRequest;++httpEvidenceRequest;httpDetail=null;if(httpReturnFocus?.isConnected&&typeof httpReturnFocus.focus==='function')httpReturnFocus.focus();}
function setHttpDetailTab(name){
 if(!['overview','evidence'].includes(name))return;
 for(const key of ['overview','evidence']){$('http-pane-'+key).hidden=key!==name;$('http-tab-'+key).setAttribute('aria-selected',String(key===name));$('http-tab-'+key).tabIndex=key===name?0:-1;}
}
function initializeHttp(){
 setHttpDetailTab('overview');
 for(const name of ['overview','evidence']){
  $('http-tab-'+name).addEventListener('click',()=>setHttpDetailTab(name));
  $('http-tab-'+name).addEventListener('keydown',event=>{if(['ArrowLeft','ArrowRight','Home','End'].includes(event.key)){event.preventDefault();const next=event.key==='Home'?'overview':event.key==='End'?'evidence':name==='overview'?'evidence':'overview';setHttpDetailTab(next);$('http-tab-'+next).focus();}});
 }

 $('http-source').addEventListener('change',()=>{httpServices();loadHttp(1);});for(const id of ['http-service','http-focus'])$(id).addEventListener('change',()=>loadHttp(1));
 $('http-refresh').addEventListener('click',()=>loadHttp());$('http-prev').addEventListener('click',()=>loadHttp(httpPage-1));$('http-next').addEventListener('click',()=>loadHttp(httpPage+1));
 $('http-close').addEventListener('click',()=>{const dialog=$('http-dialog');if(typeof dialog.close==='function')dialog.close();else{dialog.removeAttribute('open');clearHttpDetail();}});$('http-dialog').addEventListener('close',clearHttpDetail);
 $('http-current').addEventListener('click',()=>{if(httpDetail)showHttpIncident(httpDetail.incident_id);});
 $('http-revision-prev').addEventListener('click',()=>{if(httpDetail)showHttpIncident(httpDetail.incident_id,httpDetail.revision-1);});$('http-revision-next').addEventListener('click',()=>{if(httpDetail)showHttpIncident(httpDetail.incident_id,httpDetail.revision+1);});
 $('http-evidence-prev').addEventListener('click',()=>loadHttpEvidence(httpEvidencePage-1));$('http-evidence-next').addEventListener('click',()=>loadHttpEvidence(httpEvidencePage+1));
}
"""
