"""Read-only network findings, source quality and immutable evidence revisions."""

SECTION = """<section id="network-section" aria-busy="false"><h2>网络检测</h2>
<p id="network-boundary">目前检测已核验本机入站日志中的 TCP 多端口探测模式。命中不代表入侵成功；来源 IP 不等于人员身份，日志条数不等于独立连接数。没有事件也不代表安全或完整覆盖。</p>
<p id="network-health" role="status" aria-live="polite">切换到此页后读取网络检测状态。</p>
<details id="network-source-quality"><summary id="network-quality-summary">采集来源与覆盖限制</summary><p>采集问题与检测结果分开显示。采集心跳正常不代表覆盖完整；来源未接入或日志缺失时不能据此判断没有异常。</p><div class="table-wrap"><table><thead><tr><th>来源</th><th>采集状态</th><th>接收 / 拒收</th><th>覆盖限制</th></tr></thead><tbody id="network-sources"></tbody></table></div><p id="network-coverage"></p></details>
<div class="actions"><label for="network-source">网络来源</label><select id="network-source"><option value="">全部</option></select><label for="network-focus">事件筛选</label><select id="network-focus"><option value="all">全部事件</option><option value="attention">优先核查</option><option value="low">低分事件</option><option value="stale">待重新核验</option><option value="retracted">已撤回</option></select><button id="network-refresh" type="button">刷新网络检测</button></div>
<div class="table-wrap"><table aria-describedby="network-boundary"><thead><tr><th>最近证据</th><th>来源</th><th>源 IP → 目的 IP</th><th>检测模式</th><th>评分 / 状态</th><th>详情</th></tr></thead><tbody id="network-rows"></tbody></table></div>
<div class="pager"><button id="network-prev" type="button" disabled>上一页</button><span id="network-page"></span><button id="network-next" type="button" disabled>下一页</button></div><p id="network-status" class="list-status" role="status" aria-live="polite"></p></section>"""

DIALOG = """<dialog id="network-dialog" aria-labelledby="network-detail-title"><div class="network-detail-body"><div class="drawer-heading"><h2 id="network-detail-title">网络事件详情</h2><button id="network-close" type="button" aria-label="关闭网络详情">关闭 ✕</button></div>
<p id="network-detail-status" role="status" aria-live="polite"></p><div class="actions"><button id="network-revision-prev" type="button" disabled>上一版本</button><span id="network-revision"></span><button id="network-revision-next" type="button" disabled>下一版本</button><button id="network-current" type="button" disabled>读取当前版本</button></div>
<div class="detail-tabs" role="tablist" aria-label="网络详情内容"><button id="network-tab-overview" type="button" role="tab" aria-controls="network-pane-overview" aria-selected="true">概览</button><button id="network-tab-evidence" type="button" role="tab" aria-controls="network-pane-evidence" aria-selected="false" tabindex="-1">证据</button></div>
<div id="network-pane-overview" class="network-detail-scroll" role="tabpanel" aria-labelledby="network-tab-overview"><div id="network-ssh-search"></div><p>查证入口查询全部 SSH 来源及处置状态，默认网络证据前后各 30 分钟，可在搜索页调整；命中相同 IP 不代表已确认关联。</p><dl id="network-fields" class="detail-fields"></dl><details><summary>版本与关联标识</summary><dl id="network-provenance" class="detail-fields"></dl></details></div>
<div id="network-pane-evidence" class="network-detail-scroll" role="tabpanel" aria-labelledby="network-tab-evidence" hidden><p>只显示该版本保存的规范化证据。时间来自来源主机日志，可能发生时钟跳变；关联使用同一次启动内的单调时钟。拒绝相关日志标签不证明最终防火墙处置结果。</p><div class="table-wrap"><table><thead><tr><th>日志时间</th><th>源 IP / 端口</th><th>目的 IP / 端口</th><th>协议 / 标志</th><th>采集位置 / 限制</th></tr></thead><tbody id="network-evidence"></tbody></table></div><div class="pager"><button id="network-evidence-prev" type="button" disabled>上一页</button><span id="network-evidence-page"></span><button id="network-evidence-next" type="button" disabled>下一页</button><button id="network-evidence-retry" type="button" disabled>重试证据</button></div><p id="network-evidence-status" role="status" aria-live="polite"></p></div></div></dialog>"""

STYLE = """
#network-health,#network-coverage{white-space:pre-line}#network-coverage{max-height:160px;overflow:auto}#network-source-quality{margin:10px 0;color:#a9bacd;font-size:13px}#network-source-quality summary{cursor:pointer;padding:8px 0}#network-section>.table-wrap table{min-width:820px}#network-source-quality .table-wrap{max-height:220px}#network-source-quality table{min-width:560px}#network-section .actions select{max-width:100%}
#network-dialog{position:fixed;inset:0 0 0 auto;margin:0;width:min(920px,100vw);max-width:100vw;height:100dvh;max-height:100dvh;border:0;border-left:1px solid #385475;background:#101d2e;color:#e7edf5;padding:22px}#network-dialog::backdrop{background:#030b17a6}.network-detail-body{height:100%;display:flex;flex-direction:column;gap:12px;min-width:0}.network-detail-scroll{min-height:0;overflow:auto;flex:1}#network-dialog .actions{margin:0;flex-shrink:0}#network-dialog .detail-tabs{margin:0;padding:0 0 10px;flex-shrink:0}#network-pane-evidence{display:flex;flex-direction:column;overflow:hidden}.network-detail-scroll .table-wrap{overflow:auto;min-height:0;flex:1}.network-detail-scroll .table-wrap table{min-width:720px}.network-detail-scroll .pager{flex-shrink:0}.network-detail-scroll p{font-size:13px}.network-detail-scroll details>summary{cursor:pointer;margin:12px 0}#network-detail-status:empty,#network-evidence-status:empty{display:none}#network-detail-status,#network-evidence-status{font-size:13px;margin:0}#network-provenance{margin-top:16px}
@media(max-width:850px){#network-dialog{padding:16px}#network-dialog .drawer-heading h2{font-size:17px}#network-dialog .actions,#network-dialog .pager{gap:6px;font-size:12px}#network-dialog button{font-size:12px;padding:7px 9px}#network-section .actions{gap:8px}#network-source-quality .table-wrap{max-height:180px}}
"""

SCRIPT = r"""
let networkPage=1,networkPages=1,networkRequest=0,networkLoading=false,networkAvailable=false;
let networkDetail=null,networkLatest=0,networkDetailRequest=0,networkEvidenceRequest=0;
let networkEvidencePage=1,networkEvidencePages=1,networkEvidenceLoading=false,networkEvidenceAvailable=false,networkReturnFocus=null;
const networkCollection={never_seen:'尚未收到日志',stale:'采集心跳过期',delayed:'采集延迟',degraded:'采集有缺口、拒收或尚未追平',current:'近期采集正常'};
const networkCoverage={
 offline_context_only:'仅依据已保存的日志上下文',observations_are_lower_bounds:'记录仅为可见流量的下限',apparent_source_not_identity:'来源地址不能确认人员身份',
 dynamic_terminal_filtering:'动态封禁可能提前过滤部分流量',
 logging_rate_limited:'日志有限速，可能缺少记录',logging_limits_unknown:'日志限速范围未知',journal_retention_unknown:'来源日志保留范围未知',
 unverified_local_input:'未核验本机入站路径',incomplete_interfaces:'接口覆盖不完整',missing_transport_ports:'缺少传输层端口',tcp_flags_unavailable:'缺少 TCP 标志',
 truncated_transport_header:'传输层头部不完整',fragmented_packet:'分片报文',unsupported_protocol:'不支持的协议',ipv6_extension_headers:'IPv6 扩展头影响可见范围',
 journal_clock_discontinuity:'来源主机时钟发生跳变',context_limit:'关联上下文超过处理上限',expired_context:'关联上下文已过期',
 coverage_start:'仅从登记的覆盖起点开始',journal_cursor_unavailable:'来源日志游标缺失，历史可能有缺口',profile_drift:'来源规则配置发生变化',
 catching_up:'尚有待采集日志',profile_boundary:'来源配置版本边界',invalid_record:'部分记录未通过校验',rejected_records:'部分记录被拒收',profile_context_unavailable:'无法核验来源配置',
 event_history_expired:'历史原始事件已按保留策略过期',event_retention_incomplete:'保留范围不完整',missing_raw_records:'部分记录在分析前已过期',
 raw_history_expired_before_analysis:'原始记录在分析前已过期',collection_backlog_observed:'曾观测到采集积压',monotonic_hour_review_bucket:'按同次启动的单调时钟小时归并核查'
};
function networkQuality(codes){return (codes||[]).map(code=>networkCoverage[code]||networkCollection[code]||`覆盖限制：${code}`).join('；');}
function networkDate(value){return Number.isSafeInteger(value)?when(value/1000):'时间超出精确显示范围';}
function networkFields(target,values){const fields=$(target);fields.replaceChildren();for(const [label,value] of values){const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=label;dd.textContent=String(value??'—');fields.append(dt,dd);}}
function networkPageValid(data,requested){return data&&Array.isArray(data.items)&&Number.isSafeInteger(data.page)&&data.page>=1&&Number.isSafeInteger(data.total_pages)&&data.total_pages>=1&&Number.isSafeInteger(data.total)&&data.total>=0&&data.page===Math.min(requested,data.total_pages);}
function networkItemValid(item){return item&&typeof item.incident_id==='string'&&Number.isSafeInteger(item.revision)&&item.revision>=1&&typeof item.source_id==='string'&&typeof item.src_ip==='string'&&typeof item.dst_ip==='string'&&Array.isArray(item.rules)&&Array.isArray(item.coverage)&&item.assessment&&Number.isFinite(item.assessment.score)&&Array.isArray(item.assessment.reasons);}
function networkPager(){
 $('network-prev').disabled=networkLoading||!networkAvailable||networkPage<=1;$('network-next').disabled=networkLoading||!networkAvailable||networkPage>=networkPages;
 $('network-section').setAttribute('aria-busy',String(networkLoading));
}
function networkHealth(status){
 if(!status.enabled){text('network-health','网络来源尚未配置，当前没有在线网络检测覆盖。');$('network-sources').replaceChildren();empty($('network-sources'),4,'尚未接入网络来源。');text('network-coverage','');text('network-quality-summary','采集来源与覆盖限制 · 尚未配置');return;}
 const analysis=status.analysis||{},sources=status.sources||[],select=$('network-source'),previous=select.value;
 select.replaceChildren();for(const item of [{source_id:'',hostname:'全部'},...sources]){const option=document.createElement('option');option.value=item.source_id;option.textContent=item.source_id?`${item.hostname||item.source_id} · ${item.source_id}`:'全部';select.append(option);}select.value=sources.some(s=>s.source_id===previous)?previous:'';
 const notes=[status.analysis_enabled===false?'持续检测尚未启用。':`最近检测：${analysis.last_run?when(analysis.last_run):'尚未运行'} · ${analysis.pending?'有待分析记录':'已处理当前收到的记录'} · 累计读取 ${analysis.analyzed_input_records??0} 条`];
 if(status.analysis_enabled!==false&&(!analysis.last_run||Date.now()-Date.parse(analysis.last_run)>120000))notes.push('检测任务尚未更新，请检查后台服务。');
 if(analysis.last_error)notes.push(`检测暂不可用：${analysis.last_error}`);
 if(analysis.missing_raw_records)notes.push(`有 ${analysis.missing_raw_records} 条原始记录在分析前已过期，检测覆盖不完整。`);
 if((status.coverage||[]).length)notes.push(`${networkQuality(status.coverage)}；已过期 ${status.expired_events??0} 条原始事件。`);
 if(Number.isFinite(status.storage_bytes)&&Number.isFinite(status.limits?.storage_bytes))notes.push(`网络存储 ${(status.storage_bytes/1048576).toFixed(1)} / ${(status.limits.storage_bytes/1048576).toFixed(1)} MiB。`);
 if(status.capacity_available===false){const names={events:'原始事件数',receipts:'去重凭据数',batches:'采集批次数',storage:'存储空间'};notes.push('容量已耗尽：'+(status.exhausted||[]).map(key=>names[key]||key).join('、')+'。请处理容量问题后继续接收新数据。');}
 text('network-health',notes.join('\n'));
 const quality=new Map((analysis.source_coverage||[]).map(row=>[row.source_id,row.coverage]));
 const rows=[];for(const source of sources){const tr=document.createElement('tr');cell(tr,`${source.hostname||source.source_id} · ${source.source_id}`);cell(tr,networkCollection[source.status]||source.status);cell(tr,`${source.accepted_total??0} / ${source.rejected_total??0}`);cell(tr,networkQuality(quality.get(source.source_id))||'未记录额外限制；请核对来源登记范围。');rows.push(tr);}
 $('network-sources').replaceChildren(...rows);if(!rows.length)empty($('network-sources'),4,'没有已登记的网络来源。');
 const issues=analysis.coverage_issues||[];
 text('network-coverage',issues.length?`近期 ${issues.length>=50?'至少 ':''}${issues.length} 个关联窗口覆盖不完整，相关结果需要重新核验。\n`+issues.slice(0,5).map(row=>`${row.source_id}：${networkQuality(row.coverage)}`).join('\n')+(issues.length>5?'\n仅展示前 5 个窗口；状态接口最多返回最近 50 个窗口。':''):'当前未记录关联窗口缺口；这不代表完整流量覆盖。');
 text('network-quality-summary',`采集来源与覆盖限制 · ${sources.length} 个来源 · ${sources.filter(row=>row.status!=='current').length} 个采集异常 · ${(analysis.source_coverage||[]).filter(row=>row.coverage?.length).length} 个来源有覆盖限制 · ${issues.length>=50?'至少 ':''}${issues.length} 个不完整窗口`);
}
async function loadNetwork(page=networkPage){
 const request=++networkRequest;networkLoading=true;networkPager();text('network-status','正在读取网络检测…');
 try{
  const status=await get('/api/network/status');if(request!==networkRequest)return;networkHealth(status);
  if(!status.enabled){networkPage=networkPages=1;networkAvailable=false;$('network-rows').replaceChildren();empty($('network-rows'),6,'网络来源尚未配置，暂无检测结果。');text('network-page','');text('network-status','');return;}
  const query=new URLSearchParams({page:String(page),limit:'50',focus:$('network-focus').value||'all'});if($('network-source').value)query.set('source_id',$('network-source').value);
  const data=await get('/api/network/incidents?'+query);if(request!==networkRequest)return;
  if(!networkPageValid(data,page)||!data.items.every(networkItemValid))throw new Error('网络事件返回异常，请刷新重试。');
  const rows=[];for(const item of data.items){const tr=document.createElement('tr');cell(tr,when(item.last_seen));cell(tr,item.source_id);const peers=cell(tr,`${item.src_ip} → ${item.dst_ip}`);peers.append(networkSSHSearchActions(item));cell(tr,item.rules.map(rule=>rule.label).join('、')||'模式已撤回');cell(tr,`${item.assessment.score} 分 · ${item.stale?'待重新核验':item.active?(item.assessment.priority||'低分'):'已撤回'}`);const button=document.createElement('button');button.type='button';button.textContent='查看详情';button.addEventListener('click',()=>showNetworkIncident(item.incident_id,item.revision));cell(tr,'').append(button);rows.push(tr);}
  $('network-rows').replaceChildren(...rows);if(!rows.length)empty($('network-rows'),6,'暂无符合条件的事件；没有命中不代表安全或完整覆盖。');
  networkPage=data.page;networkPages=data.total_pages;networkAvailable=data.total>0;text('network-page',`第 ${data.page} / ${data.total_pages} 页 · 共 ${data.total} 个事件`);text('network-status','');
 }catch(error){if(request===networkRequest)text('network-status',error.message+' 已保留上次读取的网络事件与页码；可能不符合新筛选条件。');}
 finally{if(request===networkRequest){networkLoading=false;networkPager();}}
}
function renderNetworkDetail(item){
 networkDetail=item;
 $('network-ssh-search').replaceChildren(networkSSHSearchActions(item));
 networkFields('network-fields',[
  ['标题',item.title],['来源',item.source_id],['源 IP → 目的 IP',`${item.src_ip} → ${item.dst_ip}`],
  ['日志显示时段',`${when(item.first_seen)} — ${when(item.last_seen)}`],['版本',`${item.revision} · ${when(item.updated_at)}`],
  ['评分',`${item.assessment.score} 分 · ${item.assessment.priority||'低分'}；规则核查优先级，不是攻击概率。`],
  ['检测状态',item.stale?'待重新核验，保留上次可核验结果':item.active?'命中探测模式，需人工核查':'原模式已撤回'],
  ['覆盖限制',networkQuality(item.coverage)||'未记录额外限制；仍受登记来源范围约束。'],
  ['规则',item.rules.map(rule=>`${rule.label} · v${rule.rule_version} · ${rule.window_seconds} 秒内 ${rule.evidence_count} 条证据；目的端口 ${(rule.distinct_dst_ports||[]).join('、')}`).join('\n')||'当前无命中'],
  ['计分依据',item.assessment.reasons.map(reason=>`${reason.reason} +${reason.points}：${reason.criteria}`).join('；')||'当前无命中'],
  ['证据数量',item.evidence_count],['判断边界',item.assessment.note]
 ]);
 networkFields('network-provenance',[['事件 ID',item.incident_id],['关联版本',item.correlation_version],['评分版本',item.assessment.version],['启动 ID',item.boot_id],['来源配置版本',item.source_profile_revision],['单调时钟区间（微秒）',`${item.window_start_monotonic_us} — ${item.window_end_monotonic_us}（不是日历时间）`],['证据摘要',item.evidence_sha256]]);
 text('network-revision',`版本 ${item.revision} / ${networkLatest}${item.revision<networkLatest?' · 历史快照':''}`);$('network-revision-prev').disabled=item.revision<=1;$('network-revision-next').disabled=item.revision>=networkLatest;
}
function networkEvidencePager(){
 $('network-evidence-prev').disabled=networkEvidenceLoading||!networkEvidenceAvailable||networkEvidencePage<=1;$('network-evidence-next').disabled=networkEvidenceLoading||!networkEvidenceAvailable||networkEvidencePage>=networkEvidencePages;
 $('network-evidence-retry').disabled=networkEvidenceLoading||!networkDetail;
}
async function loadNetworkEvidence(page=1){
 if(!networkDetail)return;const request=++networkEvidenceRequest,identity=networkDetail.incident_id,revision=networkDetail.revision;
 networkEvidenceLoading=true;networkEvidencePager();text('network-evidence-status','正在读取此版本的证据…');
 try{
  const data=await get('/api/network/incidents/'+encodeURIComponent(identity)+'/evidence?'+new URLSearchParams({revision:String(revision),page:String(page),limit:'25'}));
  if(request!==networkEvidenceRequest||!networkDetail||networkDetail.incident_id!==identity||networkDetail.revision!==revision)return;
  if(data.incident_id!==identity||data.revision!==revision||!networkPageValid(data,page))throw new Error('网络证据身份、版本或页码不匹配。');
  const rows=[];for(const item of data.items){
   if(item.source_id!==networkDetail.source_id||item.src_ip!==networkDetail.src_ip||item.dst_ip!==networkDetail.dst_ip||item.boot_id!==networkDetail.boot_id||item.source_profile_revision!==networkDetail.source_profile_revision||!Number.isFinite(item.journal_realtime_us)||!Array.isArray(item.coverage))throw new Error('网络证据与事件来源不匹配。');
   const tr=document.createElement('tr');cell(tr,networkDate(item.journal_realtime_us));cell(tr,`${item.src_ip} / ${item.src_port??'未知'}`);cell(tr,`${item.dst_ip} / ${item.dst_port??'未知'}`);cell(tr,`${item.protocol} · ${(item.tcp_flags||[]).join(', ')||'未知标志'}`);cell(tr,`${item.direction==='inbound'?'入站':item.direction==='local_input'?'本机入站':item.direction} · ${item.observation_point==='local_input'?'本机入站位置':'采集位置未知'} · ${item.ingress_interface||'未知接口'}\n${networkQuality(item.coverage)||'无额外记录限制'}；最终处置${item.final_outcome==='unknown'?'未知':item.final_outcome}`);rows.push(tr);
  }
  $('network-evidence').replaceChildren(...rows);if(!rows.length)empty($('network-evidence'),5,'此版本没有命中证据。');
  networkEvidencePage=data.page;networkEvidencePages=data.total_pages;networkEvidenceAvailable=data.total>0;text('network-evidence-page',`第 ${data.page} / ${data.total_pages} 页 · ${data.total} 条证据`);text('network-evidence-status','');
 }catch(error){if(request===networkEvidenceRequest)text('network-evidence-status',error.message+' 证据读取失败；已保留此版本上次读取的证据页。');}
 finally{if(request===networkEvidenceRequest){networkEvidenceLoading=false;networkEvidencePager();}}
}
async function showNetworkIncident(identity,revision=null){
 const dialog=$('network-dialog');if(!dialog.open){networkReturnFocus=document.activeElement;setNetworkDetailTab('overview');if(typeof dialog.showModal==='function')dialog.showModal();else dialog.setAttribute('open','');}
 const request=++networkDetailRequest;++networkEvidenceRequest;networkDetail=null;networkEvidencePage=networkEvidencePages=1;networkEvidenceLoading=false;networkEvidenceAvailable=false;
 for(const id of ['network-fields','network-provenance','network-evidence','network-ssh-search'])$(id).replaceChildren();for(const id of ['network-revision','network-evidence-page','network-evidence-status'])text(id,'');
 for(const id of ['network-revision-prev','network-revision-next','network-current'])$(id).disabled=true;networkEvidencePager();text('network-detail-status','正在读取网络事件版本…');
 try{
  const path='/api/network/incidents/'+encodeURIComponent(identity),latest=await get(path);if(request!==networkDetailRequest)return;
  if(!networkItemValid(latest)||latest.incident_id!==identity)throw new Error('网络事件身份或版本不匹配。');
  networkLatest=latest.revision;const item=revision===null||revision===latest.revision?latest:await get(path+'?revision='+encodeURIComponent(revision));if(request!==networkDetailRequest)return;
  if(!networkItemValid(item)||item.incident_id!==identity||revision!==null&&item.revision!==revision||item.revision>networkLatest)throw new Error('网络事件身份或版本不匹配。');
  renderNetworkDetail(item);$('network-current').disabled=false;text('network-detail-status','');await loadNetworkEvidence();
 }catch(error){if(request===networkDetailRequest)text('network-detail-status',error.message+' 请关闭后重新打开事件。');}
}
function clearNetworkDetail(){++networkDetailRequest;++networkEvidenceRequest;networkDetail=null;networkEvidenceLoading=false;networkEvidenceAvailable=false;networkEvidencePager();if(networkReturnFocus?.isConnected&&typeof networkReturnFocus.focus==='function')networkReturnFocus.focus();}
function setNetworkDetailTab(name){if(!['overview','evidence'].includes(name))return;for(const key of ['overview','evidence']){$('network-pane-'+key).hidden=key!==name;$('network-tab-'+key).setAttribute('aria-selected',String(key===name));$('network-tab-'+key).tabIndex=key===name?0:-1;}}
function initializeNetwork(){
 setNetworkDetailTab('overview');
 for(const id of ['network-source','network-focus'])$(id).addEventListener('change',()=>loadNetwork(1));
 $('network-refresh').addEventListener('click',()=>loadNetwork());$('network-prev').addEventListener('click',()=>loadNetwork(networkPage-1));$('network-next').addEventListener('click',()=>loadNetwork(networkPage+1));
 $('network-close').addEventListener('click',()=>{const dialog=$('network-dialog');if(typeof dialog.close==='function')dialog.close();else{dialog.removeAttribute('open');clearNetworkDetail();}});$('network-dialog').addEventListener('close',clearNetworkDetail);
 $('network-current').addEventListener('click',()=>{if(networkDetail)return showNetworkIncident(networkDetail.incident_id);});
 $('network-revision-prev').addEventListener('click',()=>{if(networkDetail)return showNetworkIncident(networkDetail.incident_id,networkDetail.revision-1);});$('network-revision-next').addEventListener('click',()=>{if(networkDetail)return showNetworkIncident(networkDetail.incident_id,networkDetail.revision+1);});
 $('network-evidence-prev').addEventListener('click',()=>loadNetworkEvidence(networkEvidencePage-1));$('network-evidence-next').addEventListener('click',()=>loadNetworkEvidence(networkEvidencePage+1));$('network-evidence-retry').addEventListener('click',()=>loadNetworkEvidence(networkEvidencePage));
 for(const name of ['overview','evidence']){$('network-tab-'+name).addEventListener('click',()=>setNetworkDetailTab(name));$('network-tab-'+name).addEventListener('keydown',event=>{if(['ArrowLeft','ArrowRight','Home','End'].includes(event.key)){event.preventDefault();const next=event.key==='Home'?'overview':event.key==='End'?'evidence':name==='overview'?'evidence':'overview';setNetworkDetailTab(next);$('network-tab-'+next).focus();}});}
}
"""
