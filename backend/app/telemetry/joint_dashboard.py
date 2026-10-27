"""Read-only joint observations, fixed revision details and bounded timelines."""

SECTION = """<section id="joint-section" aria-busy="false"><h2>联合案件</h2>
<p id="joint-boundary">按明确资产映射，查看同一来源 IP 在相邻时间内的 SSH 与 TCP 证据。关联不代表同一攻击者或入侵成功；只覆盖已登记案件与保留的告警证据，没有匹配不代表安全。</p>
<p id="joint-health" role="status" aria-live="polite">切换到此页后读取已生成的联合观察。</p>
<p id="joint-update-note">观察由操作员在服务器显式运行更新命令生成。这里的刷新只读取已有结果，不会启动检测、AI 或封禁。</p>
<form id="joint-search" class="search-fields"><label>完整来源 IP<input id="joint-ip" type="text" maxlength="64" placeholder="IPv4 / IPv6，不支持 CIDR" autocomplete="off"></label><label>资产<select id="joint-asset"><option value="">全部已登记资产</option></select></label><label>关联状态<select id="joint-state"><option value="">全部状态</option><option value="linked">发现关联证据</option><option value="unmatched">未找到匹配证据</option><option value="partial">观察不完整</option><option value="stale">原网络案件待核验</option><option value="retracted">原网络模式已撤回</option></select></label><label>窗口起点（本地）<input id="joint-start" type="datetime-local" step="1"></label><label>窗口终点（本地）<input id="joint-end" type="datetime-local" step="1"></label><div class="actions"><button type="submit">查询案件</button><button id="joint-clear" type="button">清空条件</button></div></form>
<p id="joint-query-scope" class="muted"></p><div class="actions"><button id="joint-refresh" type="button">刷新当前页</button><button id="joint-latest" type="button">读取最新观察</button><span id="joint-new" role="status"></span></div>
<div class="table-wrap"><table aria-describedby="joint-boundary"><thead><tr><th>关联时间窗</th><th>资产</th><th>来源 IP</th><th>SSH / 网络证据</th><th>关联 / 保存范围</th><th>详情</th></tr></thead><tbody id="joint-rows"></tbody></table></div>
<div class="pager"><button id="joint-prev" type="button" disabled>上一页</button><span id="joint-page"></span><button id="joint-next" type="button" disabled>下一页</button></div><p id="joint-status" class="list-status" role="status" aria-live="polite"></p></section>"""

DIALOG = """<dialog id="joint-dialog" aria-labelledby="joint-detail-title"><div class="joint-detail-body"><div class="drawer-heading"><h2 id="joint-detail-title">联合案件详情</h2><button id="joint-close" type="button" aria-label="关闭联合案件详情">关闭 ✕</button></div>
<p id="joint-detail-status" role="status" aria-live="polite"></p><div class="actions"><button id="joint-revision-prev" type="button" disabled>上一版本</button><span id="joint-revision"></span><button id="joint-revision-next" type="button" disabled>下一版本</button><button id="joint-current" type="button" disabled>读取当前版本</button></div>
<div class="detail-tabs" role="tablist" aria-label="联合案件详情内容"><button id="joint-tab-overview" type="button" role="tab" aria-controls="joint-pane-overview" aria-selected="true">关联理由</button><button id="joint-tab-timeline" type="button" role="tab" aria-controls="joint-pane-timeline" aria-selected="false" tabindex="-1">时间线</button><button id="joint-tab-sources" type="button" role="tab" aria-controls="joint-pane-sources" aria-selected="false" tabindex="-1">来源与版本</button></div>
<div id="joint-pane-overview" class="joint-detail-scroll" role="tabpanel" aria-labelledby="joint-tab-overview"><dl id="joint-fields" class="detail-fields"></dl><h3>该版本的关联理由与限制</h3><p id="joint-reasons"></p><p id="joint-uncertainties"></p><h3>当前刷新状态</h3><p id="joint-freshness"></p><p>当前状态可能晚于所选历史版本；来源刷新失败不会删除此前保存的观察。</p></div>
<div id="joint-pane-timeline" class="joint-detail-scroll" role="tabpanel" aria-labelledby="joint-tab-timeline" hidden><p id="joint-timeline-boundary">只显示此版本实际保存的规范化时间线；截断后未保存的记录不会从当前日志补入。日志时间来自来源主机，不代表跨库原子快照。</p><div class="table-wrap"><table><thead><tr><th>证据时间</th><th>类型 / 来源</th><th>观察</th><th>原案件引用</th></tr></thead><tbody id="joint-timeline"></tbody></table></div><div class="pager"><button id="joint-timeline-prev" type="button" disabled>上一页</button><span id="joint-timeline-page"></span><button id="joint-timeline-next" type="button" disabled>下一页</button><button id="joint-timeline-retry" type="button" disabled>重试时间线</button></div><p id="joint-timeline-status" role="status" aria-live="polite"></p></div>
<div id="joint-pane-sources" class="joint-detail-scroll" role="tabpanel" aria-labelledby="joint-tab-sources" hidden><dl id="joint-provenance" class="detail-fields"></dl><div id="joint-source-actions" class="actions"></div><p>网络入口读取此观察引用的网络版本。SSH 查询读取当前保留记录、最近 24 小时和全部来源，可能与历史联合观察不同；SSH 来源没有可还原的持久版本。可在搜索页调整时间范围。</p><p>时间线中的原案件与 canonical 引用仅代表保存时的证据归属；当前 SSH 案件之后可能合并。关联范围受明确映射、来源覆盖与保留策略限制。</p></div>
</div></dialog>"""

STYLE = """
#joint-health,#joint-query-scope,#joint-reasons,#joint-uncertainties,#joint-freshness{white-space:pre-line;overflow-wrap:anywhere}#joint-section>.table-wrap table{min-width:790px}#joint-search{grid-template-columns:repeat(3,minmax(0,1fr))}#joint-search label{display:flex;flex-direction:column;gap:6px;min-width:0}#joint-search input,#joint-search select{min-width:0;max-width:100%}#joint-new{color:#dec080;font-size:13px}#joint-dialog{position:fixed;inset:0 0 0 auto;margin:0;width:min(930px,100vw);max-width:100vw;height:100dvh;max-height:100dvh;border:0;border-left:1px solid #385475;background:#101d2e;color:#e7edf5;padding:22px}#joint-dialog::backdrop{background:#030b17a6}.joint-detail-body{height:100%;display:flex;flex-direction:column;gap:12px;min-width:0}.joint-detail-scroll{min-height:0;overflow:auto;flex:1}#joint-dialog .actions{margin:0;flex-shrink:0}#joint-dialog .detail-tabs{margin:0;padding:0 0 10px;flex-shrink:0}#joint-pane-timeline{display:flex;flex-direction:column;overflow:hidden}.joint-detail-scroll .table-wrap{overflow:auto;min-height:0;flex:1}.joint-detail-scroll table{min-width:720px}.joint-detail-scroll .pager{flex-shrink:0;flex-wrap:wrap}.joint-detail-scroll p{font-size:13px}.joint-detail-scroll dd{overflow-wrap:anywhere}#joint-detail-status:empty,#joint-timeline-status:empty{display:none}#joint-detail-status,#joint-timeline-status{font-size:13px;margin:0}
@media(max-width:850px){#joint-dialog{padding:16px}#joint-dialog .drawer-heading h2{font-size:17px}#joint-dialog .actions,#joint-dialog .pager{gap:6px;font-size:12px}#joint-dialog button{font-size:12px;padding:7px 9px}#joint-search{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:480px){#joint-search{grid-template-columns:1fr}#joint-dialog .detail-tabs{gap:4px}}
"""

SCRIPT = r"""
let jointPage=1,jointPages=1,jointSnapshot=null,jointPinnedGeneration=null,jointFilters={},jointRequest=0,jointController=null,jointLoading=false,jointAvailable=false;
let jointDetail=null,jointDetailRequest=0,jointDetailController=null,jointReturnFocus=null,jointTimelineRequest=0,jointTimelineController=null;
let jointTimelinePage=1,jointTimelinePages=1,jointTimelineLoaded=false,jointTimelineLoading=false,jointTimelineAvailable=false;
const jointStates={linked:'发现关联证据',unmatched:'未找到匹配证据',partial:'观察不完整',stale:'原网络案件待核验',retracted:'原网络模式已撤回'};
const jointRefreshStates={fresh:'最近一次刷新成功',pending:'等待操作员更新',current:'最近一次刷新成功',available:'最近一次刷新成功',unavailable:'最近刷新失败，保留历史',needs_review:'需要重新核验',not_eligible:'不符合关联范围'};
const jointCodes={shared_ip_does_not_establish_identity:'相同来源 IP 不能确认是同一使用者',cross_source_clock_alignment_unknown:'不同来源的时钟对齐情况未知',single_network_observation_clock_unverifiable:'单条网络观察无法核验时钟连续性',ssh_authentication_failure_observed:'观察到 SSH 认证失败',ssh_authentication_success_observed:'观察到 SSH 认证成功，但不证明入侵',ssh_preauth_abort_observed:'观察到 SSH 认证前断开',no_matching_retained_ssh_evidence:'本次未找到匹配的保留 SSH 告警证据',ssh_association_not_evaluated:'本次未评估 SSH 时间关联',network_evidence_unavailable:'没有可用于关联的网络证据',explicit_asset_mapping:'已按明确资产映射核对来源',network_anchor_retained:'引用已保留的网络证据',same_observed_peer:'观察到相同来源 IP',mapped_ssh_evidence_in_window:'映射的 SSH 来源在关联时间窗内有实际证据',no_mapped_ssh_evidence_in_window:'本次未找到时间窗内的匹配 SSH 证据',timeline_truncated:'时间线已截断，只保存部分记录',temporal_association_unavailable:'无法可靠使用时间建立关联',network_clock_discontinuity:'网络来源时钟异常',ssh_clock_discontinuity:'SSH 来源时钟异常',network_anchor_time_span_exceeded:'网络证据时间跨度超限',network_anchor_retracted:'原网络探测模式已撤回',network_anchor_stale:'原网络案件待重新核验',network_evidence_incomplete:'提供的网络证据不完整',ssh_candidate_evidence_incomplete:'提供的 SSH 候选证据不完整',shared_ip_not_actor_identity:'共享 IP 不能确认人员身份',coverage_unknown:'来源覆盖未知',source_unavailable:'来源不可用',source_busy:'来源暂忙',source_schema_unavailable:'来源结构不兼容',network_revision_missing:'缺少所需网络版本',adapter_limit_exceeded:'来源读取达到上限',query_deadline_exceeded:'来源读取超时',joint_capacity_exceeded:'派生存储达到容量上限'};
function jointLabel(code){const parts=String(code).split(':');if(parts.length===2&&['network','ssh'].includes(parts[0]))return `${parts[0]==='ssh'?'SSH':'网络'}：${jointCodes[parts[1]]||networkCoverage[parts[1]]||parts[1]}`;return jointCodes[code]||networkCoverage[code]||String(code);}
const jointEventTypes={auth_failure:'认证失败',ssh_failure:'认证失败',invalid_user:'无效账号',auth_success:'认证成功（不证明入侵）',ssh_success:'认证成功（不证明入侵）',preauth_abort:'认证前断开',probe:'协议探测',disconnect:'断开连接',session_open:'会话打开',session_close:'会话关闭',daemon:'服务状态',other:'其他'};
function jointNumber(value){return Number.isSafeInteger(value)&&value>=0;}
function jointDate(value){return Number.isSafeInteger(value)?when(value/1000):'不可用';}
function jointWindow(start,end,available=true){return available&&Number.isSafeInteger(start)&&Number.isSafeInteger(end)?`${jointDate(start)} — ${jointDate(end)}`:'时间关联不可用';}
function jointFields(id,values){const node=$(id);node.replaceChildren();for(const [label,value] of values){const term=document.createElement('dt'),detail=document.createElement('dd');term.textContent=label;detail.textContent=String(value??'—');node.append(term,detail);}}
async function jointGet(path,signal){
 const result=await fetch(path,{credentials:'same-origin',cache:'no-store',signal});
 if(!result.ok){const messages={401:'登录已失效，请刷新页面重新登录。',404:'联合案件或指定版本不可用。',409:'此查询快照已失效，请点击“读取最新观察”重新查询。',422:'查询条件无效，请核对完整 IP、资产、状态及时间范围。',503:'联合案件暂不可用，请稍后重试；此前保存的证据不会因此被判为安全。'};throw new Error(messages[result.status]||'联合案件读取失败，请检查服务状态。');}
 return result.json();
}
function jointPageValid(data,page,totalKey='total'){return data&&Array.isArray(data.items)&&jointNumber(data[totalKey])&&Number.isSafeInteger(data.page)&&data.page>=1&&Number.isSafeInteger(data.total_pages)&&data.total_pages>=1&&data.page===Math.min(page,data.total_pages);}
function jointItemValid(item){return item&&typeof item.case_id==='string'&&/^JOINT-[a-f0-9]{32}$/.test(item.case_id)&&Number.isSafeInteger(item.revision)&&item.revision>=1&&jointNumber(item.publish_generation)&&typeof item.asset_id==='string'&&typeof item.peer_ip==='string'&&Object.hasOwn(jointStates,item.association_state)&&jointNumber(item.network_count)&&jointNumber(item.ssh_count)&&jointNumber(item.saved_count)&&jointNumber(item.observed_count)&&item.saved_count<=item.observed_count&&typeof item.timeline_complete==='boolean'&&typeof item.temporal_available==='boolean'&&(!item.temporal_available||(Number.isSafeInteger(item.window_start_us)&&Number.isSafeInteger(item.window_end_us)&&item.window_start_us<=item.window_end_us));}
function jointPager(){
 $('joint-prev').disabled=jointLoading||!jointAvailable||jointPage<=1;$('joint-next').disabled=jointLoading||!jointAvailable||jointPage>=jointPages;
 $('joint-section').setAttribute('aria-busy',String(jointLoading));
}
function jointHealth(data){
 if(typeof data?.enabled!=='boolean')throw new Error('联合案件状态返回异常。');
 if(!data.enabled){text('joint-health','联合案件尚未配置，暂无已生成的联合观察。');return;}
 const labels={ready:'可以查看已保存的观察',empty:'尚未生成联合观察',processing:'登记或刷新尚未完成',unavailable:'最近更新不可用，已有历史仍可查阅',revalidation_pending:'来源待重新核验，历史不代表当前状态'};
 const notes=[labels[data.state]||'仅查看已保存的观察；最新状态未知'];
 if(data.revalidation_pending&&data.state!=='revalidation_pending')notes.push(labels.revalidation_pending);
 if(jointNumber(data.catalog_min_seq))notes.push(`网络目录范围从序号 ${data.catalog_min_seq} 起；这不是完整历史或全部流量。`);
 if(data.discovery){const d=data.discovery;notes.push(`目录检查：${d.complete?'本轮已结束':'本轮未完成'}${jointNumber(d.scanned_count)?` · 已检查 ${d.scanned_count} 个候选`:''}`);if(d.error)notes.push('目录更新限制：'+jointLabel(d.error));}
 if(data.cycle){const c=data.cycle;notes.push(c.all_items_refreshed?'登记范围内本轮刷新完成；不代表来源覆盖完整。':c.attempted_complete?'本轮已尝试完，部分条目未成功刷新。':'登记范围内还有待处理条目。');if(c.counts?.failed)notes.push(`本轮 ${c.counts.failed} 个条目刷新失败，历史证据仍保留。`);}
 if(data.error)notes.push('最近更新限制：'+jointLabel(data.error));
 const capacity=data.capacity;if(capacity&&jointNumber(capacity.registrations)&&jointNumber(capacity.registration_limit)&&jointNumber(capacity.revisions)&&jointNumber(capacity.revision_limit)){notes.push(`保存范围：${capacity.registrations} / ${capacity.registration_limit} 个登记案件 · ${capacity.revisions} / ${capacity.revision_limit} 个观察版本`);if(capacity.registrations>=capacity.registration_limit||capacity.revisions>=capacity.revision_limit||(jointNumber(capacity.payload_bytes)&&jointNumber(capacity.payload_byte_limit)&&capacity.payload_bytes>=capacity.payload_byte_limit))notes.push('部分派生容量已达到上限，需要操作员处理。');}
 text('joint-health',notes.join('\n'));
 if(Array.isArray(data.assets)){
  const select=$('joint-asset'),selected=select.value;select.replaceChildren();
  for(const asset of [{asset_id:''},...data.assets]){if(typeof asset?.asset_id!=='string')throw new Error('联合案件资产返回异常。');const option=document.createElement('option');option.value=asset.asset_id;option.textContent=asset.asset_id||'全部已登记资产';select.append(option);}
  if(selected&&!data.assets.some(asset=>asset.asset_id===selected)){const option=document.createElement('option');option.value=selected;option.textContent=selected+'（不在当前登记中）';select.append(option);}select.value=selected;
 }
 if(jointPinnedGeneration!==null&&jointNumber(data.generation)&&data.generation>jointPinnedGeneration)text('joint-new','有新观察，点击“读取最新观察”查看；当前分页保持不变。');
}
function jointScope(){text('joint-query-scope',`当前查询：${jointFilters.ip||'全部来源 IP'} · ${jointFilters.asset_id||'全部已登记资产'} · ${jointStates[jointFilters.state]||'全部关联状态'}\n${jointFilters.start?when(jointFilters.start):'未限定起点'} — ${jointFilters.end?when(jointFilters.end):'未限定终点'}；按关联时间窗重叠筛选，时间异常的案件不匹配时间条件。`);}
function jointClearRows(message){$('joint-rows').replaceChildren();empty($('joint-rows'),6,message);jointAvailable=false;text('joint-page','');jointPager();}
async function loadJoint(page=jointPage){
 const request=++jointRequest;if(jointController)jointController.abort();const controller=new AbortController();jointController=controller;
 const filters={...jointFilters},snapshot=jointSnapshot;const query=new URLSearchParams({page:String(page),limit:'20'});for(const [key,value] of Object.entries(filters))if(value)query.set(key,value);if(snapshot)query.set('snapshot',snapshot);
 jointLoading=true;jointPager();jointScope();text('joint-status','正在读取已保存的联合观察…');
 try{
  const status=await jointGet('/api/joint/status',controller.signal);if(request!==jointRequest)return;jointHealth(status);
  if(!status.enabled){jointPage=jointPages=1;jointSnapshot=null;jointPinnedGeneration=null;jointClearRows('尚未配置联合案件。现有 SSH 与网络页面仍可使用。');text('joint-new','');text('joint-status','');return;}
  const data=await jointGet('/api/joint/cases?'+query,controller.signal);if(request!==jointRequest)return;
  if(!jointPageValid(data,page)||data.items.length>20||!data.items.every(jointItemValid)||typeof data.snapshot!=='string'||!data.snapshot||data.snapshot.length>8192||!jointNumber(data.current_generation)||(snapshot!==null&&snapshot!==data.snapshot))throw new Error('联合案件页码、快照或数据返回异常。');
  const rows=[];for(const item of data.items){const tr=document.createElement('tr');cell(tr,jointWindow(item.window_start_us,item.window_end_us,item.temporal_available));cell(tr,item.asset_id);cell(tr,item.peer_ip);cell(tr,`${item.ssh_count} / ${item.network_count}`);cell(tr,`${jointStates[item.association_state]} · 保存 ${item.saved_count} / 观察 ${item.observed_count} 条${item.timeline_complete?'':' · 已截断'}`);const button=document.createElement('button');button.type='button';button.textContent='查看详情';button.addEventListener('click',()=>showJointCase(item.case_id,item.revision));cell(tr,'').append(button);rows.push(tr);}
  $('joint-rows').replaceChildren(...rows);if(!rows.length)empty($('joint-rows'),6,'没有符合条件的已保存案件；可能尚未登记、尚未处理或未匹配，不能据此判断安全。');
  jointPage=data.page;jointPages=data.total_pages;jointAvailable=data.total>0;jointSnapshot=data.snapshot;
  if(jointPinnedGeneration===null)jointPinnedGeneration=data.current_generation;
  if(data.current_generation>jointPinnedGeneration)text('joint-new','有新观察，点击“读取最新观察”查看；当前分页保持不变。');
  text('joint-page',`第 ${data.page} / ${data.total_pages} 页 · 共 ${data.total} 个案件`);text('joint-status','');
 }catch(error){if(request===jointRequest&&error.name!=='AbortError')text('joint-status',error.message+(jointAvailable?' 已保留上次读取的案件与页码。':' 当前没有可展示的查询结果。'));}
 finally{if(request===jointRequest){jointLoading=false;jointPager();}}
}
function jointReadFilters(){
 const filters={};for(const [id,key] of [['joint-ip','ip'],['joint-asset','asset_id'],['joint-state','state']]){const value=$(id).value.trim();if(value)filters[key]=value;}
 for(const key of ['start','end']){const raw=$('joint-'+key).value;if(raw){const date=new Date(raw);if(!Number.isFinite(date.valueOf()))throw new Error('请输入有效的本地时间。');filters[key]=date.toISOString();}}
 if(filters.start&&filters.end&&filters.start>filters.end)throw new Error('开始时间不能晚于结束时间。');return filters;
}
function jointResetQuery(filters){++jointRequest;if(jointController)jointController.abort();jointLoading=false;jointFilters=filters;jointPage=jointPages=1;jointSnapshot=null;jointPinnedGeneration=null;text('joint-new','');jointClearRows('正在查询新的条件…');jointScope();}
async function submitJointSearch(){try{const filters=jointReadFilters();jointResetQuery(filters);await loadJoint(1);}catch(error){++jointRequest;if(jointController)jointController.abort();jointLoading=false;jointClearRows('查询条件无效；未显示此前条件的结果。');text('joint-status',error.message);}}
function jointTimelinePager(){
 $('joint-timeline-prev').disabled=jointTimelineLoading||!jointTimelineAvailable||jointTimelinePage<=1;$('joint-timeline-next').disabled=jointTimelineLoading||!jointTimelineAvailable||jointTimelinePage>=jointTimelinePages;$('joint-timeline-retry').disabled=jointTimelineLoading||!jointDetail;
}
function jointRefs(item){return item.incident_refs.map(ref=>item.kind==='network'?`${ref.incident_id} · 网络版本 ${ref.revision}`:`${ref.incident_id} → ${ref.canonical_incident_id}（保存时归属）`).join('\n');}
function jointTimelineItemValid(item){return item&&['network','ssh'].includes(item.kind)&&Number.isSafeInteger(item.event_ts_us)&&typeof item.source_id==='string'&&typeof item.src_ip==='string'&&Array.isArray(item.incident_refs)&&item.incident_refs.length>0&&item.incident_refs.every(ref=>typeof ref?.incident_id==='string'&&(item.kind==='network'?Number.isSafeInteger(ref.revision)&&ref.revision>=1:typeof ref.canonical_incident_id==='string'));}
async function loadJointTimeline(page=1){
 if(!jointDetail)return;const identity=jointDetail.case_id,revision=jointDetail.revision,request=++jointTimelineRequest;if(jointTimelineController)jointTimelineController.abort();jointTimelineController=new AbortController();
 jointTimelineLoading=true;jointTimelinePager();text('joint-timeline-status','正在读取该版本保存的时间线…');
 try{
  const data=await jointGet('/api/joint/cases/'+encodeURIComponent(identity)+'/timeline?'+new URLSearchParams({revision:String(revision),page:String(page),limit:'25'}),jointTimelineController.signal);
  if(request!==jointTimelineRequest||jointDetail?.case_id!==identity||jointDetail?.revision!==revision)return;
  if(data.case_id!==identity||data.revision!==revision||!jointPageValid(data,page,'total_saved')||data.items.length>25||!data.items.every(jointTimelineItemValid)||!jointNumber(data.observed_count)||data.observed_count<data.total_saved||typeof data.timeline_complete!=='boolean'||data.items.some(item=>item.src_ip!==jointDetail.projection.anchor.src_ip||(item.kind==='network'?item.source_id!==jointDetail.projection.anchor.source_id||item.incident_refs.some(ref=>ref.incident_id!==jointDetail.projection.anchor.incident_id||ref.revision!==jointDetail.projection.anchor.revision):!Object.hasOwn(jointDetail.projection.counts?.ssh||{},item.source_id))))throw new Error('时间线身份、版本或范围不匹配。');
  const rows=[];for(const item of data.items){const tr=document.createElement('tr');cell(tr,jointDate(item.event_ts_us));cell(tr,`${item.kind==='ssh'?'SSH':'网络'} · ${item.source_id}`);cell(tr,item.kind==='ssh'?`${jointEventTypes[item.event_type]||item.event_type||'—'} · ${item.account??'—'} · ${item.src_ip}`:`${item.src_ip} → ${item.dst_ip??'—'}:${item.dst_port??'—'} · ${item.protocol??'—'} · ${item.direction==='local_input'?'本机入站':item.direction??'—'}`);cell(tr,jointRefs(item));rows.push(tr);}
  $('joint-timeline').replaceChildren(...rows);if(!rows.length)empty($('joint-timeline'),4,'此版本没有保存可展示的时间线记录。');
  jointTimelinePage=data.page;jointTimelinePages=data.total_pages;jointTimelineAvailable=data.total_saved>0;jointTimelineLoaded=true;
  text('joint-timeline-page',`第 ${data.page} / ${data.total_pages} 页 · 保存 ${data.total_saved} / 观察 ${data.observed_count} 条${data.timeline_complete?'':' · 截断，未保存部分不可翻页'}`);text('joint-timeline-status','');
 }catch(error){if(request===jointTimelineRequest&&error.name!=='AbortError')text('joint-timeline-status',error.message+(jointTimelineAvailable?' 保留此版本上次读取的时间线。':' 请重试此版本的时间线。'));}
 finally{if(request===jointTimelineRequest){jointTimelineLoading=false;jointTimelinePager();}}
}
function jointDetailValid(data,identity,revision){const p=data?.projection;return data?.case_id===identity&&data.revision===revision&&p?.case_id===identity&&Object.hasOwn(jointStates,p.state)&&p.anchor&&typeof p.anchor.src_ip==='string'&&typeof p.anchor.incident_id==='string'&&Number.isSafeInteger(p.anchor.revision)&&p.anchor.revision>=1&&p.window&&Array.isArray(p.reasons)&&p.reasons.every(x=>typeof x==='string')&&Array.isArray(p.uncertainties)&&p.uncertainties.every(x=>typeof x==='string')&&Array.isArray(p.timeline)&&data.current&&Number.isSafeInteger(data.current.revision)&&data.current.revision>=revision;}
function renderJointDetail(data){
 jointDetail=data;const p=data.projection,current=data.current;
 jointFields('joint-fields',[['资产',p.asset_id],['来源 IP',p.anchor.src_ip],['关联状态',jointStates[p.state]],['关联时间窗',jointWindow(p.window.start_us,p.window.end_us,p.temporal_association_available)],['时间线保存范围',`${p.timeline.length} / 观察 ${p.observed_evidence_count??'未知'} 条${p.timeline_complete?'':'（截断）'}`],['来源覆盖','只包含映射的保留告警证据；不代表完整采集'],['判断边界','证据关联，不是攻击概率或自动处置建议']]);
 text('joint-reasons',p.reasons.map(jointLabel).join('\n')||'未提供关联理由。');text('joint-uncertainties',p.uncertainties.map(jointLabel).join('\n')||'未记录额外限制；仍不能证明覆盖完整。');
 text('joint-freshness',`${jointRefreshStates[current.refresh_state]||current.refresh_state||'未知'}\n最近成功观察：${current.last_success?when(current.last_success):'未知'}${current.error?'\n限制：'+jointLabel(current.error):''}`);
 const meta=data.first_read_metadata||{};
 jointFields('joint-provenance',[['联合案件',data.case_id],['所选观察版本',data.revision],['当前观察版本',current.revision],['网络案件版本',`${p.anchor.incident_id} · ${p.anchor.revision}`],['网络来源',p.anchor.source_id],['网络生产者',p.anchor.producer_id],['映射摘要',p.mapping_sha256],['证据摘要',p.evidence_sha256],['来源观察','网络与 SSH 顺序读取，不是跨库原子快照'],['SSH 上游版本','无持久版本；只保存本次选定证据'],['首次网络读取',meta.network_observation?.started_at?`${when(meta.network_observation.started_at)} — ${when(meta.network_observation.finished_at)}`:'未知'],['首次 SSH 读取',meta.ssh_observation?.state==='read'?`${when(meta.ssh_observation.started_at)} — ${when(meta.ssh_observation.finished_at)}`:'未执行或未知']]);
 text('joint-revision',`观察版本 ${data.revision} / 当前 ${current.revision}${data.revision<current.revision?' · 历史观察':''}`);
 $('joint-revision-prev').disabled=data.revision<=1;$('joint-revision-next').disabled=data.revision>=current.revision;$('joint-current').disabled=false;
 const actions=$('joint-source-actions');actions.replaceChildren();
 const net=document.createElement('button');net.type='button';net.textContent='查看引用的网络版本';net.addEventListener('click',()=>{closeJointDetail();return showNetworkIncident(p.anchor.incident_id,p.anchor.revision);});actions.append(net);
 for(const [kind,label] of [['incident','查当前 SSH 告警'],['event','查当前 SSH 日志']]){const button=document.createElement('button');button.type='button';button.textContent=label;button.addEventListener('click',()=>{closeJointDetail();return searchSSHFromIP(kind,p.anchor.src_ip);});actions.append(button);}
}
async function showJointCase(identity,revision){
 const dialog=$('joint-dialog');if(!dialog.open)jointReturnFocus=document.activeElement;
 const request=++jointDetailRequest;++jointTimelineRequest;if(jointDetailController)jointDetailController.abort();if(jointTimelineController)jointTimelineController.abort();jointDetailController=new AbortController();
 jointDetail=null;jointTimelineLoaded=false;jointTimelineAvailable=false;jointTimelineLoading=false;jointTimelinePage=jointTimelinePages=1;
 for(const id of ['joint-fields','joint-provenance','joint-timeline','joint-source-actions'])$(id).replaceChildren();
 for(const id of ['joint-revision','joint-reasons','joint-uncertainties','joint-freshness','joint-timeline-page','joint-timeline-status'])text(id,'');
 for(const id of ['joint-revision-prev','joint-revision-next','joint-current'])$(id).disabled=true;
 jointTimelinePager();setJointTab('overview');text('joint-detail-status','正在读取指定观察版本…');
 if(!dialog.open){if(typeof dialog.showModal==='function')dialog.showModal();else dialog.setAttribute('open','');}
 try{const data=await jointGet('/api/joint/cases/'+encodeURIComponent(identity)+'?revision='+encodeURIComponent(revision),jointDetailController.signal);if(request!==jointDetailRequest)return;if(!jointDetailValid(data,identity,revision))throw new Error('联合案件身份或观察版本不匹配。');renderJointDetail(data);text('joint-detail-status','');}
 catch(error){if(request===jointDetailRequest&&error.name!=='AbortError')text('joint-detail-status',error.message+' 请关闭后重新打开。');}
}
function clearJointDetail(){++jointDetailRequest;++jointTimelineRequest;if(jointDetailController)jointDetailController.abort();if(jointTimelineController)jointTimelineController.abort();jointDetail=null;jointTimelineLoading=false;jointTimelineLoaded=false;jointTimelineAvailable=false;jointTimelinePager();if(jointReturnFocus?.isConnected&&typeof jointReturnFocus.focus==='function')jointReturnFocus.focus();}
function closeJointDetail(){const dialog=$('joint-dialog');if(typeof dialog.close==='function')dialog.close();else{dialog.removeAttribute('open');clearJointDetail();}}
function setJointTab(name){const names=['overview','timeline','sources'];if(!names.includes(name))return;for(const key of names){$('joint-pane-'+key).hidden=key!==name;$('joint-tab-'+key).setAttribute('aria-selected',String(key===name));$('joint-tab-'+key).tabIndex=key===name?0:-1;}if(name==='timeline'&&!jointTimelineLoaded&&!jointTimelineLoading&&jointDetail)return loadJointTimeline();}
function initializeJoint(){
 setJointTab('overview');jointScope();
 $('joint-search').addEventListener('submit',event=>{event.preventDefault();return submitJointSearch();});
 $('joint-clear').addEventListener('click',()=>{for(const id of ['joint-ip','joint-asset','joint-state','joint-start','joint-end'])$(id).value='';jointResetQuery({});return loadJoint(1);});
 $('joint-refresh').addEventListener('click',()=>loadJoint());$('joint-latest').addEventListener('click',()=>{jointResetQuery({...jointFilters});return loadJoint(1);});
 $('joint-prev').addEventListener('click',()=>loadJoint(jointPage-1));$('joint-next').addEventListener('click',()=>loadJoint(jointPage+1));
 $('joint-close').addEventListener('click',closeJointDetail);$('joint-dialog').addEventListener('close',clearJointDetail);
 $('joint-revision-prev').addEventListener('click',()=>{if(jointDetail)return showJointCase(jointDetail.case_id,jointDetail.revision-1);});$('joint-revision-next').addEventListener('click',()=>{if(jointDetail)return showJointCase(jointDetail.case_id,jointDetail.revision+1);});$('joint-current').addEventListener('click',()=>{if(jointDetail)return showJointCase(jointDetail.case_id,jointDetail.current.revision);});
 $('joint-timeline-prev').addEventListener('click',()=>loadJointTimeline(jointTimelinePage-1));$('joint-timeline-next').addEventListener('click',()=>loadJointTimeline(jointTimelinePage+1));$('joint-timeline-retry').addEventListener('click',()=>loadJointTimeline(jointTimelinePage));
 const tabs=['overview','timeline','sources'];for(const name of tabs){$('joint-tab-'+name).addEventListener('click',()=>setJointTab(name));$('joint-tab-'+name).addEventListener('keydown',event=>{const i=tabs.indexOf(name);let next=null;if(event.key==='ArrowRight')next=(i+1)%tabs.length;else if(event.key==='ArrowLeft')next=(i+tabs.length-1)%tabs.length;else if(event.key==='Home')next=0;else if(event.key==='End')next=tabs.length-1;if(next!==null){event.preventDefault();setJointTab(tabs[next]);$('joint-tab-'+tabs[next]).focus();}});}
}
"""
