"""Pinned joint observations, local previews and explicit local advisory review."""

SECTION = """<section id="joint-section" aria-busy="false"><h2>联合案件</h2>
<p id="joint-boundary">按明确资产映射，查看同一来源 IP 在相邻时间内的 SSH 与 TCP 证据。关联不代表同一攻击者或入侵成功；只覆盖已登记案件与保留的告警证据，没有匹配不代表安全。</p>
<p id="joint-health" role="status" aria-live="polite">切换到此页后读取已生成的联合观察。</p>
<p id="joint-update-note">后台持续更新默认关闭，未启用时由操作员人工更新。这里的刷新只读取已有结果，不会启动检测、AI 或封禁。“刷新当前页”保留分页快照；“读取最新观察”重新查询并回到第一页。</p>
<p id="joint-refresh-health" role="status" aria-live="polite">更新状态尚未读取。</p>
<form id="joint-search" class="search-fields"><label>完整来源 IP<input id="joint-ip" type="text" maxlength="64" placeholder="IPv4 / IPv6，不支持 CIDR" autocomplete="off"></label><label>资产<select id="joint-asset"><option value="">全部已登记资产</option></select></label><label>关联状态<select id="joint-state"><option value="">全部状态</option><option value="linked">发现关联证据</option><option value="unmatched">未找到匹配证据</option><option value="partial">观察不完整</option><option value="stale">原网络案件待核验</option><option value="retracted">原网络模式已撤回</option></select></label><label>窗口起点（本地）<input id="joint-start" type="datetime-local" step="1"></label><label>窗口终点（本地）<input id="joint-end" type="datetime-local" step="1"></label><div class="actions"><button type="submit">查询案件</button><button id="joint-clear" type="button">清空条件</button></div></form>
<p id="joint-query-scope" class="muted"></p><div class="actions"><button id="joint-refresh" type="button">刷新当前页</button><button id="joint-latest" type="button">读取最新观察</button><span id="joint-new" role="status"></span></div>
<div class="table-wrap"><table aria-describedby="joint-boundary"><thead><tr><th>关联时间窗</th><th>资产</th><th>来源 IP</th><th>SSH / 网络证据</th><th>关联 / 保存范围</th><th>详情</th></tr></thead><tbody id="joint-rows"></tbody></table></div>
<div class="pager"><button id="joint-prev" type="button" disabled>上一页</button><span id="joint-page"></span><button id="joint-next" type="button" disabled>下一页</button></div><p id="joint-status" class="list-status" role="status" aria-live="polite"></p></section>"""

DIALOG = """<dialog id="joint-dialog" aria-labelledby="joint-detail-title"><div class="joint-detail-body"><div class="drawer-heading"><h2 id="joint-detail-title">联合案件详情</h2><button id="joint-close" type="button" aria-label="关闭联合案件详情">关闭 ✕</button></div>
<p id="joint-detail-status" role="status" aria-live="polite"></p><div class="actions"><button id="joint-revision-prev" type="button" disabled>上一版本</button><span id="joint-revision"></span><button id="joint-revision-next" type="button" disabled>下一版本</button><button id="joint-current" type="button" disabled>读取当前版本</button></div>
<div class="detail-tabs" role="tablist" aria-label="联合案件详情内容"><button id="joint-tab-overview" type="button" role="tab" aria-controls="joint-pane-overview" aria-selected="true">关联理由</button><button id="joint-tab-timeline" type="button" role="tab" aria-controls="joint-pane-timeline" aria-selected="false" tabindex="-1">时间线</button><button id="joint-tab-sources" type="button" role="tab" aria-controls="joint-pane-sources" aria-selected="false" tabindex="-1">来源与版本</button><button id="joint-tab-ai" type="button" role="tab" aria-controls="joint-pane-ai" aria-selected="false" tabindex="-1">AI摘要</button></div>
<div id="joint-pane-overview" class="joint-detail-scroll" role="tabpanel" aria-labelledby="joint-tab-overview"><dl id="joint-fields" class="detail-fields"></dl><h3>该版本的关联理由与限制</h3><p id="joint-reasons"></p><p id="joint-uncertainties"></p><h3>当前刷新状态</h3><p id="joint-freshness"></p><p>当前状态可能晚于所选历史版本；来源刷新失败不会删除此前保存的观察。</p></div>
<div id="joint-pane-timeline" class="joint-detail-scroll" role="tabpanel" aria-labelledby="joint-tab-timeline" hidden><p id="joint-timeline-boundary">只显示此版本实际保存的规范化时间线；截断后未保存的记录不会从当前日志补入。日志时间来自来源主机，不代表跨库原子快照。</p><div class="table-wrap"><table><thead><tr><th>证据时间</th><th>类型 / 来源</th><th>观察</th><th>原案件引用</th></tr></thead><tbody id="joint-timeline"></tbody></table></div><div class="pager"><button id="joint-timeline-prev" type="button" disabled>上一页</button><span id="joint-timeline-page"></span><button id="joint-timeline-next" type="button" disabled>下一页</button><button id="joint-timeline-retry" type="button" disabled>重试时间线</button></div><p id="joint-timeline-status" role="status" aria-live="polite"></p></div>
<div id="joint-pane-sources" class="joint-detail-scroll" role="tabpanel" aria-labelledby="joint-tab-sources" hidden><dl id="joint-provenance" class="detail-fields"></dl><div id="joint-source-actions" class="actions"></div><p>网络入口读取此观察引用的网络版本。SSH 查询读取当前保留记录、最近 24 小时和全部来源，可能与历史联合观察不同；SSH 来源没有可还原的持久版本。可在搜索页调整时间范围。</p><p>时间线中的原案件与 canonical 引用仅代表保存时的证据归属；当前 SSH 案件之后可能合并。关联范围受明确映射、来源覆盖与保留策略限制。</p></div>
<div id="joint-pane-ai" class="joint-detail-scroll" role="tabpanel" aria-labelledby="joint-tab-ai" hidden aria-busy="false"><p id="joint-ai-boundary">本地预览，未调用模型。仅使用所选版本保存的证据，结果只代表捕获时刻；不会提交在线分析或执行处置。</p><div class="actions"><button id="joint-ai-preview" type="button" disabled>生成本地预览</button><button id="joint-ai-submit" type="button" disabled hidden>提交本地演练</button><button id="joint-ai-history-load" type="button" disabled>查看研判历史</button></div><p id="joint-ai-review-status" role="status" aria-live="polite"></p><p id="joint-ai-status" role="status" aria-live="polite"></p><div id="joint-ai-result" hidden><p id="joint-ai-state"></p><p id="joint-ai-counts"></p><p id="joint-ai-completeness"></p><details id="joint-ai-scope"><summary>摘要范围与限制</summary><dl id="joint-ai-fields" class="detail-fields"></dl><ul id="joint-ai-limitations"></ul></details><p class="muted">下表为脱敏摘要中的证据；展开的原始引用仅供本地核对，不属于候选发送内容。</p><div class="table-wrap"><table aria-describedby="joint-ai-boundary"><thead><tr><th>证据别名 / 相对时间</th><th>类型 / 来源别名</th><th>脱敏观察</th><th>仅本地引用</th></tr></thead><tbody id="joint-ai-rows"></tbody></table></div><div class="pager"><button id="joint-ai-prev" type="button" disabled>上一页</button><span id="joint-ai-page"></span><button id="joint-ai-next" type="button" disabled>下一页</button></div></div><div id="joint-ai-history" hidden><h3>本地研判历史</h3><p>这里只显示最近最多 20 条记录。点击记录读取其保存版本；历史演练或录制回放不能作为当前模型结论。</p><div class="table-wrap"><table><thead><tr><th>保存时间</th><th>观察版本 / 新鲜度</th><th>方式 / 任务状态 / 建议</th><th>详情</th></tr></thead><tbody id="joint-ai-history-rows"></tbody></table></div><div class="pager"><button id="joint-ai-history-prev" type="button" disabled>上一页</button><span id="joint-ai-history-page"></span><button id="joint-ai-history-next" type="button" disabled>下一页</button></div></div><div id="joint-ai-job" hidden><h3 id="joint-ai-job-title">本地演练记录</h3><p id="joint-ai-job-boundary">未调用模型，未执行封禁。此记录用于核对提交、保存和引用流程，演练建议不是真实模型判断。</p><div class="actions"><button id="joint-ai-job-refresh" type="button" disabled>刷新任务状态</button></div><p id="joint-ai-job-state" role="status"></p><dl id="joint-ai-job-fields" class="detail-fields"></dl><div id="joint-ai-job-result" hidden><p id="joint-ai-job-verdict"></p><details><summary id="joint-ai-job-explanation">演练说明与校验</summary><p id="joint-ai-job-rationale"></p><ul id="joint-ai-job-checks"></ul></details><div class="table-wrap"><table><thead><tr><th>通过校验的证据引用</th><th>类型 / 脱敏观察</th><th>仅本地引用</th></tr></thead><tbody id="joint-ai-job-refs"></tbody></table></div><div class="pager"><button id="joint-ai-job-prev" type="button" disabled>上一页</button><span id="joint-ai-job-page"></span><button id="joint-ai-job-next" type="button" disabled>下一页</button></div></div></div></div>
</div></dialog>"""

STYLE = """
#joint-health,#joint-refresh-health,#joint-query-scope,#joint-reasons,#joint-uncertainties,#joint-freshness{white-space:pre-line;overflow-wrap:anywhere}#joint-section>.table-wrap table{min-width:790px}#joint-search{grid-template-columns:repeat(3,minmax(0,1fr))}#joint-search label{display:flex;flex-direction:column;gap:6px;min-width:0}#joint-search input,#joint-search select{min-width:0;max-width:100%}#joint-new{color:#dec080;font-size:13px}#joint-dialog{position:fixed;inset:0 0 0 auto;margin:0;width:min(930px,100vw);max-width:100vw;height:100dvh;max-height:100dvh;border:0;border-left:1px solid #385475;background:#101d2e;color:#e7edf5;padding:22px}#joint-dialog::backdrop{background:#030b17a6}.joint-detail-body{height:100%;display:flex;flex-direction:column;gap:12px;min-width:0}.joint-detail-scroll{min-height:0;overflow:auto;flex:1}#joint-dialog .actions{margin:0;flex-shrink:0}#joint-dialog .detail-tabs{margin:0;padding:0 0 10px;flex-shrink:0}#joint-pane-timeline{display:flex;flex-direction:column;overflow:hidden}.joint-detail-scroll .table-wrap{overflow:auto;min-height:0;flex:1}.joint-detail-scroll table{min-width:720px}.joint-detail-scroll .pager{flex-shrink:0;flex-wrap:wrap}.joint-detail-scroll p{font-size:13px}.joint-detail-scroll dd{overflow-wrap:anywhere}#joint-detail-status:empty,#joint-timeline-status:empty,#joint-ai-status:empty,#joint-ai-review-status:empty{display:none}#joint-detail-status,#joint-timeline-status,#joint-ai-status,#joint-ai-review-status{font-size:13px;margin:0}
#joint-pane-ai[hidden]{display:none}#joint-ai-result p,#joint-ai-result li,#joint-ai-result td{overflow-wrap:anywhere}#joint-ai-result .table-wrap{max-height:420px;overflow:auto}#joint-ai-result .pager{position:static}#joint-ai-result td{white-space:pre-line}#joint-ai-scope{margin:12px 0}#joint-ai-scope summary,#joint-ai-rows summary{cursor:pointer}#joint-ai-scope ul{padding-left:22px}#joint-ai-state,#joint-ai-counts,#joint-ai-completeness{white-space:pre-line}
#joint-ai-history .pager,#joint-ai-job .pager{position:static}#joint-ai-history .table-wrap,#joint-ai-job .table-wrap{max-height:360px;overflow:auto}#joint-ai-job td,#joint-ai-history td,#joint-ai-job-state{white-space:pre-line;overflow-wrap:anywhere}#joint-ai-job-rationale{max-height:180px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere}#joint-ai-job-checks{padding-left:22px}#joint-ai-history,#joint-ai-job{margin-top:14px}
@media(max-width:850px){#joint-dialog{padding:16px}#joint-dialog .drawer-heading h2{font-size:17px}#joint-dialog .actions,#joint-dialog .pager{gap:6px;font-size:12px}#joint-dialog button{font-size:12px;padding:7px 9px}#joint-search{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:480px){#joint-search{grid-template-columns:1fr}#joint-dialog .detail-tabs{gap:4px}}
"""

SCRIPT = r"""
let jointStatusTimer=null,jointStatusRequest=0,jointStatusController=null,jointStatusLoading=false;
let jointPage=1,jointPages=1,jointSnapshot=null,jointPinnedGeneration=null,jointFilters={},jointRequest=0,jointController=null,jointLoading=false,jointAvailable=false;
let jointDetail=null,jointDetailRequest=0,jointDetailController=null,jointReturnFocus=null,jointTimelineRequest=0,jointTimelineController=null;
let jointTimelinePage=1,jointTimelinePages=1,jointTimelineLoaded=false,jointTimelineLoading=false,jointTimelineAvailable=false;
let jointPreview=null,jointPreviewPage=1,jointPreviewRequest=0,jointPreviewController=null,jointPreviewLoading=false,jointActiveTab='overview';
let jointReviewEpoch=0,jointSubmitLoading=false,jointSubmitController=null,jointSubmittedPreviewKey=null;
let jointHistory=null,jointHistoryPage=1,jointHistoryRequest=0,jointHistoryController=null,jointHistoryLoading=false;
let jointReviewJob=null,jointReviewJobPage=1,jointJobRequest=0,jointJobController=null,jointJobLoading=false;
const jointStates={linked:'发现关联证据',unmatched:'未找到匹配证据',partial:'观察不完整',stale:'原网络案件待核验',retracted:'原网络模式已撤回'};
const jointRefreshStates={fresh:'最近一次刷新成功',pending:'等待刷新',current:'最近一次刷新成功',available:'最近一次刷新成功',unavailable:'最近刷新失败，保留历史',needs_review:'需要重新核验',not_eligible:'不符合关联范围'};
const jointCodes={shared_ip_does_not_establish_identity:'相同来源 IP 不能确认是同一使用者',cross_source_clock_alignment_unknown:'不同来源的时钟对齐情况未知',single_network_observation_clock_unverifiable:'单条网络观察无法核验时钟连续性',ssh_authentication_failure_observed:'观察到 SSH 认证失败',ssh_authentication_success_observed:'观察到 SSH 认证成功，但不证明入侵',ssh_preauth_abort_observed:'观察到 SSH 认证前断开',no_matching_retained_ssh_evidence:'本次未找到匹配的保留 SSH 告警证据',ssh_association_not_evaluated:'本次未评估 SSH 时间关联',network_evidence_unavailable:'没有可用于关联的网络证据',explicit_asset_mapping:'已按明确资产映射核对来源',network_anchor_retained:'引用已保留的网络证据',same_observed_peer:'观察到相同来源 IP',mapped_ssh_evidence_in_window:'映射的 SSH 来源在关联时间窗内有实际证据',no_mapped_ssh_evidence_in_window:'本次未找到时间窗内的匹配 SSH 证据',timeline_truncated:'时间线已截断，只保存部分记录',temporal_association_unavailable:'无法可靠使用时间建立关联',network_clock_discontinuity:'网络来源时钟异常',ssh_clock_discontinuity:'SSH 来源时钟异常',network_anchor_time_span_exceeded:'网络证据时间跨度超限',network_anchor_retracted:'原网络探测模式已撤回',network_anchor_stale:'原网络案件待重新核验',network_evidence_incomplete:'提供的网络证据不完整',ssh_candidate_evidence_incomplete:'提供的 SSH 候选证据不完整',shared_ip_not_actor_identity:'共享 IP 不能确认人员身份',coverage_unknown:'来源覆盖未知',source_unavailable:'来源不可用',source_busy:'来源暂忙',source_schema_unavailable:'来源结构不兼容',network_revision_missing:'缺少所需网络版本',adapter_limit_exceeded:'来源读取达到上限',query_deadline_exceeded:'来源读取超时',joint_capacity_exceeded:'派生存储达到容量上限'};
function jointLabel(code){if(typeof code!=='string')return '更新遇到未识别的限制';const label=key=>Object.hasOwn(jointCodes,key)?jointCodes[key]:Object.hasOwn(networkCoverage,key)?networkCoverage[key]:'更新遇到未识别的限制';const parts=code.split(':');return parts.length===2&&['network','ssh'].includes(parts[0])?`${parts[0]==='ssh'?'SSH':'网络'}：${label(parts[1])}`:label(code);}
const jointEventTypes={auth_failure:'认证失败',ssh_failure:'认证失败',invalid_user:'无效账号',auth_success:'认证成功（不证明入侵）',ssh_success:'认证成功（不证明入侵）',preauth_abort:'认证前断开',probe:'协议探测',disconnect:'断开连接',session_open:'会话打开',session_close:'会话关闭',daemon:'服务状态',other:'其他'};
function jointNumber(value){return Number.isSafeInteger(value)&&value>=0;}
function jointDate(value){return Number.isSafeInteger(value)?when(value/1000):'不可用';}
function jointWindow(start,end,available=true){return available&&Number.isSafeInteger(start)&&Number.isSafeInteger(end)?`${jointDate(start)} — ${jointDate(end)}`:'时间关联不可用';}
function jointFields(id,values){const node=$(id);node.replaceChildren();for(const [label,value] of values){const term=document.createElement('dt'),detail=document.createElement('dd');term.textContent=label;detail.textContent=String(value??'—');node.append(term,detail);}}
async function jointGet(path,signal){
 const result=await fetch(path,{credentials:'same-origin',cache:'no-store',signal});
 if(!result.ok){const messages={401:'登录已失效，请刷新页面重新登录。',404:'联合案件或指定版本不可用。',409:'此查询快照已失效，请点击“读取最新观察”重新查询。',422:'查询条件无效，请核对完整 IP、资产、状态及时间范围。',503:'联合案件暂不可用，请稍后重试；此前保存的证据不会因此被判为安全。'};throw jointPreviewError(messages[result.status]||'联合案件读取失败，请检查服务状态。');}
 return result.json();
}
function jointPageValid(data,page,totalKey='total'){return data&&Array.isArray(data.items)&&jointNumber(data[totalKey])&&Number.isSafeInteger(data.page)&&data.page>=1&&Number.isSafeInteger(data.total_pages)&&data.total_pages>=1&&data.page===Math.min(page,data.total_pages);}
function jointItemValid(item){return item&&typeof item.case_id==='string'&&/^JOINT-[a-f0-9]{32}$/.test(item.case_id)&&Number.isSafeInteger(item.revision)&&item.revision>=1&&jointNumber(item.publish_generation)&&typeof item.asset_id==='string'&&typeof item.peer_ip==='string'&&Object.hasOwn(jointStates,item.association_state)&&jointNumber(item.network_count)&&jointNumber(item.ssh_count)&&jointNumber(item.saved_count)&&jointNumber(item.observed_count)&&item.saved_count<=item.observed_count&&typeof item.timeline_complete==='boolean'&&typeof item.temporal_available==='boolean'&&(!item.temporal_available||(Number.isSafeInteger(item.window_start_us)&&Number.isSafeInteger(item.window_end_us)&&item.window_start_us<=item.window_end_us));}
function jointPager(){
 $('joint-prev').disabled=jointLoading||!jointAvailable||jointPage<=1;$('joint-next').disabled=jointLoading||!jointAvailable||jointPage>=jointPages;
 $('joint-section').setAttribute('aria-busy',String(jointLoading));
}
function jointRefreshTime(value,empty='尚无记录'){
 if(value===null||value===undefined)return empty;
 if(typeof value!=='string'||value.length>64||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/.test(value))return '时间不可用';
 const date=new Date(value);return Number.isFinite(date.valueOf())?date.toLocaleString('zh-CN',{hour12:false}):'时间不可用';
}
function jointAge(value){if(!jointNumber(value))return '未知';if(value<60)return `${value} 秒`;if(value<3600)return `${Math.floor(value/60)} 分 ${value%60} 秒`;return `${Math.floor(value/3600)} 小时 ${Math.floor(value%3600/60)} 分`;}
function jointRefreshHealth(data){
 const node=$('joint-refresh-health'),refresh=data.refresh;
 node.className='';
 if(!data.enabled){node.textContent='联合案件尚未启用；这里不会启动后台更新。';return;}
 if(!refresh||typeof refresh.enabled!=='boolean'){node.textContent='持续更新状态未提供；不能确认自动更新已启用，请沿用人工更新。已有观察仍可查看。';return;}
 if(!refresh.enabled){node.textContent='持续更新未启用：当前使用人工更新。这里的按钮只读取已保存的观察，不会启动更新任务。';return;}
 const states={not_started:'后台持续更新已启用，尚未开始',running:'后台正在更新联合观察',waiting:['discover','refresh'].includes(refresh.phase)?'后台等待继续本轮更新':'后台等待下一轮更新',backoff:'最近更新失败，等待重试',blocked:'后台更新受阻，需要操作员处理',unavailable:'无法确认后台更新状态'};
 const notes=[Object.hasOwn(states,refresh.state)?states[refresh.state]:'后台更新状态未知'];
 if(['running','waiting'].includes(refresh.state)){const phases={discover:'正在检查网络案件',refresh:'正在刷新已登记案件'};if(Object.hasOwn(phases,refresh.phase))notes.push(phases[refresh.phase]);}
 if(refresh.stalled===true)notes.push('更新进度停滞，已有观察仍保留，暂不能视为最新结果。');
 if(refresh.stale===true)notes.push('更新已延迟，以下观察可能已过时；不影响查阅已有历史。');
 if(refresh.stale===true||refresh.stalled===true||['backoff','blocked','unavailable'].includes(refresh.state))node.className='error';
 notes.push(`最近尝试：${jointRefreshTime(refresh.last_attempt_at)}（本地时间）`);
 notes.push(`最近完整成功：${jointRefreshTime(refresh.last_success_at,'尚无完整成功记录')}（本地时间）`);
 if(refresh.last_complete_at!==null&&refresh.last_complete_at!==undefined&&refresh.last_complete_at!==refresh.last_success_at)notes.push(`最近一轮结束：${jointRefreshTime(refresh.last_complete_at)}；结束不代表全部刷新成功。`);
 notes.push(`距上次完整成功：${jointAge(refresh.age_seconds)} · 待处理：${jointNumber(refresh.pending)?refresh.pending:'未知'} · 失败：${jointNumber(refresh.failed)?refresh.failed:'未知'}`);
 if(refresh.next_attempt_at!==null&&refresh.next_attempt_at!==undefined)notes.push(`下次尝试：${jointRefreshTime(refresh.next_attempt_at)}（本地时间）`);
 if(jointNumber(refresh.interval_seconds)&&refresh.interval_seconds>0)notes.push(`更新间隔约 ${jointAge(refresh.interval_seconds)}${jointNumber(refresh.stale_after_seconds)&&refresh.stale_after_seconds>0?` · 超过 ${jointAge(refresh.stale_after_seconds)} 未完整成功会提示延迟`:''}。`);
 if(refresh.error)notes.push('更新限制：'+jointLabel(refresh.error));
 notes.push('页面每 15 秒只读取更新状态；有新观察时会提示，当前案件和分页不会自动替换。');
 node.textContent=notes.join('\n');
}
function cancelJointStatusPoll(){++jointStatusRequest;if(jointStatusController)jointStatusController.abort();jointStatusController=null;jointStatusLoading=false;}
async function pollJointStatus(){
 if(document.hidden||workspaceView!=='joint'||jointLoading||jointStatusLoading)return;
 const request=++jointStatusRequest,listRequest=jointRequest,controller=new AbortController();jointStatusController=controller;jointStatusLoading=true;
 const timeout=setTimeout(()=>controller.abort(),10000);
 try{
  const status=await jointGet('/api/joint/status',controller.signal);
  if(request!==jointStatusRequest||listRequest!==jointRequest||workspaceView!=='joint'||document.hidden)return;
  if(controller.signal.aborted)throw new Error('更新状态读取超时。');
  jointHealth(status);
 }catch(error){if(request===jointStatusRequest&&listRequest===jointRequest&&workspaceView==='joint'&&!document.hidden){$('joint-refresh-health').className='error';text('joint-refresh-health','更新状态暂无法确认，已保留当前案件与分页。稍后自动重试；可点击“刷新当前页”重新读取。');}}
 finally{clearTimeout(timeout);if(request===jointStatusRequest){jointStatusLoading=false;jointStatusController=null;}}
}
function scheduleJointStatus(){if(jointStatusTimer!==null)clearTimeout(jointStatusTimer);jointStatusTimer=setTimeout(async()=>{jointStatusTimer=null;try{await pollJointStatus();}finally{scheduleJointStatus();}},15000);}
function jointHealth(data){
 if(typeof data?.enabled!=='boolean')throw new Error('联合案件状态返回异常。');
 jointRefreshHealth(data);
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
  const select=$('joint-asset'),selected=select.value;
  const assets=data.assets.map(asset=>{if(typeof asset?.asset_id!=='string')throw new Error('联合案件资产返回异常。');return asset.asset_id;});
  const missing=selected&&!assets.includes(selected)?selected:null,signature=JSON.stringify([assets,missing]);
  if(select.dataset.jointOptions!==signature){
   select.replaceChildren();for(const id of ['',...assets]){const option=document.createElement('option');option.value=id;option.textContent=id||'全部已登记资产';select.append(option);}
   if(missing){const option=document.createElement('option');option.value=missing;option.textContent=missing+'（不在当前登记中）';select.append(option);}
   select.value=selected;select.dataset.jointOptions=signature;
  }
 }
 if(jointPinnedGeneration!==null&&jointNumber(data.generation)&&data.generation>jointPinnedGeneration)text('joint-new','有新观察，点击“读取最新观察”查看；当前分页保持不变。');
}
function jointScope(){text('joint-query-scope',`当前查询：${jointFilters.ip||'全部来源 IP'} · ${jointFilters.asset_id||'全部已登记资产'} · ${jointStates[jointFilters.state]||'全部关联状态'}\n${jointFilters.start?when(jointFilters.start):'未限定起点'} — ${jointFilters.end?when(jointFilters.end):'未限定终点'}；按关联时间窗重叠筛选，时间异常的案件不匹配时间条件。`);}
function jointClearRows(message){$('joint-rows').replaceChildren();empty($('joint-rows'),6,message);jointAvailable=false;text('joint-page','');jointPager();}
async function loadJoint(page=jointPage){
 cancelJointStatusPoll();
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
 finally{if(request===jointRequest){jointLoading=false;jointPager();scheduleJointStatus();}}
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

const jointPreviewStates={current:'捕获时版本可核验；不保证此刻仍为最新',historical:'历史观察，只供回看，不代表当前可用',stale:'观察已过期或原网络模式已变化，需要重新核验',unavailable:'来源状态不可用，不能据此形成当前判断',revalidation_required:'恢复后尚待重新核验，不能作为当前证据',unknown:'无法确认新鲜度，不能作为当前证据'};
const jointPreviewLimits={source_coverage_unknown:'来源覆盖未知，没有匹配证据不代表安全',cross_store_not_atomic:'网络与 SSH 分别读取，不是跨库原子快照',shared_ip_not_identity:'共享来源 IP 不能确认是同一使用者',clock_alignment_unknown:'不同来源的时钟对齐情况未知',retained_incidents_only:'只包含保留告警中的证据，不是全部原始日志',observed_counts_lower_bounds:'观察数量只是已知下界，不代表全部活动',projection_input_incomplete:'输入证据不完整',timeline_truncated:'保存的时间线已截断，未保存部分不会补入',summary_truncated:'摘要已达到条数上限，只包含部分已保存证据',network_coverage_limited:'网络来源覆盖受限',ssh_coverage_limited:'SSH 来源覆盖受限',temporal_association_unavailable:'不能可靠地建立时间关联',network_anchor_span_exceeded:'网络证据时间跨度超过允许范围',network_clock_unverifiable:'网络来源时钟连续性无法核验',network_evidence_unavailable:'缺少网络证据'};
function jointPreviewPager(){const pages=Math.max(1,Math.ceil((jointPreview?.case.evidence.length||0)/10));$('joint-ai-prev').disabled=!jointPreview||jointPreviewLoading||jointPreviewPage<=1;$('joint-ai-next').disabled=!jointPreview||jointPreviewLoading||jointPreviewPage>=pages;$('joint-ai-preview').disabled=!jointDetail||jointPreviewLoading;$('joint-pane-ai').setAttribute('aria-busy',String(jointPreviewLoading));jointReviewButtons();}
function clearJointPreview(){clearJointReview();++jointPreviewRequest;if(jointPreviewController)jointPreviewController.abort();jointPreviewController=null;jointPreview=null;jointPreviewPage=1;jointPreviewLoading=false;$('joint-ai-result').hidden=true;$('joint-ai-scope').open=false;for(const id of ['joint-ai-rows','joint-ai-fields','joint-ai-limitations'])$(id).replaceChildren();for(const id of ['joint-ai-state','joint-ai-counts','joint-ai-completeness','joint-ai-page','joint-ai-status'])text(id,'');jointPreviewPager();}
function jointPreviewAlias(value,prefix){return typeof value==='string'&&new RegExp('^'+prefix+'-[a-f0-9]{24}$').test(value);}
function jointPreviewValid(data,identity,revision){
 const c=data?.case,m=data?.meta,s=m?.snapshot_context,p=data?.preview,refs=data?.local_refs;
 if(data?.dossier_version!=='joint-local-envelope-v1'||c?.dossier_version!=='joint-v1'||c.kind!=='network_ssh'||m?.case_id!==identity||m.case_revision!==revision||!Number.isSafeInteger(m.current_revision)||m.current_revision<revision||s?.case_id!==identity||s.case_revision!==revision||s.current_revision!==m.current_revision||p?.version!=='joint-preview-v1'||p.mode!=='local'||p.external_calls!==false||typeof p.captured_at!=='string'||!Number.isFinite(Date.parse(p.captured_at)))return false;
 if(!Object.hasOwn(jointPreviewStates,c.review_state)||!Object.hasOwn(jointStates,c.association_state)||!jointPreviewAlias(c.case_id,'J')||!jointPreviewAlias(c.revision,'R')||!jointPreviewAlias(c.asset,'A')||!jointPreviewAlias(c.peer,'P'))return false;
 if(typeof s.revalidation_pending!=='boolean'||typeof s.refresh_error!=='boolean'||!['current','stale','unknown'].includes(s.freshness))return false;
 const review=s.revalidation_pending?'revalidation_required':revision!==m.current_revision?'historical':['stale','retracted'].includes(c.association_state)||s.freshness==='stale'?'stale':s.refresh_state!=='fresh'||s.refresh_error?'unavailable':s.freshness==='current'?'current':'unknown';if(c.review_state!==review)return false;
 if(!['input_complete','timeline_complete','summary_complete','temporal_association_available'].every(key=>typeof c[key]==='boolean')||c.coverage_complete!==null||!Array.isArray(c.limitations)||!c.limitations.every(x=>typeof x==='string')||!Array.isArray(c.evidence)||c.evidence.length>40||!refs||typeof refs!=='object'||Array.isArray(refs))return false;
 if(c.temporal_association_available?!jointNumber(c.window_duration_us):c.window_duration_us!==null)return false;
 const ids=new Set();for(const row of c.evidence){
  if(!row||!['network_tcp','ssh'].includes(row.kind)||!jointPreviewAlias(row.event_id,'E')||ids.has(row.event_id)||!jointPreviewAlias(row.source,'S')||row.asset!==c.asset||row.peer!==c.peer||!jointNumber(row.offset_us))return false;ids.add(row.event_id);
  if(row.kind==='network_tcp'?!jointPreviewAlias(row.destination,'D')||!Number.isSafeInteger(row.dst_port)||row.dst_port<1||row.dst_port>65535||row.protocol!=='TCP'||row.direction!=='local_input':!Object.hasOwn(jointEventTypes,row.event_type)||(row.account!==null&&!jointPreviewAlias(row.account,'U')))return false;
  const ref=refs[row.event_id];if(!ref||ref.kind!==(row.kind==='ssh'?'ssh':'network')||typeof ref.source_id!=='string'||typeof ref.event_id!=='string'||!Array.isArray(ref.incident_refs)||!ref.incident_refs.length||!ref.incident_refs.every(item=>typeof item?.incident_id==='string'&&(ref.kind==='network'?Number.isSafeInteger(item.revision)&&item.revision>=1:typeof item.canonical_incident_id==='string')))return false;
 }
 if(Object.keys(refs).length!==ids.size||!Object.keys(refs).every(id=>ids.has(id)))return false;
 for(const key of ['network','ssh']){const count=c.counts?.[key];if(!count||!['observed','retained','included'].every(name=>jointNumber(count[name]))||count.included>count.retained||count.retained>count.observed||count.included!==c.evidence.filter(row=>row.kind===(key==='network'?'network_tcp':'ssh')).length)return false;}
 return c.summary_complete===['network','ssh'].every(key=>c.counts[key].included===c.counts[key].retained)&&c.timeline_complete===['network','ssh'].every(key=>c.counts[key].retained===c.counts[key].observed);
}
function renderJointPreviewPage(page=1){
 if(!jointPreview)return;const c=jointPreview.case,pages=Math.max(1,Math.ceil(c.evidence.length/10));jointPreviewPage=Math.max(1,Math.min(page,pages));const rows=[];
 for(const item of c.evidence.slice((jointPreviewPage-1)*10,jointPreviewPage*10)){
  const tr=document.createElement('tr');cell(tr,`${item.event_id}\n+${item.offset_us/1000000} 秒`);cell(tr,`${item.kind==='ssh'?'SSH':'网络 TCP'}\n${item.source}`);cell(tr,item.kind==='ssh'?`${jointEventTypes[item.event_type]}\n账号：${item.account??'未提供'}`:`${item.peer} → ${item.destination}:${item.dst_port}\nTCP · 本机入站`);
  const ref=jointPreview.local_refs[item.event_id],detail=document.createElement('details'),label=document.createElement('summary'),value=document.createElement('p');label.textContent='查看本地引用';value.textContent=`来源：${ref.source_id}\n事件：${ref.event_id}\n${jointRefs(ref)}`;detail.append(label,value);cell(tr,'').append(detail);rows.push(tr);
 }
 $('joint-ai-rows').replaceChildren(...rows);if(!rows.length)empty($('joint-ai-rows'),4,'摘要没有可展示的证据，不能据此判断安全。');text('joint-ai-page',`第 ${jointPreviewPage} / ${pages} 页 · 摘要证据 ${c.evidence.length} 条`);jointPreviewPager();
}
function renderJointPreview(data){
 jointPreview=data;const c=data.case,m=data.meta;const status=$('joint-ai-state');status.className=c.review_state==='current'?'':'error';status.textContent=`${jointPreviewStates[c.review_state]}\n观察版本 ${m.case_revision} / 捕获时当前 ${m.current_revision} · ${jointRefreshTime(data.preview.captured_at)}（本地时间）`;
 text('joint-ai-counts',['network','ssh'].map(key=>{const n=c.counts[key];return `${key==='network'?'网络':'SSH'}：观察 ${n.observed} / 保存 ${n.retained} / 纳入摘要 ${n.included} 条`;}).join('\n'));
 const missing=['network','ssh'].filter(key=>c.counts[key].included===0).map(key=>key==='network'?'网络':'SSH');text('joint-ai-completeness',`${c.input_complete?'所提供输入完整':'输入不完整'} · ${c.timeline_complete?'所提供时间线未截断':'保存时间线已截断'} · ${c.summary_complete?'摘要纳入全部已保存证据':'摘要已截断'}\n来源覆盖始终未知${missing.length?'；缺少 '+missing.join('、')+' 摘要证据':''}。`);
 jointFields('joint-ai-fields',[['案件别名',c.case_id],['摘要版本',c.revision],['资产 / 来源 IP 别名',`${c.asset} / ${c.peer}`],['关联状态',jointStates[c.association_state]],['相对时间基准',c.temporal_association_available?`关联窗口起点，窗口长 ${c.window_duration_us/1000000} 秒`:'最早已保存证据；不用于跨源时间关联'],['采样方式','网络与 SSH 轮流选取前缀，再按时间排序']]);
 const limits=c.limitations.map(code=>{const li=document.createElement('li');li.textContent=Object.hasOwn(jointPreviewLimits,code)?jointPreviewLimits[code]:'存在未识别的证据限制，需要人工核对';return li;});$('joint-ai-limitations').replaceChildren(...limits);$('joint-ai-result').hidden=false;renderJointPreviewPage();
}
function jointPreviewError(message){const error=new Error(message);error.previewMessage=message;return error;}
async function loadJointPreview(){
 if(!jointDetail||jointActiveTab!=='ai')return;clearJointPreview();const identity=jointDetail.case_id,revision=jointDetail.revision,request=jointPreviewRequest,controller=new AbortController();jointPreviewController=controller;jointPreviewLoading=true;jointPreviewPager();text('joint-ai-status','正在从所选版本生成本地脱敏预览…');const timeout=setTimeout(()=>controller.abort(),15000);
 try{
  const result=await fetch('/api/joint/cases/'+encodeURIComponent(identity)+'/ai/preview?'+new URLSearchParams({revision:String(revision)}),{credentials:'same-origin',cache:'no-store',signal:controller.signal});
  if(!result.ok){const body=await result.json().catch(()=>({})),messages={joint_ai_preview_unavailable:'本地预览暂不可用：尚未准备好脱敏配置。',joint_preview_changed:'读取期间案件状态已变化，请重新生成预览。',joint_ai_capacity_exceeded:'摘要超出允许范围，无法生成预览。'};throw jointPreviewError((Object.hasOwn(messages,body?.error||body?.detail)?messages[body.error||body.detail]:null)||({401:'登录已失效，请刷新页面重新登录。',404:'联合案件或所选版本不可用。',409:'观察状态已变化，请重新生成预览。',422:'此版本无法生成预览，请核对证据范围。',503:'本地预览暂不可用，请稍后重试。'}[result.status]||'本地预览读取失败，请重试。'));}
  const data=await result.json();if(request!==jointPreviewRequest||jointDetail?.case_id!==identity||jointDetail?.revision!==revision||jointActiveTab!=='ai')return;if(controller.signal.aborted)throw jointPreviewError('本地预览读取超时，请重试。');
  if(!jointPreviewValid(data,identity,revision))throw jointPreviewError('摘要身份、版本或证据范围不匹配，请重新读取案件。');renderJointPreview(data);text('joint-ai-status','本地预览完成，未调用模型。结果只代表捕获时刻。');
 }catch(error){if(request===jointPreviewRequest){clearJointPreview();text('joint-ai-status',error.name==='AbortError'?'本地预览读取超时，请重试。':error.previewMessage||'本地预览读取失败，请重试。');}}
 finally{clearTimeout(timeout);if(request===jointPreviewRequest){jointPreviewLoading=false;jointPreviewController=null;jointPreviewPager();}}
}


const jointReviewStates={queued:'等待本地演练',running:'本地演练处理中',recoverable:'等待恢复本地记录',review:'演练完成，保留人工复核',complete:'演练完成',stale:'摘要已变化，需要重新预览',failed:'演练失败',uncertain:'任务状态待核实',budget_exhausted:'任务受限，需人工核查'};
const jointReviewVerdicts={escalate:'演练建议：优先人工核查',abstain:'演练建议：保留人工复核'};
const jointReviewConfidence={low:'低',medium:'中',high:'高'};
const jointReviewReasons={invalid_response:'响应格式未通过校验',unknown_evidence:'引用包含摘要中不存在的证据',stale_revision:'引用的摘要版本不匹配',unsupported_claim:'引用证据不支持声明',evidence_not_current:'证据状态不支持当前判断',missing_observed_evidence:'缺少可引用的观察证据',missing_supported_claim:'缺少有证据支持的声明'};
function jointExecutionMode(mode){return mode==='offline'||mode==='recorded';}
function jointExecutionLabel(mode){return mode==='recorded'?'本地录制回放':'本地演练';}
function jointStateLabel(job){return job.execution_mode==='recorded'?jointReviewStates[job.state].replaceAll('演练','录制回放'):jointReviewStates[job.state];}
function jointVerdictLabel(job){return job.execution_mode==='recorded'?jointReviewVerdicts[job.result.verdict].replace('演练建议','录制建议'):jointReviewVerdicts[job.result.verdict];}
function jointCanSubmit(){return !!(jointDetail&&jointActiveTab==='ai'&&jointPreview&&!$('joint-ai-result').hidden&&jointPreview.execution?.enabled===true&&jointExecutionMode(jointPreview.execution.mode)&&jointPreview.execution.external_calls===false&&typeof jointPreview.preview_key==='string'&&/^[a-f0-9]{64}$/.test(jointPreview.preview_key)&&jointSubmittedPreviewKey!==jointPreview.preview_key);}
function jointReviewButtons(){
 const enabled=jointPreview?.execution?.enabled===true&&jointExecutionMode(jointPreview.execution.mode)&&jointPreview.execution.external_calls===false;
 $('joint-ai-submit').textContent=jointPreview?.execution?.mode==='recorded'?'提交本地录制回放':'提交本地演练';
 $('joint-ai-submit').hidden=!enabled;$('joint-ai-submit').disabled=!jointCanSubmit()||jointSubmitLoading||jointPreviewLoading||jointHistoryLoading||jointJobLoading;
 $('joint-ai-preview').disabled=!jointDetail||jointPreviewLoading||jointSubmitLoading;
 $('joint-ai-history-load').disabled=!jointDetail||jointSubmitLoading||jointHistoryLoading;
 $('joint-ai-job-refresh').disabled=!jointReviewJob||jointSubmitLoading||jointJobLoading||jointHistoryLoading;
 const hp=Math.max(1,Math.ceil((jointHistory?.length||0)/5)),rp=Math.max(1,Math.ceil((jointReviewJob?.result?.evidence_ids.length||0)/10));
 $('joint-ai-history-prev').disabled=!jointHistory||jointHistoryLoading||jointHistoryPage<=1;$('joint-ai-history-next').disabled=!jointHistory||jointHistoryLoading||jointHistoryPage>=hp;
 $('joint-ai-job-prev').disabled=!jointReviewJob?.result||jointJobLoading||jointReviewJobPage<=1;$('joint-ai-job-next').disabled=!jointReviewJob?.result||jointJobLoading||jointReviewJobPage>=rp;
}
function clearJointJob(){++jointJobRequest;if(jointJobController)jointJobController.abort();jointJobController=null;jointJobLoading=false;jointReviewJob=null;jointReviewJobPage=1;$('joint-ai-job').hidden=true;$('joint-ai-job-result').hidden=true;for(const id of ['joint-ai-job-fields','joint-ai-job-checks','joint-ai-job-refs'])$(id).replaceChildren();for(const id of ['joint-ai-job-state','joint-ai-job-verdict','joint-ai-job-rationale','joint-ai-job-page'])text(id,'');}
function clearJointReview(){++jointReviewEpoch;++jointHistoryRequest;if(jointSubmitController)jointSubmitController.abort();if(jointHistoryController)jointHistoryController.abort();jointSubmitController=jointHistoryController=null;jointSubmitLoading=jointHistoryLoading=false;jointSubmittedPreviewKey=null;jointHistory=null;jointHistoryPage=1;clearJointJob();$('joint-ai-history').hidden=true;$('joint-ai-history-rows').replaceChildren();text('joint-ai-history-page','');text('joint-ai-review-status','');}
function jointReviewActive(epoch,identity,revision){return epoch===jointReviewEpoch&&jointDetail?.case_id===identity&&jointDetail?.revision===revision&&jointActiveTab==='ai';}
function jointJobIdentity(value){return typeof value==='string'&&/^[a-f0-9]{32}$/.test(value);}
function jointJobLightValid(job,identity){return job&&jointJobIdentity(job.id)&&job.case_id===identity&&Number.isSafeInteger(job.case_revision)&&job.case_revision>=1&&Object.hasOwn(jointReviewStates,job.state)&&typeof job.created==='number'&&Number.isFinite(job.created)&&job.created>=0&&job.created<=253402300799&&typeof job.updated==='number'&&Number.isFinite(job.updated)&&job.updated>=0&&job.updated<=253402300799&&typeof job.stale==='boolean'&&Object.hasOwn(jointPreviewStates,job.current_review_state)&&jointExecutionMode(job.execution_mode)&&(job.result===null||(job.result&&Object.hasOwn(jointReviewVerdicts,job.result.verdict)&&Object.hasOwn(jointReviewConfidence,job.result.confidence)));}
function jointJobFullValid(job,identity,revision,id=null){
 if(!jointJobLightValid(job,identity)||job.case_revision!==revision||(id!==null&&job.id!==id)||!job.local)return false;
 const envelope={dossier_version:'joint-local-envelope-v1',case:job.case,local_refs:job.local.local_refs,meta:job.local.meta,preview:{version:'joint-preview-v1',mode:'local',external_calls:false,captured_at:new Date(job.created*1000).toISOString()}};
 if(!jointPreviewValid(envelope,identity,revision))return false;
 const mode=job.execution_mode,local=job.local.meta;
 if((mode==='recorded'&&local.execution_mode!=='recorded')||(local.execution_mode!==undefined&&local.execution_mode!==mode))return false;
 if(mode==='recorded'&&(typeof local.recording_sha256!=='string'||!/^[a-f0-9]{64}$/.test(local.recording_sha256)))return false;
 if(job.result===null)return true;const result=job.result,metadata=result.metadata,validation=metadata?.evidence_validation;
 if((mode==='recorded'&&metadata?.execution_mode!=='recorded')||(metadata?.execution_mode!==undefined&&metadata.execution_mode!==mode))return false;
 if(mode==='recorded'&&(metadata.recording_sha256!==local.recording_sha256||metadata.recorded_generation_cost!=='unknown'||metadata.provenance_verified!==false))return false;
 return result.metadata?.offline===true&&result.usd===0&&typeof result.rationale==='string'&&Array.isArray(result.attack_techniques)&&result.attack_techniques.every(value=>typeof value==='string')&&Array.isArray(result.evidence_ids)&&result.evidence_ids.length<=40&&new Set(result.evidence_ids).size===result.evidence_ids.length&&result.evidence_ids.every(id=>job.case.evidence.some(row=>row.event_id===id)&&Object.hasOwn(job.local.local_refs,id))&&['valid','requires_review'].includes(validation?.status)&&Array.isArray(validation.reasons)&&validation.reasons.every(value=>value&&typeof value.code==='string')&&(validation.revision===undefined||validation.revision===job.case.revision)&&(validation.status!=='requires_review'||(result.verdict==='abstain'&&result.evidence_ids.length===0));
}
async function jointReviewFetch(path,signal,body=null,csrf=null){
 const options={credentials:'same-origin',cache:'no-store',signal};if(body!==null){options.method='POST';options.headers={'Content-Type':'application/json','X-RiskOps-CSRF':csrf};options.body=JSON.stringify(body);}
 const response=await fetch(path,options);const data=await response.json().catch(()=>null);
 if(!response.ok){const code=data?.detail,messages={joint_ai_disabled:'本地研判尚未启用。',joint_ai_record_not_found:'这条本地研判记录不可用，请重新查看历史。',joint_ai_request_changed:'摘要或执行条件已变化，请重新预览。',joint_preview_changed:'案件状态已变化，请重新预览。',joint_ai_unavailable:'本地研判暂不可用，请稍后重试。',joint_ai_recording_missing:'未找到与当前摘要匹配的录制响应，需要人工核查。',joint_ai_recording_unavailable:'录制响应不可用，需要人工核查。'};throw jointPreviewError((typeof code==='string'&&Object.hasOwn(messages,code)?messages[code]:null)||({401:'登录已失效，请重新登录。',403:'操作校验已失效，请重新预览后再提交。',409:'摘要或执行条件已变化，请重新预览。',422:'本次请求无法处理，请重新读取案件。'}[response.status]||'本地研判读取失败，请稍后重试。'));}
 if(data===null)throw jointPreviewError('本地研判响应无效，请重新读取。');return data;
}
function renderJointHistory(page=1){
 if(!jointHistory)return;const pages=Math.max(1,Math.ceil(jointHistory.length/5));jointHistoryPage=Math.max(1,Math.min(page,pages));const rows=[];
 for(const job of jointHistory.slice((jointHistoryPage-1)*5,jointHistoryPage*5)){const row=document.createElement('tr');cell(row,when(job.created*1000));cell(row,`版本 ${job.case_revision}${job.case_revision!==jointDetail.revision?' · 与所选版本不同':''}\n${job.stale?'证据或条件已变化，仅供回看':jointPreviewStates[job.current_review_state]}`);cell(row,`${jointExecutionLabel(job.execution_mode)} · ${jointStateLabel(job)}\n${job.result?jointVerdictLabel(job):'尚无结果'}`);const button=document.createElement('button');button.type='button';button.textContent='查看记录';button.addEventListener('click',()=>loadJointJob(job.id,job.case_revision,job.execution_mode));cell(row,'').append(button);rows.push(row);}
 $('joint-ai-history-rows').replaceChildren(...rows);if(!rows.length)empty($('joint-ai-history-rows'),4,'尚无本地研判记录；不会自动提交任务。');text('joint-ai-history-page',`第 ${jointHistoryPage} / ${pages} 页 · 本次读取 ${jointHistory.length} 条（最多 20 条）`);$('joint-ai-history').hidden=false;jointReviewButtons();
}
function renderJointJobReferences(page=1){
 if(!jointReviewJob?.result)return;const job=jointReviewJob,ids=job.result.evidence_ids,pages=Math.max(1,Math.ceil(ids.length/10));jointReviewJobPage=Math.max(1,Math.min(page,pages));const rows=[];
 for(const id of ids.slice((jointReviewJobPage-1)*10,jointReviewJobPage*10)){const evidence=job.case.evidence.find(value=>value.event_id===id),ref=job.local.local_refs[id],row=document.createElement('tr');cell(row,id);cell(row,evidence.kind==='ssh'?`SSH · ${jointEventTypes[evidence.event_type]}\n${evidence.source} · ${evidence.account??'未提供账号'}`:`网络 TCP · 本机入站\n${evidence.source} → ${evidence.destination}:${evidence.dst_port}`);const details=document.createElement('details'),summary=document.createElement('summary'),content=document.createElement('p');summary.textContent='查看本地引用';content.textContent=`来源：${ref.source_id}\n事件：${ref.event_id}\n${jointRefs(ref)}`;details.append(summary,content);cell(row,'').append(details);rows.push(row);}
 $('joint-ai-job-refs').replaceChildren(...rows);if(!rows.length)empty($('joint-ai-job-refs'),3,'没有通过校验的证据引用，不能据此判断安全。');text('joint-ai-job-page',`第 ${jointReviewJobPage} / ${pages} 页 · 通过校验的引用 ${ids.length} 条`);jointReviewButtons();
}
function renderJointJob(job){
 jointReviewJob=job;$('joint-ai-result').hidden=true;$('joint-ai-job').hidden=false;const historical=job.case_revision!==jointDetail.revision,recorded=job.execution_mode==='recorded',label=jointExecutionLabel(job.execution_mode);
 text('joint-ai-job-title',label+'记录');text('joint-ai-job-explanation',recorded?'录制响应说明与校验':'演练说明与校验');
 text('joint-ai-job-boundary',recorded?'本次仅回放本地录制，未调用模型，未执行封禁。录制来源未核验，不能据此确认模型身份；原始生成费用未知。说明文本仍需人工核对。':'未调用模型，未执行封禁。此记录用于核对提交、保存和引用流程，演练建议不是真实模型判断。');
 text('joint-ai-job-state',`${jointStateLabel(job)}${job.stale?' · 证据或执行条件已变化，仅供回看':''}${historical?' · 与当前所选版本不同的历史记录':''}\n当前核验状态：${jointPreviewStates[job.current_review_state]}`);
 jointFields('joint-ai-job-fields',[['保存的观察版本',job.case_revision],['当前所选观察版本',jointDetail.revision],['创建 / 更新',`${when(job.created*1000)} / ${when(job.updated*1000)}`],['保存时摘要状态',jointPreviewStates[job.case.review_state]],['执行方式',recorded?'本地录制回放，本次未调用模型；仅本次回放费用为 0，原始生成费用未知':'本地演练，未调用模型，费用为 0'],...(recorded?[['录制来源','未核验；不能据此确认模型或提供方身份']]:[])]);
 $('joint-ai-job-result').hidden=job.result===null;if(job.result){const result=job.result,validation=result.metadata.evidence_validation;text('joint-ai-job-verdict',`${jointVerdictLabel(job)} · ${recorded?'录制':'演练'}置信度：${jointReviewConfidence[result.confidence]}`);text('joint-ai-job-rationale',label+'记录说明（仍需人工核对）：'+result.rationale);const checks=[validation.status==='valid'?'类型与引用校验通过；说明文本仍需人工核对':'类型与引用校验未通过，结果保留人工复核',...validation.reasons.map(reason=>Object.hasOwn(jointReviewReasons,reason.code)?jointReviewReasons[reason.code]:'存在未识别的校验限制，需要人工核对')].map(value=>{const li=document.createElement('li');li.textContent=value;return li;});$('joint-ai-job-checks').replaceChildren(...checks);renderJointJobReferences();}
 if(job.error_code){const errors={joint_ai_recording_missing:'未找到与这条任务摘要匹配的录制响应，需要人工核查。',joint_ai_recording_unavailable:'这条任务的录制响应不可用，需要人工核查。'};text('joint-ai-review-status',typeof job.error_code==='string'&&Object.hasOwn(errors,job.error_code)?errors[job.error_code]:'这条本地记录存在处理限制，请人工核查；页面不展示内部错误详情。');}jointReviewButtons();
}
async function submitJointReview(){
 if(!jointCanSubmit()||jointSubmitLoading||jointPreviewLoading||jointHistoryLoading||jointJobLoading)return;
 const epoch=jointReviewEpoch,identity=jointDetail.case_id,revision=jointDetail.revision,preview=jointPreview,controller=new AbortController();jointSubmitController=controller;jointSubmitLoading=true;clearJointJob();jointReviewButtons();text('joint-ai-review-status','正在核对'+jointExecutionLabel(preview.execution.mode)+'状态…');const timeout=setTimeout(()=>controller.abort(),20000);let sent=false;
 try{
  const status=await jointReviewFetch('/api/joint/ai/status',controller.signal);
  if(!jointReviewActive(epoch,identity,revision)||jointPreview!==preview||controller.signal.aborted)return;
  if(status.enabled!==true||!jointExecutionMode(status.mode)||status.mode!==preview.execution.mode||status.external_calls!==false||status.error||typeof status.csrf_token!=='string'||!status.csrf_token||status.csrf_token.length>512)throw jointPreviewError('本地研判未启用或执行模式不匹配，未提交任务。');
  sent=true;jointSubmittedPreviewKey=preview.preview_key;text('joint-ai-review-status','正在保存'+jointExecutionLabel(preview.execution.mode)+'任务，未调用模型…');
  const job=await jointReviewFetch('/api/joint/cases/'+encodeURIComponent(identity)+'/ai',controller.signal,{revision,preview_key:preview.preview_key},status.csrf_token);
  if(!jointReviewActive(epoch,identity,revision)||jointPreview!==preview)return;if(controller.signal.aborted)throw jointPreviewError('提交状态暂无法确认，请先查看研判历史。');
  if(!jointJobFullValid(job,identity,revision)||job.execution_mode!==preview.execution.mode)throw jointPreviewError('演练记录身份、版本或执行模式不匹配，请先查看历史。');renderJointJob(job);text('joint-ai-review-status',jointExecutionLabel(job.execution_mode)+'任务已保存；相同摘要会复用记录。本次未调用模型，可手动刷新任务状态。'+(job.execution_mode==='recorded'?'录制来源未核验，原始生成费用未知。':''));
 }catch(error){if(jointReviewActive(epoch,identity,revision)){clearJointPreview();text('joint-ai-review-status',(error.previewMessage||(sent?'提交状态暂无法确认，请先查看研判历史。':'本地演练状态读取失败，未提交任务。'))+(sent?' 请先核对历史，避免重复提交。':''));}}
 finally{clearTimeout(timeout);if(epoch===jointReviewEpoch){jointSubmitLoading=false;jointSubmitController=null;jointReviewButtons();}}
}
async function loadJointHistory(){
 if(!jointDetail||jointActiveTab!=='ai'||jointSubmitLoading||jointHistoryLoading)return;
 const epoch=jointReviewEpoch,identity=jointDetail.case_id,revision=jointDetail.revision,request=++jointHistoryRequest,controller=new AbortController();if(jointHistoryController)jointHistoryController.abort();jointHistoryController=controller;jointHistoryLoading=true;jointHistory=null;jointHistoryPage=1;clearJointJob();$('joint-ai-result').hidden=true;$('joint-ai-history').hidden=true;$('joint-ai-history-rows').replaceChildren();text('joint-ai-history-page','');text('joint-ai-review-status','正在读取本地研判历史…');jointReviewButtons();const timeout=setTimeout(()=>controller.abort(),15000);
 try{const data=await jointReviewFetch('/api/joint/cases/'+encodeURIComponent(identity)+'/ai/history',controller.signal);if(!jointReviewActive(epoch,identity,revision)||request!==jointHistoryRequest)return;if(controller.signal.aborted)throw jointPreviewError('研判历史读取超时，请重试。');if(data.case_id!==identity||!Array.isArray(data.items)||data.items.length>20||!data.items.every(job=>jointJobLightValid(job,identity))||new Set(data.items.map(job=>job.id)).size!==data.items.length)throw jointPreviewError('研判历史身份或范围不匹配，请重新读取。');jointHistory=data.items;renderJointHistory();text('joint-ai-review-status','历史读取完成；结果只代表本次读取时刻，没有自动提交任务。');}
 catch(error){if(jointReviewActive(epoch,identity,revision)&&request===jointHistoryRequest)text('joint-ai-review-status',error.previewMessage||'研判历史读取失败，请重试。');}
 finally{clearTimeout(timeout);if(epoch===jointReviewEpoch&&request===jointHistoryRequest){jointHistoryLoading=false;jointHistoryController=null;jointReviewButtons();}}
}
async function loadJointJob(id,jobRevision,expectedMode=null){
 if(!jointDetail||jointActiveTab!=='ai'||jointSubmitLoading||jointHistoryLoading||!jointJobIdentity(id)||!Number.isSafeInteger(jobRevision)||jobRevision<1||(expectedMode!==null&&!jointExecutionMode(expectedMode)))return;
 const epoch=jointReviewEpoch,identity=jointDetail.case_id,viewRevision=jointDetail.revision;clearJointJob();const request=jointJobRequest,controller=new AbortController();jointJobController=controller;jointJobLoading=true;$('joint-ai-result').hidden=true;const timeout=setTimeout(()=>controller.abort(),15000);text('joint-ai-review-status','正在读取保存的本地研判记录…');jointReviewButtons();
 try{const job=await jointReviewFetch('/api/joint/ai/jobs/'+encodeURIComponent(id),controller.signal);if(!jointReviewActive(epoch,identity,viewRevision)||request!==jointJobRequest)return;if(controller.signal.aborted)throw jointPreviewError('演练记录读取超时，请重试。');if(!jointJobFullValid(job,identity,jobRevision,id)||(expectedMode!==null&&job.execution_mode!==expectedMode))throw jointPreviewError('演练记录身份、版本或引用不匹配，请重新查看历史。');text('joint-ai-review-status','已读取保存的'+jointExecutionLabel(job.execution_mode)+'记录；本次未调用模型。');renderJointJob(job);}
 catch(error){if(jointReviewActive(epoch,identity,viewRevision)&&request===jointJobRequest)text('joint-ai-review-status',error.previewMessage||'演练记录读取失败，请重新查看历史。');}
 finally{clearTimeout(timeout);if(epoch===jointReviewEpoch&&request===jointJobRequest){jointJobLoading=false;jointJobController=null;jointReviewButtons();}}
}

function jointDetailValid(data,identity,revision){const p=data?.projection;return data?.case_id===identity&&data.revision===revision&&p?.case_id===identity&&Object.hasOwn(jointStates,p.state)&&p.anchor&&typeof p.anchor.src_ip==='string'&&typeof p.anchor.incident_id==='string'&&Number.isSafeInteger(p.anchor.revision)&&p.anchor.revision>=1&&p.window&&Array.isArray(p.reasons)&&p.reasons.every(x=>typeof x==='string')&&Array.isArray(p.uncertainties)&&p.uncertainties.every(x=>typeof x==='string')&&Array.isArray(p.timeline)&&data.current&&Number.isSafeInteger(data.current.revision)&&data.current.revision>=revision;}
function renderJointDetail(data){
 jointDetail=data;jointPreviewPager();const p=data.projection,current=data.current;
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
 jointDetail=null;clearJointPreview();jointTimelineLoaded=false;jointTimelineAvailable=false;jointTimelineLoading=false;jointTimelinePage=jointTimelinePages=1;
 for(const id of ['joint-fields','joint-provenance','joint-timeline','joint-source-actions'])$(id).replaceChildren();
 for(const id of ['joint-revision','joint-reasons','joint-uncertainties','joint-freshness','joint-timeline-page','joint-timeline-status'])text(id,'');
 for(const id of ['joint-revision-prev','joint-revision-next','joint-current'])$(id).disabled=true;
 jointTimelinePager();setJointTab('overview');text('joint-detail-status','正在读取指定观察版本…');
 if(!dialog.open){if(typeof dialog.showModal==='function')dialog.showModal();else dialog.setAttribute('open','');}
 try{const data=await jointGet('/api/joint/cases/'+encodeURIComponent(identity)+'?revision='+encodeURIComponent(revision),jointDetailController.signal);if(request!==jointDetailRequest)return;if(!jointDetailValid(data,identity,revision))throw new Error('联合案件身份或观察版本不匹配。');renderJointDetail(data);text('joint-detail-status','');}
 catch(error){if(request===jointDetailRequest&&error.name!=='AbortError')text('joint-detail-status',error.message+' 请关闭后重新打开。');}
}
function clearJointDetail(){++jointDetailRequest;++jointTimelineRequest;if(jointDetailController)jointDetailController.abort();if(jointTimelineController)jointTimelineController.abort();jointDetail=null;clearJointPreview();jointTimelineLoading=false;jointTimelineLoaded=false;jointTimelineAvailable=false;jointTimelinePager();if(jointReturnFocus?.isConnected&&typeof jointReturnFocus.focus==='function')jointReturnFocus.focus();}
function closeJointDetail(){const dialog=$('joint-dialog');if(typeof dialog.close==='function')dialog.close();else{dialog.removeAttribute('open');clearJointDetail();}}
function setJointTab(name){const names=['overview','timeline','sources','ai'];if(!names.includes(name))return;if(name!==jointActiveTab)clearJointPreview();jointActiveTab=name;for(const key of names){$('joint-pane-'+key).hidden=key!==name;$('joint-tab-'+key).setAttribute('aria-selected',String(key===name));$('joint-tab-'+key).tabIndex=key===name?0:-1;}if(name==='timeline'&&!jointTimelineLoaded&&!jointTimelineLoading&&jointDetail)return loadJointTimeline();}
function initializeJoint(){
 setJointTab('overview');jointScope();
 if(typeof document.addEventListener==='function')document.addEventListener('visibilitychange',()=>{if(document.hidden)cancelJointStatusPoll();});
 $('joint-search').addEventListener('submit',event=>{event.preventDefault();return submitJointSearch();});
 $('joint-clear').addEventListener('click',()=>{for(const id of ['joint-ip','joint-asset','joint-state','joint-start','joint-end'])$(id).value='';jointResetQuery({});return loadJoint(1);});
 $('joint-refresh').addEventListener('click',()=>loadJoint());$('joint-latest').addEventListener('click',()=>{jointResetQuery({...jointFilters});return loadJoint(1);});
 $('joint-prev').addEventListener('click',()=>loadJoint(jointPage-1));$('joint-next').addEventListener('click',()=>loadJoint(jointPage+1));
 $('joint-close').addEventListener('click',closeJointDetail);$('joint-dialog').addEventListener('close',clearJointDetail);
 $('joint-revision-prev').addEventListener('click',()=>{if(jointDetail)return showJointCase(jointDetail.case_id,jointDetail.revision-1);});$('joint-revision-next').addEventListener('click',()=>{if(jointDetail)return showJointCase(jointDetail.case_id,jointDetail.revision+1);});$('joint-current').addEventListener('click',()=>{if(jointDetail)return showJointCase(jointDetail.case_id,jointDetail.current.revision);});
 $('joint-timeline-prev').addEventListener('click',()=>loadJointTimeline(jointTimelinePage-1));$('joint-timeline-next').addEventListener('click',()=>loadJointTimeline(jointTimelinePage+1));$('joint-timeline-retry').addEventListener('click',()=>loadJointTimeline(jointTimelinePage));
 $('joint-ai-submit').addEventListener('click',submitJointReview);$('joint-ai-history-load').addEventListener('click',loadJointHistory);$('joint-ai-history-prev').addEventListener('click',()=>renderJointHistory(jointHistoryPage-1));$('joint-ai-history-next').addEventListener('click',()=>renderJointHistory(jointHistoryPage+1));$('joint-ai-job-refresh').addEventListener('click',()=>{if(jointReviewJob)return loadJointJob(jointReviewJob.id,jointReviewJob.case_revision,jointReviewJob.execution_mode);});$('joint-ai-job-prev').addEventListener('click',()=>renderJointJobReferences(jointReviewJobPage-1));$('joint-ai-job-next').addEventListener('click',()=>renderJointJobReferences(jointReviewJobPage+1));
 $('joint-ai-preview').addEventListener('click',loadJointPreview);$('joint-ai-prev').addEventListener('click',()=>renderJointPreviewPage(jointPreviewPage-1));$('joint-ai-next').addEventListener('click',()=>renderJointPreviewPage(jointPreviewPage+1));
 const tabs=['overview','timeline','sources','ai'];for(const name of tabs){$('joint-tab-'+name).addEventListener('click',()=>setJointTab(name));$('joint-tab-'+name).addEventListener('keydown',event=>{const i=tabs.indexOf(name);let next=null;if(event.key==='ArrowRight')next=(i+1)%tabs.length;else if(event.key==='ArrowLeft')next=(i+tabs.length-1)%tabs.length;else if(event.key==='Home')next=0;else if(event.key==='End')next=tabs.length-1;if(next!==null){event.preventDefault();setJointTab(tabs[next]);$('joint-tab-'+tabs[next]).focus();}});}
}
"""
