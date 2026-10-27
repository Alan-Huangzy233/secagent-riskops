"""Tabbed console workspace and nearby record details, without external assets."""
import re

from .http_dashboard import SECTION as HTTP_SECTION, DIALOG as HTTP_DIALOG
from .network_dashboard import SECTION as NETWORK_SECTION, DIALOG as NETWORK_DIALOG
from .joint_dashboard import SECTION as JOINT_SECTION, DIALOG as JOINT_DIALOG


VIEWS = (("incidents", "告警", "incident-section"), ("events", "日志", "event-section"),
         ("http", "HTTP 检测", "http-section"),
         ("network", "网络检测", "network-section"),
         ("joint", "联合案件", "joint-section"),
         ("overview", "来源概览", "overview-section"), ("notifications", "通知与简报", "notification-section"),
         ("collection", "采集记录", "collection-section"), ("ip", "IP 查询", "ip-query-section"),
         ("controls", "响应操作", "control-section"))

STYLE = r"""
[hidden]{display:none!important}body{margin:0;padding:0;max-width:none;height:100dvh;overflow:hidden}
.workspace-shell{display:flex;height:100dvh;min-height:0}.workspace-nav{width:174px;flex-shrink:0;background:#0b1523;border-right:1px solid #263a53;padding:26px 14px;display:flex;flex-direction:column;gap:7px}.workspace-brand{font-size:19px;font-weight:700;padding:0 12px 28px;letter-spacing:.04em}.workspace-brand small{display:block;font-size:12px;color:#8ca4c3;font-weight:400;margin-top:7px;letter-spacing:0}.workspace-nav button{text-align:left;border-color:transparent;background:transparent;border-radius:7px;padding:12px;font-size:14px;color:#9cafc7}.workspace-nav button[aria-selected=true]{background:#183456;color:#d8eaff;border-color:#315680}.workspace-nav button:hover{background:#152942}.workspace-nav .nav-note{margin-top:auto;padding:18px 12px 0;font-size:12px;color:#8196b1}
.workspace-main{flex:1;min-width:0;min-height:0;display:flex;flex-direction:column}.workspace-header{padding:22px 26px 12px}.workspace-header h1{font-size:23px;margin:0 0 6px}.workspace-header>p{color:#9cafc7;font-size:13px;margin:4px 0 16px}.workspace-header .toolbar{margin:12px 0 8px;gap:10px}#error:empty{display:none}.workspace-header .cards{gap:10px;margin-top:14px}.workspace-header .card{padding:12px 16px;margin:0;font-size:12px}.workspace-header .number{font-size:24px;margin:4px 0 0}.workspace-header #refresh-help{font-size:12px;margin:8px 0;color:#8ca4c3}.sync-line{display:flex;align-items:center;gap:10px;font-size:12px;min-height:22px;color:#9bb8da}.sync-dot{width:7px;height:7px;background:#73c6b5;border-radius:50%;flex-shrink:0}.sync-line[data-stale=true] .sync-dot{background:#dfb26a}.workspace-panel{min-height:0;flex:1;overflow:auto;padding:0 26px 24px}.workspace-panel>section{margin:0;min-height:100%;box-sizing:border-box;padding:18px}.workspace-panel h2{font-size:18px;margin-top:0}.workspace-panel p{font-size:13px;line-height:1.6}.workspace-panel .table-wrap{max-height:calc(100dvh - 440px);min-height:120px;overflow:auto;border:1px solid #263a53;border-radius:7px;margin-top:12px}.workspace-panel thead{position:sticky;top:0;z-index:1;background:#17273b}.workspace-panel .pager{position:sticky;bottom:0;background:#111e30;padding-top:14px}.workspace-panel .help-note{margin:8px 0;color:#a9bacd;font-size:12px}.workspace-panel .help-note>p{margin:8px 0}.workspace-panel .table-wrap table{margin:0}.workspace-panel td{padding-top:10px;padding-bottom:10px}.workspace-panel .list-status:empty{display:none}.local-ip-search{margin:12px 0}.local-ip-search .actions{margin-top:8px}.local-ip-search .ip-form input{min-width:160px}.local-ip-search .search-fields{margin-top:10px;grid-template-columns:repeat(2,minmax(0,1fr))}.search-scope{white-space:pre-line;overflow-wrap:anywhere;margin:8px 0;color:#b4c9e0;font-size:12px}.ip-search-link{display:flex;flex-wrap:wrap;gap:6px;margin-top:7px}.ip-search-link button{font-size:12px;padding:4px 7px}@media(max-width:480px){.local-ip-search .search-fields{grid-template-columns:1fr}.local-ip-search select{max-width:100%}}
.search-options>summary{font-size:13px;cursor:pointer;padding:8px 0;color:#adc4df}
.workspace-skeleton{display:grid;gap:12px;padding:18px 0}.skeleton-line{height:14px;max-width:100%;border-radius:4px;background:linear-gradient(90deg,#15263c 20%,#253e5b 50%,#15263c 80%);background-size:200% 100%;animation:workspace-shimmer 1.5s infinite}.skeleton-line:nth-child(2){width:72%}.skeleton-line:nth-child(3){width:88%}@keyframes workspace-shimmer{to{background-position:-200% 0}}@media(prefers-reduced-motion:reduce){.skeleton-line{animation:none}}
#detail-dialog{position:fixed;inset:0 0 0 auto;margin:0;width:min(820px,100vw);max-width:100vw;height:100dvh;max-height:100dvh;border:0;border-left:1px solid #385475;background:#101d2e;color:#e7edf5;padding:0;box-shadow:-16px 0 55px #0006}#detail-dialog::backdrop{background:#030b17a6}#detail-dialog[open]{display:flex;flex-direction:column}#detail-section{display:flex;flex-direction:column;min-height:0;width:100%;height:100%;margin:0;border:0;border-radius:0;padding:22px}.drawer-heading{display:flex;align-items:center;justify-content:space-between;gap:14px}.drawer-heading h2{font-size:19px;margin:0}.drawer-heading button{flex-shrink:0}.detail-tabs{display:flex;gap:8px;border-bottom:1px solid #30445f;padding:17px 0 10px;margin-bottom:16px}.detail-tabs button[aria-selected=true]{border-color:#568aca;background:#1c3b60}.detail-pane{min-height:0;overflow:auto;flex:1;padding:0 2px 18px}.detail-fields{display:grid;grid-template-columns:120px minmax(0,1fr);font-size:14px;gap:14px 12px;margin:4px 0 22px}.detail-fields dt{color:#95abc6}.detail-fields dd{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}.detail-pane pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px;max-height:55vh;overflow:auto}.detail-pane #evidence-view .table-wrap{max-width:100%;overflow:auto}.detail-pane #ai-panel{margin:0}.detail-pane details summary{cursor:pointer;font-size:13px;color:#9cb6d5;padding:12px 0}
@media(max-width:850px){.workspace-shell{flex-direction:column}.workspace-nav{width:auto;padding:10px 12px;flex-direction:row;overflow-x:auto;border-right:0;border-bottom:1px solid #263a53;gap:4px}.workspace-brand,.workspace-nav .nav-note{display:none}.workspace-nav button{white-space:nowrap;padding:10px}.workspace-main{min-height:0}.workspace-header{padding:14px 14px 10px}.workspace-header h1{font-size:19px}.workspace-header>p{display:none}.workspace-header .cards{grid-template-columns:repeat(2,minmax(0,1fr));gap:6px}.workspace-header .card{padding:9px 11px}.workspace-header .number{font-size:21px}.workspace-header #refresh-help{display:none}.workspace-header .toolbar{gap:6px;font-size:12px}.workspace-header .toolbar button,.workspace-header .toolbar select{padding:6px 8px;font-size:12px}.workspace-header #source-filter{max-width:215px}.workspace-header #refresh-interval{max-width:135px}.workspace-header .card small{font-size:10px}.workspace-header .card{font-size:11px}.workspace-header .number{font-size:20px}.workspace-panel .pager{position:static;gap:8px;font-size:12px}.workspace-panel{padding:0 12px 12px}.workspace-panel>section{padding:13px}.workspace-panel .table-wrap{max-height:48dvh}.detail-fields{grid-template-columns:90px minmax(0,1fr);font-size:13px}#detail-section{padding:16px}.workspace-header #updated{display:none}}
"""

SCRIPT = r"""
let workspaceView='incidents',bootstrapPacket=null,bootstrapReceivedAt=0,bootstrapPromise=null,bootstrapTimer=null;
let detailReturnFocus=null,detailTab='overview',bootstrapBlocked=false,bootstrapBlockedGeneration=null,controlsPromise=null;
const workspaceViews=['incidents','events','http','network','joint','overview','notifications','collection','ip','controls'];
function searchPrefix(kind){return kind==='event'?'search':'incident-search';}
function searchFilters(kind){return kind==='event'?eventFilters:incidentFilters;}
function localInput(value){const date=new Date(value);if(!value||Number.isNaN(date.valueOf()))return '';return new Date(date.valueOf()-date.getTimezoneOffset()*60000).toISOString().slice(0,19);}
function syncIPInputs(kind){
 const prefix=searchPrefix(kind),filters=searchFilters(kind);$(prefix+'-ip').value=filters.ip||'';
 for(const key of ['start','end'])$(prefix+'-'+key).value=localInput(filters[key]);
 $(kind+'-search-window').value=searchWindows[kind];$(kind+'-search-dates').hidden=searchWindows[kind]!=='custom';
}
function renderIPScopes(){
 for(const kind of ['event','incident']){
  const filters=searchFilters(kind),range=filters.start||filters.end?`${filters.start?when(filters.start):'保留起点未知'} 至 ${filters.end?when(filters.end):'最新保留记录'}`:'全部保留时间（实际边界未知）';
  const source=currentSource?`来源 ${currentSource}`:'全部 SSH 来源',ip=filters.ip?`完整来源 IP ${filters.ip}`:'全部来源 IP';
  const state=kind==='incident'?` · ${incidentTriage==='all'?'全部处置状态':triageLabels[incidentTriage]} · ${incidentFocus==='all'?'全部评分':incidentFocus==='attention'?'优先核查 + 未评分':incidentFocus==='low'?'低分':'未评分'}`:'';
  const advanced=kind==='event'&&['username','event_type','q'].some(key=>filters[key])?' · 已应用高级筛选':'';
  text(kind+'-search-scope',`当前查询：${ip} · ${source}${state}${advanced}\n${range}（浏览器本地时间）；${kind==='incident'?'按告警证据时段重叠匹配':'按日志时间匹配'}。`);
  let coverage='采集与保留边界未知；仅查询当前已保留记录。';
  if(searchSources){const sources=currentSource?searchSources.filter(source=>source.source_id===currentSource):searchSources;
   if(!sources.length)coverage='当前未登记匹配的 SSH 来源；已保留记录仍可查询。';
   else{const gaps=sources.filter(source=>source.collection?.gaps_since_coverage>0).length,unknown=sources.filter(source=>!source.collection||!source.collection.coverage_start||source.collection.coverage_note).length,delayed=sources.filter(source=>source.connection_status!=='online'||source.collection?.caught_up===false).length;
    coverage=`${sources.length} 个登记来源；${gaps?`${gaps} 个来源有已知采集缺口；`:''}${delayed?`${delayed} 个来源离线或待追赶；`:''}${unknown?'部分采集覆盖未知；':''}实际保留边界未知。可在“概览 / 采集记录”核对覆盖。`;
   }
  }
  text(kind+'-search-coverage',coverage+' 无匹配不代表安全或没有活动。');
 }
}
function searchWindow(kind){
 const mode=$(kind+'-search-window').value||'24h',prefix=searchPrefix(kind);
 if(mode==='all')return {mode,filters:{}};
 if(mode==='24h'){const end=new Date();return {mode,filters:{start:new Date(end.valueOf()-86400000).toISOString(),end:end.toISOString()}};}
 const start=new Date($(prefix+'-start').value),end=new Date($(prefix+'-end').value);
 if(!$(prefix+'-start').value||!$(prefix+'-end').value||Number.isNaN(start.valueOf())||Number.isNaN(end.valueOf())||start>end)throw new Error('请输入有效的开始、结束时间，开始时间不能晚于结束时间。');
 return {mode:'custom',filters:{start:start.toISOString(),end:end.toISOString()}};
}
function applyIPSearch(kind,filters,mode){
 if(kind==='event'){eventFilters=filters;eventSnapshot=null;setFilterInputs();}else incidentFilters=filters;
 searchWindows[kind]=mode;syncIPInputs(kind);pages[kind].page=1;saveView();renderIPScopes();return loadList(kind,1);
}
function submitIPSearch(kind){
 try{const window=searchWindow(kind),filters={...window.filters},ip=$(searchPrefix(kind)+'-ip').value.trim();if(ip)filters.ip=ip;
  if(kind==='event')for(const key of ['username','event_type','q']){const value=$('search-'+key).value.trim();if(value)filters[key]=value;}
  return applyIPSearch(kind,filters,window.mode);
 }catch(error){text(kind+'-status',error.message);$(kind+'-status').className='list-status error';}
}
function clearIPSearch(kind){
 if(kind==='event'){eventFilters={};eventSnapshot=null;setFilterInputs();}else incidentFilters={};
 searchWindows[kind]='24h';syncIPInputs(kind);pages[kind].page=1;saveView();return loadList(kind,1);
}
function searchSSHFromIP(kind,ip,first=null,last=null){
 const start=new Date(first),end=new Date(last),hasWindow=first&&last&&Number.isFinite(start.valueOf())&&Number.isFinite(end.valueOf())&&start<=end;
 const finish=hasWindow?end.valueOf()+1800000:Date.now(),begin=hasWindow?start.valueOf()-1800000:finish-86400000;
 currentSource='';$('source-filter').value='';incidentTriage='all';incidentFocus='all';incidentSort='recent';
 $('incident-triage').value=incidentTriage;$('incident-focus').value=incidentFocus;$('incident-sort').value=incidentSort;
 eventFilters={};incidentFilters={};eventSnapshot=null;setFilterInputs();syncIPInputs('incident');
 for(const key of ['event','incident']){const state=pages[key];++state.requestId;if(state.controller)state.controller.abort();state.pending=false;state.page=1;state.totalPages=null;state.total=0;state.visible=null;state.displayed=null;updatePager(key);}
 closeRecordDrawer();const dialog=$('network-dialog');if(dialog.open){if(typeof dialog.close==='function')dialog.close();else{dialog.removeAttribute('open');clearNetworkDetail();}}
 selectWorkspace(kind==='event'?'events':'incidents',false);
 if(controlsData){$('control-sources').dataset.key='';renderControlSources(controlsData.sources||[]);}
 const task=applyIPSearch(kind,{ip:String(ip),start:new Date(begin).toISOString(),end:new Date(finish).toISOString()},hasWindow?'custom':'24h');
 $(searchPrefix(kind)+'-ip').focus?.();return task;
}
function networkSSHSearchActions(item){
 const actions=document.createElement('div');actions.className='ip-search-link';
 for(const [kind,label] of [['incident','查 SSH 告警'],['event','查 SSH 日志']]){const button=document.createElement('button');button.type='button';button.textContent=label;button.setAttribute('aria-label',`${label}：${item.src_ip}`);button.title='查询全部 SSH 来源和处置状态，默认网络证据前后各 30 分钟；不代表事件已关联。';button.addEventListener('click',event=>{event.stopPropagation();return searchSSHFromIP(kind,item.src_ip,item.first_seen,item.last_seen);});actions.append(button);}return actions;
}
function initializeIPSearch(){
 for(const kind of ['event','incident']){
  syncIPInputs(kind);$(kind+'-ip-form').addEventListener('submit',event=>{event.preventDefault();return submitIPSearch(kind);});
  $(kind+'-ip-clear').addEventListener('click',()=>clearIPSearch(kind));
  $(kind+'-search-window').addEventListener('change',()=>{$(kind+'-search-dates').hidden=$(kind+'-search-window').value!=='custom';});
  $(kind+'-search-all').addEventListener('click',()=>{const filters={...searchFilters(kind)};delete filters.start;delete filters.end;return applyIPSearch(kind,filters,'all');});
 }
 renderIPScopes();
}
function setDetailTab(name){
 if(!['overview','evidence','ai'].includes(name))return;detailTab=name;
 for(const key of ['overview','evidence','ai']){$('detail-pane-'+key).hidden=key!==name;$('detail-tab-'+key).setAttribute('aria-selected',String(key===name));$('detail-tab-'+key).tabIndex=key===name?0:-1;}
}
function openRecordDrawer(){
 const dialog=$('detail-dialog');if(!dialog.open)detailReturnFocus=document.activeElement;
 setDetailTab('overview');
 if(typeof dialog.showModal==='function'){if(!dialog.open)dialog.showModal();}else dialog.setAttribute('open','');
}
function closeRecordDrawer(){const dialog=$('detail-dialog');if(typeof dialog.close==='function'){if(dialog.open)dialog.close();}else{dialog.removeAttribute('open');clearDetails();}}
function renderRecordOverview(record){
 const box=$('detail-fields');box.replaceChildren();
 const values=[['标题',record.title],['时间',record.timestamp||record.last_seen],['来源',record.hostnames||record.source_ids||record.hostname||record.source_id],['来源 IP',record.peer_ip||record.src_ip],['管理保护',protectedSource(record)?managementProtectionLabel+'；明确的认证异常仍需核查。':null],['账号',record.usernames||record.username||record.ssh_user],['失败日志',record.failure_count],['成功日志',record.success_count],['关联规则',incidentRules(record).map(rule=>detectionRuleLabels[rule.rule_id]||rule.rule_id||'未知规则')],['类型',record.event_kind||record.event_type],['处置状态',triageLabels[record.triage_status]||record.triage_status],['证据数量',record.evidence_count],['评分',record.assessment?.score],['原始消息',record.message]];
 for(const [label,value] of values){if(value===undefined||value===null||value===''||Array.isArray(value)&&!value.length)continue;const term=document.createElement('dt'),detail=document.createElement('dd');term.textContent=label;detail.textContent=Array.isArray(value)?value.join('、'):String(value);box.append(term,detail);}
}
function setWorkspace(name){
 if(!workspaceViews.includes(name))name='incidents';workspaceView=name;
 for(const key of workspaceViews){$('workspace-'+key).hidden=key!==name;$('workspace-tab-'+key).setAttribute('aria-selected',String(key===name));$('workspace-tab-'+key).tabIndex=key===name?0:-1;}
 $('source-filter').disabled=['http','network','joint'].includes(name);
 try{sessionStorage.setItem('riskops-workspace',name);}catch{}
}
async function selectWorkspace(name,load=true){setWorkspace(name);if(load)await loadWorkspaceView();}
function invalidateBootstrap(){bootstrapBlocked=true;bootstrapBlockedGeneration=bootstrapPacket?.generation;}
function updateLatestLabel(){text('event-latest',bootstrapPacket?.data&&eventSnapshot!==null&&eventSnapshot!==bootstrapPacket.data.events.snapshot?'有新日志，获取最新':'获取最新日志');}
function showListSkeleton(rows,span){
 const tr=document.createElement('tr'),td=document.createElement('td'),box=document.createElement('div');td.colSpan=span;box.className='workspace-skeleton';box.setAttribute('aria-hidden','true');
 for(let i=0;i<3;i++){const line=document.createElement('div');line.className='skeleton-line';box.append(line);}td.append(box);tr.append(td);rows.append(tr);
}
function cachedListAvailable(kind){
 if(bootstrapBlocked||!bootstrapPacket?.data||bootstrapPacket.stale||currentSource)return false;
 const age=Number(bootstrapPacket.age_seconds)+(performance.now()-bootstrapReceivedAt)/1000;
 if(age>bootstrapPacket.max_age_seconds)return false;
 if(kind==='incident')return pages.incident.page===1&&incidentTriage==='pending'&&incidentFocus==='all'&&incidentSort==='score'&&Object.values(incidentFilters).every(value=>!value);
 return pages.event.page===1&&Object.values(eventFilters).every(value=>!value)&&(eventSnapshot===null||eventSnapshot===bootstrapPacket.data.events.snapshot);
}
async function cachedOrLiveList(kind,force=false){
 if(!force&&cachedListAvailable(kind)){
  const view=beginList(kind,1);try{await acceptList(view,bootstrapPacket.data[kind==='incident'?'incidents':'events']);}catch(error){failList(view,error);}finally{finishList(view);}
 }else await loadList(kind);
}
async function loadWorkspaceView(force=false){
 const view=workspaceView;
 try{
  if(view==='incidents'){await cachedOrLiveList('incident',force);if(!controlsData&&!controlsPromise){controlsPromise=loadControls();try{await controlsPromise;}finally{controlsPromise=null;}}}
  else if(view==='events')await cachedOrLiveList('event',force);
  else if(view==='http')await loadHttp();
  else if(view==='network')await loadNetwork();
  else if(view==='joint')await loadJoint();
  else if(view==='notifications')await loadNotifications();
  else if(view==='collection')await loadCollection();
  else if(view==='controls')await loadControls();
  else if(view==='overview'&&!bootstrapPacket?.data)renderSummary(await get('/api/summary'));
 }catch(error){text('error',error.message);}
}
async function readBootstrap(){
 if(bootstrapPromise)return bootstrapPromise;
 bootstrapPromise=(async()=>{
  const packet=await get('/api/console/bootstrap');
  if(packet.state==='disabled'){bootstrapPacket=null;text('console-sync','按需读取当前视图');$('console-sync-line').dataset.stale='false';return packet;}
  if(packet.state!=='ready'||!packet.data){text('console-sync','服务器正在准备数据，完成后自动显示…');$('console-sync-line').dataset.stale='true';return packet;}
  if(!packet.data.summary||!packet.data.events||!packet.data.incidents)throw new Error('预载数据暂不可用，请重试。');
  if(bootstrapBlocked&&!packet.stale&&packet.generation!==bootstrapBlockedGeneration)bootstrapBlocked=false;
  bootstrapPacket=packet;bootstrapReceivedAt=performance.now();if(!bootstrapBlocked)renderSummary(packet.data.summary);
  $('console-sync-line').dataset.stale=String(Boolean(packet.stale));
  text('console-sync',`数据准备于 ${when(packet.generated_at)}${packet.stale?' · 正在同步最新数据':' · 后台自动同步'}`);
  updateLatestLabel();
  return packet;
 })();
 try{return await bootstrapPromise;}finally{bootstrapPromise=null;}
}
function scheduleBootstrap(delay=15000){
 if(bootstrapTimer!==null)clearTimeout(bootstrapTimer);
 bootstrapTimer=setTimeout(async()=>{
  if(document.hidden||isBusy()||controlBusy||triageBusy){scheduleBootstrap();return;}
  try{
   const previous=bootstrapPacket?.generation,packet=await readBootstrap();
   if(packet.state==='disabled')return;
   const safeToUpdate=!bootstrapBlocked&&!packet.stale&&!$('detail-dialog').open&&!selectedTargets.size;
   if(packet.data&&safeToUpdate&&packet.generation!==previous&&(workspaceView==='overview'||workspaceView==='incidents'&&cachedListAvailable('incident')||workspaceView==='events'&&cachedListAvailable('event')))await loadWorkspaceView();
   scheduleBootstrap(packet.state==='warming'?2000:15000);
  }catch(error){$('console-sync-line').dataset.stale='true';text('console-sync','同步暂不可用，已保留上次显示的数据。');scheduleBootstrap();}
 },delay);
}
async function refreshWorkspace(event){
 if(refreshRunning)return;refreshRunning=true;updateRefreshButton();text('error','');
 try{
  const packet=await readBootstrap();
  if(packet.state==='disabled'){renderSummary(await get('/api/summary'));await loadWorkspaceView(true);}
  else if(packet.data){await loadWorkspaceView(Boolean(event));scheduleBootstrap();}
  else scheduleBootstrap(2000);
 }catch(error){
  $('console-sync-line').dataset.stale='true';text('error',error.message+' 已保留上次成功读取的数据。');
  if(event){
   if(workspaceView==='overview')text('console-sync','概览暂不可用，后台会继续重试。');
   else{text('console-sync','概览暂不可用，正在直接刷新当前视图。');await loadWorkspaceView(true);}
  }
  scheduleBootstrap();
 }
 finally{refreshRunning=false;updateRefreshButton();scheduleAutoRefresh();}
}
function changeWorkspaceSource(){
 currentSource=$('source-filter').value;eventSnapshot=null;closeRecordDrawer();clearDetails();
 for(const kind of ['event','incident']){const state=pages[kind];++state.requestId;if(state.controller)state.controller.abort();state.pending=false;state.page=1;state.totalPages=null;state.total=0;state.visible=null;state.displayed=null;text(kind+'-updated','');updatePager(kind);}
 ++collectionRequestId;collectionPage=1;
 if(controlsData){$('control-sources').dataset.key='';renderControlSources(controlsData.sources||[]);}
 saveView();updateRefreshButton();loadWorkspaceView();scheduleAutoRefresh();
}
function initializeWorkspace(){
 initializeIPSearch();
 initializeHttp();
 initializeNetwork();
 initializeJoint();
 for(const name of workspaceViews){
  const button=$('workspace-tab-'+name);button.addEventListener('click',()=>selectWorkspace(name));
  button.addEventListener('keydown',event=>{const index=workspaceViews.indexOf(name);let next=null;if(['ArrowDown','ArrowRight'].includes(event.key))next=(index+1)%workspaceViews.length;else if(['ArrowUp','ArrowLeft'].includes(event.key))next=(index+workspaceViews.length-1)%workspaceViews.length;else if(event.key==='Home')next=0;else if(event.key==='End')next=workspaceViews.length-1;if(next!==null){event.preventDefault();selectWorkspace(workspaceViews[next]);$('workspace-tab-'+workspaceViews[next]).focus();}});
 }
 let saved;try{saved=sessionStorage.getItem('riskops-workspace');}catch{}setWorkspace(saved||'incidents');
 const detailTabs=['overview','evidence','ai'];
 for(const name of detailTabs){
  $('detail-tab-'+name).addEventListener('click',()=>setDetailTab(name));
  $('detail-tab-'+name).addEventListener('keydown',event=>{const index=detailTabs.indexOf(name);let next=null;if(event.key==='ArrowRight')next=(index+1)%3;else if(event.key==='ArrowLeft')next=(index+2)%3;else if(event.key==='Home')next=0;else if(event.key==='End')next=2;if(next!==null){event.preventDefault();setDetailTab(detailTabs[next]);$('detail-tab-'+detailTabs[next]).focus();}});
 }
 $('detail-close').addEventListener('click',closeRecordDrawer);
 $('detail-dialog').addEventListener('close',()=>{clearDetails();if(detailReturnFocus?.isConnected&&typeof detailReturnFocus.focus==='function')detailReturnFocus.focus();});
 setDetailTab('overview');
 // A new visit starts with current logs. Pagination within this visit still
 // preserves its receipt boundary; saved search fields remain available.
 eventSnapshot=null;pages.event.page=1;$('event-search-options').open=['username','event_type','q'].some(key=>Boolean(eventFilters[key]));$('incident-options').open=incidentTriage!=='pending'||incidentFocus!=='all'||incidentSort!=='score';
 showListSkeleton($('incidents'),6);showListSkeleton($('events'),5);
}
"""


def ip_search_form(kind):
    prefix = "search" if kind == "event" else "incident-search"
    label = "日志" if kind == "event" else "告警"
    return f'''<form id="{kind}-ip-form" class="local-ip-search"><div class="ip-form"><label for="{prefix}-ip">搜索来源 IP</label><input id="{prefix}-ip" type="text" maxlength="128" placeholder="输入完整 IPv4 / IPv6" autocomplete="off" autocapitalize="off" spellcheck="false" aria-describedby="{kind}-search-scope {kind}-search-coverage"><button type="submit">搜索 SSH {label}</button><button id="{kind}-ip-clear" type="button">清空搜索</button></div><div class="actions"><label for="{kind}-search-window">查询时间</label><select id="{kind}-search-window"><option value="24h">最近 24 小时</option><option value="custom">自定义 / 网络事件时段</option><option value="all">全部保留时间</option></select><button id="{kind}-search-all" type="button">扩展到全部保留时间</button></div><div id="{kind}-search-dates" class="search-fields" hidden><label for="{prefix}-start">开始时间（本地）<input id="{prefix}-start" type="datetime-local" step="1"></label><label for="{prefix}-end">结束时间（本地）<input id="{prefix}-end" type="datetime-local" step="1"></label></div></form><p id="{kind}-search-scope" class="search-scope" role="status" aria-live="polite"></p><p id="{kind}-search-coverage" class="muted search-scope"></p>'''


def arrange(html):
    head, body = html.split("<body>", 1)
    content, script = body.split("<script>", 1)
    prefix = content[:content.index("<section>")]
    sections = re.findall(r"<section(?:\s[^>]*)?>.*?</section>", content, flags=re.S)
    assert len(sections) == 8
    sections[0] = sections[0].replace("<section>", '<section id="overview-section">', 1)
    mapped = {re.search(r'id="([^"]+)"', section).group(1): section for section in sections}
    mapped["http-section"] = HTTP_SECTION
    mapped["network-section"] = NETWORK_SECTION
    mapped["joint-section"] = JOINT_SECTION
    detail = mapped.pop("detail-section")
    detail = detail.replace('<h2 id="detail-title">记录详情</h2>', '<div class="drawer-heading"><h2 id="detail-title">记录详情</h2><button id="detail-close" type="button" aria-label="关闭详情">关闭 ✕</button></div>', 1)
    original = '<pre id="detail">选择上方记录查看详情。</pre>'
    tabs = '<div class="detail-tabs" role="tablist" aria-label="详情内容">' + ''.join(
        f'<button id="detail-tab-{key}" type="button" role="tab" aria-controls="detail-pane-{key}" aria-selected="{str(key == "overview").lower()}">{label}</button>'
        for key, label in (("overview", "概览"), ("evidence", "证据"), ("ai", "AI 分析"))) + '</div>'
    detail = detail.replace(original, tabs + '<div id="detail-pane-overview" class="detail-pane" role="tabpanel" aria-labelledby="detail-tab-overview"><dl id="detail-fields" class="detail-fields"></dl><details><summary>完整记录</summary>' + original + '</details></div><div id="detail-pane-ai" class="detail-pane" role="tabpanel" aria-labelledby="detail-tab-ai" hidden>', 1)
    detail = detail.replace('<div id="evidence-view"', '</div><div id="detail-pane-evidence" class="detail-pane" role="tabpanel" aria-labelledby="detail-tab-evidence" hidden><div id="evidence-view"', 1)
    detail = detail.removesuffix('</section>') + '</div></section>'
    nav = '<nav class="workspace-nav" role="tablist" aria-label="控制台视图" aria-orientation="vertical"><div class="workspace-brand">RiskOps<small>安全运营控制台</small></div>'
    panels = []
    for key, label, section_id in VIEWS:
        active = key == 'incidents'
        nav += f'<button id="workspace-tab-{key}" type="button" role="tab" aria-controls="workspace-{key}" aria-selected="{str(active).lower()}" tabindex="{0 if active else -1}">{label}</button>'
        section = mapped[section_id]
        # Keep explanatory prose together; status elements stay next to controls.
        notes = [p for p in re.findall(r'<p>.*?</p>', section, flags=re.S) if 'id="' not in p]
        for note in notes:
            section = section.replace(note, '', 1)
        if notes:
            help_html = '<details class="help-note"><summary>查看说明</summary>' + ''.join(notes) + '</details>'
            section = re.sub(r'(<h2>.*?</h2>)', lambda match: match[0] + help_html, section, count=1, flags=re.S)
        if key == 'incidents':
            selected = '<button id="incident-control-open" type="button">查看已选目标与封禁预览（0）</button>'
            assert selected in section
            section = section.replace(selected, '', 1)
            section = section.replace('<div class="actions">', '<details id="incident-options" class="search-options"><summary>筛选与处置选项</summary><div class="actions">', 1)
            section = section.replace('</div><p id="incident-score-counts"', '</div></details>' + selected + '<p id="incident-score-counts"', 1)
            section = section.replace('</h2>', '</h2>' + ip_search_form('incident'), 1)
        if key == 'events':
            for field in ('ip', 'start', 'end'):
                section = re.sub(r'<label>[^<]*<input id="search-' + field + r'"[^>]*></label>', '', section, count=1)
            section = section.replace('</h2>', '</h2>' + ip_search_form('event'), 1)
            latest = '<button id="event-latest" type="button">获取最新日志</button>'
            section = section.replace(latest, '', 1)
            section = section.replace('<form id="search-form">', '<details id="event-search-options" class="search-options"><summary>高级筛选：账号、事件类型、消息关键字</summary><form id="search-form">', 1)
            section = section.replace('</form><p><small id="event-updated">', '</form></details>' + latest + '<p><small id="event-updated">', 1)
        panels.append(f'<div id="workspace-{key}" class="workspace-panel" role="tabpanel" aria-labelledby="workspace-tab-{key}"' + ('' if active else ' hidden') + '>' + section + '</div>')
    nav += '<div class="nav-note">证据核对 · 人工处置</div></nav>'
    prefix = prefix.replace('SecAgent RiskOps · 实时日志', '安全运营工作区', 1)
    prefix = prefix.replace('默认手动刷新，保留当前来源、筛选、页码与已打开的详情。日志查询固定在本次快照；点击“获取最新日志”重新查询并回到第一页。自动刷新仅在页面可见且没有读取任务时运行。', '后台同步概览与首页告警。日志翻页固定在本次快照；“获取最新日志”重新读取。自定义视图可选择刷新间隔。')
    prefix = prefix.replace('<div class="card">', '<div class="card"><span class="muted">SSH · </span>')
    sync = '<div id="console-sync-line" class="sync-line" data-stale="true"><span class="sync-dot" aria-hidden="true"></span><span id="console-sync" role="status">正在读取服务器准备的数据…</span></div>'
    return head + '<body><div class="workspace-shell">' + nav + '<main class="workspace-main"><header class="workspace-header">' + prefix + sync + '</header>' + ''.join(panels) + '</main></div><dialog id="detail-dialog" aria-labelledby="detail-title">' + detail + '</dialog>' + HTTP_DIALOG + NETWORK_DIALOG + JOINT_DIALOG + '<script>' + script
