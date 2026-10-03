"""Manual-analysis controls embedded in the existing self-contained console."""

AI_PANEL = """
<div id="ai-panel" hidden><h3>AI 人工复核</h3>
<p>建议与规则评分分别展示。复核只记录你的意见；事件处置仍使用原有操作。</p>
<p id="ai-status" role="status"></p><p id="ai-meta" class="muted"></p>
<div class="actions"><button id="ai-preview-button" type="button">预览分析摘要</button>
<button id="ai-start" type="button" disabled>开始分析</button>
<button id="ai-reload" type="button">刷新结果</button></div>
<pre id="ai-preview" hidden></pre><p id="ai-job-state" role="status"></p>
<div id="ai-result" hidden><p id="ai-verdict"></p><p id="ai-rationale"></p>
<details><summary>查看证据引用、校验原因与版本</summary><pre id="ai-result-details"></pre></details></div>
<div id="ai-history" class="actions"></div>
<form id="ai-feedback" hidden><label for="ai-review">复核意见</label>
<select id="ai-review"><option value="agree">同意建议</option><option value="disagree">不同意建议</option>
<option value="needs_more">需要更多证据</option></select>
<label for="ai-note">说明（可选）</label><textarea id="ai-note" maxlength="1000" rows="2"></textarea>
<button id="ai-review-save" type="submit">保存复核意见</button><p id="ai-review-status" role="status"></p></form>
</div>
"""

AI_SCRIPT = """
let aiEpoch=0,aiPreview=null,aiConfig=null,aiJob=null,aiTimer=null,aiBusy=false;
const aiStates={queued:'等待分析',running:'分析中',recoverable:'恢复已完成的调用',complete:'分析完成，待人工复核',
 review:'需要人工复核',uncertain:'调用结果待核实，费用预留保留',budget_exhausted:'预算不足，未发起调用',
 failed:'分析失败',stale:'证据已更新，请重新预览'};
function aiClear(){
 ++aiEpoch;if(aiTimer!==null)clearTimeout(aiTimer);aiTimer=null;aiPreview=null;aiJob=null;aiBusy=false;
 $('ai-panel').hidden=true;$('ai-preview').hidden=true;$('ai-result').hidden=true;$('ai-feedback').hidden=true;
 $('ai-start').disabled=true;$('ai-history').replaceChildren();text('ai-job-state','');text('ai-review-status','');
}
async function aiPost(path,body){
 const response=await fetch(path,{method:'POST',credentials:'same-origin',cache:'no-store',
  headers:{'Content-Type':'application/json','X-RiskOps-CSRF':aiConfig?.csrf_token||''},body:JSON.stringify(body)});
 const data=await response.json().catch(()=>null);
 if(!response.ok)throw new Error(response.status===409?'证据或配置可能已变化，请重新预览后再试。':
  response.status===403?'操作校验已过期，请刷新分析区域。':data?.detail&&typeof data.detail==='string'?data.detail:'分析服务暂不可用。');
 return data;
}
function aiRenderJob(job){
 aiJob=job;text('ai-job-state',(aiStates[job.state]||job.state)+(job.stale?' · 旧版本：证据或配置已更新':''));
 $('ai-result').hidden=!job.result;
 if(job.result){
  const result=job.result,checked=result.metadata?.evidence_validation||{};
  const labels={escalate:'建议优先人工核查',dismiss:'可能噪声，仍待人工复核',abstain:'需要人工复核'};
  text('ai-verdict',(labels[result.verdict]||'需人工复核')+' · '+result.model);
  text('ai-rationale',result.model==='offline-review'?'这是本地流程演练，未调用模型。':
   '模型原始理由（文字尚需复核）：'+(checked.proposal?.rationale||'未取得有效理由。'));
  text('ai-result-details',JSON.stringify({revision:job.case.revision,summary:job.local.meta,
   evidence_ids:result.evidence_ids,local_references:job.local.local_refs,claims:checked.proposal?.claims||[],
   validation_reasons:checked.reasons||[],estimated_additional_usd:result.metadata?.additional_usd||0},null,2));
 }
 $('ai-feedback').hidden=['queued','running','recoverable'].includes(job.state);
 const reviews=(job.audit||[]).filter(row=>row.event==='reviewed');
 text('ai-review-status',reviews.length?'最近复核：'+({agree:'同意',disagree:'不同意',needs_more:'需要更多证据'}[reviews[0].details.verdict]||'已记录')+
  (reviews[0].details.note?' · '+reviews[0].details.note:''):'');
 if(job.error_code)text('ai-status','本次状态：'+(aiStates[job.state]||job.state)+'。可保留给人工处理。');
}
async function aiWatch(id,epoch=aiEpoch,attempt=0){
 try{
  const job=await get('/api/ai/jobs/'+encodeURIComponent(id));
  if(epoch!==aiEpoch)return;
  aiRenderJob(job);
  if(['queued','running','recoverable'].includes(job.state)){
   if(attempt<100)aiTimer=setTimeout(()=>aiWatch(id,epoch,attempt+1),3000);
   else text('ai-status','任务仍在处理中，可稍后刷新结果；再次点击相同摘要会复用该任务。');
  }
 }catch(error){if(epoch===aiEpoch)text('ai-status',error.message+' 可刷新结果，已有任务会保留。');}
}
async function loadAnalysis(id,showPreview=false){
 if(!id||id!==detailIncident)return;
 const epoch=++aiEpoch;if(aiTimer!==null)clearTimeout(aiTimer);aiTimer=null;
 $('ai-panel').hidden=false;$('ai-start').disabled=true;aiPreview=null;aiJob=null;
 $('ai-result').hidden=true;$('ai-feedback').hidden=true;$('ai-preview').hidden=true;
 text('ai-status','正在读取分析状态…');text('ai-job-state','');text('ai-review-status','');$('ai-history').replaceChildren();
 try{
  const config=await get('/api/ai/status');
  if(epoch!==aiEpoch||id!==detailIncident)return;
  aiConfig=config;$('ai-preview-button').disabled=!config.enabled;
  if(!config.enabled){text('ai-status',config.error?'分析配置暂不可用，事件仍可人工处理。':'人工 AI 分析尚未启用。');text('ai-meta','');return;}
  const preview=await get('/api/incidents/'+encodeURIComponent(id)+'/ai/preview');
  if(epoch!==aiEpoch||id!==detailIncident)return;
  aiPreview=preview;
  const mode={offline:'本地流程演练，不调用模型',recorded:'录制回放，本次不调用模型',api:'发送已批准的摘要给模型'}[config.mode];
  text('ai-status',mode+'。'+(showPreview?'请核对下方摘要后开始。':'先预览将用于分析的摘要。'));
  text('ai-meta','模型：'+config.model+' · 本次纳入 '+preview.meta.observed_included+' / '+preview.meta.evidence_count+
   ' 条观测 · '+({complete:'证据完整',gapped:'存在采集缺口',truncated:'摘要已截断',unknown:'完整性或部分字段未知',stale:'证据过期'}[preview.case.evidence_status]||'需复核'));
  text('ai-start',config.mode==='offline'?'提交本地演练':config.mode==='recorded'?'读取录制结果':'开始模型分析');
  text('ai-preview',JSON.stringify(preview.case,null,2));$('ai-preview').hidden=!showPreview;$('ai-start').disabled=!showPreview;
  for(const job of preview.history){
   const button=document.createElement('button');button.type='button';
   button.textContent=when(job.created*1000)+' · '+(aiStates[job.state]||job.state)+(job.stale?' · 旧版本':'');
   button.addEventListener('click',()=>{++aiEpoch;if(aiTimer!==null)clearTimeout(aiTimer);aiWatch(job.id);});
   $('ai-history').append(button);
  }
  if(preview.history.length){aiRenderJob(preview.history[0]);if(['queued','running','recoverable'].includes(preview.history[0].state))aiWatch(preview.history[0].id,epoch);}
 }catch(error){if(epoch===aiEpoch)text('ai-status',error.message+' 请刷新分析区域，原有采集和人工处置不受影响。');}
}
$('ai-preview-button').addEventListener('click',()=>loadAnalysis(detailIncident,true));
$('ai-reload').addEventListener('click',()=>loadAnalysis(detailIncident));
$('ai-start').addEventListener('click',async()=>{
 if(aiBusy||!aiPreview||!detailIncident)return;
 const epoch=aiEpoch,id=detailIncident,preview=aiPreview;aiBusy=true;$('ai-start').disabled=true;
 try{
  const job=await aiPost('/api/incidents/'+encodeURIComponent(id)+'/ai',{preview_key:preview.preview_key});
  if(epoch!==aiEpoch||id!==detailIncident)return;
  text('ai-status','任务已保存；相同证据和配置会复用此任务。');aiRenderJob(job);await aiWatch(job.id,epoch);
 }catch(error){if(epoch===aiEpoch){aiPreview=null;text('ai-status',error.message);}}
 finally{aiBusy=false;}
});
$('ai-feedback').addEventListener('submit',async event=>{
 event.preventDefault();if(!aiJob||aiBusy)return;
 const epoch=aiEpoch,id=aiJob.id;aiBusy=true;$('ai-review-save').disabled=true;
 try{
  const job=await aiPost('/api/ai/jobs/'+encodeURIComponent(id)+'/review',
   {verdict:$('ai-review').value,note:$('ai-note').value});
  if(epoch!==aiEpoch)return;aiRenderJob(job);text('ai-status','复核意见已保存。');
 }catch(error){if(epoch===aiEpoch)text('ai-review-status',error.message);}
 finally{aiBusy=false;$('ai-review-save').disabled=false;}
});
"""
