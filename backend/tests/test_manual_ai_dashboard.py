"""Exercise the shipped analysis controls without external requests."""

from test_dashboard_control import run_dashboard


def test_preview_enqueue_poll_and_feedback_are_explicit_and_text_only():
    run_dashboard(r"""
detailIncident='fixture';const hostile='<img src=x onerror=alert(1)>';
const job={id:'job',state:'complete',created:1800000000,stale:false,case:{revision:'r1'},
 local:{meta:{},local_refs:{}},audit:[],result:{verdict:'escalate',model:'fixture-model',evidence_ids:['E1'],
 metadata:{additional_usd:0,evidence_validation:{proposal:{rationale:hostile,claims:[]},reasons:[]}}}};
route=(path,options)=>{
 if(path==='/api/ai/status')return response({enabled:true,mode:'offline',model:'offline-review',csrf_token:'fixture-csrf'});
 if(path==='/api/incidents/fixture/ai/preview')return response({preview_key:'frozen',case:{revision:'r1',evidence_status:'complete'},
  meta:{observed_included:3,evidence_count:3},history:[]});
 if(path==='/api/incidents/fixture/ai'){
  assert.deepEqual(JSON.parse(options.body),{preview_key:'frozen'});
  assert.equal(options.headers['X-RiskOps-CSRF'],'fixture-csrf');return response({...job,state:'queued',result:null});
 }
 if(path==='/api/ai/jobs/job')return response(job);
 if(path==='/api/ai/jobs/job/review'){
  assert.deepEqual(JSON.parse(options.body),{verdict:'needs_more',note:'human review'});
  return response({...job,audit:[{event:'reviewed',details:{verdict:'needs_more',note:'human review'}}]});
 }
 throw new Error('unexpected '+path);
};
await loadAnalysis('fixture');assert.equal($('ai-start').disabled,true);
assert.equal(calls.filter(c=>c.options.method==='POST').length,0);
await loadAnalysis('fixture',true);assert.equal($('ai-start').disabled,false);assert.equal($('ai-preview').hidden,false);
await $('ai-start').listeners.click();
assert.equal(calls.filter(c=>c.path==='/api/incidents/fixture/ai'&&c.options.method==='POST').length,1);
assert.match($('ai-rationale').textContent,/<img/);assert.equal($('ai-rationale').children.length,0);
$('ai-review').value='needs_more';$('ai-note').value='human review';
await $('ai-feedback').listeners.submit({preventDefault(){}});
assert.match($('ai-review-status').textContent,/需要更多证据/);
assert.equal(calls.some(c=>c.path==='/api/incidents/triage'||c.path.includes('/controls/execute')),false);
""")


def test_switching_incidents_discards_late_analysis_preview():
    run_dashboard(r"""
let finishOld,oldStarted;const started=new Promise(resolve=>oldStarted=resolve);
route=path=>{
 if(path==='/api/ai/status')return response({enabled:true,mode:'offline',model:'offline-review'});
 if(path==='/api/incidents/old/ai/preview')return new Promise(resolve=>{finishOld=()=>resolve(response({preview_key:'old',case:{revision:'old',evidence_status:'complete'},meta:{observed_included:1,evidence_count:1},history:[]}));oldStarted();});
 if(path==='/api/incidents/new/ai/preview')return response({preview_key:'new',case:{revision:'new',evidence_status:'complete'},meta:{observed_included:2,evidence_count:2},history:[]});
 throw new Error(path);
};
detailIncident='old';const pending=loadAnalysis('old',true);
await started;
clearDetails();detailIncident='new';await loadAnalysis('new',true);finishOld();await pending;
assert.equal(aiPreview.preview_key,'new');assert.match($('ai-preview').textContent,/new/);
assert.equal(calls.some(c=>c.options.method==='POST'),false);
""")
