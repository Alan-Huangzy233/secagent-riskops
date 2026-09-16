"""Run the shipped dashboard with an inert DOM and mocked HTTP only."""
from __future__ import annotations

from html.parser import HTMLParser
import json
import re
import shutil
import subprocess

import pytest

from app.telemetry.dashboard import DASHBOARD_HTML, _SCRIPT


class ControlsHTML(HTMLParser):
    def __init__(self):
        super().__init__()
        self.elements = {}
        self.duplicates = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if ident := values.get("id"):
            if ident in self.elements:
                self.duplicates.append(ident)
            self.elements[ident] = (tag, values)


def test_control_html_has_safe_defaults_and_all_bound_nodes():
    html = ControlsHTML()
    html.feed(DASHBOARD_HTML)
    assert not html.duplicates
    assert set(re.findall(r"\$\('([^']+)'\)", _SCRIPT)) <= html.elements.keys()
    assert "checked" in html.elements["control-channel-ssh"][1]
    assert "checked" not in html.elements["control-channel-tcp"][1]
    assert "checked" not in html.elements["control-channel-udp"][1]
    assert 'value="3600" selected' in DASHBOARD_HTML
    assert html.elements["control-reason"][1]["maxlength"] == "300"
    assert 'value="auth_success"' in DASHBOARD_HTML
    assert 'value="ssh_failure"' not in DASHBOARD_HTML
    assert 'value="ssh_success"' not in DASHBOARD_HTML
    assert "当前待核实" in _SCRIPT and "无法核实" in _SCRIPT
    assert "全部 TCP（包含 SSH）" in DASHBOARD_HTML
    assert "innerHTML" not in _SCRIPT


RUNNER = r"""
const vm=require('node:vm'),fs=require('node:fs'),assert=require('node:assert/strict');
const input=JSON.parse(fs.readFileSync(0,'utf8'));
class Element{
 constructor(tag){this.tag=tag;this.children=[];this._text='';this.value='';this.dataset={};this.listeners={};this.attrs={};this.checked=false;this.disabled=false;this.hidden=false;}
 set textContent(value){this._text=String(value);this.children=[];}
 get textContent(){return this._text+this.children.map(child=>child.textContent).join('');}
 append(...nodes){this.children.push(...nodes);}
 replaceChildren(...nodes){this.children=nodes;this._text='';}
 setAttribute(key,value){this.attrs[key]=value;} removeAttribute(key){delete this.attrs[key];}
 addEventListener(event,fn){this.listeners[event]=fn;}
 scrollIntoView(){}
 querySelectorAll(query){let result=[];for(const child of this.children){if(query==='input:checked'&&child.tag==='input'&&child.checked)result.push(child);result.push(...child.querySelectorAll(query));}return result;}
}
const nodes=new Map(),calls=[],timers=[];
const document={hidden:false,getElementById(id){if(!nodes.has(id))nodes.set(id,new Element('node'));return nodes.get(id);},createElement(tag){return new Element(tag);}};
const storage=new Map(),memory={getItem(key){return storage.get(key)||null;},setItem(key,value){storage.set(key,value);}};
const response=data=>({ok:true,status:200,json:async()=>data});
const context={document,assert,calls,timers,response,URLSearchParams,AbortController,Date,performance:{now:()=>100},localStorage:memory,sessionStorage:memory,
 setTimeout(fn,ms){timers.push({fn,ms});return timers.length;},clearTimeout(){},
 fetch:async(path,options={})=>{calls.push({path,options});if(!context.route)throw new Error('Unexpected request: '+path);return context.route(path,options);}};
vm.createContext(context);
vm.runInContext(input.script.replace(/refresh\(\);\s*$/,''),context);
document.getElementById('control-duration').value='3600';document.getElementById('control-channel-ssh').checked=true;document.getElementById('refresh-interval').value='0';
vm.runInContext('(async()=>{'+input.scenario+'})()',context).then(result=>process.stdout.write(JSON.stringify(result??{ok:true}))).catch(error=>{process.stderr.write(error.stack);process.exitCode=1;});
"""


def run_dashboard(scenario):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is optional for the inert dashboard regression")
    result = subprocess.run(
        [node, "-e", RUNNER], input=json.dumps({"script": _SCRIPT, "scenario": scenario}),
        text=True, encoding="utf-8", capture_output=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_only_explicit_incident_targets_are_selected_and_source_scoped():
    run_dashboard(r"""
const incident={incident_id:'example',source_id:'source-a',source_ids:['source-a','source-b'],src_ip:'192.0.2.7',status:'open'};
renderIncidents([incident,{...incident,src_ip:'192.0.2.8'}]);
assert.equal(selectedTargets.size,0);
const checkbox=$('incidents').children[0].children[5].children[1].children[0];
checkbox.checked=true;checkbox.listeners.change();
assert.equal(selectedTargets.size,2);
assert.deepEqual([...selectedTargets.values()].map(t=>t.ip),['192.0.2.7','192.0.2.7']);
renderIncidents([{...incident,src_ip:'192.0.2.9'}]);
assert.equal(selectedTargets.size,2,'Navigating a page must not add its IPs');
selectedTargets.clear();currentSource='source-b';
assert.deepEqual(incidentTargets(incident),[{source_id:'source-b',ip:'192.0.2.7'}]);
assert.equal(calls.length,0,'Selection alone must never call an execution endpoint');
""")


def test_preview_confirmation_csrf_and_job_polling_are_separate():
    run_dashboard(r"""
const capability={enabled:true,csrf_token:'fixture-csrf',sources:[{source_id:'source-a',hostname:'fixture',ssh_ports:[2222]}],blocks:[],source_checks:[],jobs:[]};
let checks=0;
route=(path,options)=>{
 if(path==='/api/controls')return response(capability);
 if(path==='/api/controls/preview'){const body=JSON.parse(options.body);return response({plan_id:'fixture-plan',expires_at:Date.now()/1000+300,items:body.targets.map(t=>({...t,channel:'ssh',action:'ban',duration_seconds:3600}))});}
 if(path==='/api/controls/execute')return response({id:'fixture-job',status:'queued',items:[]});
 if(path==='/api/controls/jobs/fixture-job')return response({id:'fixture-job',status:++checks===1?'running':'done',items:[{source_id:'source-a',ip:'192.0.2.7',channel:'ssh',status:'ok'}]});
 throw new Error('Unexpected path '+path);
};
await loadControls();selectedTargets.set('fixture',{source_id:'source-a',ip:'192.0.2.7'});$('control-reason').value='人工核查扫描证据';
await previewControl();assert.equal($('control-plan').hidden,false);assert.equal($('control-execute').disabled,true);
const preview=calls.find(call=>call.path==='/api/controls/preview');
assert.deepEqual(JSON.parse(preview.options.body),{action:'ban',targets:[{source_id:'source-a',ip:'192.0.2.7'}],channels:['ssh'],duration_seconds:3600,reason:'人工核查扫描证据'});
assert.equal(preview.options.headers['X-RiskOps-CSRF'],'fixture-csrf');
await executeControl();assert.equal(calls.filter(call=>call.path==='/api/controls/execute').length,0);
$('control-confirm').checked=true;controlState();await executeControl();
assert.equal(calls.filter(call=>call.path==='/api/controls/execute').length,1);
assert.deepEqual(JSON.parse(calls.find(call=>call.path==='/api/controls/execute').options.body),{plan_id:'fixture-plan'});
assert.equal(timers[0].ms,3000);await executeControl();assert.equal(calls.filter(call=>call.path==='/api/controls/execute').length,1);
await timers[0].fn();assert.match($('control-job-title').textContent,/已完成/);assert.match($('control-job-items').textContent,/成功/);
""")


def test_edit_or_cancel_invalidates_preview_without_execution():
    run_dashboard(r"""
controlsData={enabled:true,csrf_token:'fixture-csrf'};selectedTargets.set('fixture',{source_id:'source-a',ip:'192.0.2.7'});$('control-reason').value='人工确认';
let finish;
route=()=>new Promise(resolve=>{finish=()=>resolve(response({plan_id:'old-plan',expires_at:Date.now()/1000+300,items:[{source_id:'source-a',ip:'192.0.2.7',channel:'ssh',action:'ban',duration_seconds:3600}]}));});
const pending=previewControl();$('control-duration').value='permanent';$('control-duration').listeners.input();finish();await pending;
assert.equal(controlPlan,null);assert.equal($('control-plan').hidden,true);
controlPlan={plan_id:'cancelled-plan'};$('control-confirm').checked=true;$('control-cancel').listeners.click();await executeControl();
assert.equal(controlPlan,null);assert.equal(calls.filter(call=>call.path==='/api/controls/execute').length,0);
""")


def test_unban_uses_exact_block_and_unknown_state_is_visible():
    run_dashboard(r"""
controlsData={enabled:true,csrf_token:'fixture-csrf',source_checks:[{source_id:'source-a',checked_at:1800000000,error:'连接失败'}]};
const block={source_id:'source-a',ip:'192.0.2.7',channel:'udp',expires_at:null,verified_at:1799999900};
renderBlocks([block]);assert.match($('control-blocks').textContent,/当前待核实/);assert.match($('control-source-checks').textContent,/无法核实：连接失败/);
route=(path,options)=>{assert.equal(path,'/api/controls/preview');const payload=JSON.parse(options.body);assert.deepEqual(payload.targets,[{source_id:'source-a',ip:'192.0.2.7'}]);assert.deepEqual(payload.channels,['udp']);assert.equal(payload.action,'unban');return response({plan_id:'unban-plan',items:[{...block,action:'unban'}]});};
await previewUnban(block);assert.match($('control-plan-title').textContent,/解封/);assert.equal(calls.length,1);
""")


def test_search_uses_server_snapshot_and_stale_request_cannot_replace_rows():
    run_dashboard(r"""
eventFilters={ip:'192.0.2.7',username:'root',q:'[preauth]'};eventSnapshot='r1:7';
const query=sourceQuery(3,'source-a','event');assert.equal(query.get('snapshot'),'r1:7');assert.equal(query.get('page'),'3');assert.equal(query.get('ip'),'192.0.2.7');assert.equal(query.get('q'),'[preauth]');
assert.equal(sourceQuery(2,'','incident').get('include_evidence'),'false');
const old=beginList('event',1),latest=beginList('event',2);
await acceptList(old,{items:[{event_id:'stale'}],total:2,total_pages:2,page:1,snapshot:'r1:old'});assert.equal(pages.event.displayed,null);
await acceptList(latest,{items:[{event_id:'new',source_id:'source-a',message:'current'}],total:2,total_pages:2,page:2,snapshot:'r1:7'});assert.equal(pages.event.displayed.items[0].event_id,'new');
const retry=beginList('event',2);failList(retry,new Error('读取失败'));assert.equal(pages.event.displayed.items[0].event_id,'new');assert.match($('event-status').textContent,/已保留第 2 页/);
""")


def test_incident_evidence_is_paginated_and_untrusted_messages_are_text():
    run_dashboard(r"""
const hostile='<img src=x onerror=alert(1)>';
route=path=>{
 if(path==='/api/incidents/fixture%2Fid')return response({incident_id:'fixture/id',evidence_count:75,rules:[]});
 if(path==='/api/incidents/fixture%2Fid/evidence?page=1&limit=50')return response({page:1,total_pages:2,total:75,items:[{timestamp:'2026-01-01T00:00:00Z',source_id:'source-a',message:hostile}]});
 if(path==='/api/incidents/fixture%2Fid/evidence?page=2&limit=50')return response({page:2,total_pages:2,total:75,items:[{source_id:'source-b',message:'last page'}]});
 throw new Error('Unexpected path '+path);
};
await showIncident({incident_id:'fixture/id'});assert.equal(calls.length,2);assert.equal($('evidence-view').hidden,false);
const message=$('evidence-rows').children[0].children[5];assert.equal(message.textContent,hostile);assert.equal(message.children.length,0);assert.match($('evidence-page').textContent,/共 2 页/);
await loadEvidence(2);assert.equal($('evidence-next').disabled,true);assert.match($('evidence-rows').textContent,/source-b/);assert.match($('evidence-page').textContent,/第 2 页/);
""")
