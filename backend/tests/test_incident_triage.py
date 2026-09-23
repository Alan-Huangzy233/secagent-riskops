"""Incident triage: operator transitions, verified-block resolution, reopening."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.live_api import create_app
from app.telemetry import control as control_module
from app.telemetry import store as module
from app.telemetry.config import LiveConfig, hash_operator_password
from app.telemetry.control import ControlService
from app.telemetry.store import TRIAGE_STATES, TRIAGE_TRANSITIONS, TelemetryStore
from test_dashboard_control import run_dashboard
from test_manual_control import PASSWORD, FakeTransport

NOW = datetime(2026, 9, 16, 12, tzinfo=timezone.utc)
PEER = "198.51.100.23"
AUTH = ("operator", PASSWORD)


@pytest.fixture
def clock(monkeypatch):
    value = SimpleNamespace(now=NOW)
    monkeypatch.setattr(module, "_now", lambda: value.now)
    monkeypatch.setattr(control_module.time, "time", lambda: value.now.timestamp())
    return value


@pytest.fixture
def store(tmp_path, clock):
    return TelemetryStore(tmp_path / "live.sqlite")


def failure(event_id, at, *, ip=PEER, user="root"):
    return {"event_id": event_id, "timestamp": at.isoformat(), "identifier": "sshd", "unit": "ssh.service",
            "message": f"Failed password for invalid user {user} from {ip} port 42000 ssh2"}


def burst(store, source, start, *, prefix="", count=3, step=20, ip=PEER):
    rows = [failure(f"{prefix}{source}-{index}", start + timedelta(seconds=step * index), ip=ip) for index in range(count)]
    return store.ingest(source, "host-" + source[-1], f"{prefix}{source}-{start.timestamp()}", rows)


def only(store, **filters):
    incident, = store.list_incidents(**filters)
    return incident


def two_incidents_one_peer(store):
    """Two separate incidents for one peer on one source: (survivor, absorbed).

    A merge keeps the identity created first; the fixed clock makes both
    creation times equal, so the store's tie-break on incident_id decides.
    """
    burst(store, "source-a", NOW - timedelta(minutes=100))
    burst(store, "source-a", NOW - timedelta(minutes=20), prefix="late-")
    ordered = sorted(store.list_incidents(), key=lambda item: (item["created_at"], item["incident_id"]))
    return ordered[0]["incident_id"], ordered[1]["incident_id"]


def bridge(store):
    """Low-rate failures that make the two incidents one slow scan."""
    rows = [failure(f"bridge-{index}", NOW - timedelta(minutes=80 - 10 * index)) for index in range(6)]
    store.ingest("source-a", "host-a", "bridge", rows)


def log(store, incident_id):
    return [(entry["from_state"], entry["to_state"], entry["cause"], entry["actor"])
            for entry in reversed(store.get_incident(incident_id)["triage_log"])]


def test_new_incidents_are_pending_and_operator_transitions_follow_the_table(store):
    burst(store, "source-a", NOW - timedelta(minutes=30))
    incident = only(store)
    assert incident["triage_status"] == "pending" and incident["triage_updated_at"] is None
    assert store.get_incident(incident["incident_id"])["triage_log"] == []
    assert store.triage_counts() == {"pending": 1, "acknowledged": 0, "resolved": 0, "total": 1}
    identity = incident["incident_id"]

    result = store.set_triage([identity], "acknowledged", actor="operator", note="  looking  ")
    assert result["changed"] == 1 and result["results"][0]["result"] == "changed"
    assert result["results"][0]["previous"] == "pending" and result["results"][0]["state"] == "acknowledged"
    assert result["triage_counts"]["acknowledged"] == 1
    assert store.set_triage([identity], "acknowledged", actor="operator")["results"][0]["result"] == "unchanged"
    assert store.set_triage([identity], "resolved", actor="operator")["results"][0]["result"] == "changed"
    refused = store.set_triage([identity], "acknowledged", actor="operator")
    assert refused["changed"] == 0 and refused["results"][0]["result"] == "invalid"
    assert refused["results"][0]["state"] == "resolved"
    assert store.set_triage(["SSH-missing"], "pending", actor="operator")["results"] == [{"incident_id": "SSH-missing", "result": "missing"}]
    detail = store.get_incident(identity)
    assert detail["triage_status"] == "resolved" and detail["triage_updated_at"] == "2026-09-16T12:00:00.000000Z"
    assert log(store, identity) == [("pending", "acknowledged", "manual", "operator"), ("acknowledged", "resolved", "manual", "operator")]
    assert detail["triage_log"][-1]["note"] == "looking" and detail["triage_log"][0]["note"] is None
    assert "triage_ts" not in detail
    for state in TRIAGE_STATES:
        assert TRIAGE_TRANSITIONS[state] and state not in TRIAGE_TRANSITIONS[state]


def test_transition_validation_rejects_bad_input(store):
    with pytest.raises(ValueError, match="state"):
        store.set_triage(["x"], "closed", actor="operator")
    with pytest.raises(ValueError, match="incident_ids"):
        store.set_triage([], "pending", actor="operator")
    with pytest.raises(ValueError, match="incident_ids"):
        store.set_triage(["x"] * 101, "pending", actor="operator")
    with pytest.raises(ValueError, match="note"):
        store.set_triage(["x"], "pending", actor="operator", note="n" * 301)
    with pytest.raises(ValueError, match="actor"):
        store.set_triage(["x"], "pending", actor="")
    with pytest.raises(ValueError, match="triage"):
        store.paginate_incidents(triage="closed")


def test_lists_filter_by_state_and_report_counts_per_source_scope(store):
    burst(store, "source-a", NOW - timedelta(minutes=50))
    burst(store, "source-b", NOW - timedelta(minutes=10))
    latest, earlier = [item["incident_id"] for item in store.list_incidents()]
    assert only(store, source_id="source-b")["incident_id"] == latest
    store.set_triage([latest], "resolved", actor="operator")
    page = store.paginate_incidents(triage="pending", include_evidence=False)
    assert [item["incident_id"] for item in page["items"]] == [earlier]
    assert page["total"] == 1 and page["triage"] == "pending"
    assert page["triage_counts"] == {"pending": 1, "acknowledged": 0, "resolved": 1, "total": 2}
    assert store.paginate_incidents(triage="all")["total"] == store.paginate_incidents()["total"] == 2
    assert [item["incident_id"] for item in store.list_incidents(triage="resolved")] == [latest]
    scoped = store.paginate_incidents("source-b", triage="pending")
    assert scoped["total"] == 0 and scoped["triage_counts"] == {"pending": 0, "acknowledged": 0, "resolved": 1, "total": 1}
    assert store.count_incidents() == 2 and store.get_source("source-b")["incident_count"] == 1


def test_merged_alias_resolves_to_the_canonical_incident(store):
    survivor, absorbed = two_incidents_one_peer(store)
    bridge(store)
    assert only(store)["incident_id"] == survivor
    result = store.set_triage([absorbed, survivor], "acknowledged", actor="operator")
    assert [item["result"] for item in result["results"]] == ["changed", "unchanged"]
    assert result["results"][0]["canonical_incident_id"] == survivor
    assert store.get_incident(absorbed)["triage_status"] == "acknowledged"


def test_verified_block_resolves_only_fully_covered_incidents(store):
    # Two bursts ten minutes apart correlate as one cross-source incident.
    burst(store, "source-a", NOW - timedelta(minutes=40))
    burst(store, "source-b", NOW - timedelta(minutes=30))
    burst(store, "source-a", NOW - timedelta(minutes=20), ip="203.0.113.9", prefix="other-")
    shared = only(store, triage="pending", source_id="source-b")
    assert shared["source_ids"] == ["source-a", "source-b"]
    assert store.resolve_blocked_incidents(PEER, ["source-a"], actor="operator", reference="job-1") == []
    assert store.resolve_blocked_incidents(PEER, [], actor="operator", reference="job-1") == []
    assert store.get_incident(shared["incident_id"])["triage_status"] == "pending"
    resolved = store.resolve_blocked_incidents(PEER, ["source-b", "source-a", "source-c"], actor="operator",
                                               reference="job-2", note="scan confirmed")
    assert resolved == [shared["incident_id"]]
    detail = store.get_incident(shared["incident_id"])
    assert detail["triage_status"] == "resolved"
    assert detail["triage_log"][0]["cause"] == "block" and detail["triage_log"][0]["reference"] == "job-2"
    assert detail["triage_log"][0]["note"] == "scan confirmed"
    assert store.resolve_blocked_incidents(PEER, ["source-a", "source-b"], actor="operator", reference="job-3") == []
    other = only(store, triage="pending")
    assert other["src_ip"] == "203.0.113.9"
    with pytest.raises(ValueError):
        store.resolve_blocked_incidents("not-an-ip", ["source-a"], actor="operator", reference="job-4")


def test_newer_evidence_reopens_a_resolved_incident_but_older_evidence_does_not(store, clock):
    burst(store, "source-a", NOW - timedelta(seconds=120))
    identity = only(store)["incident_id"]
    store.set_triage([identity], "resolved", actor="operator")
    # Collector lag delivers a record from before the resolution.
    store.ingest("source-a", "host-a", "late", [failure("late", NOW - timedelta(seconds=30))])
    assert only(store, triage="all")["triage_status"] == "resolved"
    assert only(store, triage="all")["failure_count"] == 4
    clock.now = NOW + timedelta(minutes=2)
    store.ingest("source-a", "host-a", "again", [failure("again", NOW + timedelta(seconds=60))])
    reopened = only(store, triage="pending")
    assert reopened["incident_id"] == identity and reopened["failure_count"] == 5
    entry = store.get_incident(identity)["triage_log"][0]
    assert (entry["from_state"], entry["to_state"], entry["cause"], entry["actor"]) == ("resolved", "pending", "evidence", "system")
    assert entry["reference"] == '{"event_id":"again","source_id":"source-a"}'
    # Acknowledged means "seen"; further activity does not change that.
    store.set_triage([identity], "acknowledged", actor="operator")
    store.ingest("source-a", "host-a", "more", [failure("more", NOW + timedelta(seconds=90))])
    assert only(store, triage="all")["triage_status"] == "acknowledged"
    assert store.rebuild_detections()["incidents_created"] == 0
    assert only(store, triage="all")["triage_status"] == "acknowledged"


def test_merge_keeps_the_least_handled_state(store):
    survivor, absorbed = two_incidents_one_peer(store)
    store.set_triage([survivor], "resolved", actor="operator")
    bridge(store)
    incident = only(store)
    assert incident["incident_id"] == survivor and incident["triage_status"] == "pending"
    assert store.get_incident(absorbed)["triage_status"] == "pending"
    assert log(store, survivor) == [("pending", "resolved", "manual", "operator"), ("resolved", "pending", "merge", "system")]
    assert store.get_incident(survivor)["triage_log"][0]["reference"] == absorbed


def test_older_database_without_triage_tables_is_upgraded_in_place(tmp_path, clock):
    first = TelemetryStore(tmp_path / "live.sqlite")
    burst(first, "source-a", NOW - timedelta(minutes=5))
    with first._connection(write=True) as db:
        db.executescript("DROP TABLE incident_triage_log; DROP TABLE incident_triage;")
    upgraded = TelemetryStore(tmp_path / "live.sqlite")
    incident = only(upgraded)
    assert incident["triage_status"] == "pending"
    assert upgraded.set_triage([incident["incident_id"]], "resolved", actor="operator")["changed"] == 1


# ---------------------------------------------------------------------------
# HTTP surface and the control-channel hook
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def password_hash():
    return hash_operator_password(PASSWORD)


@pytest.fixture
def config(tmp_path, password_hash):
    return LiveConfig(database_path=str(tmp_path / "telemetry.sqlite3"),
        sources=[{"id": "source-a", "hostname": "host-a", "token_sha256": hashlib.sha256(b"token-a-tests-only-1234567890").hexdigest()},
                 {"id": "source-b", "hostname": "host-b", "token_sha256": hashlib.sha256(b"token-b-tests-only-1234567890").hexdigest()}],
        operator_username="operator", operator_password_pbkdf2=password_hash)


@pytest.fixture
def control_config(tmp_path):
    return {"database_path": str(tmp_path / "controls.sqlite"), "ssh_config": str(tmp_path / "ssh-config"),
            "sources": [{"source_id": "source-a", "ssh_host": "control-a", "ssh_ports": [22]},
                        {"source_id": "source-b", "ssh_host": "control-b", "ssh_ports": [22]}],
            "protected_networks": ["192.0.2.0/28"]}


@pytest.fixture
def transport():
    return FakeTransport()


@pytest.fixture
def service(config, control_config, transport, clock):
    return ControlService(control_config, config.sources, transport=transport)


@pytest.fixture
def client(config, store, service, monkeypatch):
    monkeypatch.setattr(control_module.subprocess, "run", lambda *a, **k: pytest.fail("no subprocess"))
    with TestClient(create_app(config, store=store, control=service)) as value:
        assert service._thread is None and service.block_listener is not None
        yield value


def headers(service, **changes):
    result = {"x-riskops-csrf": service.csrf_token, "Origin": "http://testserver"}
    result.update(changes)
    return result


def test_triage_endpoint_requires_operator_csrf_and_valid_body(client, store, service):
    burst(store, "source-a", NOW - timedelta(minutes=5))
    identity = only(store)["incident_id"]
    body = {"incident_ids": [identity], "state": "acknowledged", "note": "seen"}
    assert client.post("/api/incidents/triage", json=body).status_code == 401
    assert client.post("/api/incidents/triage", json=body, auth=AUTH).status_code == 403
    assert client.post("/api/incidents/triage", json=body, auth=AUTH, headers=headers(service, Origin="http://evil.example")).status_code == 403
    assert client.post("/api/incidents/triage", content="incident_ids=x", auth=AUTH,
                       headers=headers(service, **{"content-type": "text/plain"})).status_code == 415
    for bad in ({"incident_ids": [identity], "state": "closed"}, {"incident_ids": [], "state": "pending"},
                {"incident_ids": [identity], "state": "pending", "extra": 1},
                {"incident_ids": [identity], "state": "pending", "note": "n" * 301}, [identity]):
        assert client.post("/api/incidents/triage", json=bad, auth=AUTH, headers=headers(service)).status_code == 422
    assert store.get_incident(identity)["triage_status"] == "pending"
    response = client.post("/api/incidents/triage", json=body, auth=AUTH, headers=headers(service))
    assert response.status_code == 200
    payload = response.json()
    assert payload["changed"] == 1 and payload["results"][0]["state"] == "acknowledged"
    assert payload["triage_counts"] == {"pending": 0, "acknowledged": 1, "resolved": 0, "total": 1}
    assert store.get_incident(identity)["triage_log"][0]["actor"] == "operator"


def test_incident_reads_expose_state_filter_counts_and_history(client, store, service):
    burst(store, "source-a", NOW - timedelta(minutes=50))
    burst(store, "source-b", NOW - timedelta(minutes=10))
    first, second = [item["incident_id"] for item in store.list_incidents()]
    store.set_triage([second], "resolved", actor="operator", note="handled")
    summary = client.get("/api/summary", auth=AUTH).json()
    assert summary["totals"]["incidents"] == 2
    assert summary["triage_counts"] == {"pending": 1, "acknowledged": 0, "resolved": 1, "total": 2}
    listed = client.get("/api/incidents", params={"page": 1, "triage": "pending", "include_evidence": "false"}, auth=AUTH).json()
    assert [item["incident_id"] for item in listed["items"]] == [first] and listed["triage_counts"]["resolved"] == 1
    assert [item["incident_id"] for item in client.get("/api/incidents", params={"triage": "resolved"}, auth=AUTH).json()] == [second]
    assert client.get("/api/incidents", params={"triage": "closed"}, auth=AUTH).status_code == 422
    assert client.get("/api/incidents", params={"page": 1}, auth=AUTH).json()["total"] == 2
    snapshot = client.get("/api/dashboard", params={"incident_triage": "resolved"}, auth=AUTH).json()
    assert [item["incident_id"] for item in snapshot["incidents"]["items"]] == [second]
    assert snapshot["summary"]["triage_counts"]["pending"] == 1
    assert client.get("/api/dashboard", params={"incident_triage": "nope"}, auth=AUTH).status_code == 422
    detail = client.get(f"/api/incidents/{second}", auth=AUTH).json()
    assert detail["triage_status"] == "resolved" and detail["triage_log"][0]["note"] == "handled"
    assert "triage_log" not in listed["items"][0]


def test_verified_ban_marks_covered_incidents_resolved_with_job_reference(client, store, service, transport):
    burst(store, "source-a", NOW - timedelta(minutes=40))
    burst(store, "source-b", NOW - timedelta(minutes=30))
    shared = only(store)
    assert shared["source_ids"] == ["source-a", "source-b"]
    plan = client.post("/api/controls/preview", auth=AUTH, headers=headers(service), json={
        "action": "ban", "targets": [{"source_id": "source-a", "ip": PEER}, {"source_id": "source-b", "ip": PEER}],
        "channels": ["ssh"], "duration_seconds": 3600, "reason": "confirmed scan"}).json()
    job = client.post("/api/controls/execute", auth=AUTH, headers=headers(service), json={"plan_id": plan["plan_id"]}).json()
    assert service.run_once()
    assert store.get_incident(shared["incident_id"])["triage_status"] == "pending", "one covered source is not enough"
    assert service.run_once()
    detail = store.get_incident(shared["incident_id"])
    assert detail["triage_status"] == "resolved"
    assert detail["triage_log"][0]["reference"] == job["id"] and detail["triage_log"][0]["note"] == "confirmed scan"
    assert detail["triage_log"][0]["cause"] == "block" and detail["triage_log"][0]["actor"] == "operator"
    assert client.get("/api/controls/jobs/" + job["id"], auth=AUTH).json()["status"] == "done"
    assert client.get("/api/incidents", params={"page": 1, "triage": "pending"}, auth=AUTH).json()["total"] == 0


def test_udp_only_bans_and_listener_failures_never_touch_incidents_or_jobs(client, store, service, transport):
    burst(store, "source-a", NOW - timedelta(minutes=5))
    identity = only(store)["incident_id"]
    plan = service.preview("operator", {"action": "ban", "targets": [{"source_id": "source-a", "ip": PEER}],
                                        "channels": ["udp"], "duration_seconds": 3600, "reason": "udp only"})
    service.execute("operator", plan["plan_id"])
    assert service.run_once()
    assert store.get_incident(identity)["triage_status"] == "pending"

    calls = []

    def failing(event):
        calls.append(event)
        raise RuntimeError("bookkeeping unavailable")

    service.block_listener = failing
    plan = service.preview("operator", {"action": "ban", "targets": [{"source_id": "source-a", "ip": PEER}],
                                        "channels": ["ssh"], "duration_seconds": None, "reason": "permanent"})
    job = service.execute("operator", plan["plan_id"])
    assert service.run_once()
    assert calls == [{"ip": PEER, "source_ids": ["source-a"], "job_id": job["id"], "actor": "operator", "reason": "permanent"}]
    assert service.job(job["id"])["status"] == "done"
    assert store.get_incident(identity)["triage_status"] == "pending"
    with service.connection() as db:
        events = [row[0] for row in db.execute("SELECT event FROM audit ORDER BY seq")]
    assert events[-1] == "incident_update_failed" and events[-2] == "result"


# ---------------------------------------------------------------------------
# Dashboard behaviour with an inert DOM
# ---------------------------------------------------------------------------

def test_dashboard_filters_by_state_renders_badges_and_reloads_after_triage_or_block():
    run_dashboard(r"""
assert.equal(incidentTriage,'pending');
assert.equal(sourceQuery(2,'source-a','incident').get('triage'),'pending');
incidentTriage='resolved';assert.equal(sourceQuery(1,'','incident').get('triage'),'resolved');assert.equal(listKey('incident'),'resolved');incidentTriage='pending';
const incident={incident_id:'SSH-1',source_id:'source-a',source_ids:['source-a'],src_ip:'192.0.2.7',status:'open',triage_status:'pending'};
renderIncidents([incident,{...incident,incident_id:'SSH-2',triage_status:'resolved',triage_updated_at:'2026-09-16T12:00:00Z'}]);
const first=$('incidents').children[0].children[5],second=$('incidents').children[1].children[5];
assert.equal(first.children[0].textContent,'待处理');assert.equal(first.children[0].className,'triage triage-pending');
assert.equal(first.children[2].children.map(b=>b.textContent).join('|'),'标为已知晓|标为已处理');
assert.equal(typeof first.children[2].children[0].listeners.click,'function');
assert.equal(second.children[0].textContent,'已处理');assert.match(second.children[1].textContent,/更新于/);
assert.equal(second.children[3].children.map(b=>b.textContent).join('|'),'重新打开');
renderTriageCounts({pending:3,acknowledged:1,resolved:7,total:11});
assert.equal($('incident-total').textContent,'3');assert.match($('incident-triage-summary').textContent,/已知晓 1 · 已处理 7 · 合计 11/);
await triageIncident('SSH-1','acknowledged');assert.match($('triage-status').textContent,/操作校验尚未准备好/);
assert.equal(calls.filter(call=>call.path==='/api/incidents/triage').length,0,'no CSRF token means no write request');calls.length=0;
controlsData={enabled:false,csrf_token:'fixture-csrf'};$('triage-note').value=' internal scan ';
route=(path,options)=>{
 if(path==='/api/incidents/triage'){const body=JSON.parse(options.body);assert.deepEqual(body,{incident_ids:['SSH-1'],state:'acknowledged',note:'internal scan'});assert.equal(options.headers['X-RiskOps-CSRF'],'fixture-csrf');return response({changed:1,results:[{incident_id:'SSH-1',result:'changed',state:'acknowledged'}],triage_counts:{pending:2,acknowledged:2,resolved:7,total:11}});}
 if(path.startsWith('/api/incidents?')){assert.ok(path.includes('triage=pending'));return response({items:[],total:0,total_pages:1,page:1,triage_counts:{pending:0,acknowledged:2,resolved:7,total:9}});}
 throw new Error('Unexpected path '+path);
};
await triageIncident('SSH-1','acknowledged');
assert.match($('triage-status').textContent,/已将告警标为已知晓/);
assert.equal(calls.filter(call=>call.path==='/api/incidents/triage').length,1);
assert.equal(calls.filter(call=>call.path.startsWith('/api/incidents?')).length,1,'the list reloads after a state change');
assert.equal($('incident-total').textContent,'0');
calls.length=0;
route=path=>{
 if(path==='/api/controls/jobs/job-1')return response({id:'job-1',status:'done',items:[{source_id:'source-a',ip:'192.0.2.7',channel:'ssh',status:'ok'}]});
 if(path==='/api/controls')return response({enabled:true,csrf_token:'fixture-csrf',sources:[],blocks:[],source_checks:[],jobs:[]});
 if(path.startsWith('/api/incidents?'))return response({items:[],total:0,total_pages:1,page:1});
 throw new Error('Unexpected path '+path);
};
await watchJob('job-1');
assert.equal(calls.filter(call=>call.path.startsWith('/api/incidents?')).length,1,'finished block jobs reload the incident list');
assert.match($('control-status').textContent,/自动标为已处理/);
$('incident-triage').value='all';$('incident-triage').listeners.change();
assert.equal(incidentTriage,'all');assert.equal(JSON.parse(sessionStorage.getItem('riskops-view')).incidentTriage,'all');
assert.ok(calls.some(call=>call.path.startsWith('/api/incidents?')&&call.path.includes('triage=all')));
$('incident-triage').value='bogus';$('incident-triage').listeners.change();assert.equal(incidentTriage,'pending');
""")
