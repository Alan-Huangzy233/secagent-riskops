"""Operator controls use fake transport only; no test contacts a real host."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.live_api import create_app
from app.telemetry import control as module
from app.telemetry.config import LiveConfig, hash_operator_password
from app.telemetry.control import ControlService


PASSWORD = "operator-control-tests-only"
TOKEN = "collector-test-token-not-a-secret"
AUTH = ("operator", PASSWORD)


class FakeTransport:
    """Mutable in-memory remote state with deterministic response faults."""

    def __init__(self):
        self.calls = []
        self.outcomes = []
        self.blocks = {}

    def __call__(self, source, payload):
        self.calls.append((deepcopy(source), deepcopy(payload)))
        if self.outcomes:
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            if callable(outcome):
                return outcome(source, deepcopy(payload))
            if outcome is not None:
                return deepcopy(outcome)
        response = {"version": 1, "status": "ok", "source_id": source["source_id"],
                    "request_id": payload["request_id"]}
        if payload["action"] == "status":
            response.update(ready=True, table_present=True)
            response["blocks"] = [deepcopy(value) for key, value in self.blocks.items()
                                  if key[0] == source["source_id"]]
            return response
        key = (source["source_id"], payload["ip"], payload["channel"])
        if payload["action"] == "add":
            self.blocks[key] = {"ip": payload["ip"], "channel": payload["channel"],
                                "expires_at": payload["expires_at"]}
        else:
            self.blocks.pop(key, None)
        return {**response, "ip": payload["ip"], "channel": payload["channel"],
                "blocked": payload["action"] == "add",
                **({"expires_at": payload["expires_at"]} if payload["action"] == "add" else {})}


@pytest.fixture(autouse=True)
def prohibit_real_ssh(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("manual-control tests must not launch subprocesses or SSH")
    monkeypatch.setattr(module.subprocess, "run", forbidden)


@pytest.fixture
def clock(monkeypatch):
    value = SimpleNamespace(now=2_000_000_000.0)
    monkeypatch.setattr(module.time, "time", lambda: value.now)
    return value


@pytest.fixture(scope="module")
def password_hash():
    return hash_operator_password(PASSWORD)


@pytest.fixture
def config(tmp_path, password_hash):
    return LiveConfig(database_path=str(tmp_path / "telemetry.sqlite"),
        sources=[{"id": "server-a", "hostname": "host-a.example", "token_sha256": hashlib.sha256(TOKEN.encode()).hexdigest()},
                 {"id": "server-b", "hostname": "host-b.example", "token_sha256": hashlib.sha256(b"another-test-token").hexdigest()}],
        operator_username="operator", operator_password_pbkdf2=password_hash)


@pytest.fixture
def control_config(tmp_path):
    return {"database_path": str(tmp_path / "controls.sqlite"),
            "ssh_config": str(tmp_path / "unused-ssh-config"),
            "sources": [{"source_id": "server-a", "ssh_host": "control-a", "ssh_ports": [22]},
                        {"source_id": "server-b", "ssh_host": "control-b", "ssh_ports": [2222]}],
            "protected_networks": ["192.0.2.0/28", "2001:db8:1::/64"]}


@pytest.fixture
def transport():
    return FakeTransport()


@pytest.fixture
def service(config, control_config, transport, clock):
    return ControlService(control_config, config.sources, transport=transport)


@pytest.fixture
def client(config, service):
    with TestClient(create_app(config, control=service)) as value:
        assert service._thread is None
        yield value


def request(**changes):
    body = {"action": "ban", "targets": [{"source_id": "server-a", "ip": "203.0.113.30"}],
            "channels": ["ssh"], "duration_seconds": 3600, "reason": "Investigated SSH scan"}
    body.update(changes)
    return body


def queue(service, **changes):
    plan = service.preview("operator", request(**changes))
    return service.execute("operator", plan["plan_id"])


def write_headers(service, **changes):
    result = {"x-riskops-csrf": service.csrf_token, "Origin": "http://testserver"}
    result.update(changes)
    return result


def test_preview_is_persistent_but_never_executes_or_creates_blocks(service, transport, clock):
    plan = service.preview("operator", request(reason="  reviewed  "))
    assert plan["expires_at"] == clock.now + 300
    assert plan["reason"] == "reviewed"
    assert transport.calls == []
    assert service.capabilities()["jobs"] == service.capabilities()["blocks"] == []
    with service.connection() as db:
        assert db.execute("SELECT actor FROM plans").fetchone()[0] == "operator"
        assert db.execute("SELECT event FROM audit").fetchone()[0] == "preview"
    public = service.capabilities()
    assert all("ssh_host" not in item for item in public["sources"])


@pytest.mark.parametrize("duration", [300, 900, 1800, 3600, 86400, None])
def test_every_supported_duration_has_fixed_confirmation_deadline(service, clock, duration):
    plan = service.preview("operator", request(duration_seconds=duration))
    clock.now += 45
    job = service.execute("operator", plan["plan_id"])
    assert job["items"][0]["expires_at"] == (None if duration is None else clock.now + duration)
    assert job["status"] == "queued"


@pytest.mark.parametrize("changes", [
    {"duration_seconds": True}, {"duration_seconds": 3600.0}, {"duration_seconds": -1},
    {"duration_seconds": 60}, {"action": "shell"}, {"channels": []},
    {"channels": ["icmp"]}, {"channels": ["ssh"] * 4}, {"channels": "ssh"},
    {"targets": []}, {"targets": [{"source_id": "unknown", "ip": "203.0.113.30"}]},
    {"targets": [{"source_id": "server-a", "ip": "203.0.113.30", "command": "anything"}]},
    {"reason": " "}, {"reason": "x" * 301}, {"extra": "value"},
])
def test_preview_rejects_unbounded_or_unsupported_request(service, transport, changes):
    with pytest.raises(ValueError):
        service.preview("operator", request(**changes))
    assert not transport.calls
    assert not service.capabilities()["jobs"]


@pytest.mark.parametrize("ip", ["192.0.2.5", "::ffff:192.0.2.5", "2001:db8:1::a",
                               "127.0.0.1", "::1", "0.0.0.0", "::", "224.0.0.1",
                               "169.254.1.1", "fe80::1", "203.0.113.0/24",
                               "203.0.113.30; command", "example.org", "fe80::1%eth0"])
def test_management_and_non_host_targets_fail_closed(service, ip):
    with pytest.raises(ValueError):
        service.preview("operator", request(targets=[{"source_id": "server-a", "ip": ip}]))


@pytest.mark.parametrize("operator_ip", ["203.0.113.30", "::ffff:203.0.113.30"])
def test_current_operator_address_is_protected_after_normalization(service, operator_ip):
    with pytest.raises(ValueError, match="管理"):
        service.preview("operator", request(), operator_ip=operator_ip)


def test_target_dedup_normalizes_ipv6_and_tcp_subsumes_ssh(service):
    targets = [{"source_id": "server-a", "ip": "2001:0db8:2::1"},
               {"source_id": "server-a", "ip": "2001:db8:2::1"}]
    plan = service.preview("operator", request(targets=targets, channels=["ssh", "tcp", "udp"]))
    assert [(item["ip"], item["channel"]) for item in plan["items"]] == [
        ("2001:db8:2::1", "tcp"), ("2001:db8:2::1", "udp")]
    unban = service.preview("operator", request(action="unban", targets=targets, channels=["ssh", "tcp", "udp"]))
    assert {item["channel"] for item in unban["items"]} == {"ssh", "tcp", "udp"}


def test_batch_has_both_target_and_expanded_item_limits(service):
    targets = [{"source_id": "server-a", "ip": f"203.0.113.{i}"} for i in range(1, 102)]
    with pytest.raises(ValueError, match="100"):
        service.preview("operator", request(targets=targets))
    with pytest.raises(ValueError, match="100"):
        service.preview("operator", request(targets=targets[:51], channels=["ssh", "udp"]))
    assert len(service.preview("operator", request(targets=targets[:50], channels=["ssh", "udp"]))["items"]) == 100


def test_execute_requires_same_actor_and_unexpired_plan(service, clock):
    plan = service.preview("operator", request())
    with pytest.raises(ValueError, match="不存在"):
        service.execute("someone-else", plan["plan_id"])
    clock.now += 301
    with pytest.raises(ValueError, match="过期"):
        service.execute("operator", plan["plan_id"])
    assert service.capabilities()["jobs"] == []


def test_execute_is_idempotent_even_after_plan_expires(service, clock, transport):
    plan = service.preview("operator", request())
    first = service.execute("operator", plan["plan_id"])
    clock.now += 900
    again = service.execute("operator", plan["plan_id"])
    assert first == again
    assert not transport.calls
    assert len(service.capabilities()["jobs"]) == 1
    assert service.run_once()
    assert service.execute("operator", plan["plan_id"])["status"] == "done"
    assert len(transport.calls) == 1


def test_worker_success_and_unban_persist_across_restart(service, config, control_config, transport):
    ban = queue(service)
    assert service.run_once()
    assert service.job(ban["id"])["status"] == "done"
    assert len(service.capabilities()["blocks"]) == 1
    restarted = ControlService(control_config, config.sources, transport=transport)
    assert restarted.job(ban["id"])["items"][0]["status"] == "ok"
    assert len(restarted.capabilities()["blocks"]) == 1
    unban = queue(restarted, action="unban", duration_seconds=None)
    assert restarted.run_once()
    assert "expires_at" not in transport.calls[-1][1]
    assert restarted.job(unban["id"])["status"] == "done"
    again = ControlService(control_config, config.sources, transport=transport)
    assert again.capabilities()["blocks"] == []
    assert not again.run_once()


def rejected_response(source, payload):
    return {"version": 1, "status": "rejected", "source_id": source["source_id"], "request_id": payload["request_id"]}


def test_batch_partial_keeps_individual_outcomes_and_persisted_success(service, transport):
    job = queue(service, targets=[{"source_id": "server-a", "ip": "203.0.113.30"},
                                  {"source_id": "server-b", "ip": "203.0.113.30"}])
    transport.outcomes = [None, rejected_response]
    assert service.run_once()
    assert service.job(job["id"])["status"] == "running"
    assert service.run_once()
    result = service.job(job["id"])
    assert result["status"] == "partial"
    assert [item["status"] for item in result["items"]] == ["ok", "rejected"]
    assert [item["source_id"] for item in service.capabilities()["blocks"]] == ["server-a"]
    assert not service.run_once()


def test_remote_refusal_finishes_without_retries(service, transport):
    job = queue(service)
    transport.outcomes = [rejected_response]
    assert service.run_once()
    assert service.job(job["id"])["status"] == "failed"
    assert service.job(job["id"])["items"][0]["status"] == "rejected"
    assert service.capabilities()["blocks"] == []
    assert not service.run_once()


def test_timeout_retry_uses_same_request_and_deadline_and_hides_remote_error(service, transport, clock):
    job = queue(service, duration_seconds=300)
    transport.outcomes = [TimeoutError("remote private path and details")]
    assert service.run_once()
    first = deepcopy(transport.calls[0][1])
    state = service.job(job["id"])
    assert state["items"][0]["status"] == "pending"
    assert "private" not in json.dumps(state)
    assert not service.run_once()
    clock.now += 11
    assert service.run_once()
    assert transport.calls[1][1] == first
    state = service.job(job["id"])
    assert state["status"] == "done"
    assert state["items"][0]["attempts"] == 2
    assert "error" not in state["items"][0]


def test_exhausted_timeouts_stay_uncertain_and_do_not_create_blocks(service, transport, clock):
    job = queue(service)
    transport.outcomes = [TimeoutError()] * 3
    for _ in range(3):
        assert service.run_once()
        clock.now += 11
    state = service.job(job["id"])
    assert state["status"] == "failed"
    assert state["items"][0]["status"] == "uncertain"
    assert state["items"][0]["attempts"] == 3
    assert not service.capabilities()["blocks"]
    assert not service.run_once()


@pytest.mark.parametrize("change", [{"source_id": "server-b"}, {"request_id": "wrong-request"},
                                  {"ip": "203.0.113.31"}, {"channel": "udp"},
                                  {"blocked": False}, {"blocked": 1}, {"expires_at": None},
                                  {"status": "uncertain"}])
def test_mismatched_success_cannot_be_recorded_as_verified(service, transport, change):
    job = queue(service)
    def mismatch(source, payload):
        return {"version": 1, "source_id": source["source_id"], "request_id": payload["request_id"],
                "ip": payload["ip"], "channel": payload["channel"], "blocked": True,
                "expires_at": payload["expires_at"], "status": "ok", **change}
    transport.outcomes = [mismatch]
    assert service.run_once()
    assert service.job(job["id"])["items"][0]["status"] == "pending"
    assert service.capabilities()["blocks"] == []


def test_expired_worker_lease_recovers_same_request_after_restart(service, config, control_config, transport, clock):
    job = queue(service)
    item = deepcopy(job["items"][0])
    item.update(status="running", attempts=1)
    with service.connection(write=True) as db:
        db.execute("UPDATE jobs SET status='running',items=?,lease_until=? WHERE id=?",
                   (json.dumps([item]), clock.now + 90, job["id"]))
    restarted = ControlService(control_config, config.sources, transport=transport)
    assert not restarted.run_once()
    assert not transport.calls
    clock.now += 91
    assert restarted.run_once()
    sent = transport.calls[-1][1]
    assert (sent["request_id"], sent["expires_at"]) == (item["request_id"], item["expires_at"])
    assert restarted.job(job["id"])["items"][0]["attempts"] == 2


def test_pending_ban_finishes_before_new_unban(service, transport, clock):
    queue(service)
    transport.outcomes = [TimeoutError()]
    assert service.run_once()
    clock.now += 1
    unban = queue(service, action="unban")
    assert not service.run_once()
    clock.now += 10
    assert service.run_once()
    assert transport.calls[-1][1]["action"] == "add"
    assert service.run_once()
    assert transport.calls[-1][1]["action"] == "delete"
    assert service.job(unban["id"])["status"] == "done"
    assert service.capabilities()["blocks"] == []


def test_reconcile_remote_failure_preserves_last_verified_blocks(service, transport):
    queue(service)
    assert service.run_once()
    before = service.capabilities()["blocks"]
    transport.outcomes = [RuntimeError("sensitive remote error")]
    service.reconcile()
    result = service.capabilities()
    assert result["blocks"] == before
    assert result["source_checks"][0]["error"]
    assert "sensitive" not in json.dumps(result)
    assert result["source_checks"][1]["error"] is None


@pytest.mark.parametrize("blocks", [[{"ip": "203.0.113.30", "channel": "shell"}],
                                    [{"ip": "127.0.0.1", "channel": "ssh"}],
                                    [{"ip": "203.0.113.30", "channel": "ssh", "expires_at": True}],
                                    ["invalid"], None])
def test_invalid_status_inventory_never_replaces_verified_blocks(service, transport, blocks):
    queue(service)
    assert service.run_once()
    before = service.capabilities()["blocks"]
    transport.outcomes = [lambda source, payload: {"version": 1, "status": "ok", "ready": True,
                          "table_present": True, "source_id": source["source_id"],
                          "request_id": payload["request_id"], "blocks": blocks}]
    service.reconcile()
    assert service.capabilities()["blocks"] == before
    assert service.capabilities()["source_checks"][0]["error"]


@pytest.mark.parametrize("change", [{"source_id": "server-b"}, {"request_id": "another-request"}, {"version": 2}])
def test_reconcile_checks_response_identity_before_replacing_blocks(service, transport, change):
    queue(service)
    assert service.run_once()
    before = service.capabilities()["blocks"]
    transport.outcomes = [lambda source, payload: {"version": 1, "status": "ok", "ready": True,
                          "table_present": True, "source_id": source["source_id"],
                          "request_id": payload["request_id"], "blocks": [], **change}]
    service.reconcile()
    assert service.capabilities()["blocks"] == before
    assert service.capabilities()["source_checks"][0]["error"]


@pytest.mark.parametrize("readiness", [{"ready": True, "table_present": False},
                                     {"ready": True},
                                     {"ready": True, "table_present": 1},
                                     {"ready": True, "table_present": "true"},
                                     {"ready": False, "table_present": True}])
def test_missing_firewall_never_erases_confirmed_permanent_blocks(service, transport, readiness):
    queue(service, duration_seconds=None)
    assert service.run_once()
    before = service.capabilities()["blocks"]
    transport.outcomes = [lambda source, payload: {
        "version": 1, "status": "ok", "source_id": source["source_id"],
        "request_id": payload["request_id"], "blocks": [], **readiness}]
    service.reconcile()
    result = service.capabilities()
    assert result["blocks"] == before
    assert "防火墙尚未就绪" in result["source_checks"][0]["error"]
    assert result["source_checks"][1]["error"] is None

    # A later successful observation clears the warning; a genuinely empty
    # installed table is distinct from an absent table after a firewall reload.
    transport.blocks.clear()
    service.reconcile()
    result = service.capabilities()
    assert result["blocks"] == []
    assert all(check["error"] is None for check in result["source_checks"])


def test_reconcile_confirms_removed_block_and_expiry_hides_elapsed_rows(service, transport, clock):
    queue(service, duration_seconds=300)
    assert service.run_once()
    clock.now += 301
    assert service.capabilities()["blocks"] == []
    transport.blocks.clear()
    service.reconcile()
    with service.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0] == 0
    assert all(row["error"] is None for row in service.capabilities()["source_checks"])


def test_preview_execute_api_needs_explicit_confirmation_and_is_async(client, service, transport):
    assert client.get("/api/controls").status_code == 401
    capabilities = client.get("/api/controls", auth=AUTH)
    assert capabilities.status_code == 200
    assert capabilities.json()["enabled"] is True
    headers = write_headers(service)
    preview = client.post("/api/controls/preview", json=request(), auth=AUTH, headers=headers)
    assert preview.status_code == 200
    assert not transport.calls
    result = client.post("/api/controls/execute", json={"plan_id": preview.json()["plan_id"]}, auth=AUTH, headers=headers)
    assert result.status_code == 202
    assert result.json()["status"] == "queued"
    assert not transport.calls
    again = client.post("/api/controls/execute", json={"plan_id": preview.json()["plan_id"]}, auth=AUTH, headers=headers)
    assert again.json()["id"] == result.json()["id"]
    assert service.run_once()
    job = client.get("/api/controls/jobs/" + result.json()["id"], auth=AUTH)
    assert job.json()["status"] == "done"
    assert client.get("/api/controls/jobs/missing", auth=AUTH).status_code == 404


@pytest.mark.parametrize("path,payload", [("preview", request()), ("execute", {"plan_id": "missing"})])
def test_collector_bearer_token_cannot_write_controls(client, service, path, payload):
    response = client.post("/api/controls/" + path, json=payload,
                           headers={**write_headers(service), "Authorization": "Bearer " + TOKEN})
    assert response.status_code == 401
    assert service.capabilities()["jobs"] == []


@pytest.mark.parametrize("headers", [{}, {"x-riskops-csrf": "wrong"},
                                    {"Origin": "http://other.example"},
                                    {"Origin": "null"}, {"sec-fetch-site": "cross-site"}])
def test_control_posts_reject_missing_csrf_or_cross_site_origin(client, service, headers):
    selected = write_headers(service)
    if not headers or "x-riskops-csrf" in headers:
        selected.pop("x-riskops-csrf")
    selected.update(headers)
    response = client.post("/api/controls/preview", json=request(), auth=AUTH, headers=selected)
    assert response.status_code == 403


def test_non_ascii_csrf_returns_forbidden_instead_of_server_error(client, service):
    headers = [(b"x-riskops-csrf", b"\xff"), (b"origin", b"http://testserver")]
    response = client.post("/api/controls/preview", json=request(), auth=AUTH, headers=headers)
    assert response.status_code == 403


def test_json_only_and_malformed_requests_are_rejected(client, service):
    headers = write_headers(service)
    assert client.post("/api/controls/preview", content="{}", auth=AUTH,
                       headers={**headers, "Content-Type": "text/plain"}).status_code == 415
    assert client.post("/api/controls/preview", content="{invalid", auth=AUTH,
                       headers={**headers, "Content-Type": "application/json"}).status_code == 422
    for body in (None, [], {}, {"plan_id": []}, {"plan_id": "x", "targets": []}):
        assert client.post("/api/controls/execute", content=json.dumps(body), auth=AUTH,
                           headers={**headers, "Content-Type": "application/json"}).status_code == 422


def test_disabled_controls_remain_readable_but_cannot_mutate(config):
    disabled = ControlService(None, config.sources)
    with TestClient(create_app(config, control=disabled)) as client:
        state = client.get("/api/controls", auth=AUTH)
        assert state.status_code == 200
        assert state.json()["enabled"] is False
        assert client.post("/api/controls/preview", json=request(), auth=AUTH,
                           headers=write_headers(disabled)).status_code == 503
        assert client.get("/api/controls/jobs/anything", auth=AUTH).status_code == 503


def test_persistent_audit_hash_chain_covers_preview_confirmation_and_result(service):
    queue(service)
    assert service.run_once()
    with service.connection() as db:
        rows = list(db.execute("SELECT * FROM audit ORDER BY seq"))
    assert [row["event"] for row in rows] == ["preview", "confirmed", "result"]
    previous = "0" * 64
    for row in rows:
        assert row["previous_hash"] == previous
        expected = hashlib.sha256(module.encoded([previous, row["timestamp"], row["actor"],
                                                 row["event"], row["body"]]).encode()).hexdigest()
        assert row["hash"] == expected
        previous = expected
