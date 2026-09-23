from __future__ import annotations

import hashlib
import importlib.util
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
import threading
import time

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.live_api import MAX_BODY_BYTES, create_app
from app.telemetry import operator_auth
from app.telemetry.config import LiveConfig, hash_operator_password, load_config

TOKEN_A = "a-source-token-for-tests-only-1234567890"
TOKEN_B = "b-source-token-for-tests-only-1234567890"
PASSWORD = "test-password-only-1234567890"


@pytest.fixture(scope="module")
def password_hash():
    return hash_operator_password(PASSWORD)


@pytest.fixture
def config(tmp_path, password_hash):
    return LiveConfig(
        database_path=str(tmp_path / "telemetry.sqlite3"),
        sources=[{"id": "server-a", "hostname": "host-a", "token_sha256": hashlib.sha256(TOKEN_A.encode()).hexdigest()},
                 {"id": "server-b", "hostname": "host-b", "token_sha256": hashlib.sha256(TOKEN_B.encode()).hexdigest()}],
        operator_username="operator", operator_password_pbkdf2=password_hash,
    )


@pytest.fixture
def client(config):
    with TestClient(create_app(config)) as test_client:
        yield test_client


def batch(**updates):
    value = {"source_id": "server-a", "hostname": "host-a", "batch_id": "batch-one", "records": [
        {"event_id": "cursor-1", "timestamp": datetime.now(timezone.utc).isoformat(),
         "message": "Failed password for invalid user test from 192.0.2.10 port 22 ssh2", "identifier": "sshd"}
    ]}
    value.update(updates)
    return value


def send(client, payload=None, token=TOKEN_A):
    return client.post("/api/telemetry/batches", json=payload if payload is not None else batch(),
                       headers={"Authorization": "Bearer " + token})


def test_live_entrypoint_requires_configuration(monkeypatch):
    monkeypatch.delenv("RISKOPS_CONFIG", raising=False)
    with pytest.raises(RuntimeError, match="RISKOPS_CONFIG"):
        with TestClient(create_app()):
            pass


def test_summary_counts_cross_source_incident_once(client):
    start = datetime.now(timezone.utc) - timedelta(minutes=25)
    for source, host, token, offset in (("server-a", "host-a", TOKEN_A, 0),
                                        ("server-b", "host-b", TOKEN_B, 300)):
        rows = [{"event_id": str(i), "timestamp": (start + timedelta(seconds=offset + i * 600)).isoformat(),
                 "message": "Connection closed by authenticating user root 192.0.2.10 port 42000 [preauth]",
                 "identifier": "sshd"} for i in range(3)]
        response = send(client, batch(source_id=source, hostname=host, records=rows), token)
        assert response.status_code == 200
    summary = client.get("/api/summary", auth=("operator", PASSWORD)).json()
    assert summary["totals"]["incidents"] == 1
    assert [source["incident_count"] for source in summary["sources"]] == [1, 1]
    for source in ("server-a", "server-b"):
        page = client.get(f"/api/incidents?source_id={source}&page=1", auth=("operator", PASSWORD)).json()
        assert page["total"] == 1 and page["items"][0]["source_ids"] == ["server-a", "server-b"]


def test_invalid_config_never_echoes_secret(tmp_path):
    path = tmp_path / "config.json"
    path.write_text('{"operator_password":"must-never-appear-in-error"}')
    with pytest.raises(RuntimeError) as exc:
        load_config(str(path))
    assert "must-never-appear" not in str(exc.value)


def test_configuration_rejects_reused_source_token(config):
    data = config.model_dump()
    data["sources"][1]["token_sha256"] = data["sources"][0]["token_sha256"]
    with pytest.raises(ValidationError):
        LiveConfig.model_validate(data)


def test_health_is_real_but_read_apis_require_login(client):
    assert client.get("/health").json() == {"status": "ok"}
    for path in ("/", "/api/events", "/api/incidents", "/api/summary", "/api/dashboard", "/api/ip-info?ip=8.8.8.8"):
        assert client.get(path).status_code == 401
        assert client.get(path, auth=("operator", "wrong-password")).status_code == 401
    assert client.get("/api/summary", auth=("wrong-user", PASSWORD)).status_code == 401
    response = client.get("/", auth=("operator", PASSWORD))
    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert "innerHTML" not in response.text
    assert client.post("/flows/run", auth=("operator", PASSWORD)).status_code == 404


def test_source_token_cannot_read_or_impersonate_other_source(client):
    assert send(client, token="wrong-token-that-is-long-enough").status_code == 401
    assert client.post("/api/telemetry/batches", json=batch()).status_code == 401
    assert send(client, batch(source_id="unknown")).status_code == 403
    assert send(client, batch(source_id="server-b", hostname="host-b")).status_code == 403
    assert send(client, batch(hostname="spoofed-host")).status_code == 403
    assert client.get("/api/events", headers={"Authorization": "Bearer " + TOKEN_A}).status_code == 401
    assert client.post("/api/telemetry/batches", json=batch(), auth=("operator", PASSWORD)).status_code == 401


def test_persistent_ingest_ack_and_idempotency(client, config):
    payload = batch()
    response = send(client, payload)
    assert response.status_code == 200
    assert response.json()["durable"] is True
    assert response.json()["batch_id"] == payload["batch_id"]
    assert response.json()["accepted"] == 1
    duplicate = send(client, payload)
    assert duplicate.status_code == 200
    with TestClient(create_app(config)) as restarted:
        events = restarted.get("/api/events", auth=("operator", PASSWORD)).json()
        assert len(events) == 1
        assert events[0]["source_id"] == "server-a"


def test_heartbeat_and_collection_error_are_visible(client):
    response = send(client, batch(records=[], reports=[{"code": "journal_read_failed", "message": "journal unavailable"}]))
    assert response.status_code == 200
    summary = client.get("/api/summary", auth=("operator", PASSWORD)).json()
    observed = {source["source_id"]: source for source in summary["sources"]}
    assert observed["server-a"]["connection_status"] == "error"
    assert "journal unavailable" in observed["server-a"]["last_error"]
    assert observed["server-b"]["connection_status"] == "never_seen"
    assert summary["totals"]["events"] == 0


def test_page_envelope_filters_bounds_and_offset_compatibility(client):
    assert send(client).status_code == 200
    auth = ("operator", PASSWORD)
    response = client.get("/api/events?page=999&limit=1&source_id=server-a", auth=auth)
    assert response.status_code == 200
    data = response.json()
    assert (data["total"], data["total_pages"], data["page"], data["offset"]) == (1, 1, 1, 0)
    assert data["items"][0]["source_id"] == "server-a"
    assert client.get("/api/events?offset=1", auth=auth).json() == []
    assert client.get("/api/events?page=1&source_id=server-b", auth=auth).json()["total"] == 0
    assert client.get("/api/incidents?page=1", auth=auth).json()["total_pages"] == 1
    for url in ("/api/events?page=0", "/api/events?page=1.5", "/api/incidents?page=-1"):
        assert client.get(url, auth=auth).status_code == 422
    assert client.get("/api/events?page=1&source_id=missing", auth=auth).status_code == 404


def test_dashboard_refresh_one_auth_and_preserves_filter_pages(client, monkeypatch):
    assert send(client).status_code == 200
    calls = []
    original = operator_auth.verify_operator_password
    def counted(*args):
        calls.append(True)
        return original(*args)
    monkeypatch.setattr(operator_auth, "verify_operator_password", counted)
    response = client.get("/api/dashboard?source_id=server-a&event_page=2&incident_page=1&limit=1", auth=("operator", PASSWORD))
    assert response.status_code == 200
    data = response.json()
    assert len(calls) == 1
    assert data["events"]["page"] == 1 and data["events"]["total"] == 1
    assert data["events"]["items"][0]["source_id"] == "server-a"
    assert data["summary"]["totals"]["events"] == 1
    assert data["incidents"]["items"] == []
    assert client.get("/api/dashboard?source_id=missing", auth=("operator", PASSWORD)).status_code == 404
    assert client.get("/api/dashboard?event_page=0", auth=("operator", PASSWORD)).status_code == 422


def test_abuseipdb_is_authenticated_explicit_and_accepts_only_ip(client, monkeypatch):
    calls = []
    def check(ip):
        calls.append(ip)
        return {"ip":ip,"status":"ok","score":42,"total_reports":2,"notice":"test"}
    monkeypatch.setattr(client.app.state.abuseipdb,"lookup",check)
    auth = ("operator", PASSWORD)
    assert client.post("/api/abuseipdb/check",json={"ip":"8.8.8.8"}).status_code == 401
    assert client.get("/api/abuseipdb/check",auth=auth).status_code == 405
    assert client.get("/api/dashboard",auth=auth).status_code == 200
    assert client.get("/api/ip-info?ip=127.0.0.1",auth=auth).status_code == 200
    assert calls == []
    assert client.post("/api/abuseipdb/check",json={"ip":"8.8.8.8","message":"private log"},auth=auth).status_code == 422
    response = client.post("/api/abuseipdb/check",json={"ip":"8.8.8.8"},auth=auth)
    assert response.status_code == 200 and response.json()["score"] == 42
    assert calls == ["8.8.8.8"]


@pytest.mark.parametrize("state,status",[("not_configured",503),("rate_limited",429),("unavailable",502),("not_public",200)])
def test_abuseipdb_upstream_failure_is_not_zero_risk(client,monkeypatch,state,status):
    monkeypatch.setattr(client.app.state.abuseipdb,"lookup",lambda ip:{"ip":ip,"status":state,"score":None,"notice":"check unavailable"})
    response = client.post("/api/abuseipdb/check",json={"ip":"8.8.8.8"},auth=("operator",PASSWORD))
    assert response.status_code == status
    assert response.json()["score"] is None


def test_ip_api_is_local_authenticated_and_degrades_independently(client, monkeypatch):
    auth = ("operator", PASSWORD)
    assert client.get("/api/ip-info?ip=8.8.8.8").status_code == 401
    private = client.get("/api/ip-info?ip=192.168.1.1", auth=auth)
    assert private.status_code == 200
    assert private.json()["status"] == "not_public"
    assert client.get("/api/ip-info?ip=https://8.8.8.8", auth=auth).status_code == 422
    client.app.state.geoip.directory = None
    public = client.get("/api/ip-info?ip=8.8.8.8", auth=auth)
    assert public.status_code == 503
    assert public.json()["status"] == "unavailable"
    assert send(client).status_code == 200
    assert client.get("/health").status_code == 200


@pytest.mark.parametrize("timestamp", ["invalid", "2026-01-01T12:00:00", (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()])
def test_invalid_or_future_record_time_rejects_entire_batch(client, timestamp):
    payload = batch()
    payload["records"][0]["timestamp"] = timestamp
    assert send(client, payload).status_code == 422
    assert client.get("/api/events", auth=("operator", PASSWORD)).json() == []


def test_batch_count_and_field_limits(client):
    payload = batch()
    assert send(client, batch(records=payload["records"] * 501)).status_code == 422
    payload["records"][0]["message"] = "x" * 16385
    assert send(client, payload).status_code == 422
    payload = batch()
    payload["records"][0]["source_id"] = "server-b"
    assert send(client, payload).status_code == 422


def test_body_limit_includes_chunked_requests(client):
    headers = {"Authorization": "Bearer " + TOKEN_A, "Content-Type": "application/json"}
    assert client.post("/api/telemetry/batches", content=b"x" * (MAX_BODY_BYTES + 1), headers=headers).status_code == 413
    def chunks():
        for _ in range(17):
            yield b"x" * 65536
    response = client.post("/api/telemetry/batches", content=chunks(), headers=headers)
    assert response.status_code == 413


def test_pagination_and_filters_are_bounded(client):
    for query in ("limit=201", "limit=0", "offset=-1"):
        assert client.get("/api/events?" + query, auth=("operator", PASSWORD)).status_code == 422
    assert client.get("/api/events?source_id=missing", auth=("operator", PASSWORD)).status_code == 404


def test_log_markup_is_only_returned_as_json_data(client):
    payload = batch()
    payload["records"][0]["message"] = "<img src=x onerror=alert(1)>"
    assert send(client, payload).status_code == 200
    response = client.get("/api/events", auth=("operator", PASSWORD))
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()[0]["message"] == payload["records"][0]["message"]
    page = client.get("/", auth=("operator", PASSWORD)).text
    assert payload["records"][0]["message"] not in page


def test_storage_failure_is_never_acknowledged(client, monkeypatch):
    def failure(*args, **kwargs):
        raise OSError("private-database-path")
    monkeypatch.setattr(client.app.state.store, "ingest", failure)
    response = send(client)
    assert response.status_code == 503
    assert "durable" not in response.json()
    assert "private-database-path" not in response.text
    monkeypatch.setattr(client.app.state.store, "healthcheck", lambda: False)
    assert client.get("/health").status_code == 503


def test_password_hash_work_does_not_block_the_http_event_loop(client, monkeypatch):
    entered = threading.Event()
    release = threading.Event()
    original = operator_auth.verify_operator_password

    def slow_password_check(*args):
        entered.set()
        release.wait(timeout=3)
        return original(*args)

    monkeypatch.setattr(operator_auth, "verify_operator_password", slow_password_check)
    with ThreadPoolExecutor(max_workers=1) as pool:
        protected_request = pool.submit(client.get, "/api/summary", auth=("operator", PASSWORD))
        try:
            assert entered.wait(timeout=2)
            started = time.monotonic()
            assert client.get("/health").status_code == 200
            assert time.monotonic() - started < 1
        finally:
            release.set()
        assert protected_request.result(timeout=3).status_code == 200


def test_real_collector_payload_retry_and_heartbeat_contract(client, tmp_path):
    path = Path(__file__).parents[2] / "scripts" / "telemetry_collector.py"
    spec = importlib.util.spec_from_file_location("collector_api_contract", path)
    collector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(collector)
    collector_config = {"endpoint": "http://127.0.0.1:8088/api/telemetry/batches", "state_dir": str(tmp_path / "spool"),
                        "ssh_timeout_seconds": 2, "http_timeout_seconds": 2, "max_spool_bytes": 1_000_000,
                        "sources": [{"id": "server-a", "hostname": "host-a", "token": TOKEN_A,
                                     "ssh_command": ["not-executed"]}]}
    now = datetime.now(timezone.utc)

    def export(_source, cursor, _timeout):
        records = [] if cursor else [
            {"__CURSOR": f"s=sample;i={index}", "__REALTIME_TIMESTAMP": str(int((now - timedelta(seconds=10-index)).timestamp() * 1_000_000)),
             "MESSAGE": "Failed password for invalid user test from 192.0.2.10 port 22 ssh2",
             "SYSLOG_IDENTIFIER": "sshd", "_SYSTEMD_UNIT": "ssh.service", "PRIORITY": "6"}
            for index in range(3)
        ]
        checkpoint = {"__riskops_checkpoint__": cursor or records[-1]["__CURSOR"],
                      "cursor_status": "ok" if cursor else "initial"}
        return b"\n".join(collector.encode(item) for item in [*records, checkpoint]) + b"\n"

    def submit(_endpoint, token, payload, _timeout):
        response = send(client, payload, token)
        assert response.status_code == 200, response.text
        return response.json()

    def dropped_ack(*args):
        submit(*args)
        raise collector.CollectorError("http_unavailable")

    first = collector.run_once(collector_config, export, dropped_ack)
    assert first[0]["code"] == "http_unavailable"
    assert not (tmp_path / "spool/server-a.state.json").exists()
    retried = collector.run_once(collector_config, lambda *args: pytest.fail("must reuse spool"), submit)
    assert retried[0]["status"] == "acknowledged"
    assert json.loads((tmp_path / "spool/server-a.state.json").read_text())["cursor"] == "s=sample;i=2"
    assert len(client.get("/api/events", auth=("operator", PASSWORD)).json()) == 3
    assert len(client.get("/api/incidents", auth=("operator", PASSWORD)).json()) == 1
    heartbeat = collector.run_once(collector_config, export, submit)
    assert heartbeat[0]["records"] == 0
    source = client.get("/api/summary", auth=("operator", PASSWORD)).json()["sources"][0]
    assert source["connection_status"] == "online"
    assert source["event_count"] == 3
