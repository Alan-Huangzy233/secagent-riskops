"""Durability/failure tests for the independently runnable stdlib collector."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys

import pytest

MODULE = Path(__file__).resolve().parents[2] / "scripts" / "telemetry_collector.py"
SPEC = importlib.util.spec_from_file_location("riskops_collector", MODULE)
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


@pytest.fixture
def config(tmp_path):
    return {"endpoint": "http://127.0.0.1:8088/api/telemetry/batches", "state_dir": str(tmp_path),
            "ssh_timeout_seconds": 2, "http_timeout_seconds": 2, "max_spool_bytes": 16 * 1024 * 1024,
            "sources": [{"id": "source-a", "hostname": "test-host", "token": "do-not-spool-this-test-token-1234567890",
                         "ssh_command": ["not-called-in-unit-tests"]}]}


def journal(cursor="cursor-1", message="Failed password for test from 192.0.2.1"):
    return {"__CURSOR": cursor, "__REALTIME_TIMESTAMP": "1788796800123456", "MESSAGE": message,
            "_SYSTEMD_UNIT": "ssh.service", "SYSLOG_IDENTIFIER": "sshd", "PRIORITY": "6"}


def exported(records=None, checkpoint="cursor-1", status="ok"):
    records = [journal()] if records is None else records
    return b"\n".join(collector.encode(value) for value in [*records,
                        {"__riskops_checkpoint__": checkpoint, "cursor_status": status}]) + b"\n"


def durable(endpoint, token, body, timeout):
    return {"durable": True, "batch_id": body["batch_id"]}


def fail_send(*args):
    raise collector.CollectorError("http_unavailable")


def test_retry_preserves_batch_and_cursor_until_durable_ack(config):
    requests = []

    def fetch(source, cursor, timeout):
        requests.append(cursor)
        return exported()

    first = collector.run_once(config, fetch, fail_send)
    root = Path(config["state_dir"])
    assert first[0]["code"] == "http_unavailable"
    assert not (root / "source-a.state.json").exists()
    pending = json.loads((root / "source-a.pending.json").read_text())
    assert config["sources"][0]["token"] not in (root / "source-a.pending.json").read_text()
    sent = []

    def acknowledge(endpoint, token, body, timeout):
        sent.append(body)
        return durable(endpoint, token, body, timeout)

    second = collector.run_once(config, fetch, acknowledge)
    assert second[0]["status"] == "acknowledged"
    assert sent == [pending["body"]]
    assert requests == [None]  # Retrying never fetches and overwrites a pending batch.
    assert json.loads((root / "source-a.state.json").read_text())["cursor"] == "cursor-1"
    assert not (root / "source-a.pending.json").exists()


@pytest.mark.parametrize("ack", [{}, {"durable": False}, {"durable": True, "batch_id": "wrong"}, []])
def test_2xx_without_matching_durable_receipt_does_not_advance(config, ack):
    result = collector.run_once(config, lambda *args: exported(), lambda *args: ack)
    assert result[0]["code"] == "invalid_ack"
    assert not (Path(config["state_dir"]) / "source-a.state.json").exists()
    assert (Path(config["state_dir"]) / "source-a.pending.json").exists()


def test_crash_after_server_ack_replays_identical_pending_batch(config, monkeypatch):
    original = collector.atomic_write
    submitted = []

    def record_ack(endpoint, token, body, timeout):
        submitted.append(body)
        return durable(endpoint, token, body, timeout)

    def fail_cursor_commit(path, value):
        if path.name.endswith(".state.json"):
            raise OSError("simulated fsync failure")
        original(path, value)

    monkeypatch.setattr(collector, "atomic_write", fail_cursor_commit)
    assert collector.run_once(config, lambda *args: exported(), record_ack)[0]["code"] == "local_storage_failed"
    monkeypatch.setattr(collector, "atomic_write", original)
    collector.run_once(config, lambda *args: pytest.fail("must retry spool"), record_ack)
    assert submitted[0] == submitted[1]


@pytest.mark.parametrize("bad", [
    b"not json\n", exported(checkpoint="wrong"),
    exported([{"__CURSOR": "cursor-1", "__REALTIME_TIMESTAMP": "1788796800123456"}]),
    exported([journal(), journal()]),
    collector.encode(journal()) + b"\n",
])
def test_bad_lines_are_reported_without_skipping_or_advancing(config, bad):
    root = Path(config["state_dir"])
    collector.atomic_write(root / "source-a.state.json", {"cursor": "old"})
    bodies = []

    def send(endpoint, token, body, timeout):
        bodies.append(body)
        return durable(endpoint, token, body, timeout)

    result = collector.run_once(config, lambda *args: bad, send)
    assert result[0]["status"] == "source_error"
    assert bodies[0]["records"] == []
    assert bodies[0]["reports"][0]["code"] == "invalid_journal_export"
    assert json.loads((root / "source-a.state.json").read_text())["cursor"] == "old"


def test_cursor_reset_is_visible_and_checkpoint_is_validated():
    records, cursor, reports = collector.parse_export(exported(status="reset"), "expired")
    assert cursor == "cursor-1" and len(records) == 1
    assert reports[0]["code"] == "retention_gap"
    with pytest.raises(collector.CollectorError):
        collector.parse_export(exported(status="initial"), "expired")


def test_heartbeat_preserves_cursor_and_ssh_failure_is_visible(config):
    root = Path(config["state_dir"])
    collector.atomic_write(root / "source-a.state.json", {"cursor": "old"})
    result = collector.run_once(config, lambda *args: exported([], "old"), durable)
    assert result[0]["records"] == 0 and result[0]["status"] == "acknowledged"

    def unavailable(*args):
        raise collector.CollectorError("ssh_timeout")

    result = collector.run_once(config, unavailable, durable)
    assert result[0]["code"] == "ssh_timeout"
    assert json.loads((root / "source-a.state.json").read_text())["cursor"] == "old"


def test_source_failure_does_not_stop_other_sources(config):
    config["sources"].append({**config["sources"][0], "id": "source-b"})

    def fetch(source, *args):
        if source["id"] == "source-a":
            raise collector.CollectorError("ssh_timeout")
        return exported()

    results = collector.run_once(config, fetch, durable)
    assert [r["status"] for r in results] == ["source_error", "acknowledged"]
    assert json.loads((Path(config["state_dir"]) / "source-b.state.json").read_text())["cursor"] == "cursor-1"


def test_spool_capacity_does_not_advance_or_create_partial_batch(config):
    config["max_spool_bytes"] = 1
    result = collector.run_once(config, lambda *args: exported(), lambda *args: pytest.fail("not durable locally"))
    assert result[0]["code"] == "spool_capacity_reached"
    assert not list(Path(config["state_dir"]).glob("*.json"))


def test_unicode_message_truncation_is_explicit_and_batch_prefix_resumes(config, monkeypatch):
    records = [journal("cursor-1", "敏" * 4000), journal("cursor-2", "a" * 4096)]
    parsed, cursor, reports = collector.parse_export(exported(records, "cursor-2"), None)
    assert len(parsed[0]["message"].encode("utf-8")) <= 4096
    assert any(r["code"] == "message_truncated" for r in reports)
    monkeypatch.setattr(collector, "MAX_BATCH_BYTES", 6000)
    pending = collector.build_pending(config["sources"][0], None, lambda *args: exported(records, "cursor-2"), 2)
    assert pending["next_cursor"] == "cursor-1"
    assert len(pending["body"]["records"]) == 1
    assert len(collector.encode(pending["body"])) <= 6000
    assert any(r["code"] == "batch_limited" for r in pending["body"]["reports"])


def test_fixed_ssh_argv_stdin_protocol_and_output_limit(config, tmp_path, monkeypatch):
    fake = tmp_path / "fake_ssh.py"
    fake.write_text("import json,sys\nrequest=json.load(sys.stdin)\n"
                    "assert request == {'source_id':'source-a','cursor':'old','limit':200,'since_minutes':10}\n"
                    "assert len(sys.argv)==1\n"
                    "print(json.dumps({'__riskops_checkpoint__':'old','cursor_status':'ok'}))\n", encoding="utf-8")
    source = {**config["sources"][0], "ssh_command": [sys.executable, str(fake)]}
    raw = collector.ssh_export(source, "old", 3)
    assert collector.parse_export(raw, "old")[1] == "old"
    monkeypatch.setattr(collector, "MAX_EXPORT_BYTES", 10)
    with pytest.raises(collector.CollectorError, match="ssh_output_limit"):
        collector.ssh_export(source, "old", 3)


def test_config_rejects_remote_plaintext_and_path_traversal(config, tmp_path):
    path = tmp_path / "config.json"
    config["endpoint"] = "http://203.0.113.1/api/telemetry/batches"
    path.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(collector.CollectorError, match="invalid_config"):
        collector.load_config(path)
    config["endpoint"] = "http://127.0.0.1:8088/api/telemetry/batches"
    config["sources"][0]["id"] = "../escape"
    path.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(collector.CollectorError, match="invalid_config"):
        collector.load_config(path)


def test_corrupt_cursor_is_not_silently_reset(config):
    (Path(config["state_dir"]) / "source-a.state.json").write_text("broken", encoding="utf-8")
    result = collector.run_once(config, lambda *args: pytest.fail("must not reset"), durable)
    assert result[0]["code"] == "invalid_cursor_state"


def test_corrupt_spool_record_is_reported_and_not_discarded(config):
    root = Path(config["state_dir"])
    pending = collector.build_pending(config["sources"][0], None, lambda *args: exported(), 2)
    pending["body"]["records"] = ["corrupt"]
    collector.atomic_write(root / "source-a.pending.json", pending)
    result = collector.run_once(config, lambda *args: pytest.fail("must not fetch"),
                                lambda *args: pytest.fail("must not send"))
    assert result[0]["code"] == "invalid_spool"
    assert (root / "source-a.pending.json").exists()


def test_ssh_timeout_is_bounded(config, tmp_path):
    fake = tmp_path / "stalled_ssh.py"
    fake.write_text("import time\ntime.sleep(20)\n", encoding="utf-8")
    source = {**config["sources"][0], "ssh_command": [sys.executable, str(fake)]}
    with pytest.raises(collector.CollectorError, match="ssh_timeout"):
        collector.ssh_export(source, None, 1)


def test_http_transport_does_not_follow_redirects_or_leak_token():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading

    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(self.path)
            self.send_response(307)
            self.send_header("Location", "/other-host")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(collector.CollectorError, match="http_rejected"):
            collector.post_batch(f"http://127.0.0.1:{server.server_port}/ingest", "secret", {}, 2)
        assert received == ["/ingest"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_truncated_spool_bytes_are_preserved_without_cursor_commit(config):
    root = Path(config["state_dir"])
    broken = b'{"version":1,"body":{"batch_id":"partial'
    (root / "source-a.pending.json").write_bytes(broken)
    collector.atomic_write(root / "source-a.state.json", {"cursor": "old"})
    result = collector.run_once(config, lambda *args: pytest.fail("must not fetch"),
                                lambda *args: pytest.fail("must not send"))
    assert result[0]["code"] == "invalid_spool"
    assert (root / "source-a.pending.json").read_bytes() == broken
    assert json.loads((root / "source-a.state.json").read_text())["cursor"] == "old"


def test_typical_190_character_cursor_fits_protocol():
    cursor = "s=" + "a" * 188
    records, checkpoint, _ = collector.parse_export(exported([journal(cursor)], cursor), None)
    assert checkpoint == records[0]["event_id"] == cursor


def test_minimum_json_configuration_gets_operational_defaults(config, tmp_path):
    minimal = {key: config[key] for key in ("endpoint", "state_dir", "sources")}
    path = tmp_path / "config.json"
    path.write_text(json.dumps(minimal), encoding="utf-8")
    loaded = collector.load_config(path)
    assert loaded["ssh_timeout_seconds"] == 20
    assert loaded["http_timeout_seconds"] == 10
    assert loaded["max_spool_bytes"] == 16 * 1024 * 1024


def test_invalid_source_token_is_rejected_without_echoing_it(config, tmp_path):
    config["sources"][0]["token"] = "too-short-secret"
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(collector.CollectorError) as exc:
        collector.load_config(path)
    assert str(exc.value) == "invalid_config"


def test_collector_error_heartbeat_and_ack_match_live_api(config):
    import hashlib
    from fastapi.testclient import TestClient
    from app.live_api import create_app
    from app.telemetry.config import LiveConfig, hash_operator_password

    source = config["sources"][0]
    service_config = LiveConfig(
        database_path=str(Path(config["state_dir"]) / "api.sqlite3"),
        sources=[{"id": source["id"], "hostname": source["hostname"],
                  "token_sha256": hashlib.sha256(source["token"].encode()).hexdigest()}],
        operator_username="test-operator",
        operator_password_pbkdf2=hash_operator_password("test-only-password-123456789"),
    )
    responses = []
    with TestClient(create_app(service_config)) as client:
        def send(endpoint, token, body, timeout):
            response = client.post("/api/telemetry/batches", content=collector.encode(body),
                                   headers={"Authorization": "Bearer " + token,
                                            "Content-Type": "application/json"})
            assert response.status_code == 200
            responses.append(response.json())
            return response.json()

        assert collector.run_once(config, lambda *args: exported(), send)[0]["status"] == "acknowledged"
        assert responses[-1]["accepted"] == 1
        assert responses[-1]["durable"] is True

        def unavailable(*args):
            raise collector.CollectorError("ssh_timeout")

        assert collector.run_once(config, unavailable, send)[0]["code"] == "ssh_timeout"
        assert responses[-1]["accepted"] == 0
        assert json.loads((Path(config["state_dir"]) / "source-a.state.json").read_text())["cursor"] == "cursor-1"
        assert collector.run_once(config, lambda *args: exported([], "cursor-1"), send)[0]["status"] == "acknowledged"
