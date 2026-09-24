"""Collection integrity: gaps are kept forever, delays open and close, catch-up is bounded.

Each scenario is one of P03's acceptance cases: a source that cannot be read, a
cursor the source journal no longer holds, a collector or API that was down, a
burst larger than one page, and a restore from a recovery package.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3

from fastapi.testclient import TestClient
import pytest

from app.live_api import create_app
from app.telemetry import store as module
from app.telemetry.config import LiveConfig, hash_operator_password
from app.telemetry.store import TelemetryStore

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


collector = _load("riskops_collector_integrity", ROOT / "scripts" / "telemetry_collector.py")
recovery = _load("recovery_package_integrity", ROOT / "scripts" / "recovery_package.py")

NOW = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)
TOKEN = "integrity-source-token-for-tests-only-123"
PASSWORD = "integrity-test-password-1234567890"


@pytest.fixture
def clock(monkeypatch):
    current = [NOW]
    monkeypatch.setattr(module, "_now", lambda: current[0])
    return current


@pytest.fixture
def store(tmp_path, clock):
    return TelemetryStore(tmp_path / "live.sqlite3")


def rows(*seconds: int, start: datetime = NOW) -> list[dict]:
    return [{"event_id": f"e{start.timestamp()}-{s}", "timestamp": (start + timedelta(seconds=s)).isoformat(),
             "message": "Accepted publickey for ops from 192.0.2.7 port 50000 ssh2", "identifier": "sshd"}
            for s in seconds]


def ingest(store, batch_id, records, *codes, collected_at=None):
    return store.ingest("src", "host", batch_id, records, reports=[{"code": c, "message": c} for c in codes],
                        collected_at=collected_at)


def issues(store, **kwargs):
    return store.paginate_collection_issues("src", **kwargs)["items"]


def state(store):
    return store.get_source("src")["collection"]


# --------------------------------------------------------------------------- store
def test_coverage_start_is_a_boundary_not_a_loss(store):
    ingest(store, "b1", rows(-300, -60), "coverage_start")
    [issue] = issues(store)
    assert (issue["kind"], issue["category"], issue["started_at"]) == ("coverage_start", "gap", None)
    assert issue["ended_at"] == rows(-300)[0]["timestamp"].replace("+00:00", ".000000Z")
    summary = state(store)
    assert summary["coverage_start"] == issue["ended_at"] and summary["gaps_since_coverage"] == 0


def test_a_rotated_cursor_is_a_gap_that_later_batches_never_erase(store, clock):
    """The collector was away an hour and the journal rotated: only the recent ten minutes come back."""
    ingest(store, "b1", rows(0), "coverage_start")
    clock[0] = NOW + timedelta(minutes=1)
    ingest(store, "b2", rows(30))
    clock[0] = NOW + timedelta(hours=1)
    ingest(store, "b3", rows(3000), "retention_gap", collected_at=clock[0].isoformat())
    for n in range(3):
        clock[0] = NOW + timedelta(hours=1, minutes=1 + n)
        ingest(store, f"b{4 + n}", rows(3100 + n))
    gap = next(i for i in issues(store) if i["kind"] == "retention_gap")
    assert gap["category"] == "gap" and gap["started_at"].startswith("2026-09-24T12:00:30")
    assert gap["ended_at"].startswith("2026-09-24T12:50:00")  # the recovered window's start
    assert state(store)["gaps_since_coverage"] == 1 and state(store)["last_gap"]["issue_id"] == gap["issue_id"]


def test_a_reset_whose_window_overlaps_what_was_collected_loses_nothing(store, clock):
    ingest(store, "b1", rows(0), "coverage_start")
    clock[0] = NOW + timedelta(minutes=2)
    ingest(store, "b2", rows(60), "retention_gap", collected_at=clock[0].isoformat())
    reset = next(i for i in issues(store) if i["kind"] == "cursor_reset")
    assert reset["category"] == "notice" and "nothing is missing" in reset["detail"]
    assert state(store)["gaps_since_coverage"] == 0


@pytest.mark.parametrize("code", ["ssh_export_failed", "journal_read_failed"])
def test_a_source_that_cannot_be_read_is_a_delay_that_closes(store, clock, code):
    ingest(store, "b1", rows(0), "coverage_start")
    for n in range(3):
        clock[0] = NOW + timedelta(seconds=30 * (n + 1))
        ingest(store, f"fail{n}", [], code)
    [delay] = [i for i in issues(store) if i["kind"] == "source_error"]
    assert delay["ended_at"] is None and delay["batches"] == 3 and state(store)["open"] == ["source_error"]
    assert state(store)["gaps_since_coverage"] == 0
    clock[0] = NOW + timedelta(minutes=3)
    ingest(store, "ok", rows(10))
    [delay] = [i for i in issues(store) if i["kind"] == "source_error"]
    assert delay["ended_at"] is not None and state(store)["open"] == []


def test_silence_and_a_late_batch_are_delays(store, clock):
    ingest(store, "b1", rows(0), "coverage_start")
    clock[0] = NOW + timedelta(minutes=20)
    ingest(store, "b2", rows(60), collected_at=(NOW + timedelta(minutes=16)).isoformat())
    kinds = {i["kind"]: i for i in issues(store)}
    assert kinds["silence"]["category"] == "delay" and kinds["silence"]["ended_at"] is not None
    assert "20 min" in kinds["silence"]["detail"]
    assert kinds["delivery_delay"]["category"] == "delay"
    assert state(store)["last_delivery_lag_seconds"] == 240.0 and state(store)["gaps_since_coverage"] == 0


def test_a_full_page_opens_catching_up_until_a_short_page(store, clock):
    ingest(store, "b1", rows(0), "coverage_start")
    for n in range(2):
        clock[0] = NOW + timedelta(seconds=10 * (n + 1))
        ingest(store, f"full{n}", rows(1 + n), "page_full")
    assert state(store)["caught_up"] is False and state(store)["open"] == ["catching_up"]
    clock[0] = NOW + timedelta(seconds=40)
    ingest(store, "short", rows(5))
    assert state(store)["caught_up"] is True and state(store)["open"] == []


def test_a_replayed_batch_is_not_counted_twice(store, clock):
    ingest(store, "b1", rows(0), "coverage_start")
    clock[0] = NOW + timedelta(minutes=1)
    ingest(store, "b2", [], "ssh_timeout")
    ingest(store, "b2", [], "ssh_timeout")
    assert [i["batches"] for i in issues(store) if i["kind"] == "source_error"] == [1]


def test_losing_the_cursor_of_a_known_source_is_a_gap(store, clock):
    ingest(store, "b1", rows(0), "coverage_start")
    clock[0] = NOW + timedelta(hours=1)
    ingest(store, "b2", rows(3500), "coverage_start")
    lost = next(i for i in issues(store) if i["kind"] == "cursor_lost")
    assert lost["category"] == "gap" and lost["started_at"].startswith("2026-09-24T12:00:00")
    assert lost["ended_at"].startswith("2026-09-24T12:50:00")
    assert state(store)["gaps_since_coverage"] == 1


def test_a_source_collected_before_tracking_gets_an_estimated_start(store, clock):
    ingest(store, "b1", rows(0))
    with store._connection(write=True) as db:  # noqa: SLF001 - simulate data from before this release
        db.execute("DELETE FROM source_collection")
        db.execute("DELETE FROM collection_issues")
    clock[0] = NOW + timedelta(minutes=1)
    ingest(store, "b2", rows(60))
    summary = state(store)
    assert summary["coverage_start"] == store.get_source("src")["first_seen"]
    assert summary["coverage_note"] and summary["tracking_since"].startswith("2026-09-24T12:01")


# ----------------------------------------------------------------------- collector
@pytest.fixture
def collector_config(tmp_path):
    return {"endpoint": "http://127.0.0.1:8088/api/telemetry/batches", "state_dir": str(tmp_path / "state"),
            "ssh_timeout_seconds": 2, "http_timeout_seconds": 2, "max_spool_bytes": 16 * 1024 * 1024,
            "max_pages_per_run": 5, "max_seconds_per_source": 20,
            "sources": [{"id": "src", "hostname": "host", "token": TOKEN, "ssh_command": ["unused"]}]}


class Journal:
    """A source journal of ``size`` records that serves pages after a cursor."""

    def __init__(self, size: int):
        base = int(NOW.timestamp() * 1_000_000)
        self.records = [{"__CURSOR": f"c{n:05d}", "__REALTIME_TIMESTAMP": str(base + n * 1000),
                         "MESSAGE": "Failed password for root from 192.0.2.9 port 2 ssh2",
                         "SYSLOG_IDENTIFIER": "sshd", "PRIORITY": "6"} for n in range(size)]
        self.requests: list[str | None] = []

    def fetch(self, source, cursor, timeout):
        self.requests.append(cursor)
        start = 0 if cursor is None else next(i for i, r in enumerate(self.records) if r["__CURSOR"] == cursor) + 1
        page = self.records[start:start + collector.MAX_RECORDS]
        checkpoint = page[-1]["__CURSOR"] if page else cursor
        status = "initial" if cursor is None else "ok"
        return b"".join(collector.encode(v) + b"\n" for v in
                        [*page, {"__riskops_checkpoint__": checkpoint, "cursor_status": status}])


def test_config_defaults_bound_the_catch_up(collector_config, tmp_path):
    del collector_config["max_pages_per_run"], collector_config["max_seconds_per_source"]
    path = tmp_path / "collector.json"
    path.write_text(json.dumps(collector_config))
    loaded = collector.load_config(path)
    assert (loaded["max_pages_per_run"], loaded["max_seconds_per_source"]) == (5, 20)
    collector_config["max_pages_per_run"] = 0
    path.write_text(json.dumps(collector_config))
    with pytest.raises(collector.CollectorError):
        collector.load_config(path)


def test_a_burst_is_read_in_bounded_pages_each_durably_acknowledged(collector_config):
    journal, sent = Journal(1050), []

    def send(endpoint, token, body, timeout):
        sent.append(body)
        return {"durable": True, "batch_id": body["batch_id"]}

    first = collector.run_once(collector_config, journal.fetch, send)[0]
    assert (first["pages"], first["records"], first["caught_up"]) == (5, 1000, False)
    assert "page_full" in first["report_codes"]
    assert [len(body["records"]) for body in sent] == [200] * 5
    cursor = json.loads((Path(collector_config["state_dir"]) / "src.state.json").read_text())["cursor"]
    assert cursor == "c00999"
    second = collector.run_once(collector_config, journal.fetch, send)[0]
    assert (second["pages"], second["records"], second["caught_up"]) == (1, 50, True)


def test_the_time_budget_stops_catch_up(collector_config):
    Path(collector_config["state_dir"]).mkdir()
    ticks = iter([0, 5, 25, 30])
    result = collector.collect_source(collector_config, collector_config["sources"][0], Journal(1000).fetch,
                                      lambda e, t, body, timeout: {"durable": True, "batch_id": body["batch_id"]},
                                      clock=lambda: next(ticks))
    assert result["pages"] == 2 and result["caught_up"] is False


def test_a_failure_mid_catch_up_keeps_the_pages_already_acknowledged(collector_config):
    calls = []

    def send(endpoint, token, body, timeout):
        calls.append(body)
        if len(calls) == 2:
            raise collector.CollectorError("http_unavailable")
        return {"durable": True, "batch_id": body["batch_id"]}

    result = collector.run_once(collector_config, Journal(600).fetch, send)[0]
    assert (result["status"], result["code"], result["pages"]) == ("error", "http_unavailable", 1)
    state_dir = Path(collector_config["state_dir"])
    assert json.loads((state_dir / "src.state.json").read_text())["cursor"] == "c00199"
    assert (state_dir / "src.pending.json").exists()  # page two is resent next run, unchanged


def test_an_export_cut_short_by_size_counts_as_full(collector_config, monkeypatch):
    """The exporter stops near 3 MiB without saying so; three records that fill it mean more are waiting."""
    data = Journal(3).fetch(None, None, 2)
    source = collector_config["sources"][0]
    codes = lambda: [r["code"] for r in collector.build_pending(source, None, lambda *a: data, 2)["body"]["reports"]]  # noqa: E731
    assert "page_full" not in codes()
    monkeypatch.setattr(collector, "EXPORT_PAGE_BYTES", len(data))
    assert "page_full" in codes()


# ---------------------------------------------------------------- end to end, API
@pytest.fixture
def api(tmp_path):
    config = LiveConfig(database_path=str(tmp_path / "api.sqlite3"),
                        sources=[{"id": "src", "hostname": "host",
                                  "token_sha256": hashlib.sha256(TOKEN.encode()).hexdigest()}],
                        operator_username="operator", operator_password_pbkdf2=hash_operator_password(PASSWORD))
    with TestClient(create_app(config)) as client:
        yield client


def through(api):
    def send(endpoint, token, body, timeout):
        response = api.post("/api/telemetry/batches", content=collector.encode(body),
                            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
        assert response.status_code == 200, response.text
        return response.json()
    return send


def summary(api):
    return next(s for s in api.get("/api/summary", auth=("operator", PASSWORD)).json()["sources"])


def test_collector_to_console_burst_outage_and_recovery(api, collector_config):
    journal, send = Journal(700), through(api)
    collector_config["max_pages_per_run"] = 2
    collector.run_once(collector_config, journal.fetch, send)
    source = summary(api)
    assert source["connection_status"] == "online"  # a coverage report does not make a source unhealthy
    assert source["collection"]["caught_up"] is False and source["collection"]["gaps_since_coverage"] == 0

    def down(*args):
        raise collector.CollectorError("ssh_export_failed")

    collector.run_once(collector_config, down, send)
    assert summary(api)["connection_status"] == "error"
    for _ in range(3):
        collector.run_once(collector_config, journal.fetch, send)
    source = summary(api)
    assert source["connection_status"] == "online" and source["collection"]["caught_up"] is True
    assert source["accepted_total"] == 700
    history = api.get("/api/collection-issues?source_id=src", auth=("operator", PASSWORD)).json()
    kinds = [item["kind"] for item in history["items"]]
    assert kinds.count("coverage_start") == 1 and "source_error" in kinds and "catching_up" in kinds
    assert all(item["ended_at"] for item in history["items"] if item["category"] == "delay")
    assert api.get("/api/collection-issues?source_id=nope", auth=("operator", PASSWORD)).status_code == 404
    assert api.get("/api/collection-issues").status_code == 401


# ------------------------------------------------------------------------ restore
def test_a_restore_point_is_recorded_per_source(tmp_path, store, capsys):
    ingest(store, "b1", rows(0), "coverage_start")
    store.ingest("other", "host-2", "b2", rows(1))
    lib = tmp_path / "lib"
    lib.mkdir()
    (lib / "snapshot.sqlite").write_bytes(Path(store.path).read_bytes())
    config = tmp_path / "package.json"
    config.write_text(json.dumps({"host_id": "h", "description": "d", "components": [
        {"name": "telemetry", "kind": "sqlite", "path": str(lib / "snapshot.sqlite")}]}))
    assert recovery.main(["build", "--config", str(config), "--output-dir", str(tmp_path / "store"),
                          "--allow-unencrypted"]) == 0
    package = next((tmp_path / "store").iterdir())
    bare = tmp_path / "bare.sqlite"
    sqlite3.connect(bare).close()
    assert recovery.main(["mark-restored", str(bare), str(package)]) != 0
    assert "start the API on it once" in capsys.readouterr().err
    assert recovery.main(["mark-restored", str(store.path), str(package)]) == 0
    marks = [i for i in store.paginate_collection_issues()["items"] if i["kind"] == "restore"]
    assert sorted(m["source_id"] for m in marks) == ["other", "src"]
    assert all(m["category"] == "notice" and m["started_at"] < m["ended_at"] for m in marks)
    assert state(store)["gaps_since_coverage"] == 0

