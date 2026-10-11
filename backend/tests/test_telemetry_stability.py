"""Bounded live maintenance and merge work, using isolated synthetic history."""
from contextlib import contextmanager
from datetime import timedelta
import json

import pytest

from app.telemetry import store as module
from app.telemetry.store import TelemetryStore
from test_telemetry_store import NOW, clock as clock, record, store as store


def test_expiry_backlog_resumes_after_restart_and_keeps_ack_evidence_and_receipts(store, clock, monkeypatch):
    original = [record(str(i), i) for i in range(3)]
    count = 2 * module._INGEST_CLEANUP_LIMIT + 5
    rows = original + [record(str(i), message="Listening on port 22") for i in range(3, count)]
    first = store.ingest("source-a", "host-a", "original", rows[:500])
    for start in range(500, len(rows), 500):
        store.ingest("source-a", "host-a", f"seed-{start}", rows[start:start + 500])
    evidence = store.get_incident(first["incident_ids"][0])["evidence_snapshots"]
    clock[0] += timedelta(days=15)
    latest = {**record("new", message="Listening on port 22"), "timestamp": clock[0].isoformat()}
    assert store.ingest("source-a", "host-a", "new", [latest])["durable"]
    with store._connection() as db:
        remaining = db.execute("SELECT count(*) FROM events").fetchone()[0]
        assert remaining == count + 1 - module._INGEST_CLEANUP_LIMIT
        assert db.execute("SELECT value FROM maintenance WHERE name='last_cleanup'").fetchone()[0] == NOW.date().isoformat()

    restarted = TelemetryStore(store.path)
    # An uncertain ACK retries the same durable batch without fetching or
    # deleting another slice; the next new heartbeat continues maintenance.
    assert restarted.ingest("source-a", "host-a", "new", [latest])["replayed_batch"]
    with restarted._connection() as db:
        assert db.execute("SELECT count(*) FROM events").fetchone()[0] == remaining
    assert restarted.ingest("source-b", "host-b", "heartbeat-1", [])["durable"]
    cleanup = restarted._cleanup

    def interrupted(*args, **kwargs):
        cleanup(*args, **kwargs)
        raise RuntimeError("synthetic failure before commit")

    with monkeypatch.context() as patch:
        patch.setattr(restarted, "_cleanup", interrupted)
        with pytest.raises(RuntimeError):
            restarted.ingest("source-b", "host-b", "heartbeat-2", [])
    with restarted._connection() as db:
        assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 6
        assert not db.execute("SELECT 1 FROM batches WHERE batch_id='heartbeat-2'").fetchone()
        assert db.execute("SELECT value FROM maintenance WHERE name='last_cleanup'").fetchone()[0] == NOW.date().isoformat()
    assert restarted.ingest("source-b", "host-b", "heartbeat-2", [])["durable"]
    assert [row["event_id"] for row in restarted.list_events()] == ["new"]
    assert restarted.get_incident(first["incident_ids"][0])["evidence_snapshots"] == evidence
    assert restarted.ingest("source-a", "host-a", "original", rows[:500])["duplicates"] == 500
    with restarted._connection() as db:
        assert db.execute("SELECT count(*) FROM event_receipts").fetchone()[0] == count + 1
        assert db.execute("SELECT value FROM maintenance WHERE name='last_cleanup'").fetchone()[0] == clock[0].date().isoformat()


def seed_unrelated(store, count, *, when=NOW):
    # Isolate maintenance/merge costs from detector work. Long journal cursors
    # and JSON resemble retained rows, without using production data.
    with store._connection(write=True) as db:
        db.executemany("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?)", (
            ("unrelated", f"{i:06}-" + "c" * 300, "host-c", when.isoformat(), when.timestamp(),
             when.isoformat(), "other", None, None, json.dumps({"message": "synthetic " * 40}), None)
            for i in range(count)))


def bound_instructions(store, monkeypatch, budget):
    original = store._connection
    instructions = [0]

    @contextmanager
    def bounded(**kwargs):
        with original(**kwargs) as db:
            def progress():
                instructions[0] += 100
                return int(instructions[0] > budget)
            db.set_progress_handler(progress, 100)
            try:
                yield db
            finally:
                db.set_progress_handler(None, 0)

    monkeypatch.setattr(store, "_connection", bounded)
    return instructions


def test_heartbeat_work_is_bounded_with_large_expiry_backlog(store, clock, monkeypatch):
    seed_unrelated(store, 20_000)
    clock[0] += timedelta(days=15)
    with monkeypatch.context() as patch:
        # Fixed budget for one ACK, independent of the daily expiry backlog.
        bound_instructions(store, patch, 150_000)
        assert store.ingest("source-a", "host-a", "heartbeat", [])["durable"]
    with store._connection() as db:
        assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 20_000 - module._INGEST_CLEANUP_LIMIT


def test_merge_work_follows_evidence_not_unrelated_raw_history(store, monkeypatch):
    target = store.ingest("source-a", "host-a", "target", [record(str(i), i) for i in range(3)])["incident_ids"][0]
    other = store.ingest("source-b", "host-b", "other", [record(str(i), i, ip="198.51.100.24") for i in range(3)])["incident_ids"][0]
    seed_unrelated(store, 20_000)
    with store._connection(write=True) as db:
        db.execute("DELETE FROM events WHERE source_id='source-b' AND event_id='0'")
    with monkeypatch.context() as patch:
        bound_instructions(store, patch, 20_000)
        with store._connection(write=True) as db:
            store._merge_incident(db, target, other, module._iso(NOW))
    with store._connection() as db:
        assert db.execute("SELECT count(*) FROM events WHERE incident_id=?", (target,)).fetchone()[0] == 5
        assert db.execute("SELECT count(*) FROM events WHERE source_id='unrelated' AND incident_id IS NULL").fetchone()[0] == 20_000
        assert db.execute("SELECT count(*) FROM incident_evidence WHERE incident_id=?", (target,)).fetchone()[0] == 6
        assert db.execute("SELECT count(*) FROM event_receipts").fetchone()[0] == 6
        assert db.execute("SELECT merged_into FROM incidents WHERE incident_id=?", (other,)).fetchone()[0] == target


def test_automatic_expiry_preserves_exact_cutoff(store, clock):
    clock[0] += timedelta(days=15)
    cutoff = clock[0] - timedelta(days=store.retention_days)
    rows = [{**record(label, message="Listening on port 22"), "timestamp": stamp.isoformat()}
            for label, stamp in (("expired", cutoff - timedelta(microseconds=1)), ("boundary", cutoff), ("recent", clock[0]))]
    store.ingest("source-a", "host-a", "cutoff", rows)
    assert {row["event_id"] for row in store.list_events()} == {"boundary", "recent"}
    assert store.ingest("source-a", "host-a", "cutoff", rows)["duplicates"] == 3


@pytest.mark.parametrize("failure", [False, True])
def test_slow_transaction_reports_phases_without_sql_or_evidence(store, monkeypatch, caplog, failure):
    monkeypatch.setattr(module, "_SLOW_TRANSACTION_SECONDS", 0)
    with caplog.at_level("WARNING", logger=module.__name__):
        try:
            with store._connection(write=True, operation="ingest") as db:
                db.execute("SELECT ?", ("sensitive-fixture-payload",))
                if failure:
                    raise RuntimeError("sensitive-fixture-exception")
        except RuntimeError:
            pass
    message = caplog.records[-1].getMessage()
    assert "telemetry_db_slow operation=ingest write=True" in message
    assert ("outcome=failed" if failure else "outcome=ok") in message
    assert all(name + "=" in message for name in ("wait_ms", "work_ms", "finish_ms"))
    assert "sensitive-fixture" not in caplog.text and "SELECT" not in caplog.text
