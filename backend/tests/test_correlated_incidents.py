from datetime import datetime, timedelta, timezone
import json

import pytest

from app.telemetry import store as module
from app.telemetry.store import TelemetryStore


NOW = datetime(2026, 9, 13, 12, tzinfo=timezone.utc)
START = NOW - timedelta(hours=4)


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "_now", lambda: NOW)
    return TelemetryStore(tmp_path / "live.sqlite")


def record(event_id, seconds, *, user="root", ip="198.51.100.23", success=False):
    message = (f"Accepted publickey for {user} from {ip} port 42000 ssh2" if success else
               f"Connection closed by authenticating user {user} {ip} port 42000 [preauth]")
    return {"event_id": event_id, "timestamp": (START + timedelta(seconds=seconds)).isoformat(),
            "message": message, "identifier": "sshd", "unit": "ssh.service", "priority": "6"}


def rules(incident):
    return {rule["rule_id"] for rule in incident["rules"]}


def immutable_rows(store):
    with store._connection() as db:
        return {table: [tuple(row) for row in db.execute(f"SELECT * FROM {table} ORDER BY source_id,{key}")]
                for table, key in (("batches", "batch_id"), ("event_receipts", "event_id"))}


@pytest.mark.parametrize("reverse", [False, True])
def test_slow_scan_across_batches_and_late_arrival(store, reverse):
    rows = [record(str(i), 5700 * i / 23) for i in range(24)]
    for row in reversed(rows) if reverse else rows:
        store.ingest("source-a", "host-a", row["event_id"], [row])
    incident, = store.list_incidents()
    assert rules(incident) == {"slow_scan"}
    assert incident["failure_count"] == incident["evidence_count"] == 24
    assert incident["source_ids"] == ["source-a"] and incident["usernames"] == ["root"]
    assert len(incident["evidence_snapshots"]) == 20 and incident["evidence_truncated"]
    before = immutable_rows(store)
    again = TelemetryStore(store.path)
    for row in rows:
        ack = again.ingest("source-a", "host-a", row["event_id"], [row])
        assert ack["accepted"] == 0
    assert immutable_rows(store) == before
    assert again.list_incidents()[0]["failure_count"] == 24


def test_cross_source_same_event_ids_have_distinct_evidence_and_shared_filter(store):
    for source, offset in (("source-a", 0), ("source-b", 300)):
        rows = [record(str(i), offset + 600 * i) for i in range(3)]
        store.ingest(source, "host-" + source[-1], "batch", rows)
    incident, = store.list_incidents()
    assert rules(incident) == {"cross_source"}
    assert incident["source_ids"] == ["source-a", "source-b"]
    assert incident["hostnames"] == ["host-a", "host-b"]
    assert incident["failure_count"] == 6
    assert len({(ref["source_id"], ref["event_id"]) for ref in incident["evidence_refs"]}) == 6
    for source in incident["source_ids"]:
        assert store.paginate_incidents(source)["items"] == [incident]
        assert store.get_source(source)["incident_count"] == 1
    assert store.count_incidents() == 1 and store.list_incidents("source-c") == []


def test_cross_source_merges_existing_bursts_and_resolves_old_ack(store):
    first = [record(str(i), i) for i in range(3)]
    ack_a = store.ingest("source-a", "host-a", "batch", first)
    second = [record(str(i), 600 + i) for i in range(3)]
    store.ingest("source-b", "host-b", "batch", second)
    incident, = store.list_incidents()
    assert rules(incident) == {"burst", "cross_source"}
    assert incident["failure_count"] == 6
    assert store.ingest("source-a", "host-a", "batch", first)["incident_ids"] == [incident["incident_id"]]
    with store._connection() as db:
        assert db.execute("SELECT 1 FROM incidents WHERE incident_id=?", (ack_a["incident_ids"][0],)).fetchone()
        assert db.execute("SELECT count(*) FROM incident_evidence").fetchone()[0] == 6
    assert store.rebuild_detections()["evidence_added"] == 0


def test_multi_account_and_no_unqualified_tail_attachment(store):
    seconds = [0, 1500, 3000, 4500, 6000, 7200]
    users = ["guest", "root", "admin", "root", "admin", "root"]
    rows = [record(str(i), at, user=users[i]) for i, at in enumerate(seconds)]
    store.ingest("source-a", "host-a", "initial", rows)
    incident, = store.list_incidents()
    assert rules(incident) == {"multi_account"} and incident["username_count"] == 3
    # The only third username has left the two-hour window. A previous long
    # window incident must not make the burst rule attach an unmatched tail.
    ack = store.ingest("source-a", "host-a", "tail", [record("tail", 7300)])
    assert ack["incident_ids"] == []
    assert store.list_incidents()[0]["failure_count"] == 6
    assert store.list_events()[0]["incident_id"] is None


@pytest.mark.parametrize("success_first", [False, True])
def test_success_after_failures_retains_both_outcomes(store, success_first, monkeypatch):
    failures = [record(str(i), i * 600) for i in range(3)]
    success = record("success", 1500, user="admin", success=True)
    batches = [("failed", failures), ("succeeded", [success])]
    for batch, rows in reversed(batches) if success_first else batches:
        store.ingest("source-a", "host-a", batch, rows)
    incident, = store.list_incidents()
    assert rules(incident) == {"success_after_failures"}
    assert incident["failure_count"] == 3 and incident["success_count"] == 1
    assert incident["evidence_count"] == 4 and incident["severity"] == "high"
    before = immutable_rows(store)
    assert store.reparse_sshd() == {"changed_events": 0, "changed_evidence": 0, "newly_detectable": 0}
    monkeypatch.setattr(module, "_now", lambda: NOW + timedelta(days=15))
    store.cleanup()
    restarted = TelemetryStore(store.path)
    assert restarted.list_events() == [] and restarted.list_incidents() == [incident]
    assert immutable_rows(restarted) == before


def test_reparse_success_evidence_allows_username_repair_but_not_outcome_change(store, monkeypatch):
    store.ingest("source-a", "host-a", "batch",
                 [record(str(i), i * 600) for i in range(3)] + [record("success", 1500, success=True)])
    with store._connection(write=True) as db:
        row = db.execute("SELECT snapshot_json FROM incident_evidence WHERE event_id='success'").fetchone()
        old = json.loads(row[0])
        old["ssh_user"] = None
        db.execute("UPDATE incident_evidence SET snapshot_json=? WHERE event_id='success'", (json.dumps(old),))
    assert store.reparse_sshd()["changed_evidence"] == 1
    original = module._classify
    def wrong_outcome(message, identifier, unit):
        if message.startswith("Accepted "):
            return "auth_failure", "198.51.100.23", "root"
        return original(message, identifier, unit)
    monkeypatch.setattr(module, "_classify", wrong_outcome)
    with pytest.raises(ValueError, match="review"):
        store.reparse_sshd()
    assert store.list_incidents()[0]["success_count"] == 1


def test_legacy_database_additive_migration_preserves_evidence_and_receipts(store):
    store.ingest("source-a", "host-a", "legacy", [record(str(i), i) for i in range(3)])
    original = store.list_incidents()[0]
    before = immutable_rows(store)
    with store._connection(write=True) as db:
        for table in ("incident_details", "incident_rules", "incident_sources"):
            db.execute(f"DROP TABLE {table}")
        db.execute("DELETE FROM maintenance WHERE name='detection_metadata_v1'")
    migrated = TelemetryStore(store.path)
    current, = migrated.list_incidents()
    assert current["incident_id"] == original["incident_id"]
    assert current["evidence_snapshots"] == original["evidence_snapshots"]
    assert current["failure_count"] == 3 and rules(current) == {"burst"}
    assert immutable_rows(migrated) == before


def test_failed_correlation_rolls_back_whole_ingestion(store, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("simulated detection failure")
    monkeypatch.setattr(store, "_apply_match", broken)
    with pytest.raises(RuntimeError):
        store.ingest("source-a", "host-a", "failed", [record(str(i), i) for i in range(3)])
    assert store.list_events() == [] and store.list_sources() == []
    assert all(not rows for rows in immutable_rows(store).values())


def test_isolated_sources_and_widely_spaced_failures_do_not_create_incidents(store):
    for source, ip in (("source-a", "198.51.100.1"), ("source-b", "198.51.100.2")):
        store.ingest(source, source, "sparse", [record(str(i), i * 900, ip=ip) for i in range(12)])
    assert store.list_incidents() == []
