from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib

import pytest

from app.telemetry import store as module
from app.telemetry.store import TelemetryStore


NOW = datetime(2026, 9, 8, 8, 0, tzinfo=timezone.utc)


@pytest.fixture
def clock(monkeypatch):
    current = [NOW]
    monkeypatch.setattr(module, "_now", lambda: current[0])
    return current


@pytest.fixture
def store(tmp_path, clock):
    return TelemetryStore(tmp_path / "live.sqlite3")


def record(event_id, seconds=0, *, ip="198.51.100.23", message=None, identifier="sshd"):
    return {
        "event_id": event_id,
        "timestamp": (NOW + timedelta(seconds=seconds)).isoformat(),
        "message": message or f"Failed password for invalid user admin from {ip} port 51412 ssh2",
        "unit": "ssh.service", "priority": "6", "identifier": identifier,
    }


def test_restart_preserves_ack_events_incident_and_idempotency(store):
    rows = [record(str(i), i) for i in range(3)]
    ack = store.ingest("source-a", "trusted-source-a", "batch1", rows)
    assert ack["durable"] is True and ack["batch_id"] == "batch1"
    assert ack["accepted"] == 3 and len(ack["incident_ids"]) == 1
    restarted = TelemetryStore(store.path)
    assert restarted.healthcheck()
    duplicate = restarted.ingest("source-a", "trusted-source-a", "batch1", rows)
    assert duplicate["accepted"] == 0 and duplicate["duplicates"] == 3
    assert duplicate["incident_ids"] == ack["incident_ids"]
    assert len(restarted.list_events()) == 3
    assert restarted.list_incidents()[0]["failure_count"] == 3
    assert restarted.get_source("source-a")["accepted_total"] == 3


def test_cross_batch_window_ipv6_and_incident_count_update(store):
    for index in range(4):
        result = store.ingest("source-a", "source-a", str(index), [record(str(index), index * 60, ip="2001:db8::1")])
        assert len(store.list_incidents()) == (0 if index < 2 else 1)
    incident = store.list_incidents()[0]
    assert result["incident_ids"] == [incident["incident_id"]]
    assert incident["src_ip"] == "2001:db8::1"
    assert incident["failure_count"] == 4
    assert len(incident["event_ids"]) == len(incident["evidence_snapshots"]) == 4
    assert store.list_events()[0]["username"] == "admin"


def test_other_sources_peers_and_slow_failures_do_not_combine(store):
    for index in range(3):
        store.ingest("source-a", "source-a", str(index), [record(str(index), index * 240)])
        store.ingest(f"source-{index}", "trusted", "one", [record("one")])
        store.ingest("separate-peers", "trusted", str(index), [record(str(index), ip=f"198.51.100.{index + 1}")])
    assert store.list_incidents() == []


def test_rolling_window_across_minute_boundary_and_out_of_order(store):
    for event_id, seconds in [("last", 301), ("first", 299), ("middle", 300)]:
        store.ingest("source-a", "source-a", event_id, [record(event_id, seconds)])
    incident = store.list_incidents()[0]
    assert incident["failure_count"] == 3
    assert incident["event_ids"] == ["first", "middle", "last"]


def test_duplicate_events_in_and_across_batches_do_not_increment_attack(store):
    row = record("cursor1")
    first = store.ingest("source-a", "source-a", "one", [row, row, row])
    second = store.ingest("source-a", "source-a", "two", [row])
    assert (first["accepted"], first["duplicates"]) == (1, 2)
    assert (second["accepted"], second["duplicates"]) == (0, 1)
    assert store.list_incidents() == []


def test_committed_batch_receipt_is_independent_of_later_classifier_changes(store, monkeypatch):
    rows = [record("cursor")]
    store.ingest("source-a", "source-a", "before-upgrade", rows)
    monkeypatch.setattr(module, "_classify", lambda *args: ("other", None, None))
    ack = TelemetryStore(store.path).ingest("source-a", "source-a", "before-upgrade", rows)
    assert ack["durable"] is True and ack["accepted"] == 0 and ack["duplicates"] == 1
    assert store.list_events()[0]["event_type"] == "auth_failure"


def test_concurrent_batches_are_durable_and_do_not_duplicate_incidents(store):
    def send(index):
        # Independent instances/connections represent simultaneous API workers.
        return TelemetryStore(store.path).ingest("source-a", "source-a", f"batch-{index}", [record(f"event-{index}", index)])
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(send, range(20)))
    assert sum(item["accepted"] for item in results) == 20
    assert len(store.list_events()) == 20
    incidents = store.list_incidents()
    assert len(incidents) == 1 and incidents[0]["failure_count"] == 20
    with ThreadPoolExecutor(max_workers=8) as pool:
        duplicates = list(pool.map(send, range(20)))
    assert sum(item["accepted"] for item in duplicates) == 0
    assert store.list_incidents()[0]["failure_count"] == 20


def test_bad_messages_and_success_are_preserved_without_false_incidents(store):
    rows = [
        record("bad-ip", message="Failed password for root from not-an-ip port 22 ssh2"),
        record("wrong-process", identifier="application"),
        record("other", message="Listening on port 22"),
        record("pam", message="pam_unix(sshd:auth): authentication failure; user=root"),
        record("success", message="Accepted publickey for root from 2001:db8::9 port 12345 ssh2: ED25519 SHA256:example"),
        record("ssh-session", message="Accepted password for user from 198.51.100.9 port 22 ssh2", identifier="sshd-session"),
    ]
    store.ingest("source-a", "server-side-name", "one", rows)
    events = {event["event_id"]: event for event in store.list_events()}
    assert len(events) == 6 and store.list_incidents() == []
    assert all(events[name]["event_type"] == "other" for name in ("bad-ip", "other", "pam"))
    assert events["wrong-process"]["event_type"] == "non_sshd"
    assert events["success"]["event_type"] == "auth_success"
    assert events["success"]["peer_ip"] == "2001:db8::9"
    assert all(event["hostname"] == "server-side-name" for event in events.values())
    raw = rows[4]["message"]
    assert events["success"]["message_hash"] == "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
    assert store.get_source("source-a")["ssh_success_count"] == 2


def test_invalid_record_and_identity_conflicts_roll_back_entire_batch(store):
    with pytest.raises(ValueError, match="timezone-aware"):
        store.ingest("source-a", "source-a", "invalid", [record("good"), {**record("bad"), "timestamp": "nonsense"}])
    assert store.list_events() == [] and store.list_sources() == []
    store.ingest("source-a", "source-a", "original", [record("cursor")])
    with pytest.raises(ValueError, match="event_id"):
        store.ingest("source-a", "source-a", "conflict", [record("would-be-new"), record("cursor", message="different")])
    assert len(store.list_events()) == 1
    assert store.get_source("source-a")["accepted_total"] == 1
    with pytest.raises(ValueError, match="batch_id"):
        store.ingest("source-a", "source-a", "original", [])


def test_empty_heartbeat_exposes_collection_errors_and_recovers(store, clock):
    store.ingest("source-b", "source-b", "failed", [], error="journal permission denied")
    source = store.get_source("source-b")
    assert source["status"] == "error" and source["last_error"] == "journal permission denied"
    assert source["event_count"] == 0 and source["last_event_at"] is None
    clock[0] += timedelta(minutes=1)
    store.ingest("source-b", "source-b", "healthy", [])
    healthy = store.get_source("source-b")
    assert healthy["status"] == "ok" and healthy["last_error"] is None
    assert healthy["last_seen"] > source["last_seen"]


def test_retention_keeps_incident_snapshots_and_event_dedup_receipts(store, clock):
    rows = [record(str(i), i) for i in range(3)]
    store.ingest("source-a", "source-a", "first", rows)
    incident = store.list_incidents()[0]
    clock[0] += timedelta(days=15)
    assert store.cleanup()["deleted_events"] == 3
    assert store.list_events() == []
    retained = store.list_incidents()[0]
    assert retained["evidence_snapshots"] == incident["evidence_snapshots"]
    assert len(retained["event_ids"]) == 3
    restarted = TelemetryStore(store.path)
    batch_ack = restarted.ingest("source-a", "source-a", "first", rows)
    assert batch_ack["accepted"] == 0 and batch_ack["duplicates"] == 3
    assert batch_ack["incident_ids"] == [incident["incident_id"]]
    ack = restarted.ingest("source-a", "source-a", "recovered-cursor", rows)
    assert ack["accepted"] == 0 and ack["duplicates"] == 3
    assert store.list_events() == [] and len(store.list_incidents()) == 1


def test_sshd_auth_identifier_and_prefix_are_classified(store):
    rows = [
        record("split-failure", identifier="sshd-auth", ip="2001:db8::8"),
        record("split-success", identifier="sshd-auth",
               message="Accepted publickey for admin from 198.51.100.8 port 1234 ssh2: ED25519 SHA256:example"),
        record("prefix", identifier="",
               message="Sep  8 08:00:00 untrusted-hostname sshd-auth[234]: Failed password for root from 2001:db8::8 port 2345 ssh2"),
    ]
    store.ingest("source-a", "trusted-name", "split-openssh", rows)
    events = {event["event_id"]: event for event in store.list_events()}
    assert events["split-failure"]["event_type"] == events["prefix"]["event_type"] == "auth_failure"
    assert events["split-success"]["event_type"] == "auth_success"
    assert events["prefix"]["hostname"] == "trusted-name"


def test_incident_response_has_bounded_evidence_preview_without_losing_count(store, clock):
    rows = [record(str(index), index) for index in range(50)]
    store.ingest("source-a", "source-a", "fifty-failures", rows)
    incident = store.list_incidents()[0]
    assert incident["failure_count"] == incident["evidence_count"] == 50
    assert incident["evidence_truncated"] is True
    assert len(incident["event_ids"]) == len(incident["evidence_snapshots"]) == 20
    assert len(store.list_events(limit=100)) == 50
    clock[0] += timedelta(days=15)
    store.cleanup()
    restarted = TelemetryStore(store.path)
    retained = restarted.list_incidents()[0]
    assert retained["evidence_snapshots"] == incident["evidence_snapshots"]
    assert retained["evidence_count"] == 50
    with restarted._connection() as db:
        # Preview truncation must not delete the other 30 retained snapshots.
        assert db.execute("SELECT count(*) FROM incident_evidence").fetchone()[0] == 50


def test_late_bridge_merges_incidents_and_old_batch_ack_resolves_current_id(store):
    first_rows = [record(f"first-{index}", index) for index in range(3)]
    last_rows = [record(f"last-{index}", 598 + index) for index in range(3)]
    store.ingest("source-a", "source-a", "first-cluster", first_rows)
    store.ingest("source-a", "source-a", "last-cluster", last_rows)
    assert len(store.list_incidents()) == 2
    bridge = store.ingest("source-a", "source-a", "late-bridge", [record("bridge", 300)])
    incidents = store.list_incidents()
    assert len(incidents) == 1 and incidents[0]["failure_count"] == 7
    assert bridge["incident_ids"] == [incidents[0]["incident_id"]]
    for batch, rows in [("first-cluster", first_rows), ("last-cluster", last_rows)]:
        ack = store.ingest("source-a", "source-a", batch, rows)
        assert ack["accepted"] == 0
        assert ack["incident_ids"] == bridge["incident_ids"]


def test_query_pagination_and_scope_filter(store):
    store.ingest("source-a", "source-a", "one", [record(str(i), i) for i in range(5)])
    store.ingest("source-b", "source-b", "one", [record("source-event")])
    assert [item["event_id"] for item in store.list_events("source-a", limit=2, offset=1)] == ["3", "2"]
    assert store.list_incidents("source-b") == []
    assert len(store.list_sources(limit=1, offset=1)) == 1
    for query in (store.list_events, store.list_sources, store.list_incidents):
        with pytest.raises(ValueError):
            query(limit=201)
        with pytest.raises(ValueError):
            query(offset=-1)


def test_live_store_refuses_ephemeral_database():
    with pytest.raises(ValueError, match="durable"):
        TelemetryStore(":memory:")
