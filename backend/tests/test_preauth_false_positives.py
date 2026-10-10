"""Regressions for management SSH disconnects mistaken for a compromised login."""
from datetime import timedelta
import json
import sqlite3

import pytest

from app.telemetry import notifications, scoring
from app.telemetry.detection import detect_matches
from app.telemetry.store import TelemetryStore
from test_live_scoring import NOW, store as store
from test_ssh_detection import event, matches


@pytest.mark.parametrize("kind", ["auth_failure", "invalid_user", "ssh_failure"])
def test_success_rule_requires_three_authentication_failures_not_disconnects(kind):
    rows = [event(n, n, kind="preauth_abort") for n in range(5)]
    rows += [event("success", 10, kind="auth_success")]
    assert not matches(rows, "success_after_failures")
    assert any(m.rule_id == "burst" for m in detect_matches(rows, {("source-a", "0")}, include_burst=True))
    rows[0]["event_type"] = rows[1]["event_type"] = kind
    assert not matches(rows, "success_after_failures")
    rows[2]["event_type"] = kind
    match, = matches(rows, "success_after_failures")
    assert match.rule_version == 2
    assert {r["event_id"] for r in match.evidence} == {"0", "1", "2", "success"}


def management_activity(store):
    start = NOW - timedelta(hours=2)
    messages = ["Connection closed by 198.51.100.7 port 42000 [preauth]"] * 4
    messages += [f"Accepted publickey for {user} from 198.51.100.7 port 42000 ssh2"
                 for user in ("root", "control-account") for _ in range(30)]
    return store.ingest("source-a", "source-a", "management", [
        {"event_id": str(n), "timestamp": (start + timedelta(seconds=n)).isoformat(),
         "identifier": "sshd", "message": message} for n, message in enumerate(messages)])


def test_disconnects_then_many_management_logins_do_not_gain_compromise_weight(store):
    ack = management_activity(store)
    item = store.get_incident(ack["incident_ids"][0])
    assert item["success_count"] == 0, "Normal logins no longer expand a preauth-only incident"
    assert item["evidence_count"] == 4
    assert sum(e["event_type"] == "auth_success" for e in store.list_events()) == 60
    assert item["assessment"]["score"] == 0 and item["assessment"]["priority"] is None
    assert item["severity"] == "medium"
    assert {r["rule_id"] for r in item["rules"]} == {"burst"}
    assert store.paginate_incidents(focus="attention")["total"] == 0
    assert store.paginate_incidents(focus="low")["total"] == 1
    assert store.triage_counts()["pending"] == 1
    store.run_notifications(["source-a"], now=NOW.timestamp())
    assert store.list_notifications(kind="incident")["items"] == []


def test_history_backfill_corrects_rule_score_and_queued_notice_preserving_evidence_and_decisions(store):
    ack = management_activity(store)
    identity = ack["incident_ids"][0]
    store.set_triage([identity], "acknowledged", actor="operator")
    with store._connection(write=True) as db:
        # Old v1 detection retained many normal successes after the disconnects.
        db.execute("""INSERT INTO incident_evidence
            SELECT source_id,event_id,?,event_ts,record_json FROM events WHERE event_type='auth_success'""", (identity,))
        store._refresh_incident(db, identity)
        # A retained v1 incident, including the unsupported high-severity rule.
        db.execute("UPDATE incident_scores SET version='ssh-evidence-v1',score=50,priority='P2',surfaced=1")
        db.execute("INSERT INTO incident_rules VALUES(?,?,?,?,?)",
                   (identity, "success_after_failures", 1, 1800, "Old preauth-only success match"))
        notifications.enqueue(db, "incident:" + identity, "incident", {"score": 50},
                              NOW.timestamp(), object_id=identity)
        before = {table: [tuple(r) for r in db.execute("SELECT * FROM " + table)]
                  for table in ("events", "event_receipts", "batches", "incident_evidence", "incidents",
                                "incident_triage", "incident_triage_log")}
    # Neither startup nor GET performs a historical evidence scan/write.
    restarted = TelemetryStore(store.path)
    assert restarted.get_incident(identity)["assessment"]["status"] == "unscored"
    assert restarted.backfill_scores(1)["scored"] == 1
    item = restarted.get_incident(identity)
    assert item["assessment"]["score"] == 0 and item["triage_status"] == "acknowledged"
    assert item["evidence_count"] == 64 and item["success_count"] == 60
    preview = restarted.paginate_incident_evidence(identity, limit=20)
    assert preview["total"] == 64 and len(preview["items"]) == 20
    assert item["severity"] == "medium" and all(r["rule_id"] != "success_after_failures" for r in item["rules"])
    assert restarted.backfill_scores(1)["scored"] == 0
    with restarted._connection() as db:
        assert before == {table: [tuple(r) for r in db.execute("SELECT * FROM " + table)] for table in before}
    restarted.run_notifications(["source-a"], now=NOW.timestamp())
    assert restarted.list_notifications(kind="incident")["items"] == []
    with restarted._connection() as db:
        assert db.execute("SELECT state FROM notification_outbox WHERE topic=?", ("incident:" + identity,)).fetchone()[0] == "cancelled"


@pytest.mark.parametrize("success_at,host,peer,failures,expected", [
    (1800, "source-a", "198.51.100.23", 3, 1),
    (1800.001, "source-a", "198.51.100.23", 3, 0),
    (0, "source-a", "198.51.100.23", 3, 0),
    (-1, "source-a", "198.51.100.23", 3, 0),
    (1, "source-b", "198.51.100.23", 3, 0),
    (1, "source-a", "198.51.100.24", 3, 0),
    (1, "source-a", "198.51.100.23", 2, 0),
])
def test_live_score_qualifies_success_on_complete_host_peer_and_time_window(success_at, host, peer, failures, expected):
    rows = [event(n, 0) for n in range(failures)]
    rows += [event("abort", 0, kind="preauth_abort"),
             event("success", success_at, source=host, peer=peer, kind="auth_success")]
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE incident_evidence(incident_id,source_id,event_ts,snapshot_json)")
        db.executemany("INSERT INTO incident_evidence VALUES(?,?,?,?)",
                       [("case", r["source_id"], r["event_ts"], json.dumps(r)) for r in rows])
        db.execute("PRAGMA query_only=ON")
        result, count, qualified = scoring.evaluate(db, "case")
    assert count == len(rows) and qualified == expected
    assert result.surfaced is bool(expected)
    assert bool(matches(rows, "success_after_failures")) is bool(expected)
