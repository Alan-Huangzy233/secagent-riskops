from datetime import datetime, timedelta, timezone
import json

import pytest

from app.telemetry import store as module
from app.telemetry.store import TelemetryStore


NOW = datetime(2026, 9, 11, tzinfo=timezone.utc)


def record(event_id, seconds=0, message=None):
    return {"event_id":event_id, "timestamp":(NOW+timedelta(seconds=seconds)).isoformat(),
            "message":message or "Connection closed by authenticating user root 198.51.100.8 port 42000 [preauth]",
            "identifier":"sshd", "unit":"ssh.service", "priority":"6"}


def receipt_state(store):
    with store._connection() as db:
        return {name:[tuple(row) for row in db.execute(f"SELECT * FROM {name} ORDER BY source_id, {key}")]
                for name,key in (("batches","batch_id"),("event_receipts","event_id"))}


def test_backfill_preserves_raw_receipts_and_incident_ids_and_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "_now", lambda: NOW+timedelta(seconds=30))
    store = TelemetryStore(tmp_path/"live.sqlite")
    # An existing incident must survive catch-up of newly understood messages.
    old = [record(f"old-{i}", i, "Failed password for admin from 198.51.100.9 port 42000 ssh2") for i in range(3)]
    old_id = store.ingest("source-a","relay-a","existing",old)["incident_ids"][0]
    original = module._classify
    monkeypatch.setattr(module,"_classify",lambda *args:("other",None,None))
    missed = [record(str(i), i+5) for i in range(3)]
    store.ingest("source-a","relay-a","missed",missed)
    before = receipt_state(store)
    raw_before = {row["event_id"]:row for row in store.list_events()}
    monkeypatch.setattr(module,"_classify",original)
    result = store.reparse_sshd()
    assert result == {"changed_events":3,"changed_evidence":0,"newly_detectable":3}
    assert receipt_state(store) == before
    assert old_id in {row["incident_id"] for row in store.list_incidents()}
    assert len(store.list_incidents()) == 2
    for row in store.list_events():
        for key in ("record_hash","message_hash","message","event_id","source_id","hostname","timestamp","received_at"):
            assert row[key] == raw_before[row["event_id"]][key]
    assert store.reparse_sshd() == {"changed_events":0,"changed_evidence":0,"newly_detectable":0}
    ack = store.ingest("source-a","relay-a","missed",missed)
    assert ack["durable"] and ack["accepted"] == 0


def test_expired_raw_evidence_is_enriched_without_deletion(tmp_path, monkeypatch):
    now = [NOW+timedelta(seconds=20)]
    monkeypatch.setattr(module,"_now",lambda:now[0])
    store = TelemetryStore(tmp_path/"live.sqlite")
    rows = [record(str(i), i) for i in range(3)]
    incident_id = store.ingest("source-a","relay-a","rows",rows)["incident_ids"][0]
    with store._connection(write=True) as db:
        for row in db.execute("SELECT source_id,event_id,snapshot_json FROM incident_evidence").fetchall():
            snapshot = json.loads(row["snapshot_json"])
            snapshot["ssh_user"] = None
            db.execute("UPDATE incident_evidence SET snapshot_json=? WHERE source_id=? AND event_id=?",(json.dumps(snapshot),row["source_id"],row["event_id"]))
    now[0] += timedelta(days=15)
    store.cleanup()
    assert store.list_events() == []
    before = receipt_state(store)
    assert store.reparse_sshd()["changed_evidence"] == 3
    incident = store.list_incidents()[0]
    assert incident["incident_id"] == incident_id and incident["failure_count"] == 3
    assert all(row["username"] == "root" for row in incident["evidence_snapshots"])
    assert receipt_state(store) == before


def test_reparse_error_rolls_back_and_peer_changes_require_review(tmp_path,monkeypatch):
    monkeypatch.setattr(module,"_now",lambda:NOW+timedelta(seconds=30))
    store = TelemetryStore(tmp_path/"live.sqlite")
    store.ingest("source-a","source-a","initial",[record(str(i),i) for i in range(3)])
    before = store.list_events(),store.list_incidents(),receipt_state(store)
    monkeypatch.setattr(module,"_classify",lambda *args:("preauth_abort","198.51.100.99","root"))
    with pytest.raises(ValueError,match="review"):
        store.reparse_sshd()
    assert (store.list_events(),store.list_incidents(),receipt_state(store)) == before


def test_non_sshd_never_promotes_spoofed_message_and_blank_user_is_none(tmp_path,monkeypatch):
    monkeypatch.setattr(module,"_now",lambda:NOW+timedelta(seconds=30))
    store = TelemetryStore(tmp_path/"live.sqlite")
    rows = [{**record("foreign"),"identifier":"application"},record("blank",message="Invalid user  from 198.51.100.8 port 43000")]
    store.ingest("source-a","relay-a","batch",rows)
    events = {row["event_id"]:row for row in store.list_events()}
    assert events["foreign"]["event_type"] == "non_sshd" and events["foreign"]["peer_ip"] is None
    assert events["blank"]["event_kind"] == "invalid_user" and events["blank"]["username"] is None
