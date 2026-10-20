"""Durable delivery and bounded retention tests with authored journal evidence."""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
import sqlite3

import pytest

from app.telemetry import network_store
from app.telemetry.network_parse import SourceProfile
from app.telemetry.network_protocol import encode, journal_entry, validate_ack
from app.telemetry.network_store import NetworkStore, NetworkStoreError


NOW = 1_800_000_000_000_000
DAY = 86_400_000_000


def profile(source="synthetic-a"):
    return SourceProfile(source_id=source, ruleset_sha256="a" * 64,
                         log_labels=("[UFW BLOCK]",), rejection_labels=("[UFW BLOCK]",),
                         local_input_labels=("[UFW BLOCK]",), local_input_interfaces=("eth0",))


def entry(index, *, source_profile=None, port=443, reject=False, cursor=None):
    record = {"_TRANSPORT": "kernel", "_BOOT_ID": "1" * 32,
              "__CURSOR": cursor or f"synthetic-cursor-{index}",
              "__REALTIME_TIMESTAMP": str(NOW - DAY + index),
              "__MONOTONIC_TIMESTAMP": str(1000 + index),
              "MESSAGE": (f"[UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.22 DST=192.0.2.15 "
                          f"LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=7 PROTO=TCP SPT=40000 DPT={port} "
                          "WINDOW=1024 RES=0x00 SYN URGP=0")}
    if reject:
        record["MESSAGE"] = "PRIVATE-RAW-REJECTION-TEXT"
    return journal_entry(record, source_profile or profile())


def batch(index, entries=None, *, before=None, source_profile=None, collected=NOW,
          reports=None, caught_up=True):
    source_profile = source_profile or profile()
    entries = [entry(index, source_profile=source_profile)] if entries is None else entries
    return {"version": 1, "source_id": source_profile.source_id, "profile_revision": source_profile.revision,
            "batch_id": f"synthetic-batch-{index}", "collected_at_us": collected, "cursor_before": before,
            "cursor_after": next(iter(entries[-1].values()))["journal_cursor"] if entries else before,
            "entries": entries, "reports": reports or [], "caught_up": caught_up}


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(network_store, "_now_us", lambda: NOW)
    return NetworkStore(tmp_path / "network.sqlite3")


def test_committed_ack_survives_reopen_and_keeps_three_independent_times(store):
    payload = batch(1, collected=NOW - 100)
    ack = store.ingest(payload, profile(), now_us=NOW)
    validate_ack(ack, payload)
    reopened = NetworkStore(store.path)
    assert encode(reopened.ingest(payload, profile(), now_us=NOW + DAY)) == encode(ack)
    page = reopened.page("synthetic-a")
    row, = page["items"]
    assert row["journal_realtime_us"] == NOW - DAY + 1
    assert row["collected_at_us"] == NOW - 100 and row["received_at_us"] == NOW
    assert row["source_profile_revision"] == profile().revision
    source, = reopened.sources()
    assert source["checkpoint"] == payload["cursor_after"]
    assert source["last_report"] == ack and source["accepted_total"] == 1
    assert reopened.healthcheck() is True


def test_duplicate_batch_ack_precedes_current_cursor_time_and_quota_checks(tmp_path):
    store = NetworkStore(tmp_path / "network.sqlite3", max_receipts=1, max_batches=1)
    payload = batch(1)
    ack = store.ingest(payload, profile(), now_us=NOW)
    assert store.status()["capacity_available"] is False
    assert store.ingest(payload, profile(), now_us=NOW - DAY) == ack
    conflicting = {**payload, "caught_up": False}
    with pytest.raises(NetworkStoreError, match="network_batch_conflict"):
        store.ingest(conflicting, profile(), now_us=NOW)
    assert store.status()["counts"] == {"events": 1, "receipts": 1, "batches": 1, "sources": 1}


def test_event_replay_keeps_order_and_original_rejection_codes_without_raw_content(store):
    accepted, rejected = entry(1), entry(2, reject=True)
    first = batch(1, [accepted, rejected, accepted])
    ack = store.ingest(first, profile(), now_us=NOW)
    validate_ack(ack, first)
    assert [result["status"] for result in ack["results"]] == ["accepted", "rejected", "duplicate"]
    second = batch(2, [rejected, accepted], before=first["cursor_after"])
    response = store.ingest(second, profile(), now_us=NOW)
    validate_ack(response, second)
    assert (response["accepted"], response["rejected"], response["duplicates"]) == (0, 0, 2)
    assert response["results"][0]["code"] == "invalid_record"
    assert len(store.page("synthetic-a")["items"]) == 1
    assert "PRIVATE-RAW-REJECTION-TEXT" not in json.dumps(store.page("synthetic-a", batches=True))
    assert b"PRIVATE-RAW-REJECTION-TEXT" not in Path(store.path).read_bytes()


@pytest.mark.parametrize("changed", ["content", "kind", "rejection_code", "rejection_time"])
def test_identity_conflicts_roll_back_every_row_and_checkpoint(store, changed):
    original = entry(1, reject=changed.startswith("rejection"))
    first = batch(1, [original])
    store.ingest(first, profile(), now_us=NOW)
    collision = entry(1, port=8443) if changed == "content" else deepcopy(original)
    if changed == "kind":
        collision = entry(1, reject=True)
        collision["rejection"]["content_hash"] = original["event"]["content_hash"]
    elif changed == "rejection_code":
        collision["rejection"]["code"] = "profile_context_unavailable"
    elif changed == "rejection_time":
        collision["rejection"]["journal_realtime_us"] += 1
    pending = batch(2, [entry(3), collision], before=first["cursor_after"])
    before = store.status()["counts"]
    with pytest.raises(NetworkStoreError, match="network_event_conflict"):
        store.ingest(pending, profile(), now_us=NOW)
    assert store.status()["counts"] == before
    assert store.sources()[0]["checkpoint"] == first["cursor_after"]
    assert [row["batch_id"] for row in store.page("synthetic-a", batches=True)["items"]] == [first["batch_id"]]


def test_cursor_continuity_includes_empty_gap_and_profile_reports(store):
    with pytest.raises(NetworkStoreError, match="network_cursor_conflict"):
        store.ingest(batch(1, before="uncommitted"), profile(), now_us=NOW)
    first = batch(1)
    store.ingest(first, profile(), now_us=NOW)
    with pytest.raises(NetworkStoreError, match="network_cursor_conflict"):
        store.ingest(batch(2), profile(), now_us=NOW)
    gap = batch(2, [], before=first["cursor_after"], reports=["journal_cursor_unavailable"], caught_up=False)
    ack = store.ingest(gap, profile(), now_us=NOW)
    validate_ack(ack, gap)
    assert ack["cursor_after"] == first["cursor_after"] and ack["results"] == []
    assert store.sources()[0]["last_report"]["reports"] == ["journal_cursor_unavailable"]


def test_new_future_collection_is_rejected_without_receipt(store):
    with pytest.raises(NetworkStoreError, match="network_collection_time_in_future"):
        store.ingest(batch(1, collected=NOW + 300_000_001), profile(), now_us=NOW)
    assert store.status()["counts"]["batches"] == 0
    assert store.ingest(batch(1, collected=NOW + 300_000_000), profile(), now_us=NOW)["accepted"] == 1


def test_retention_expires_by_receive_time_and_receipts_prevent_resurrection(store):
    first = batch(1)
    store.ingest(first, profile(), now_us=NOW)
    # A source timestamp one day older does not expire an otherwise recent receipt.
    store.ingest(batch(2, [], before=first["cursor_after"]), profile(), now_us=NOW + 14 * DAY)
    assert len(store.page("synthetic-a")["items"]) == 1
    duplicate = batch(3, first["entries"], before=first["cursor_after"])
    response = store.ingest(duplicate, profile(), now_us=NOW + 14 * DAY + 1)
    assert response["duplicates"] == 1 and store.page("synthetic-a")["items"] == []
    assert store.status()["counts"]["receipts"] == 1
    assert store.ingest(first, profile(), now_us=NOW + 20 * DAY)["accepted"] == 1
    expired = store.page("synthetic-a")
    assert expired["items"] == [] and expired["expired_events"] == 1
    assert expired["coverage"] == ["event_history_expired"]
    assert store.status()["expired_events"] == 1
    assert store.status()["coverage"] == ["event_history_expired"]
    assert store.page("synthetic-a", batches=True)["coverage"] == ["event_history_expired"]
    assert store.page("synthetic-b")["expired_events"] == 0


def test_retention_sweep_is_bounded_and_reports_remaining_expired_rows(store, monkeypatch):
    monkeypatch.setattr(network_store, "RETENTION_BATCH", 2)
    first = batch(1, [entry(index) for index in range(4)])
    store.ingest(first, profile(), now_us=NOW)
    after_expiry = NOW + 14 * DAY + 1
    monkeypatch.setattr(network_store, "_now_us", lambda: after_expiry)
    store.ingest(batch(2, [], before=first["cursor_after"]), profile(), now_us=after_expiry)
    page = store.page("synthetic-a")
    assert len(page["items"]) == 2
    assert "event_retention_incomplete" in page["coverage"]
    assert "event_retention_incomplete" in store.status()["coverage"]
    store.ingest(batch(3, [], before=first["cursor_after"]), profile(), now_us=after_expiry)
    assert store.page("synthetic-a")["coverage"] == ["event_history_expired"]
    assert store.page("synthetic-a")["expired_events"] == 4
    assert store.status()["counts"]["receipts"] == 4


@pytest.mark.parametrize("cap", ["max_receipts", "max_batches"])
def test_capacity_failure_rolls_back_batch_and_original_receipts_remain_replayable(tmp_path, cap):
    store = NetworkStore(tmp_path / "network.sqlite3", **{cap: 1})
    first = batch(1)
    original = store.ingest(first, profile(), now_us=NOW)
    second = batch(2, [entry(2)], before=first["cursor_after"])
    with pytest.raises(NetworkStoreError, match="network_capacity_exceeded"):
        store.ingest(second, profile(), now_us=NOW)
    assert store.ingest(first, profile(), now_us=NOW) == original
    assert store.sources()[0]["checkpoint"] == first["cursor_after"]
    assert store.status()["counts"] == {"events": 1, "receipts": 1, "batches": 1, "sources": 1}


def test_pagination_snapshot_is_source_isolated_and_does_not_include_later_commits(store):
    first = batch(1, [entry(index) for index in range(3)])
    store.ingest(first, profile(), now_us=NOW)
    page = store.page("synthetic-a", limit=2)
    assert len(page["items"]) == 2 and page["has_more"]
    other = profile("synthetic-b")
    store.ingest(batch(10, source_profile=other), other, now_us=NOW)
    store.ingest(batch(4, before=first["cursor_after"]), profile(), now_us=NOW)
    last = store.page("synthetic-a", after=page["next_after"], snapshot=page["snapshot"], limit=2)
    assert len(last["items"]) == 1 and not last["has_more"]
    assert last["items"][0]["event_id"] == first["entries"][-1]["event"]["event_id"]
    assert len(store.page("synthetic-a")["items"]) == 4
    assert len(store.page("synthetic-b")["items"]) == 1
    assert [row["batch_id"] for row in store.page("synthetic-a", batches=True)["items"]] == [
        "synthetic-batch-1", "synthetic-batch-4"]


@pytest.mark.parametrize("kwargs", [{"after": True}, {"limit": 0}, {"limit": 201},
                                     {"snapshot": -1}, {"snapshot": True}, {"batches": "yes"}])
def test_pagination_parameters_are_strict(store, kwargs):
    with pytest.raises(NetworkStoreError, match="invalid_network_page"):
        store.page("synthetic-a", **kwargs)


def test_foreign_database_and_schema_version_are_rejected_without_modifying_foreign_mode(tmp_path):
    foreign = tmp_path / "ssh.sqlite3"
    with sqlite3.connect(foreign) as db:
        db.execute("CREATE TABLE ssh_events (id INTEGER)")
        previous_mode = db.execute("PRAGMA journal_mode").fetchone()[0]
    with pytest.raises(NetworkStoreError, match="network_store_schema_mismatch"):
        NetworkStore(foreign)
    with sqlite3.connect(foreign) as db:
        assert db.execute("PRAGMA journal_mode").fetchone()[0] == previous_mode
    target = tmp_path / "network.sqlite3"
    NetworkStore(target)
    with sqlite3.connect(target) as db:
        db.execute("PRAGMA user_version=999")
    with pytest.raises(NetworkStoreError, match="network_store_schema_mismatch"):
        NetworkStore(target)


def test_sqlite_full_rolls_back_and_files_remain_below_configured_total_cap(tmp_path):
    store = NetworkStore(tmp_path / "network.sqlite3", max_storage_bytes=1_048_576)
    first = batch(0)
    original = store.ingest(first, profile(), now_us=NOW)
    rows = [entry(index + 10, cursor=f"large-{index}-" + "x" * 1900) for index in range(160)]
    pending = batch(1, rows, before=first["cursor_after"])
    with pytest.raises(NetworkStoreError, match="storage_capacity_exceeded"):
        store.ingest(pending, profile(), now_us=NOW)
    assert store.sources()[0]["checkpoint"] == first["cursor_after"]
    assert store.status()["counts"] == {"events": 1, "receipts": 1, "batches": 1, "sources": 1}
    assert store.ingest(first, profile(), now_us=NOW) == original
    assert sum(path.stat().st_size for path in tmp_path.glob("network.sqlite3*")) <= store.max_storage_bytes


def test_failed_full_receipt_batch_also_rolls_back_its_retention_sweep(tmp_path):
    store = NetworkStore(tmp_path / "network.sqlite3", max_receipts=1)
    first = batch(1)
    store.ingest(first, profile(), now_us=NOW)
    with pytest.raises(NetworkStoreError, match="network_capacity_exceeded"):
        store.ingest(batch(2, before=first["cursor_after"]), profile(), now_us=NOW + 15 * DAY)
    assert len(store.page("synthetic-a")["items"]) == 1
    assert store.sources()[0]["checkpoint"] == first["cursor_after"]


def test_held_reader_stops_new_writes_but_durable_replay_still_succeeds(store, monkeypatch):
    connection = store.connection

    @contextmanager
    def short_timeout():
        with connection() as db:
            db.execute("PRAGMA busy_timeout=20")
            yield db

    monkeypatch.setattr(store, "connection", short_timeout)
    reader = sqlite3.connect(store.path, isolation_level=None)
    try:
        reader.execute("BEGIN")
        reader.execute("SELECT count(*) FROM network_events").fetchone()
        first = batch(1)
        ack = store.ingest(first, profile(), now_us=NOW)
        assert store.status()["wal_bytes"] > 0
        assert store.ingest(first, profile(), now_us=NOW) == ack
        with pytest.raises(NetworkStoreError, match="network_storage_busy"):
            store.ingest(batch(2, before=first["cursor_after"]), profile(), now_us=NOW)
        assert store.sources()[0]["checkpoint"] == first["cursor_after"]
        reader.rollback()
        assert store.ingest(batch(2, before=first["cursor_after"]), profile(), now_us=NOW)["accepted"] == 1
    finally:
        reader.close()
