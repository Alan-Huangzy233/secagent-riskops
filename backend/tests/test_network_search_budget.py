"""Budget exhaustion and corrupt storage never become partial/empty success."""
from __future__ import annotations

import json
import sqlite3
import time

import pytest

from app.telemetry import network_search
from app.telemetry.network_search import NetworkSearchUnavailable
from test_network_search import OTHER, PEER, START, event, ingest, search, stamp
from test_network_search import store as network_store_fixture

store = network_store_fixture


@pytest.mark.parametrize("payload", [
    "{broken", "[]", "{}", '{"src_ip":"198.51.100.22","src_ip":"198.51.100.23"}',
    "x" * (network_search.MAX_RECORD_BYTES + 1), "x" * (network_search.MAX_RECORD_BYTES * 4),
    '[' * 1200 + '0' + ']' * 1200,
])
def test_corrupt_or_oversized_payload_discards_preceding_valid_match(store, payload):
    ingest(store, [event(1), event(2)])
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE network_events SET event_json=? WHERE seq=2", (payload,))
    with pytest.raises(NetworkSearchUnavailable, match="^network_search_unavailable$"):
        search(store)


@pytest.mark.parametrize("column,value", [
    ("journal_realtime_us", START+20), ("collected_at_us", -1), ("received_at_us", "invalid"),
    ("event_id", "f"*64), ("source_id", "synthetic-b"),
])
def test_stored_projection_and_normalized_payload_must_agree(store, column, value):
    ingest(store, [event(1)])
    with sqlite3.connect(store.path) as db:
        db.execute(f"UPDATE network_events SET {column}=?", (value,))
    query = {"source_id": "synthetic-b"} if column == "source_id" else {}
    with pytest.raises(NetworkSearchUnavailable):
        search(store, **query)


def test_payload_hash_corruption_fails_closed(store):
    ingest(store, [event(1)])
    with sqlite3.connect(store.path) as db:
        value = json.loads(db.execute("SELECT event_json FROM network_events").fetchone()[0])
        value["src_ip"] = OTHER
        db.execute("UPDATE network_events SET event_json=?", (json.dumps(value),))
    with pytest.raises(NetworkSearchUnavailable):
        search(store)


@pytest.mark.parametrize("peers", [[OTHER, OTHER, OTHER], [PEER, OTHER, OTHER]])
def test_candidate_exhaustion_is_neither_empty_nor_partial_success(store, monkeypatch, peers):
    ingest(store, [event(index, ip=ip) for index, ip in enumerate(peers, 1)])
    monkeypatch.setattr(network_search, "MAX_CANDIDATES", 2)
    with pytest.raises(NetworkSearchUnavailable):
        search(store)


def test_candidate_cap_allows_exact_completed_window(store, monkeypatch):
    ingest(store, [event(1, at=START), event(2, ip=OTHER)])
    monkeypatch.setattr(network_search, "MAX_CANDIDATES", 2)
    assert len(search(store)["items"]) == 1


def test_bytes_budget_includes_nonmatching_candidate_payloads(store, monkeypatch):
    ingest(store, [event(1), event(2, ip=OTHER)])
    with sqlite3.connect(store.path) as db:
        size = db.execute("SELECT length(CAST(event_json AS BLOB)) FROM network_events WHERE seq=1").fetchone()[0]
    monkeypatch.setattr(network_search, "MAX_JSON_BYTES", size)
    with pytest.raises(NetworkSearchUnavailable):
        search(store)


def test_oversized_record_never_reaches_python_decoder(store, monkeypatch):
    ingest(store, [event(1)])
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE network_events SET event_json=?", ("x"*(network_search.MAX_RECORD_BYTES+1),))
    monkeypatch.setattr(network_search, "decode", lambda raw: pytest.fail("oversized payload crossed decoder boundary"))
    with pytest.raises(NetworkSearchUnavailable):
        search(store)


def test_vm_budget_failure_closes_reader_and_allows_next_ingest(store, monkeypatch):
    checkpoint = ingest(store, [event(1)])
    with monkeypatch.context() as limited:
        limited.setattr(network_search, "MAX_VM_STEPS", 1)
        limited.setattr(network_search, "PROGRESS_STEPS", 1)
        with pytest.raises(NetworkSearchUnavailable):
            search(store)
    ingest(store, [event(2)], number=2, before=checkpoint)
    assert len(search(store)["items"]) == 2


def test_python_deadline_failure_closes_reader_and_allows_next_ingest(store, monkeypatch):
    checkpoint = ingest(store, [event(1)])
    calls = 0

    def clock():
        nonlocal calls
        calls += 1
        return 3.0 if calls > 8 else 0.0

    with monkeypatch.context() as limited:
        limited.setattr(network_search.time, "monotonic", clock)
        with pytest.raises(NetworkSearchUnavailable):
            search(store)
    ingest(store, [event(2)], number=2, before=checkpoint)
    assert len(search(store)["items"]) == 2


def test_sqlite_exclusive_lock_has_short_safe_failure(store):
    ingest(store, [event(1)])
    writer = sqlite3.connect(store.path, isolation_level=None)
    try:
        assert writer.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"
        writer.execute("BEGIN EXCLUSIVE")
        started = time.monotonic()
        with pytest.raises(NetworkSearchUnavailable, match="^network_search_unavailable$"):
            search(store)
        assert time.monotonic() - started < 1.5
    finally:
        writer.rollback()
        writer.execute("PRAGMA journal_mode=WAL")
        writer.close()
    assert len(search(store)["items"]) == 1


@pytest.mark.parametrize("mutation", [
    "PRAGMA user_version=1",
    "CREATE VIEW extra AS SELECT seq FROM network_events",
    "DROP INDEX network_events_source_time",
    "UPDATE network_meta SET value='99' WHERE key='schema_version'",
    "UPDATE sqlite_sequence SET seq=0 WHERE name='network_events'",
])
def test_unexpected_schema_metadata_or_highwater_fails_closed(store, mutation):
    ingest(store, [event(1)])
    with sqlite3.connect(store.path) as db:
        db.execute(mutation)
    with pytest.raises(NetworkSearchUnavailable):
        search(store)


def test_oversized_schema_text_is_bounded_before_comparison(store, monkeypatch):
    ingest(store, [event(1)])
    with sqlite3.connect(store.path) as db:
        db.execute('CREATE TABLE huge (value TEXT CHECK(value != "' + 'x'*40_000 + '"))')
    monkeypatch.setattr(network_search, "_expected_schema_sql", lambda version: pytest.fail("oversized schema was fetched"))
    with pytest.raises(NetworkSearchUnavailable):
        search(store)


@pytest.mark.parametrize("same_time", [False, True])
def test_deep_continuation_seeks_past_earlier_history_including_equal_time(store, monkeypatch, same_time):
    checkpoint = None
    for number, offset in enumerate(range(0, 1201, 200), 1):
        entries = [event(index, at=START if same_time else START+index)
                   for index in range(offset+1, min(offset+201, 1202))]
        checkpoint = ingest(store, entries, number=number, before=checkpoint)
    current = search(store, limit=100)
    for _ in range(10):
        current = search(store, limit=100, cursor=current["next_cursor"])
    assert current["items"][-1]["seq"] == 1100
    monkeypatch.setattr(network_search, "MAX_VM_STEPS", 8_000)
    late = search(store, limit=100, cursor=current["next_cursor"])
    assert [item["seq"] for item in late["items"]] == list(range(1101, 1201))
    final = search(store, limit=100, cursor=late["next_cursor"])
    assert [item["seq"] for item in final["items"]] == [1201]
    if not same_time:
        narrow = search(store, start=stamp(START+1200))
        assert [item["seq"] for item in narrow["items"]] == [1200, 1201]
    with sqlite3.connect(store.path) as db:
        for sql, parameters in (
            (network_search._SAME_TIME_SQL, ("synthetic-a", START, 1100, 1201)),
            (network_search._SEARCH_SQL, ("synthetic-a", START, START+10_000, 1201)),
        ):
            plan = db.execute("EXPLAIN QUERY PLAN " + sql,
                              (network_search.MAX_RECORD_BYTES, *parameters, 101)).fetchall()
            description = " ".join(row[-1] for row in plan)
            assert "SEARCH network_events USING INDEX network_events_source_time" in description
            assert "TEMP B-TREE" not in description
