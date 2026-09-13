from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json

import pytest

from app.telemetry import store as module
from app.telemetry.store import TelemetryStore


NOW = datetime(2026, 9, 9, 8, tzinfo=timezone.utc)


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "_now", lambda: NOW)
    return TelemetryStore(tmp_path / "live.sqlite")


def record(event_id, seconds=0, message="Server listening on port 22"):
    return {"event_id": event_id, "timestamp": (NOW + timedelta(seconds=seconds)).isoformat(),
            "message": message, "identifier": "sshd", "unit": "ssh.service", "priority": "6"}


def seed_events(store):
    for source, count in (("source-a", 5), ("source-b", 3)):
        store.ingest(source, source, "first", [record(f"event-{i}", i // 2) for i in range(count)])


def test_event_page_counts_scope_order_and_last_page(store):
    seed_events(store)
    pages = [store.paginate_events(limit=3, page=page) for page in range(1, 4)]
    assert [len(page["items"]) for page in pages] == [3, 3, 2]
    assert [page["offset"] for page in pages] == [0, 3, 6]
    assert all(page["total"] == 8 and page["total_pages"] == 3 and page["limit"] == 3 for page in pages)
    combined = [item for page in pages for item in page["items"]]
    assert combined == store.list_events()
    assert len({(item["source_id"], item["event_id"]) for item in combined}) == 8
    assert store.paginate_events(limit=3, page=10**30) == pages[-1]

    scoped = store.paginate_events("source-a", limit=3, page=2)
    assert (scoped["total"], scoped["total_pages"], scoped["page"], scoped["offset"]) == (5, 2, 2, 3)
    assert scoped["items"] == store.list_events("source-a", limit=3, offset=3)
    assert all(item["source_id"] == "source-a" for item in scoped["items"])


@pytest.mark.parametrize("method", ["paginate_events", "paginate_incidents"])
def test_empty_pages_and_invalid_page_numbers(store, method):
    query = getattr(store, method)
    assert query("unknown", limit=50, page=99) == {
        "items": [], "total": 0, "total_pages": 1, "page": 1, "limit": 50, "offset": 0,
    }
    for page in (0, -1, True, 1.5, "2"):
        with pytest.raises(ValueError, match="page"):
            query(page=page)
    for limit in (0, 201, True, "50"):
        with pytest.raises(ValueError, match="limit"):
            query(limit=limit)


def test_incident_page_counts_exclude_merged_and_keep_evidence(store):
    for source, count in (("source-a", 5), ("source-b", 3)):
        for peer in range(count):
            store.ingest(source, source, f"batch-{peer}", [
                record(f"{peer}-{i}", i, f"Failed password for root from 198.51.100.{peer + 1 + (100 if source == 'source-b' else 0)} port 2222 ssh2")
                for i in range(3)
            ])
    with store._connection(write=True) as db:
        removed = db.execute("SELECT incident_id FROM incidents WHERE source_id='source-a' LIMIT 1").fetchone()[0]
        db.execute("UPDATE incidents SET status='merged' WHERE incident_id=?", (removed,))
    first = store.paginate_incidents(limit=3)
    last = store.paginate_incidents(limit=3, page=999)
    assert (first["total"], first["total_pages"], last["page"], last["offset"]) == (7, 3, 3, 6)
    combined = [item for page in range(1, 4) for item in store.paginate_incidents(limit=3, page=page)["items"]]
    assert combined == store.list_incidents()
    assert all(item["incident_id"] != removed and len(item["evidence_snapshots"]) == 3 for item in combined)
    scoped = store.paginate_incidents("source-a", limit=3, page=2)
    assert (scoped["total"], scoped["total_pages"], len(scoped["items"])) == (4, 2, 1)
    assert scoped["items"] == store.list_incidents("source-a", limit=3, offset=3)


def test_counts_and_page_share_snapshot_while_collector_writes(store, monkeypatch):
    seed_events(store)
    original = store._events

    def insert_between_count_and_items(db, source_id, limit, offset):
        store.ingest("source-a", "source-a", "concurrent", [record("newest", 20)])
        return original(db, source_id, limit, offset)

    monkeypatch.setattr(store, "_events", insert_between_count_and_items)
    page = store.paginate_events(limit=2)
    assert page["total"] == 8
    assert all(item["event_id"] != "newest" for item in page["items"])
    monkeypatch.setattr(store, "_events", original)
    after = store.paginate_events(limit=2)
    assert after["total"] == 9 and after["items"][0]["event_id"] == "newest"


def test_page_reads_do_not_wait_for_pending_writer_or_prune_data(store):
    seed_events(store)
    with store._connection(write=True) as writer:
        writer.execute("UPDATE sources SET status='error' WHERE source_id='source-a'")
        # WAL readers retain the committed snapshot while collection holds its
        # transaction. A hidden cleanup/schema write here would fail or block.
        page = store.paginate_events(limit=2, page=2)
        assert page["total"] == 8 and page["page"] == 2
        assert store.paginate_incidents()["total"] == 0
        assert store.get_source("source-a")["status"] == "ok"


def test_page_clamps_after_retention(store, monkeypatch):
    seed_events(store)
    monkeypatch.setattr(module, "_now", lambda: NOW + timedelta(days=15))
    assert store.cleanup()["deleted_events"] == 8
    page = store.paginate_events(limit=3, page=3)
    assert page["items"] == [] and page["total"] == 0 and page["page"] == page["total_pages"] == 1


def test_existing_database_gains_sorting_indexes_without_losing_data(store):
    seed_events(store)
    before = store.list_events()
    with store._connection(write=True) as db:
        for name in ("events_paging", "events_source_paging", "incidents_paging", "incidents_source_paging"):
            db.execute(f"DROP INDEX {name}")
        db.execute("CREATE INDEX events_recent ON events(event_ts DESC)")
    migrated = TelemetryStore(store.path)
    assert migrated.list_events() == before
    with migrated._connection() as db:
        names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert "events_recent" not in names
    assert {"events_paging", "events_source_paging", "incidents_paging", "incidents_source_paging"} <= names


def test_deep_pages_use_ordered_indexes_on_large_database(store):
    # Seed directly to isolate list-query behavior from ingestion/detection. The
    # payload is intentionally wider than the ordering index; skipped records
    # must not require a full table sort or JSON decoding.
    payload = json.dumps({"event_id": "payload", "event_type": "other", "src_ip": None,
                          "ssh_user": None, "message": "x" * 1024})
    with store._connection(write=True) as db:
        db.executemany("""INSERT INTO events(source_id,event_id,hostname,timestamp,event_ts,received_at,
            event_type,record_json) VALUES(?,?,?,?,?,?,?,?)""",
            (("source-a" if i % 2 else "source-b", f"event-{i:05}", "host", "time", i // 3, "time", "other", payload)
             for i in range(12000)))
        db.executemany("""INSERT INTO incidents VALUES(?,?,?,'198.51.100.1','title','open',
            'time','time',0,?,3,'time','time',NULL)""",
            ((f"incident-{i:05}", "source-a" if i % 2 else "source-b", "host", i // 3) for i in range(3000)))
        db.execute("ANALYZE")
    page = store.paginate_events(limit=50, page=240)
    assert page["total"] == 12000 and page["offset"] == 11950 and len(page["items"]) == 50
    scoped = store.paginate_events("source-a", limit=50, page=120)
    assert scoped["total"] == 6000 and scoped["offset"] == 5950 and len(scoped["items"]) == 50
    queries = [
        ("SELECT record_json,incident_id FROM events ORDER BY event_ts DESC,source_id,event_id LIMIT 50 OFFSET 11950",
         (), "events_paging"),
        ("SELECT record_json,incident_id FROM events WHERE source_id=? ORDER BY event_ts DESC,source_id,event_id LIMIT 50 OFFSET 5950",
         ("source-a",), "events_source_paging"),
        ("SELECT * FROM incidents WHERE status!='merged' ORDER BY last_ts DESC,incident_id LIMIT 50 OFFSET 2900",
         (), "incidents_paging"),
        ("SELECT * FROM incidents WHERE status!='merged' AND source_id=? ORDER BY last_ts DESC,incident_id LIMIT 50 OFFSET 1400",
         ("source-a",), "incidents_source_paging"),
    ]
    with store._connection() as db:
        for sql, params, expected_index in queries:
            plan = " ".join(row["detail"] for row in db.execute("EXPLAIN QUERY PLAN " + sql, params))
            assert expected_index in plan
            assert "TEMP B-TREE" not in plan
        stats_plan = " ".join(row["detail"] for row in db.execute("""EXPLAIN QUERY PLAN
            SELECT count(*),sum(event_type='ssh_failure'),sum(event_type='ssh_success')
            FROM events WHERE source_id='source-a'"""))
        assert "COVERING INDEX" in stats_plan
