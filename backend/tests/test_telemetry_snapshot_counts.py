"""Frozen-view correctness and SQLite work bounds, using synthetic rows only."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json

import pytest

from app.telemetry import store as module
from app.telemetry.store import TelemetryStore


NOW = datetime(2026, 9, 14, tzinfo=timezone.utc)


@pytest.fixture
def store(tmp_path):
    return TelemetryStore(tmp_path / "snapshot.sqlite")


def rows(start, count, source="source-a", *, seconds=None):
    for index in range(start, start + count):
        yield {"source_id": source, "event_id": f"event-{index:06}",
               "event_ts": (NOW + timedelta(seconds=index if seconds is None else seconds)).timestamp(),
               "event_type": "auth_success" if index % 5 == 0 else "probe",
               "src_ip": f"198.51.100.{23 + index % 2}",
               "ssh_user": "user'%" if index % 3 == 0 else "root",
               "message": "synthetic marker_%" if index % 2 == 0 else "synthetic plain"}


def insert(store, records):
    # Isolate counting from detection. Each row has the same atomic receipt
    # invariant as real ingestion; equal event IDs on two sources remain distinct.
    with store._connection(write=True) as db:
        for record in records:
            timestamp = module._iso(datetime.fromtimestamp(record["event_ts"], timezone.utc))
            db.execute("INSERT INTO event_receipts VALUES(?,?,?,?)",
                       (record["source_id"], record["event_id"], "synthetic-hash", module._iso(NOW)))
            db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                       (record["source_id"], record["event_id"], "synthetic-host", timestamp,
                        record["event_ts"], module._iso(NOW), record["event_type"], record["src_ip"],
                        record["ssh_user"], json.dumps(record), None))


@pytest.mark.parametrize("arrivals", [0, 20])
@pytest.mark.parametrize("source_id", [None, "source-a"])
def test_frozen_page_receipt_work_does_not_scale_with_retained_history(store, monkeypatch, arrivals, source_id):
    count = 20_000
    insert(store, rows(0, count))
    snapshot = store.paginate_events(limit=5)["snapshot"]
    insert(store, rows(count, arrivals))
    original = store._connection
    instructions = 0
    budget = None

    @contextmanager
    def bounded_connection(**kwargs):
        nonlocal instructions
        with original(**kwargs) as db:
            def progress():
                nonlocal instructions
                instructions += 100
                return int(budget is not None and instructions > budget)
            db.set_progress_handler(progress, 100)
            try:
                yield db
            finally:
                db.set_progress_handler(None, 0)

    monkeypatch.setattr(store, "_connection", bounded_connection)
    # Source-scoped totals still scan their ordinary source index. Compare with
    # that baseline, allowing only bounded extra receipt work for a frozen view.
    store.paginate_events(source_id=source_id, limit=5)
    budget, instructions = instructions + 5_000, 0
    page = store.paginate_events(source_id=source_id, limit=5, snapshot=snapshot)
    assert (page["total"], page["total_pages"], page["snapshot"]) == (count, count // 5, snapshot)
    assert [item["event_id"] for item in page["items"]] == [f"event-{i:06}" for i in range(count - 1, count - 6, -1)]


FILTERS = [
    {}, {"source_id": "source-b"}, {"source_id": "missing"},
    {"ip": "198.51.100.23"}, {"username": "user'%"},
    {"event_type": "probe"}, {"q": "_%"},
    {"start": "2026-09-14T08:00:02+08:00", "end": "2026-09-14T00:00:08Z"},
    {"source_id": "source-b", "ip": "198.51.100.23", "username": "user'%", "event_type": "probe",
     "q": "_%", "start": "2026-09-14T00:00:00Z", "end": "2026-09-14T00:00:10Z"},
]


@pytest.mark.parametrize("filters", FILTERS)
@pytest.mark.parametrize("tail_limit", [0, 10_000])
def test_count_matches_frozen_items_with_filters_retention_and_restart(store, monkeypatch, filters, tail_limit):
    monkeypatch.setattr(module, "_SNAPSHOT_COUNT_TAIL_LIMIT", tail_limit)
    for source in ("source-a", "source-b"):
        insert(store, rows(0, 12, source))
    expected = store.list_events(limit=200, **filters)
    snapshot = store.paginate_events()["snapshot"]
    # Late arrivals have old/equal event and receive times, plus colliding IDs
    # across sources. They must not enter the frozen view's count or its items.
    for source in ("source-a", "source-b"):
        insert(store, rows(20, 4, source, seconds=6))
    with store._connection(write=True) as db:
        # Both old and newly arrived rows expire; their receipts survive.
        db.execute("DELETE FROM events WHERE event_id IN ('event-000000','event-000020')")
    expected = [item for item in expected if item["event_id"] != "event-000000"]
    restarted = TelemetryStore(store.path)
    page = restarted.paginate_events(limit=2, page=10**6, snapshot=snapshot, **filters)
    assert page["total"] == len(expected)
    assert page["page"] == page["total_pages"] == max(1, (len(expected) + 1) // 2)
    assert page["items"] == expected[page["offset"]:page["offset"] + 2]
    assert page["snapshot"] == snapshot
    assert restarted.list_events(snapshot=snapshot, limit=200, **filters) == expected


def test_concurrent_ingest_between_retained_and_newer_counts_cannot_change_view(store, monkeypatch):
    insert(store, rows(0, 4))
    snapshot = store.paginate_events()["snapshot"]
    insert(store, rows(4, 1))
    writer = TelemetryStore(store.path)
    original = store._connection
    inserted = False

    class Interleave:
        def __init__(self, db):
            self.db = db

        def execute(self, sql, params=()):
            nonlocal inserted
            cursor = self.db.execute(sql, params)
            if sql.startswith("SELECT count(*) FROM events") and not inserted:
                inserted = True
                insert(writer, rows(5, 1))
            return cursor

    @contextmanager
    def connection(**kwargs):
        with original(**kwargs) as db:
            yield Interleave(db)

    monkeypatch.setattr(store, "_connection", connection)
    page = store.paginate_events(snapshot=snapshot)
    assert inserted
    assert page["total"] == 4
    assert [item["event_id"] for item in page["items"]] == [f"event-{i:06}" for i in range(3, -1, -1)]
    assert writer.paginate_events()["total"] == 6


def test_future_boundary_and_empty_snapshot_keep_their_existing_meaning(store):
    insert(store, rows(0, 3))
    future = store.paginate_events(snapshot="r1:9223372036854775807")
    assert future["total"] == 3 and future["snapshot"] == "r1:9223372036854775807"
    assert future["items"] == store.list_events()
    empty = store.paginate_events(snapshot="r1:0", page=50)
    assert (empty["total"], empty["items"], empty["page"]) == (0, [], 1)


@pytest.mark.parametrize("source_id", [None, "source-a"])
@pytest.mark.parametrize("arrivals", [0, 3])
def test_plain_count_plan_avoids_long_cursor_indexes(store, monkeypatch, source_id, arrivals):
    # SQLite may prefer the two-column primary key for COUNT(*) even though
    # journal cursors make it much wider than the normalized detection index.
    records = [{**row, "event_id": row["event_id"] + "-" + "c" * 512} for row in rows(0, 30)]
    insert(store, records)
    snapshot = store.paginate_events()["snapshot"]
    insert(store, rows(30, arrivals))
    original = store._connection
    statements = []

    @contextmanager
    def traced_connection(**kwargs):
        with original(**kwargs) as db:
            db.set_trace_callback(statements.append)
            yield db
            db.set_trace_callback(None)

    monkeypatch.setattr(store, "_connection", traced_connection)
    page = store.paginate_events(source_id=source_id, snapshot=snapshot)
    assert page["total"] == len(records)
    counts = [sql for sql in statements if sql.startswith("SELECT count(*) FROM events ")]
    assert counts
    with original() as db:
        compact = []
        for index in db.execute('PRAGMA index_list(events)').fetchall():
            columns = {row[2] for row in db.execute('PRAGMA index_info("' + index[1] + '")')}
            if not columns & {"event_id", "record_json"}:
                compact.append(index[1])
        for sql in counts:
            plan = " ".join(row[3] for row in db.execute("EXPLAIN QUERY PLAN " + sql))
            assert any("COVERING INDEX " + index in plan for index in compact), plan
