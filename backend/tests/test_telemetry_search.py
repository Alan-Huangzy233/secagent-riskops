"""Search and evidence tests use synthetic addresses and records only."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import time

import pytest

from app.telemetry import store as module
from app.telemetry.store import TelemetryStore


NOW = datetime(2026, 9, 14, 8, tzinfo=timezone.utc)
PEER = "198.51.100.23"


@pytest.fixture
def clock(monkeypatch):
    current = [NOW]
    monkeypatch.setattr(module, "_now", lambda: current[0])
    return current


@pytest.fixture
def store(tmp_path, clock):
    return TelemetryStore(tmp_path / "search.sqlite")


def record(event_id, seconds=0, *, ip=PEER, user="root", kind="failure", message=None):
    if message is None:
        if kind == "success":
            message = f"Accepted publickey for {user} from {ip} port 42000 ssh2"
        else:
            message = f"Failed password for {user} from {ip} port 42000 ssh2"
    return {"event_id": event_id, "timestamp": (NOW + timedelta(seconds=seconds)).isoformat(),
            "message": message, "identifier": "sshd", "unit": "ssh.service", "priority": "6"}


def ids(rows):
    return [(row["source_id"], row["event_id"]) for row in rows]


def test_combined_source_ip_username_kind_and_inclusive_time_filters(store):
    store.ingest("source-a", "host-a", "a", [
        record("before", -1), record("first", 0), record("last", 10), record("after", 11),
        record("different-user", 5, user="admin"), record("success", 5, kind="success"),
        record("different-peer", 5, ip="203.0.113.9"),
    ])
    store.ingest("source-b", "host-b", "b", [record("different-source", 5)])
    # An offset timezone represents the same UTC boundary; both endpoints count.
    filters = dict(source_id="source-a", ip=PEER, username="root", event_type="auth_failure",
                   start="2026-09-14T16:00:00+08:00", end="2026-09-14T08:00:10Z")
    rows = store.list_events(**filters)
    assert ids(rows) == [("source-a", "last"), ("source-a", "first")]
    page = store.paginate_events(limit=1, **filters)
    assert (page["total"], page["total_pages"]) == (2, 2)
    tail = store.paginate_events(limit=1, page=2, snapshot=page["snapshot"], **filters)
    assert ids(page["items"] + tail["items"]) == ids(rows)


def test_ipv6_search_normalizes_full_and_compressed_notation(store):
    store.ingest("source-a", "host-a", "v6", [record("v6", ip="2001:db8::a")])
    assert ids(store.list_events(ip="2001:0DB8:0000:0000:0000:0000:0000:000A")) == [("source-a", "v6")]
    assert store.paginate_events(ip="2001:db8::b")["total"] == 0


def test_mapped_ipv6_peer_can_be_searched_using_its_displayed_address(store):
    store.ingest("source-a", "host-a", "mapped", [record("mapped", ip="::ffff:198.51.100.23")])
    row = store.list_events()[0]
    assert row["peer_ip"] is not None
    assert ids(store.list_events(ip=row["peer_ip"])) == [("source-a", "mapped")]


@pytest.mark.parametrize("needle", ["%", "_", "\\", "' OR 1=1 --", "[preauth]", "中文"])
def test_keyword_is_a_literal_substring_not_sql_or_pattern_syntax(store, needle):
    store.ingest("source-a", "host-a", "words", [
        record("match", message="unparsed prefix " + needle + " suffix"),
        record("unrelated", message="unparsed ordinary message"),
    ])
    assert ids(store.list_events(q=needle)) == [("source-a", "match")]
    assert store.paginate_events(q=needle)["total"] == 1
    assert len(store.list_events()) == 2


def test_username_and_source_values_cannot_turn_into_sql(store):
    account = "user%_\\'"
    store.ingest("source-a", "host-a", "a", [record("literal", user=account), record("normal")])
    assert ids(store.list_events(username=account)) == [("source-a", "literal")]
    assert store.list_events(username="root' OR 1=1 --") == []
    assert store.list_events(source_id="source-a' OR 1=1 --") == []


@pytest.mark.parametrize("filters", [
    {"ip": "198.51.100.999"}, {"ip": "198.51.100.23/32"},
    {"start": "2026-09-14T08:00:00"}, {"end": "not-a-time"},
    {"start": "2026-09-14T08:01:00Z", "end": "2026-09-14T08:00:00Z"},
    {"q": ""}, {"q": "x" * 257}, {"username": "x" * 257},
    {"snapshot": "r1:-1"}, {"snapshot": "r1:1 OR 1=1"}, {"snapshot": "r1:9223372036854775808"},
    {"snapshot": "2026-09-14T08:00:00Z"}, {"snapshot": "r1:1\n"},
])
def test_invalid_search_filters_are_rejected(store, filters):
    with pytest.raises(ValueError):
        store.list_events(**filters)
    with pytest.raises(ValueError):
        store.paginate_events(**filters)


def test_receipt_snapshot_excludes_late_arrivals_with_older_or_equal_receive_time(store, clock):
    store.ingest("source-a", "host-a", "before", [record(f"initial-{i}", i) for i in range(6)])
    original = store.list_events()
    first = store.paginate_events(limit=2)
    snapshot = first["snapshot"]
    assert isinstance(snapshot, str) and len(snapshot) <= 128
    # Equal receive timestamps and backdated event times defeat a time-only bound.
    store.ingest("source-a", "host-a", "same-clock", [record("late", 1), record("new", 30)])
    clock[0] = NOW - timedelta(seconds=10)
    store.ingest("source-b", "host-b", "clock-backwards", [record("clock-backwards", 2)])
    frozen = [item for page in range(1, 4)
              for item in store.paginate_events(limit=2, page=page, snapshot=snapshot)["items"]]
    assert ids(frozen) == ids(original)
    assert store.paginate_events(limit=2, snapshot=snapshot)["total"] == 6
    assert store.paginate_events(limit=2)["total"] == 9
    assert ids(store.list_events(snapshot=snapshot)) == ids(original)


def test_zero_snapshot_stays_empty_after_first_ingestion(store):
    empty = store.paginate_events(limit=2, page=40)
    assert (empty["total"], empty["page"], empty["total_pages"]) == (0, 1, 1)
    store.ingest("source-a", "host-a", "first", [record("first")])
    assert store.paginate_events(snapshot=empty["snapshot"])["total"] == 0
    assert store.paginate_events()["total"] == 1


def test_fixed_snapshot_survives_restart_and_source_scoping(store):
    store.ingest("source-a", "host-a", "a", [record("shared", 1)])
    store.ingest("source-b", "host-b", "b", [record("shared", 2)])
    snapshot = store.paginate_events()["snapshot"]
    restarted = TelemetryStore(store.path)
    restarted.ingest("source-b", "host-b", "new", [record("new", 3)])
    page = restarted.paginate_events("source-b", snapshot=snapshot)
    assert page["total"] == 1 and ids(page["items"]) == [("source-b", "shared")]


def test_retention_does_not_reuse_snapshot_boundary_for_new_raw_events(store, clock):
    store.ingest("source-a", "host-a", "old", [record(str(i), i) for i in range(3)])
    snapshot = store.paginate_events()["snapshot"]
    clock[0] += timedelta(days=15)
    assert store.cleanup()["deleted_events"] == 3
    newer = {**record("new"), "timestamp": clock[0].isoformat()}
    store.ingest("source-a", "host-a", "new", [newer])
    # The events table may reuse rowids after being emptied, but receipts never
    # expire. New arrivals must not enter an old snapshot after raw retention.
    frozen = store.paginate_events(snapshot=snapshot, page=99)
    assert frozen["total"] == 0 and frozen["items"] == [] and frozen["page"] == 1
    assert store.paginate_events()["total"] == 1


def test_read_count_and_items_share_one_transaction_snapshot(store, monkeypatch):
    store.ingest("source-a", "host-a", "first", [record(str(i), i) for i in range(3)])
    original = store._events

    def insert_before_items(db, source_id, limit, offset, **filters):
        store.ingest("source-a", "host-a", "concurrent", [record("new", 30)])
        return original(db, source_id, limit, offset, **filters)

    monkeypatch.setattr(store, "_events", insert_before_items)
    page = store.paginate_events(limit=2)
    assert page["total"] == 3
    assert all(row["event_id"] != "new" for row in page["items"])


def test_complete_evidence_pagination_survives_raw_retention(store, clock):
    store.ingest("source-a", "host-a", "a", [record(f"a-{i:03}", i) for i in range(27)])
    store.ingest("source-b", "host-b", "b", [record(f"b-{i:03}", i) for i in range(27)])
    incident_id = store.list_incidents()[0]["incident_id"]
    assert len(store.list_incidents()) == 1
    overview = store.get_incident(incident_id)
    assert overview["evidence_count"] == 54
    assert overview["source_ids"] == ["source-a", "source-b"]
    pages = [store.paginate_incident_evidence(incident_id, limit=20, page=i) for i in range(1, 4)]
    expected = [row for page in pages for row in page["items"]]
    assert [len(page["items"]) for page in pages] == [20, 20, 14]
    assert all(page["total"] == 54 and page["total_pages"] == 3 for page in pages)
    assert len(set(ids(expected))) == 54
    assert [(row["event_ts"], row["source_id"], row["event_id"]) for row in expected] == sorted(
        (row["event_ts"], row["source_id"], row["event_id"]) for row in expected)
    assert store.paginate_incident_evidence(incident_id, limit=20, page=999) == pages[-1]
    scoped = store.paginate_incident_evidence(incident_id, limit=200, source_id="source-b")
    assert scoped["total"] == 27 and all(row["source_id"] == "source-b" for row in scoped["items"])
    assert store.paginate_incident_evidence(incident_id, source_id="unknown")["total"] == 0
    clock[0] += timedelta(days=15)
    assert store.cleanup()["deleted_events"] == 54
    assert store.list_events() == []
    restarted = TelemetryStore(store.path)
    retained = restarted.paginate_incident_evidence(incident_id, limit=200)["items"]
    assert retained == expected
    assert all(row["message_hash"] and row["record_hash"] for row in retained)


def test_old_merged_incident_alias_returns_canonical_detail_and_all_evidence(store):
    first = store.ingest("source-a", "host-a", "first", [record(f"first-{i}", i) for i in range(3)])
    last = store.ingest("source-a", "host-a", "last", [record(f"last-{i}", 598 + i) for i in range(3)])
    assert len(store.list_incidents()) == 2
    bridge = store.ingest("source-a", "host-a", "bridge", [record("bridge", 300)])
    canonical = bridge["incident_ids"][0]
    for prior in first["incident_ids"] + last["incident_ids"]:
        detail = store.get_incident(prior)
        assert detail["incident_id"] == canonical
        assert detail["requested_incident_id"] == prior
        evidence = store.paginate_incident_evidence(prior, limit=3, page=3)
        assert evidence["incident_id"] == canonical and evidence["requested_incident_id"] == prior
        assert (evidence["total"], evidence["total_pages"], len(evidence["items"])) == (7, 3, 1)


def test_unknown_incident_is_distinct_from_an_empty_evidence_page(store):
    assert store.get_incident("missing") is None
    assert store.paginate_incident_evidence("missing") is None
    assert store.get_incident("' OR 1=1 --") is None
    assert store.paginate_incident_evidence("' OR 1=1 --") is None
    with pytest.raises(ValueError):
        store.paginate_incident_evidence("missing", limit=201)
    with pytest.raises(ValueError):
        store.paginate_incident_evidence("missing", page=0)


def test_incident_summary_keeps_counts_and_rules_without_loading_evidence(store, monkeypatch):
    store.ingest("source-a", "host-a", "incident", [record(str(i), i) for i in range(30)])
    full = store.paginate_incidents()["items"][0]

    def no_event_decode(record):
        raise AssertionError("Summary-only queries must not materialize evidence snapshots")

    monkeypatch.setattr(store, "_event", no_event_decode)
    lean = store.paginate_incidents(include_evidence=False)["items"][0]
    detail = store.get_incident(full["incident_id"])
    for item in (lean, detail):
        for field in ("source_ids", "rules", "evidence_count", "failure_count", "success_count", "usernames"):
            assert item[field] == full[field]
        assert item["evidence_snapshots"] == [] and item["evidence_truncated"] is True


def test_search_schema_upgrade_and_reads_do_not_modify_evidence_or_receipts(store):
    store.ingest("source-a", "host-a", "original", [record(str(i), i) for i in range(6)])
    tables = ("events", "event_receipts", "incident_evidence", "batches")

    def snapshot():
        with store._connection() as db:
            return {name: [tuple(row) for row in db.execute(f"SELECT * FROM {name} ORDER BY rowid")]
                    for name in tables}

    before = snapshot()
    with store._connection(write=True) as db:
        db.execute("DROP INDEX events_username_paging")
        db.execute("DROP INDEX events_type_paging")
    restarted = TelemetryStore(store.path)
    page = restarted.paginate_events(username="root", event_type="auth_failure", q="password")
    restarted.list_events(snapshot=page["snapshot"], ip=PEER)
    incident_id = restarted.list_incidents()[0]["incident_id"]
    restarted.get_incident(incident_id)
    restarted.paginate_incident_evidence(incident_id, page=2, limit=3)
    assert snapshot() == before
    with store._connection() as db:
        indexes = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        assert {"events_username_paging", "events_type_paging"} <= indexes
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []


def test_large_search_filters_use_indexes_and_receipt_identity_lookups(store):
    # Direct fixture insertion isolates search from detection. Every raw event
    # has the durable receipt created by normal ingestion. No production data.
    count = 50_000
    at = module._iso(NOW)
    with store._connection(write=True) as db:
        def values():
            for i in range(count):
                source, event_id = f"source-{i % 3}", f"event-{i:06}"
                kind, user, peer = "auth_failure" if i % 2 else "probe", f"user-{i % 10}", f"198.51.100.{i % 200 + 1}"
                payload = json.dumps({"source_id": source, "event_id": event_id, "event_type": kind,
                                      "src_ip": peer, "ssh_user": user, "message": "synthetic " + "x" * 512})
                yield (source, event_id, source, at, NOW.timestamp() - i // 3, at, kind, peer, user, payload)

        db.executemany("""INSERT INTO events(source_id,event_id,hostname,timestamp,event_ts,received_at,
            event_type,src_ip,ssh_user,record_json) VALUES(?,?,?,?,?,?,?,?,?,?)""", values())
        db.executemany("INSERT INTO event_receipts VALUES(?,?,?,?)",
                       ((f"source-{i % 3}", f"event-{i:06}", "synthetic-hash", at) for i in range(count)))
        db.execute("ANALYZE")
    elapsed = {}
    queries = [({}, count), ({"source_id": "source-1"}, 16667), ({"ip": "198.51.100.2"}, 250),
               ({"username": "user-1"}, 5000), ({"event_type": "auth_failure"}, 25000)]
    for filters, expected in queries:
        begin = time.perf_counter()
        result = store.paginate_events(limit=50, page=10**6, **filters)
        elapsed[str(filters)] = round((time.perf_counter() - begin) * 1000, 2)
        assert result["total"] == expected
        assert result["page"] == result["total_pages"]
        assert len(result["items"]) == (expected % 50 or 50)
        where, params = store._event_filter(**filters, snapshot=result["snapshot"])
        with store._connection() as db:
            plan = " ".join(row["detail"] for row in db.execute(
                "EXPLAIN QUERY PLAN SELECT count(*) FROM events " + where, params))
            assert "SCAN r" not in plan
            assert "SEARCH r USING" in plan or "SEARCH r EXISTS USING" in plan
            if filters:
                assert "SEARCH events USING" in plan
    print("Synthetic 50000-record local search milliseconds:", elapsed)
