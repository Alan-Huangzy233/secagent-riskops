"""IP pivots use synthetic retained SSH incidents, never production data."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import time

import pytest

from app.telemetry import store as module
from app.telemetry.store import TelemetryStore

NOW = datetime(2026, 10, 23, 8, tzinfo=timezone.utc)
PEER = "198.51.100.23"


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "_now", lambda: NOW)
    return TelemetryStore(tmp_path / "incident-search.sqlite")


def burst(store, batch, *, source="source-a", peer=PEER, seconds=0, step=1):
    records = [{"event_id": f"{batch}-{n}",
                "timestamp": (NOW + timedelta(seconds=seconds + n * step)).isoformat(),
                "message": f"Failed password for root from {peer} port 42000 ssh2",
                "identifier": "sshd"} for n in range(3)]
    return store.ingest(source, source, batch, records)


def test_incident_search_matches_inclusive_evidence_interval_not_update_time(store):
    burst(store, "span", step=120)
    incident = store.list_incidents()[0]
    store.set_triage([incident["incident_id"]], "resolved", actor="operator")
    # The query lies inside the incident's evidence interval although last_seen
    # is outside it; changing triage does not change this matching semantics.
    filters = {"ip": PEER, "start": "2026-10-23T16:01:00+08:00", "end": "2026-10-23T08:03:00Z"}
    page = store.paginate_incidents(**filters)
    assert page["total"] == 1 and page["items"][0]["triage_status"] == "resolved"
    assert store.list_incidents(**filters)[0]["incident_id"] == incident["incident_id"]
    for boundary in ("2026-10-23T08:00:00Z", "2026-10-23T08:04:00Z"):
        assert store.paginate_incidents(ip=PEER, start=boundary, end=boundary)["total"] == 1
    assert store.paginate_incidents(ip=PEER, end="2026-10-23T07:59:59Z")["total"] == 0
    assert store.paginate_incidents(ip=PEER, start="2026-10-23T08:04:01Z")["total"] == 0


def test_ipv6_equivalence_exact_peer_and_input_validation(store):
    burst(store, "ipv6", peer="2001:db8::a")
    burst(store, "other", peer="2001:db8::ab")
    result = store.paginate_incidents(ip="2001:0DB8:0000:0000:0000:0000:0000:000A")
    assert result["total"] == 1 and result["items"][0]["peer_ip"] == "2001:db8::a"
    assert result["triage_counts"]["total"] == result["score_counts"]["total"] == 1
    assert store.paginate_incidents(ip="2001:db8::b")["total"] == 0


@pytest.mark.parametrize("filters", [
    {"ip": "198.51.100.999"}, {"ip": "198.51.100.23/32"}, {"ip": "2001:db8::a/128"},
    {"ip": "2001:db8:::a"}, {"ip": "fe80::1%eth0"}, {"ip": "' OR 1=1 --"}, {"ip": ""},
    {"start": "2026-10-23T08:00:00"}, {"end": "not-a-time"},
    {"start": "2026-10-23T08:01:00Z", "end": "2026-10-23T08:00:00Z"},
])
def test_invalid_incident_search_never_becomes_unfiltered(store, filters):
    burst(store, "one")
    with pytest.raises(ValueError):
        store.paginate_incidents(**filters)
    with pytest.raises(ValueError):
        store.list_incidents(**filters)


def test_search_counts_pages_and_facets_preserve_resolved_cross_source_membership(store):
    burst(store, "first", seconds=-7200)
    burst(store, "second", seconds=-3600)
    burst(store, "third-a", source="source-a")
    burst(store, "third-b", source="source-b")
    burst(store, "unrelated", peer="203.0.113.4", seconds=-3600)
    all_items = store.list_incidents(ip=PEER)
    assert len(all_items) == 3
    cross = all_items[0]
    assert cross["source_ids"] == ["source-a", "source-b"]
    store.set_triage([cross["incident_id"]], "resolved", actor="operator")
    filters = {"ip": PEER, "start": "2026-10-23T06:30:00Z", "end": "2026-10-23T08:10:00Z"}
    first = store.paginate_incidents(limit=1, **filters)
    last = store.paginate_incidents(limit=1, page=999, **filters)
    assert (first["total"], first["total_pages"], first["page"], last["page"]) == (2, 2, 1, 2)
    assert [first["items"][0]["incident_id"], last["items"][0]["incident_id"]] == [row["incident_id"] for row in all_items[:2]]
    assert first["triage_counts"] == {"pending": 1, "acknowledged": 0, "resolved": 1, "total": 2}
    pending = store.paginate_incidents(triage="pending", **filters)
    assert pending["total"] == pending["score_counts"]["total"] == 1
    assert pending["triage_counts"]["resolved"] == 1
    scoped = store.paginate_incidents(source_id="source-b", triage="resolved", sort="score", **filters)
    assert scoped["total"] == scoped["triage_counts"]["total"] == scoped["score_counts"]["total"] == 1
    assert scoped["items"][0]["incident_id"] == cross["incident_id"]
    bucket = "attention" if scoped["items"][0]["assessment"]["surfaced"] else "low"
    assert store.paginate_incidents(focus=bucket, source_id="source-b", **filters)["total"] == 1
    assert store.paginate_incidents(source_id="source-b' OR 1=1 --", **filters)["total"] == 0


def test_search_excludes_merged_aliases_but_keeps_retained_evidence(store, monkeypatch):
    burst(store, "first")
    burst(store, "last", seconds=598)
    assert store.paginate_incidents(ip=PEER)["total"] == 2
    store.ingest("source-a", "source-a", "bridge", [{"event_id": "bridge", "timestamp": (NOW + timedelta(seconds=300)).isoformat(),
                 "message": f"Failed password for root from {PEER} port 42000 ssh2", "identifier": "sshd"}])
    result = store.paginate_incidents(ip=PEER)
    assert result["total"] == result["triage_counts"]["total"] == 1
    monkeypatch.setattr(module, "_now", lambda: NOW + timedelta(days=15))
    assert store.cleanup()["deleted_events"] == 7
    assert store.paginate_events(ip=PEER)["total"] == 0
    retained = store.paginate_incidents(ip=PEER, start=NOW.isoformat(), end=NOW.isoformat())
    assert retained["total"] == 1 and retained["items"][0]["evidence_count"] == 7


def test_incident_search_count_items_and_facets_share_snapshot(store, monkeypatch):
    burst(store, "initial", seconds=-7200)
    original = store._incidents

    def concurrent(db, source_id, limit, offset, **filters):
        burst(store, "concurrent")
        return original(db, source_id, limit, offset, **filters)

    monkeypatch.setattr(store, "_incidents", concurrent)
    page = store.paginate_incidents(ip=PEER)
    assert page["total"] == len(page["items"]) == page["triage_counts"]["total"] == page["score_counts"]["total"] == 1


def test_additive_peer_index_upgrade_preserves_existing_data(store):
    burst(store, "original")
    tables = ("incidents", "events", "event_receipts", "incident_evidence", "batches")
    with store._connection() as db:
        before = {name: [tuple(row) for row in db.execute(f"SELECT * FROM {name} ORDER BY rowid")] for name in tables}
    with store._connection(write=True) as db:
        db.execute("DROP INDEX incidents_ip_paging")
    reopened = TelemetryStore(store.path)
    assert reopened.paginate_incidents(ip=PEER)["total"] == 1
    with store._connection() as db:
        assert before == {name: [tuple(row) for row in db.execute(f"SELECT * FROM {name} ORDER BY rowid")] for name in tables}
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []


def test_50000_incident_peer_search_uses_seek_without_scanning_unrelated_history(store, monkeypatch):
    count = 50_000
    at = module._iso(NOW)
    # The high row count is a synthetic search fixture, avoiding detector work.
    with store._connection(write=True) as db:
        db.executemany("INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
            (f"SSH-{n:06}", f"source-{n % 3}", "synthetic", f"198.51.100.{n % 200 + 1}",
             "synthetic", "open", at, at, NOW.timestamp() - n - 10, NOW.timestamp() - n,
             3, at, at, None) for n in range(count)))
        db.executemany("INSERT INTO incident_sources VALUES(?,?,?)", (
            (f"SSH-{n:06}", f"source-{n % 3}", "synthetic") for n in range(count)))
        db.execute("ANALYZE")
        where, params = store._incident_filter(None, ip="198.51.100.23", start=(NOW - timedelta(hours=24)).isoformat(), end=at)
        sql = f"SELECT incidents.* {module._INCIDENT_FROM} WHERE incidents.status!='merged' {where} ORDER BY {store._incident_order('recent')} LIMIT 50"
        plan = " ".join(row["detail"] for row in db.execute("EXPLAIN QUERY PLAN " + sql, params))
        assert "SEARCH incidents USING INDEX incidents_ip_paging" in plan
        assert "USE TEMP B-TREE FOR ORDER BY" not in plan
        db.execute("DROP INDEX incidents_ip_paging")
        no_peer_index = " ".join(row["detail"] for row in db.execute("EXPLAIN QUERY PLAN " + sql + " ", params))
        # With ANALYZE, SQLite may skip-scan the source-leading peer index,
        # but it still sorts the peer's full history rather than paging in order.
        assert "SCAN incidents" in no_peer_index or "USE TEMP B-TREE FOR ORDER BY" in no_peer_index
        db.execute("CREATE INDEX incidents_ip_paging ON incidents(src_ip,last_ts DESC,incident_id,first_ts) WHERE status!='merged'")

    original = store._connection
    instructions = 0

    @contextmanager
    def bounded_connection(**kwargs):
        nonlocal instructions
        with original(**kwargs) as db:
            def progress():
                nonlocal instructions
                instructions += 100
                return int(instructions > 100_000)
            db.set_progress_handler(progress, 100)
            try:
                yield db
            finally:
                db.set_progress_handler(None, 0)

    monkeypatch.setattr(store, "_connection", bounded_connection)
    begin = time.perf_counter()
    result = store.paginate_incidents(ip="198.51.100.23", limit=50, page=999, include_evidence=False,
                                     start=(NOW - timedelta(hours=24)).isoformat(), end=at)
    assert result["total"] == 250 and result["page"] == result["total_pages"] == 5
    assert result["triage_counts"]["total"] == result["score_counts"]["total"] == 250
    assert len(result["items"]) == 50 and all(item["peer_ip"] == "198.51.100.23" for item in result["items"])
    print(f"Synthetic 50000-incident exact IP query: {(time.perf_counter() - begin) * 1000:.2f}ms; {instructions} VM steps")

    instructions = 0
    scoped = store.paginate_incidents(ip="198.51.100.23", source_id="source-1", limit=50,
                                      page=999, include_evidence=False, start=(NOW - timedelta(hours=24)).isoformat(), end=at)
    assert scoped["total"] == 84 and scoped["page"] == 2
    assert scoped["triage_counts"]["total"] == scoped["score_counts"]["total"] == 84
    assert all("source-1" in item["source_ids"] for item in scoped["items"])
    print(f"Synthetic same-IP/source query: {instructions} VM steps")
