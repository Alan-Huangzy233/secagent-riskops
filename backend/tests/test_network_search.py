"""Synthetic ingested observations exercise bounded read-only raw search."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from app.telemetry import network_search, network_store
from app.telemetry.network_protocol import journal_entry
from app.telemetry.network_search import NetworkSearchInvalid, NetworkSearchUnavailable, search_events
from app.telemetry.network_store import NetworkStore
from test_network_store import DAY, NOW, batch, profile


PEER = "198.51.100.22"
OTHER = "198.51.100.23"
START = NOW - DAY


def stamp(value):
    return (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value)).isoformat(timespec="microseconds")


def event(index, *, source_profile=None, ip=PEER, at=None):
    source_profile = source_profile or profile()
    destination = "2001:db8::15" if ":" in ip else "192.0.2.15"
    return journal_entry({
        "_TRANSPORT": "kernel", "_BOOT_ID": "1" * 32, "__CURSOR": f"search-cursor-{index}",
        "__REALTIME_TIMESTAMP": str(START + index if at is None else at),
        "__MONOTONIC_TIMESTAMP": str(1000 + index),
        "MESSAGE": (f"[UFW BLOCK] IN=eth0 OUT= SRC={ip} DST={destination} "
                    "LEN=60 PROTO=TCP SPT=40000 DPT=443 WINDOW=1024 RES=0x00 SYN URGP=0"),
    }, source_profile)


def ingest(store, entries, *, number=1, source_profile=None, before=None, received=NOW):
    selected = source_profile or profile()
    payload = batch(number, entries, before=before, source_profile=selected, collected=NOW - 100)
    ack = store.ingest(payload, selected, now_us=received)
    assert ack["accepted"] == len(entries)
    return payload["cursor_after"]


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(network_store, "_now_us", lambda: NOW)
    return NetworkStore(tmp_path / "network.sqlite3")


def search(store, **kwargs):
    return search_events(store, **{"source_id": "synthetic-a", "ip": PEER,
                                   "start": stamp(START), "end": stamp(START + 10_000), **kwargs})


def test_exact_peer_source_and_microsecond_window_without_incidents(store):
    entries = [event(1, at=START-1), event(2, at=START), event(3, at=START+1),
               event(4, at=START+2), event(5, at=START+3), event(6, ip=OTHER, at=START+1)]
    ingest(store, entries)
    other = profile("synthetic-b")
    ingest(store, [event(20, source_profile=other, at=START+1)], source_profile=other)
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT count(*) FROM network_incidents").fetchone()[0] == 0
    result = search(store, end=stamp(START+2))
    assert [item["event_id"] for item in result["items"]] == [item["event"]["event_id"] for item in entries[1:4]]
    assert [item["journal_realtime_us"] for item in result["items"]] == [START, START+1, START+2]
    assert all(item["collected_at_us"] == NOW-100 and item["received_at_us"] == NOW for item in result["items"])
    assert result["next_cursor"] is None and result["page_cursor"]
    assert result["query"] == {"source_id": "synthetic-a", "ip": PEER,
                               "start": stamp(START).replace("+00:00", "Z"),
                               "end": stamp(START+2).replace("+00:00", "Z")}
    assert result["limitations"] == list(network_search.LIMITATIONS)


def test_ipv6_and_equivalent_time_forms_are_canonical_and_cursor_bound(store):
    expanded = "2001:0db8:0000:0000:0000:0000:0000:0022"
    ingest(store, [event(1, ip=expanded), event(2, ip="2001:db8::22"), event(3, ip="2001:db8::23")])
    start = datetime.fromisoformat(stamp(START)).astimezone(timezone(timedelta(hours=2)))
    result = search(store, ip=expanded, start=start, limit=1)
    assert result["query"]["ip"] == "2001:db8::22"
    assert result["query"]["start"].endswith(".000000Z")
    last = search_events(store, **result["query"], limit=1, cursor=result["next_cursor"])
    assert len(last["items"]) == 1 and last["next_cursor"] is None


def test_same_time_keyset_late_receipts_and_back_to_page_one(store):
    checkpoint = ingest(store, [event(index, at=START) for index in range(1, 6)])
    first = search(store, limit=2)
    assert [item["seq"] for item in first["items"]] == [1, 2]
    assert first["snapshot"] == 5
    ingest(store, [event(6, at=START)], number=2, before=checkpoint)
    second = search(store, limit=2, cursor=first["next_cursor"])
    final = search(store, limit=2, cursor=second["next_cursor"])
    assert [item["seq"] for item in second["items"]] == [3, 4]
    assert [item["seq"] for item in final["items"]] == [5]
    assert final["next_cursor"] is None
    assert first == search(store, limit=2, cursor=first["page_cursor"])
    assert second == search(store, limit=2, cursor=second["page_cursor"])
    assert search(store)["snapshot"] == 6


def test_retention_between_pages_keeps_highwater_and_explicit_incompleteness(store):
    checkpoint = ingest(store, [event(index) for index in range(1, 5)])
    first = search(store, limit=2)
    # Normal ingest retention removes every row; sqlite_sequence survives it.
    ingest(store, [], number=2, before=checkpoint, received=NOW + 14*DAY + 1)
    continued = search(store, limit=2, cursor=first["next_cursor"])
    assert continued["items"] == [] and continued["snapshot"] == 4
    assert "history_may_be_incomplete" in continued["limitations"]
    ingest(store, [event(9)], number=3, before=checkpoint, received=NOW + 14*DAY + 2)
    assert search(store, limit=2, cursor=first["page_cursor"])["items"] == []
    fresh = search(store)
    assert [item["seq"] for item in fresh["items"]] == [5] and fresh["snapshot"] == 5


@pytest.mark.parametrize("kwargs", [
    {"source_id": ""}, {"source_id": "bad source"}, {"source_id": "x"*129}, {"source_id": None},
    {"ip": "198.51.100.0/24"}, {"ip": "fe80::1%eth0"}, {"ip": "198.51.100.22 "},
    {"ip": 123}, {"ip": "host.example"}, {"ip": "010.0.0.1"},
    {"start": "2026-01-01T00:00:00"}, {"end": None}, {"start": datetime(2026, 1, 1)},
    {"start": "2026-01-01T00:00:00.1234567Z"}, {"start": "2026-02-30T00:00:00Z"},
    {"start": "2026-01-01T00:00:00+00:60"}, {"start": "2026-01-01T00:00:00+01:99"},
    {"end": "2026-01-01T00:00:00-00:60"}, {"start": "2026-01-01T00:00:00+24:00"},
    {"start": "1969-12-31T23:59:59Z"}, {"start": stamp(START+10_001)},
    {"end": stamp(START+7*DAY+1)}, {"limit": 0}, {"limit": 101}, {"limit": True}, {"limit": "2"},
    {"cursor": ""}, {"cursor": "x"*513}, {"cursor": "%%%%"}, {"cursor": []},
])
def test_invalid_input_fails_before_database_access(kwargs):
    with pytest.raises(NetworkSearchInvalid, match="^invalid_network_search$"):
        search(SimpleNamespace(path="not-a-database"), **kwargs)


def test_single_instant_and_exact_seven_days_are_allowed(store):
    ingest(store, [event(1, at=START)])
    assert len(search(store, end=stamp(START))["items"]) == 1
    assert len(search(store, end=stamp(START+7*DAY))["items"]) == 1
    assert search(store, start=stamp(START+1), end=stamp(START+1))["items"] == []


@pytest.mark.parametrize("changed", [
    {"source_id": "synthetic-b"}, {"ip": OTHER}, {"start": stamp(START-1)},
    {"end": stamp(START+1)}, {"limit": 3},
])
def test_cursor_rejects_changed_query(store, changed):
    ingest(store, [event(index) for index in range(1, 5)])
    first = search(store, limit=2)
    with pytest.raises(NetworkSearchInvalid):
        search(store, **{"limit": 2, "cursor": first["next_cursor"], **changed})


def cursor_data(token):
    return json.loads(base64.urlsafe_b64decode(token + "="*(-len(token) % 4))[16:])


def make_cursor(data):
    payload = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(payload).digest()[:16]+payload).rstrip(b"=").decode()


@pytest.mark.parametrize("change", [
    lambda value: value.__setitem__(0, True), lambda value: value.__setitem__(0, 2),
    lambda value: value.__setitem__(2, True), lambda value: value.__setitem__(2, -1),
    lambda value: value.__setitem__(2, 2**63), lambda value: value.__setitem__(2, 99),
    lambda value: value.__setitem__(3, [START-1, 1]),
    lambda value: value.__setitem__(3, [START, 99]),
    lambda value: value.__setitem__(3, [START, True]), lambda value: value.append(0),
])
def test_cursor_rejects_invalid_version_snapshot_boundary_and_shape(store, change):
    ingest(store, [event(1), event(2)])
    token = search(store, limit=1)["next_cursor"]
    data = cursor_data(token)
    change(data)
    with pytest.raises(NetworkSearchInvalid):
        search(store, limit=1, cursor=make_cursor(data))


def test_mutated_or_noncanonical_cursor_fails(store):
    ingest(store, [event(1), event(2)])
    token = search(store, limit=1)["next_cursor"]
    for changed in (token+"=", ("A" if token[0] != "A" else "B")+token[1:]):
        with pytest.raises(NetworkSearchInvalid):
            search(store, limit=1, cursor=changed)


def test_search_missing_and_foreign_database_do_not_create_or_change_it(tmp_path):
    missing = tmp_path / "missing.sqlite3"
    with pytest.raises(NetworkSearchUnavailable):
        search(SimpleNamespace(path=missing))
    assert not missing.exists()
    foreign = tmp_path / "foreign.sqlite3"
    with sqlite3.connect(foreign) as db:
        db.execute("CREATE TABLE unrelated(value TEXT)")
    before = foreign.read_bytes()
    with pytest.raises(NetworkSearchUnavailable, match="^network_search_unavailable$"):
        search(SimpleNamespace(path=foreign))
    assert before == foreign.read_bytes()


def test_search_preserves_database_and_next_ingest_after_read_failure(store, monkeypatch):
    checkpoint = ingest(store, [event(1), event(2)])
    before = Path(store.path).read_bytes()
    monkeypatch.setattr(store, "connection", lambda *args, **kwargs: pytest.fail("store connection used"))
    assert len(search(store)["items"]) == 2
    with monkeypatch.context() as limited:
        limited.setattr(network_search, "MAX_CANDIDATES", 1)
        with pytest.raises(NetworkSearchUnavailable):
            search(store)
    assert before == Path(store.path).read_bytes()
    monkeypatch.undo()
    ingest(store, [event(3)], number=2, before=checkpoint)
    assert len(search(store)["items"]) == 3
