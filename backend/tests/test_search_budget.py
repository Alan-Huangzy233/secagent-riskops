"""Cooperative deadlines interrupt real SQLite work without leaking partial pages."""
from datetime import datetime, timedelta, timezone
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.live_api import create_app
from app.telemetry import store as module
from app.telemetry.store import SearchQueryUnavailable, TelemetryStore
# Imported fixtures are registered by pytest; the password is synthetic.
from test_live_api import PASSWORD, config, password_hash  # noqa: F401

PEER = "198.51.100.23"


def seed(store, batch="initial"):
    at = datetime.now(timezone.utc) - timedelta(minutes=1)
    return store.ingest("server-a", "host-a", batch, [
        {"event_id": f"{batch}-{n}", "timestamp": (at + timedelta(seconds=n)).isoformat(),
         "message": f"Failed password for root from {PEER} port 42000 ssh2", "identifier": "sshd"}
        for n in range(3)
    ])


@pytest.fixture
def store(tmp_path):
    store = TelemetryStore(tmp_path / "budget.sqlite")
    seed(store)
    return store


def expensive_rows(store, monkeypatch, method):
    """Advance a private monotonic clock *inside* SQLite, not a pre-query mock."""
    moment = [0.0]
    monkeypatch.setattr(module, "_search_now", lambda: moment[0])
    original = getattr(store, method)
    touched = []

    def wrapped(db, *args, **kwargs):
        def tick(value):
            touched.append(value)
            moment[0] += 1
            return value
        db.create_function("budget_tick", 1, tick)
        db.execute("""WITH RECURSIVE work(n) AS (
            VALUES(1) UNION ALL SELECT n+1 FROM work WHERE n<100000)
            SELECT sum(budget_tick(n)) FROM work""").fetchone()
        return original(db, *args, **kwargs)

    monkeypatch.setattr(store, method, wrapped)
    return original, touched, moment


@pytest.mark.parametrize("operation,reader", [
    ("list_events", "_events"), ("paginate_events", "_events"),
    ("list_incidents", "_incidents"), ("paginate_incidents", "_incidents"),
])
def test_filtered_reads_interrupt_sql_close_transaction_and_allow_next_ingest(store, monkeypatch, operation, reader):
    original, touched, _ = expensive_rows(store, monkeypatch, reader)
    closed = []
    base = module._SearchConnection

    class TrackedConnection(base):
        def close(self):
            # A still-installed expired progress callback would interrupt this
            # check. The handler/deadline must be reset before rollback/close.
            assert self.search_deadline is None
            assert not self.in_transaction
            assert self.execute("""WITH RECURSIVE clean(n) AS (
                VALUES(1) UNION ALL SELECT n+1 FROM clean WHERE n<2000)
                SELECT max(n) FROM clean""").fetchone()[0] == 2000
            closed.append(self)
            return super().close()

    monkeypatch.setattr(module, "_SearchConnection", TrackedConnection)
    with pytest.raises(SearchQueryUnavailable):
        getattr(store, operation)(ip=PEER)
    assert 0 < len(touched) < 100000, "SQLite must stop executing the expensive statement"
    assert len(closed) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        closed[0].execute("SELECT 1")
    monkeypatch.setattr(store, reader, original)
    assert seed(store, "after-interruption")["accepted"] == 3
    assert store.paginate_events(ip=PEER)["total"] == 6
    assert store.paginate_incidents(ip=PEER)["total"] == 1


def test_incident_count_rows_and_facets_share_one_budget_instead_of_resetting_each_statement(store, monkeypatch):
    moment = [0.0]
    monkeypatch.setattr(module, "_search_now", lambda: moment[0])
    original_items, original_scores = store._incidents, store._score_counts
    stages = []

    def items(*args, **kwargs):
        result = original_items(*args, **kwargs)
        stages.append("items")
        moment[0] += 3
        return result

    def scores(*args, **kwargs):
        stages.append("scores")
        moment[0] += 3
        return original_scores(*args, **kwargs)

    monkeypatch.setattr(store, "_incidents", items)
    monkeypatch.setattr(store, "_score_counts", scores)
    with pytest.raises(SearchQueryUnavailable):
        store.paginate_incidents(ip=PEER)
    assert stages == ["items", "scores"]
    # The operation must not return count/items before the final facet fails.
    monkeypatch.setattr(store, "_incidents", original_items)
    monkeypatch.setattr(store, "_score_counts", original_scores)
    assert store.paginate_incidents(ip=PEER)["total"] == 1


def test_filtered_lock_wait_is_short_and_translated_without_affecting_next_write(store, monkeypatch):
    monkeypatch.setattr(module, "_SEARCH_LOCK_WAIT_SECONDS", 0.02)
    holder = sqlite3.connect(store.path, isolation_level=None)
    try:
        # Rollback journaling supplies a deterministic reader/exclusive-lock
        # conflict; production remains WAL and this changes only the fixture.
        assert holder.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"
        holder.execute("BEGIN EXCLUSIVE")
        started = time.monotonic()
        with pytest.raises(SearchQueryUnavailable):
            store.paginate_events(ip=PEER)
        assert time.monotonic() - started < 2, "must not use the default 30-second busy timeout"
    finally:
        holder.rollback()
        holder.close()
    assert seed(store, "after-lock")["accepted"] == 3
    assert store.paginate_events(ip=PEER)["total"] == 6


def test_default_pages_source_disposition_and_ingest_do_not_use_search_budget(store, monkeypatch):
    monkeypatch.setattr(module, "_SEARCH_DEADLINE_SECONDS", 0)
    assert seed(store, "unfiltered")["accepted"] == 3
    assert len(store.list_events(source_id="server-a")) == 6
    assert store.paginate_events(source_id="server-a")["total"] == 6
    assert store.paginate_incidents(triage="pending")["total"] == 1
    assert len(store.list_incidents(source_id="server-a")) == 1
    for method, kwargs in ((store.paginate_events, {"q": "password"}),
                           (store.paginate_events, {"username": "root"}),
                           (store.paginate_events, {"event_type": "auth_failure"}),
                           (store.paginate_incidents, {"start": "2026-01-01T00:00:00Z"})):
        with pytest.raises(SearchQueryUnavailable):
            method(**kwargs)


@pytest.mark.parametrize("path,params,reader", [
    ("/api/events", {"ip": PEER, "page": 1}, "_events"),
    ("/api/events", {"ip": PEER}, "_events"),
    ("/api/incidents", {"ip": PEER, "page": 1}, "_incidents"),
    ("/api/incidents", {"ip": PEER}, "_incidents"),
    ("/api/dashboard", {"incident_ip": PEER}, "_incidents"),
])
def test_search_budget_api_returns_sanitized_503_not_empty_success(request, monkeypatch, path, params, reader):
    with TestClient(create_app(request.getfixturevalue("config"))) as client:
        store = client.app.state.store
        seed(store)
        original, touched, _ = expensive_rows(store, monkeypatch, reader)
        response = client.get(path, params=params, auth=("operator", PASSWORD))
        assert response.status_code == 503
        assert response.json() == {
            "code": "search_temporarily_unavailable",
            "detail": "查询耗时过长或数据库暂忙，请缩短时间范围或稍后重试；未返回部分结果。",
        }
        assert response.headers["Retry-After"] == "2"
        assert response.headers["Cache-Control"] == "no-store"
        assert 0 < len(touched) < 100000
        assert PEER not in response.text and "budget_tick" not in response.text and "sqlite" not in response.text
        monkeypatch.setattr(store, reader, original)
        assert client.get(path, params=params, auth=("operator", PASSWORD)).status_code == 200
        assert seed(store, "after-api-timeout")["accepted"] == 3
