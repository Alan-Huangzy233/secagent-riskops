"""Warm reads share bounded work; stale display data never enters write APIs."""
from concurrent.futures import ThreadPoolExecutor
import json
import threading

from fastapi.testclient import TestClient

from app.live_api import create_app
from app.telemetry.console_cache import ConsoleCache, MAX_AGE_SECONDS, MAX_BYTES
from test_live_api import PASSWORD, TOKEN_A, batch, config as config, password_hash as password_hash, send


def test_cold_stale_expired_failed_and_disabled_states():
    now = [0.0]
    value = {"display": [1]}
    cache = ConsoleCache(lambda: value, clock=lambda: now[0])
    assert cache.read()["state"] == "warming"
    assert cache.refresh_once()
    first = cache.read()
    assert first["state"] == "ready" and not first["stale"]
    first["data"]["display"].append(2)
    value["display"].append(3)
    assert cache.read()["data"] == {"display": [1]}, "Readers/builders cannot mutate a published snapshot"
    now[0] = 16
    assert cache.read()["stale"]

    def failing():
        raise RuntimeError("private-evidence-must-not-escape")

    cache.build = failing
    assert not cache.refresh_once()
    assert cache.read()["data"] == {"display": [1]}
    assert cache.read()["error"] == "refresh_failed"
    assert "private-evidence" not in json.dumps(cache.read())
    now[0] = MAX_AGE_SECONDS + 1
    assert cache.read()["data"] is None and cache.read()["state"] == "unavailable"
    disabled = ConsoleCache(failing, enabled=False)
    disabled.start()
    assert disabled.thread is None and not disabled.refresh_once()
    assert disabled.read() == {"state": "disabled", "data": None}


def test_size_limit_retains_last_good_generation():
    cache = ConsoleCache(lambda: {"value": "small"})
    assert cache.refresh_once()
    cache.build = lambda: {"value": "x" * MAX_BYTES}
    assert not cache.refresh_once()
    assert cache.read()["generation"] == 1
    assert cache.read()["data"] == {"value": "small"}
    assert cache.read()["stale"]


def test_concurrent_rebuilds_coalesce_and_mutation_during_build_stays_dirty():
    started, finish = threading.Event(), threading.Event()
    builds = []

    def build():
        builds.append(1)
        started.set()
        assert finish.wait(5)
        return {"display": "old"}

    cache = ConsoleCache(build)
    with ThreadPoolExecutor(max_workers=5) as pool:
        first = pool.submit(cache.refresh_once)
        assert started.wait(5)
        try:
            assert cache.read()["state"] == "warming"
            assert not any(pool.map(lambda _: cache.refresh_once(), range(10)))
            cache.invalidate()
        finally:
            finish.set()
        assert first.result()
    assert len(builds) == 1 and cache.read()["stale"]
    assert cache.refresh_once() and not cache.read()["stale"]


def test_worker_prepares_without_a_reader_and_stops():
    prepared = threading.Event()
    cache = ConsoleCache(lambda: prepared.set() or {"value": 1})
    cache.start()
    worker = cache.thread
    cache.start()
    assert cache.thread is worker
    try:
        assert prepared.wait(5)
    finally:
        cache.close()
    assert not worker.is_alive() and not cache.refresh_once()


def test_bootstrap_requires_operator_and_reads_do_not_query_database(config, monkeypatch):
    monkeypatch.setattr(ConsoleCache, "start", lambda self: None)
    with TestClient(create_app(config.model_copy(update={"console_cache_enabled": True}))) as client:
        cache = client.app.state.console_cache
        path = "/api/console/bootstrap"
        assert client.get(path).status_code == 401
        assert client.get(path, headers={"Authorization": "Bearer " + TOKEN_A}).status_code == 401
        assert client.get(path, auth=("operator", PASSWORD)).status_code == 202
        assert send(client).status_code == 200
        assert cache.refresh_once()
        expected = cache.read()["data"]
        assert expected["summary"]["totals"]["events"] == 1
        assert len(expected["events"]["items"]) == 1
        assert expected["incidents"]["items"] == []
        assert not any(key in json.dumps(expected) for key in ("csrf_token", "token_sha256", "password_pbkdf2"))

        def unexpected(*args, **kwargs):
            raise AssertionError("HTTP read attempted database work")

        for method in ("paginate_events", "paginate_incidents", "list_sources", "triage_counts"):
            monkeypatch.setattr(client.app.state.store, method, unexpected)
        for _ in range(3):
            result = client.get(path, auth=("operator", PASSWORD))
            assert result.status_code == 200 and result.json()["data"] == expected
            assert result.headers["Cache-Control"] == "no-store"
        cache.build = unexpected
        cache.data = None
        cache.refresh_once()
        failure = client.get(path, auth=("operator", PASSWORD))
        assert failure.status_code == 503 and failure.json()["data"] is None
        assert "database work" not in failure.text


def test_ingest_and_disposition_invalidate_without_rebuilding_in_request(config, monkeypatch):
    monkeypatch.setattr(ConsoleCache, "start", lambda self: None)
    with TestClient(create_app(config.model_copy(update={"console_cache_enabled": True}))) as client:
        cache = client.app.state.console_cache
        assert cache.refresh_once()
        row = batch()["records"][0]
        payload = batch(records=[{**row, "event_id": str(i)} for i in range(10)])
        assert send(client, payload).status_code == 200
        assert cache.read()["stale"] and cache.read()["generation"] == 1
        assert cache.refresh_once()
        incident = cache.read()["data"]["incidents"]["items"][0]["incident_id"]
        auth = ("operator", PASSWORD)
        token = client.get("/api/controls", auth=auth).json()["csrf_token"]
        result = client.post("/api/incidents/triage", auth=auth,
                             headers={"X-RiskOps-CSRF": token},
                             json={"incident_ids": [incident], "state": "acknowledged"})
        assert result.status_code == 200
        assert cache.read()["stale"] and cache.read()["generation"] == 2
        assert cache.refresh_once()
        assert cache.read()["data"]["incidents"]["items"] == []
        assert cache.read()["data"]["summary"]["triage_counts"]["acknowledged"] == 1


def test_default_disabled_preserves_on_demand_api(config):
    with TestClient(create_app(config)) as client:
        auth = ("operator", PASSWORD)
        assert client.get("/api/console/bootstrap", auth=auth).json()["state"] == "disabled"
        assert client.get("/api/summary", auth=auth).status_code == 200
        assert client.get("/api/events?page=1", auth=auth).status_code == 200
