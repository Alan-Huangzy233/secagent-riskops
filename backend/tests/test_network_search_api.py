"""Operator search over temporary retained sources, without background workers."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from app.telemetry import network_api
from app.telemetry.network_search import NetworkSearchInvalid, NetworkSearchUnavailable
from app.telemetry.network_store import NetworkStore
from app.telemetry.operator_auth import OperatorVerifier
from test_network_api import (
    NET_TOKEN, PASSWORD, app, payload, profile,
    config as config, password_hash as password_hash,
)


ROUTE = "/api/network/events/search"


def query(**changes):
    now = datetime.now(timezone.utc)
    return {"source_id": "net-a", "ip": "198.51.100.9",
            "start": (now - timedelta(hours=1)).isoformat(),
            "end": (now + timedelta(minutes=1)).isoformat(), "limit": 1, **changes}


def client_for(config, store=None):
    application = app(config)
    # Exercise the actual routes and operator verifier while keeping the test
    # independent from the background detector and its source writes.
    application.state.config = config
    application.state.operator_verifier = OperatorVerifier()
    application.state.network_store = store
    return TestClient(application)


@pytest.fixture
def client(config):
    store = NetworkStore(config.network_ingest.database_path)
    first = payload(0)
    store.ingest(first, profile())
    store.ingest(payload(1, before=first["cursor_after"]), profile())
    instance = client_for(config, store)
    yield instance
    instance.close()


def get(client, params):
    return client.get(ROUTE, params=params, auth=("operator", PASSWORD))


def test_operator_search_uses_retained_events_and_frozen_page_tokens(client):
    params = query()
    first = get(client, params)
    assert first.status_code == 200
    page = first.json()
    assert len(page["items"]) == 1 and page["next_cursor"] and page["page_cursor"]
    assert page["items"][0]["src_ip"] == params["ip"]
    assert page["query"]["source_id"] == "net-a"
    assert page["limitations"] and "total" not in page
    store = client.app.state.network_store
    assert store.incidents()["items"] == []  # Raw search does not need a finding.
    store.ingest(payload(2, before="opaque-cursor-1"), profile())
    second = get(client, {**params, "cursor": page["next_cursor"]}).json()
    assert second["snapshot"] == page["snapshot"]
    assert len(second["items"]) == 1 and second["next_cursor"] is None
    assert second["items"][0]["event_id"] != page["items"][0]["event_id"]
    assert get(client, {**params, "cursor": page["page_cursor"]}).json() == page
    assert len(get(client, {**params, "limit": 100}).json()["items"]) == 3
    assert get(client, {**params, "ip": "203.0.113.17"}).json()["items"] == []


def test_search_authentication_and_source_enrollment_precede_reader(client, monkeypatch):
    calls = []
    monkeypatch.setattr(network_api, "search_events", lambda *args, **kwargs: calls.append(kwargs))
    params = query()
    assert client.get(ROUTE, params=params).status_code == 401
    assert client.get(ROUTE, params=params, headers={"Authorization": "Bearer " + NET_TOKEN}).status_code == 401
    assert client.get(ROUTE, params=params, auth=("wrong-operator", PASSWORD)).status_code == 401
    assert get(client, {**params, "source_id": "not-enrolled"}).status_code == 404
    assert calls == []


def test_disabled_search_does_not_create_network_storage(config):
    config = config.model_copy(update={"network_ingest": None, "http_ingest": None})
    client = client_for(config)
    try:
        assert get(client, query()).status_code == 404
        assert not (Path(config.database_path).parent / "network.sqlite").exists()
    finally:
        client.close()


@pytest.mark.parametrize("changes", [
    {"ip": "198.51.100.9/32"}, {"ip": "example.invalid"}, {"ip": "fe80::1%eth0"},
    {"start": "2026-01-01T00:00:00"}, {"end": "not-a-time"},
    {"start": "2026-01-01T00:00:00Z", "end": "2026-01-09T00:00:00Z"},
    {"limit": 101}, {"limit": 0}, {"cursor": "malformed"}, {"cursor": "x" * 2049},
])
def test_search_rejects_invalid_request_without_partial_page(client, changes):
    response = get(client, query(**changes))
    assert response.status_code == 422
    assert "items" not in response.json()


@pytest.mark.parametrize("missing", ["source_id", "ip", "start", "end"])
def test_search_requires_scope_peer_and_window(client, missing):
    params = query()
    del params[missing]
    assert get(client, params).status_code == 422


@pytest.mark.parametrize("error,status,detail", [
    (NetworkSearchInvalid(), 422, "invalid_network_search"),
    (NetworkSearchUnavailable(), 503, "network_search_unavailable"),
    (RuntimeError("private-path-and-synthetic-database-error"), 503, "network_search_unavailable"),
])
def test_reader_failure_is_safe_unavailable_not_empty_success(client, monkeypatch, error, status, detail):
    def fail(*args, **kwargs):
        raise error
    monkeypatch.setattr(network_api, "search_events", fail)
    response = get(client, query())
    assert response.status_code == status
    assert response.json() == {"detail": detail}


def test_legacy_source_pagination_is_unchanged(client):
    response = client.get("/api/network/events", params={"source_id": "net-a", "limit": 1},
                          auth=("operator", PASSWORD))
    assert response.status_code == 200
    assert response.json()["has_more"] is True
    assert "next_after" in response.json() and "page_cursor" not in response.json()
