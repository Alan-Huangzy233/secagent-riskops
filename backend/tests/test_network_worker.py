"""Network analysis lifecycle, auth isolation and idempotent console imports."""
from copy import deepcopy
import time
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from app.telemetry import network_incidents as analysis
from app.telemetry import notifications
from app.telemetry.network_store import NetworkStore
from app.telemetry.network_worker import NetworkWorker, publish, source_health
from app.telemetry.store import TelemetryStore
from test_network_api import (app, config as config, password_hash as password_hash,
                              payload, post, profile, read, NET_TOKEN)


def batch(start=0, end=10, *, before=None):
    rows = [payload(index) for index in range(start, end)]
    result = deepcopy(rows[-1])
    result.update(batch_id=f'group-{start}-{end}', cursor_before=before,
                  entries=[row['entries'][0] for row in rows])
    return result


def drain(store, now):
    for _ in range(100):
        if analysis.process(store, now)['caught_up']:
            return
    pytest.fail('network analysis did not catch up')


@pytest.fixture
def stores(tmp_path):
    return NetworkStore(tmp_path/'network.sqlite'), TelemetryStore(tmp_path/'console.sqlite')


def test_notification_import_survives_destination_commit_and_process_restart(stores):
    store, console = stores
    now = time.time()
    store.ingest(batch(), profile())
    drain(store, now)
    case = store.incidents()['items'][0]
    def crash():
        raise RuntimeError('simulated destination commit loss')
    with pytest.raises(RuntimeError):
        publish(store, console, now, after_import=crash)
    restarted = NetworkStore(store.path)
    assert publish(restarted, console, now) == 1
    assert publish(restarted, console, now) == 0
    console.run_notifications([], now=now)
    inbox = console.list_notifications(kind='network_incident')
    assert inbox['total'] == 1
    assert inbox['items'][0]['payload'] == case
    assert console.list_notifications(kind='incident')['total'] == 0
    assert console.list_notifications(kind='http_incident')['total'] == 0
    assert console.list_events() == []


def test_new_revision_race_is_not_acknowledged_by_previous_delivery(stores):
    store, console = stores
    now = time.time()
    store.ingest(batch(), profile())
    drain(store, now)
    def revise():
        store.ingest(batch(10, 11, before='opaque-cursor-9'), profile())
        drain(store, now+1)
    publish(store, console, now, after_import=revise)
    assert publish(store, console, now+1) == 1
    console.run_notifications([], now=now+1)
    inbox = console.list_notifications(kind='network_incident')
    assert inbox['total'] == 1 and inbox['items'][0]['payload']['revision'] == 2


def test_stale_revision_cancels_pending_notice_but_preserves_delivered_history(stores, monkeypatch):
    store, console = stores
    now = time.time()
    store.ingest(batch(), profile())
    drain(store, now)
    publish(store, console, now)
    console.run_notifications([], now=now)
    first = console.list_notifications(kind='network_incident')['items'][0]
    monkeypatch.setattr(analysis, 'MAX_CONTEXT_RECORDS', 10)
    store.ingest(batch(10, 11, before='opaque-cursor-9'), profile())
    drain(store, now+1)
    assert store.incidents()['items'][0]['stale']
    publish(store, console, now+1)
    console.run_notifications([], now=now+4000)
    assert console.list_notifications(kind='network_incident')['items'] == [first]
    with console._connection() as db:
        assert db.execute("SELECT count(*) FROM notification_outbox WHERE kind='network_incident' AND state='pending'").fetchone()[0] == 0


def test_collection_health_is_separate_deduplicated_and_recovers(stores):
    store, console = stores
    now = time.time()
    sources = [SimpleNamespace(id='net-a')]
    source_health(store, console, sources, 300, now)
    source_health(store, console, sources, 300, now+1)
    console.run_notifications([], now=now+1)
    inbox = console.list_notifications(kind='network_collection')
    assert inbox['total'] == 1
    assert inbox['items'][0]['payload']['conditions'] == ['never_seen']
    body = batch(0, 1)
    body['reports'] = ['coverage_start']
    store.ingest(body, profile())
    source_health(store, console, sources, 300, now+2)
    console.run_notifications([], now=now+2)
    recovered = console.list_notifications(kind='network_collection')
    assert recovered['total'] == 2 and not recovered['items'][0]['payload']['active']
    assert console.list_notifications(kind='network_incident')['total'] == 0
    source_health(store, console, sources, 300, now+400)
    console.run_notifications([], now=now+4000)
    conditions = console.list_notifications(kind='network_collection')['items'][0]['payload']['conditions']
    assert conditions == ['delayed', 'stale']


def test_report_and_rejection_health_does_not_raise_security_score(stores):
    store, console = stores
    now = time.time()
    body = batch(0, 1)
    body.update(reports=['journal_cursor_unavailable'], caught_up=False)
    store.ingest(body, profile())
    source_health(store, console, [SimpleNamespace(id='net-a')], 300, now)
    console.run_notifications([], now=now)
    conditions = console.list_notifications(kind='network_collection')['items'][0]['payload']['conditions']
    assert conditions == ['catching_up', 'journal_cursor_unavailable']
    assert console.list_notifications(kind='network_incident')['total'] == 0


def test_worker_notify_off_still_analyzes_and_close_is_safe(stores):
    store, console = stores
    store.ingest(batch(), profile())
    worker = NetworkWorker(store, console, notify=False)
    for _ in range(50):
        if worker.tick()['caught_up']:
            break
    assert store.incidents()['total'] == 1
    assert console.list_notifications(kind='network_incident')['total'] == 0
    with console._connection() as db:
        assert notifications._get(db, 'network-import:anything') is None
    worker.close()


def test_operator_only_network_case_and_evidence_routes(config):
    with TestClient(app(config)) as client:
        worker = client.app.state.network_worker
        worker.close()
        assert post(client, batch()).status_code == 200
        for _ in range(50):
            if worker.tick()['caught_up']:
                break
        response = read(client, 'incidents', limit=1)
        assert response.status_code == 200, response.text
        case = response.json()['items'][0]
        identity = case['incident_id']
        endpoints = ['incidents', f'incidents/{identity}', f'incidents/{identity}/evidence']
        for endpoint in endpoints:
            assert client.get('/api/network/'+endpoint).status_code == 401
            assert client.get('/api/network/'+endpoint, headers={'Authorization': 'Bearer '+NET_TOKEN}).status_code == 401
        assert read(client, f'incidents/{identity}', revision=1).json() == case
        evidence = read(client, f'incidents/{identity}/evidence', revision=1, limit=3).json()
        assert evidence['total'] == 10 and len(evidence['items']) == 3
        assert read(client, 'incidents', source_id='unknown').status_code == 404
        assert read(client, 'incidents', focus='bad').status_code == 422
        assert read(client, 'incidents', limit=101).status_code == 422
        assert read(client, 'incidents/absent').status_code == 404
        assert read(client, f'incidents/{identity}', revision=900).status_code == 404
        assert read(client, f'incidents/{identity}/evidence', revision=900).status_code == 404
        assert read(client, f'incidents/{identity}/evidence', page=0).status_code == 422


def test_disabled_case_routes_do_not_create_database(config):
    config = config.model_copy(update={'network_ingest': None, 'http_ingest': None})
    with TestClient(app(config)) as client:
        assert client.app.state.network_worker is None
        for endpoint in ('incidents', 'incidents/NET-absent', 'incidents/NET-absent/evidence'):
            assert read(client, endpoint).status_code == 404


def test_analysis_read_errors_do_not_expose_storage_paths(config, monkeypatch):
    with TestClient(app(config)) as client:
        client.app.state.network_worker.close()
        def fail(*args, **kwargs):
            raise OSError('private-storage-location')
        for method, endpoint in [('incidents', 'incidents'), ('incident', 'incidents/NET-test'),
                                 ('evidence', 'incidents/NET-test/evidence')]:
            monkeypatch.setattr(client.app.state.network_store, method, fail)
            response = read(client, endpoint)
            assert response.status_code == 503 and 'private-storage-location' not in response.text
