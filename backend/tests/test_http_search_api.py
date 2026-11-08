"""Exact HTTP peer lookup through operator routes over synthetic saved cases."""
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from app.live_api import create_app
from app.telemetry.http_store import HttpStore
from app.telemetry.operator_auth import OperatorVerifier
from test_http_ingest import (
    HTTP_TOKEN, PASSWORD, config as config, password_hash as password_hash,
)
from test_http_incidents import drain, ingest, record, scan


ROUTE = '/api/http/incidents'


def client_for(config, store=None):
    application = create_app(config)
    # Use the real route and operator verifier without startup/background writes.
    application.state.config = config
    application.state.operator_verifier = OperatorVerifier()
    application.state.http_store = store
    return TestClient(application)


@pytest.fixture
def client(config):
    store = HttpStore(config.http_ingest.database_path)
    ingest(store, scan(), batch='public')
    ingest(store, scan(), batch='private', service='private')
    ingest(store, [record('v6-'+str(i), offset=i, peer='2001:db8::5') for i in range(20)], batch='v6')
    drain(store)
    instance = client_for(config, store)
    yield instance
    instance.close()


def get(client, **params):
    return client.get(ROUTE, params=params, auth=('operator', PASSWORD))


def test_exact_ip_filter_counts_and_pages_keep_existing_scope(client):
    first = get(client, ip='198.51.100.23', limit=1).json()
    assert first['total'] == first['total_pages'] == 2
    assert first['page'] == 1 and len(first['items']) == 1
    assert first['query'] == {'ip': '198.51.100.23', 'source_id': None, 'service_id': None, 'focus': 'all'}
    assert 'connection_peer_only' in first['limitations']
    second = get(client, ip='198.51.100.23', limit=1, page=2).json()
    assert second['items'][0]['incident_id'] != first['items'][0]['incident_id']
    assert {item['service_id'] for item in first['items'] + second['items']} == {'public', 'private'}
    filtered = get(client, ip='198.51.100.23', source_id='web', service_id='private', focus='attention').json()
    assert filtered['total'] == 1 and filtered['items'][0]['service_id'] == 'private'
    assert filtered['query']['source_id'] == 'web' and filtered['query']['focus'] == 'attention'
    assert get(client, ip='198.51.100.23', focus='low').json()['total'] == 0
    assert get(client, ip='198.51.100.230').json()['items'] == []
    assert get(client, ip='198.51.100.23', limit=1, page=100).json()['page'] == 2


@pytest.mark.parametrize('ip,canonical,total', [
    ('::ffff:198.51.100.23', '198.51.100.23', 2),
    ('::ffff:c633:6417', '198.51.100.23', 2),
    ('2001:0DB8:0000:0000:0000:0000:0000:0005', '2001:db8::5', 1),
])
def test_address_equivalence_matches_http_normalization(client, ip, canonical, total):
    response = get(client, ip=ip)
    assert response.status_code == 200
    data = response.json()
    assert data['query']['ip'] == canonical and data['total'] == total
    assert all(item['client_ip'] == canonical for item in data['items'])


@pytest.mark.parametrize('ip', [
    '', ' ', '198.51.100.23 ', ' 198.51.100.23', '198.51.100.23/32', 'fe80::1%eth0',
    'example.invalid', '198.51.100', '198.051.100.23', 'x'*46, '<img src=x onerror=alert(1)>',
])
def test_invalid_ip_is_not_unfiltered_or_empty_success(client, ip):
    response = get(client, ip=ip)
    assert response.status_code == 422
    assert 'items' not in response.json()


def test_authentication_and_enrollment_precede_search(client, monkeypatch):
    calls = []
    monkeypatch.setattr(client.app.state.http_store, 'incidents', lambda **kwargs: calls.append(kwargs))
    params = {'ip': '198.51.100.23'}
    assert client.get(ROUTE, params=params).status_code == 401
    assert client.get(ROUTE, params=params, headers={'Authorization': 'Bearer '+HTTP_TOKEN}).status_code == 401
    assert client.get(ROUTE, params=params, auth=('wrong-operator', PASSWORD)).status_code == 401
    assert get(client, **params, source_id='not-enrolled').status_code == 404
    assert get(client, **params, service_id='not-enrolled').status_code == 404
    assert calls == []


def test_disabled_http_does_not_create_storage(config):
    disabled = config.model_copy(update={'http_ingest': None})
    client = client_for(disabled)
    try:
        assert get(client, ip='198.51.100.23').status_code == 404
        assert not Path(config.http_ingest.database_path).exists()
    finally:
        client.close()


@pytest.mark.parametrize('error,status,detail', [
    (ValueError('private invalid-query detail'), 422, 'invalid_http_incident_search'),
    (RuntimeError('private store detail'), 503, 'http_incident_search_unavailable'),
])
def test_failed_search_is_safe_failure_not_empty_success(client, monkeypatch, error, status, detail):
    def fail(**kwargs):
        raise error
    monkeypatch.setattr(client.app.state.http_store, 'incidents', fail)
    response = get(client, ip='198.51.100.23')
    assert response.status_code == status
    assert response.json() == {'detail': detail}


def test_search_does_not_change_default_list_raw_records_or_versions(client):
    before = client.app.state.http_store.incidents()
    case = before['items'][0]
    saved = client.app.state.http_store.incident(case['incident_id'])
    raw_before = client.app.state.http_store.page('web', 'public')
    get(client, ip='198.51.100.23')
    default = get(client)
    assert default.status_code == 200 and default.json() == before
    assert 'query' not in default.json()
    assert client.app.state.http_store.incident(case['incident_id']) == saved
    assert client.app.state.http_store.page('web', 'public') == raw_before


@pytest.mark.parametrize('fragment', ['NaN', '1e999', '"\\ud800"'])
def test_corrupt_nonserializable_case_is_unavailable_not_response_error(client, fragment):
    store = client.app.state.http_store
    with store.connection(write=True) as db:
        row = db.execute('SELECT incident_id,payload_json FROM http_incidents WHERE client_ip=? LIMIT 1',
                         ('198.51.100.23',)).fetchone()
        raw = row['payload_json'][:-1] + ',"review_note":' + fragment + '}'
        db.execute('UPDATE http_incidents SET payload_json=? WHERE incident_id=?', (raw, row['incident_id']))
    response = get(client, ip='198.51.100.23')
    assert response.status_code == 503
    assert response.json() == {'detail': 'http_incident_search_unavailable'}
