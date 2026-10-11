"""HTTP opt-in boundary, atomic receipt and retention regressions."""
from datetime import datetime, timedelta, timezone
import hashlib
import sqlite3
import secrets

from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from app.live_api import create_app
from app.telemetry.config import LiveConfig, hash_operator_password
from app.telemetry.http_store import HttpBatch, HttpStore

HTTP_TOKEN = 'synthetic-http-token-12345678901234567890'
SSH_TOKEN = 'synthetic-ssh-token-12345678901234567890'
PASSWORD: str = secrets.token_urlsafe(24)


@pytest.fixture(scope='module')
def password_hash():
    return hash_operator_password(PASSWORD)


@pytest.fixture
def config(tmp_path, password_hash):
    return LiveConfig(database_path=str(tmp_path / 'ssh.sqlite'),
                      sources=[dict(id='ssh', hostname='ssh.invalid', token_sha256=hashlib.sha256(SSH_TOKEN.encode()).hexdigest())],
                      operator_username='operator', operator_password_pbkdf2=password_hash,
                      notifications_enabled=False,
                      http_ingest=dict(database_path=str(tmp_path / 'http.sqlite'), sources=[
                          dict(id='web', hostname='web.invalid', services=['public', 'private'],
                               token_sha256=hashlib.sha256(HTTP_TOKEN.encode()).hexdigest())]))


def record(event_id='e1', path='/.env', **updates):
    return dict(event_id=event_id, timestamp=datetime.now(timezone.utc).isoformat(), client_ip='198.51.100.23',
                method='GET', path=path, status=404, **updates)


def payload(**updates):
    return dict(source_id='web', service_id='public', batch_id='b1', records=[record()], caught_up=True,
                collected_at=datetime.now(timezone.utc).isoformat()) | updates


def post(client, body, token=HTTP_TOKEN):
    return client.post('/api/http/batches', json=body, headers={'Authorization': 'Bearer '+token})


def read(client, path, **params):
    return client.get('/api/http/'+path, params=params, auth=('operator', PASSWORD))


def test_config_disabled_has_no_http_database_and_independent_auth(config, tmp_path):
    disabled = config.model_copy(update={'http_ingest': None})
    with TestClient(create_app(disabled)) as client:
        assert post(client, payload()).status_code == 404
        assert read(client, 'streams').status_code == 404
        assert not (tmp_path / 'http.sqlite').exists()
    with TestClient(create_app(config)) as client:
        assert post(client, payload(), token=SSH_TOKEN).status_code == 401
        assert post(client, payload(source_id='other')).status_code == 403
        assert post(client, payload(service_id='unconfigured')).status_code == 403
        assert client.get('/api/http/streams').status_code == 401
        assert client.get('/api/http/streams', headers={'Authorization': 'Bearer '+HTTP_TOKEN}).status_code == 401
        assert client.post('/api/telemetry/batches', json={}, headers={'Authorization': 'Bearer '+HTTP_TOKEN}).status_code == 401
        assert read(client, 'events', source_id='web', service_id='other').status_code == 404
        assert read(client, 'streams').json()['items'][0]['status'] == 'never_seen'


@pytest.mark.parametrize('bad', ['token', 'database', 'service', 'source'])
def test_configuration_rejects_shared_or_ambiguous_boundaries(config, bad):
    data = config.model_dump()
    http = data['http_ingest']
    if bad == 'token':
        http['sources'][0]['token_sha256'] = data['sources'][0]['token_sha256']
    if bad == 'database':
        http['database_path'] = data['database_path']
    if bad == 'service':
        http['sources'][0]['services'] = ['public', 'public']
    if bad == 'source':
        http['sources'] = http['sources'] * 2
    with pytest.raises(ValidationError):
        LiveConfig.model_validate(data)


def test_atomic_replay_conflict_and_restart(config):
    body = payload()
    with TestClient(create_app(config)) as client:
        ack = post(client, body).json()
        assert ack['durable'] is True and ack['accepted'] == 1
        assert post(client, body).json() == ack
        assert post(client, {**body, 'records': [dict(body['records'][0], status=200)]}).status_code == 422
        # Entire transaction rolls back even when a fresh event preceded the conflict.
        conflict = payload(batch_id='conflict', records=[record('fresh'), dict(body['records'][0], status=200)])
        assert post(client, conflict).status_code == 422
        assert len(read(client, 'events', source_id='web', service_id='public').json()['items']) == 1
    with TestClient(create_app(config)) as client:
        assert post(client, body).json() == ack
        duplicate = post(client, dict(body, batch_id='b2')).json()
        assert duplicate['accepted'] == 0 and duplicate['duplicates'] == 1
        other = post(client, dict(body, service_id='private')).json()
        assert other['accepted'] == 1  # event IDs are scoped by source AND service
        assert read(client, 'streams').json()['items'][0]['accepted_total'] == 1
        assert read(client, 'streams').json()['items'][1]['accepted_total'] == 1


def test_spoofed_fields_queries_and_rejection_accounting(config):
    with TestClient(create_app(config)) as client:
        for field in ('x_forwarded_for', 'authorization', 'cookie', 'service_id'):
            assert post(client, payload(records=[record(**{field: 'DO-NOT-STORE'})])).status_code == 422
        response = post(client, payload(records=[record(path='/.env?token=DO-NOT-STORE')],
                                       rejected=[dict(event_id='bad-line', code='invalid_record')],
                                       reports=['rotation_gap'], caught_up=False))
        assert response.status_code == 200
        assert response.json()['rejected'] == 1
        items = read(client, 'events', source_id='web', service_id='public').json()['items']
        assert items[0]['path'] == '/.env'
        stream = read(client, 'streams').json()['items'][0]
        assert stream['status'] == 'degraded' and stream['rejected_total'] == 1
        batches = read(client, 'batches', source_id='web', service_id='public').json()['items']
        assert batches[0]['reports'] == ['rotation_gap']
        assert post(client, payload(batch_id='b2', records=[], rejected=[dict(event_id='bad-line', code='invalid_record')])).json()['duplicates'] == 1
    for path in config.http_ingest.database_path, config.http_ingest.database_path+'-wal':
        from pathlib import Path
        if Path(path).exists():
            assert b'DO-NOT-STORE' not in Path(path).read_bytes()


def test_storage_failure_returns_no_durable_ack(config, monkeypatch):
    with TestClient(create_app(config)) as client:
        def fail(*args):
            raise sqlite3.OperationalError('PRIVATE')
        monkeypatch.setattr(client.app.state.http_store, 'ingest', fail)
        response = post(client, payload())
        assert response.status_code == 503 and 'PRIVATE' not in response.text and 'durable' not in response.text
        assert client.get('/health').status_code == 200
        monkeypatch.setattr(client.app.state.http_store, 'healthcheck', fail)
        assert client.get('/health').status_code == 503


def test_snapshot_pages_keep_new_ingests_out_and_request_limits(config):
    with TestClient(create_app(config)) as client:
        assert post(client, payload(records=[record(str(i)) for i in range(4)])).status_code == 200
        first = read(client, 'events', source_id='web', service_id='public', limit=2).json()
        assert first['has_more'] and len(first['items']) == 2
        assert post(client, payload(batch_id='b2', records=[record('new')])).status_code == 200
        last = read(client, 'events', source_id='web', service_id='public', limit=2,
                    after=first['next_after'], snapshot=first['snapshot']).json()
        assert not last['has_more'] and [e['event_id'] for e in last['items']] == ['2', '3']
        assert post(client, payload(records=[record(str(i)) for i in range(201)])).status_code == 422
        assert post(client, payload(records=[dict(record(), timestamp=(datetime.now(timezone.utc)+timedelta(days=1)).isoformat())])).status_code == 422
        assert read(client, 'events', source_id='web', service_id='public', limit=201).status_code == 422
        assert client.post('/api/http/batches', content=b'x'*(1024*1024+1)).status_code == 413


def test_retention_keeps_receipts_and_bounds_cleanup(tmp_path):
    store = HttpStore(tmp_path / 'http.sqlite', retention_days=1)
    body = HttpBatch(**payload())
    first = store.ingest(body)
    with store.connection(write=True) as db:
        db.execute('UPDATE http_events SET event_ts=0')
    store.ingest(HttpBatch(**payload(batch_id='heartbeat', records=[])))
    assert store.page('web', 'public')['items'] == []
    assert store.ingest(body) == first
    assert store.ingest(body.model_copy(update={'batch_id': 'retry'}))['duplicates'] == 1
    with store.connection(write=True) as db:
        db.executemany('INSERT INTO http_events(source_id,service_id,event_id,event_ts,record_json) VALUES(?,?,?,?,?)',
                       [('old', 'old', str(i), 0, '{}') for i in range(1200)])
    store.ingest(HttpBatch(**payload(batch_id='cleanup', records=[])))
    with store.connection() as db:
        assert db.execute('SELECT count(*) FROM http_events').fetchone()[0] == 200


def test_late_spooled_batch_does_not_claim_current_collection(config):
    with TestClient(create_app(config)) as client:
        body = payload(collected_at=(datetime.now(timezone.utc)-timedelta(hours=1)).isoformat())
        assert post(client, body).status_code == 200
        assert read(client, 'streams').json()['items'][0]['status'] == 'delayed'


def test_http_store_refuses_an_existing_unrelated_database(tmp_path):
    path = tmp_path / 'unrelated.sqlite'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE private_data(value TEXT)')
    with pytest.raises(ValueError, match='separate database'):
        HttpStore(path)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [('private_data',)]


def test_rejected_line_ids_are_inspectable_and_survive_retry(config):
    with TestClient(create_app(config)) as client:
        body = payload(records=[], rejected=[dict(event_id='file-generation:24', code='invalid_record')])
        response = post(client, body).json()
        assert response['rejected_records'] == body['rejected']
        assert post(client, body).json() == response
        receipt = read(client, 'batches', source_id='web', service_id='public').json()['items'][0]
        assert receipt['rejected_records'] == body['rejected']
