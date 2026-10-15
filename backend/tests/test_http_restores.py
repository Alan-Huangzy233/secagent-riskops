"""Authenticated, global restore history with bounded read-only pages."""
import json
import sqlite3

from fastapi.testclient import TestClient
import pytest

from app.live_api import create_app
from app.telemetry.http_store import HttpBatch, HttpStore
from test_http_ingest import (config as config, password_hash as password_hash, read,
                              HTTP_TOKEN, payload)


def marker(index=0, **updates):
    return dict(schema_version=1, restore_id=f'{index:064x}', backup_id=f'rp-test-{index:03}',
                snapshot_at='2026-10-01T03:00:00.000Z', marked_at='2026-10-02T12:00:00.000Z',
                stream_count=2, verification_scope='paired_database_snapshots',
                http_component='private-http-path', console_component='private-console-path',
                producer_id='a'*32, http_sha256='b'*64, console_sha256='c'*64,
                http_bytes=4096, console_bytes=4096, signature='absent') | updates


def seed(store, rows):
    with store.connection(write=True) as db:
        db.executemany('INSERT INTO http_analysis_meta VALUES(?,?)',
                       [('restore:'+row['backup_id'], json.dumps(row)) for row in rows])


def test_history_is_read_only_global_and_survives_store_restart(tmp_path):
    store = HttpStore(tmp_path / 'http.sqlite')
    batch = HttpBatch(**payload())
    receipt = store.ingest(batch)
    seed(store, [marker(i) for i in range(5)])
    seed(store, [marker(5, marked_at='2026-10-03T00:00:00Z')])
    with store.connection() as db:
        before = list(db.iterdump())
    first = store.restores(limit=2)
    assert first['total'] == 6 and first['total_pages'] == 3
    assert [r['backup_id'] for r in first['items']] == ['rp-test-005', 'rp-test-004']
    last = store.restores(page=99, limit=2)
    assert last['page'] == 3 and [r['backup_id'] for r in last['items']] == ['rp-test-001', 'rp-test-000']
    assert set(first['items'][0]) == {'restore_id', 'backup_id', 'snapshot_at', 'marked_at',
                                    'stream_count', 'verification_scope'}
    with store.connection() as db:
        assert list(db.iterdump()) == before
    restarted = HttpStore(store.path)
    assert restarted.restores(limit=2) == first
    assert restarted.ingest(batch) == receipt
    restarted.ingest(HttpBatch(**payload(batch_id='post-restore', records=[])))
    assert restarted.restores(limit=2) == first


def test_operator_auth_disabled_empty_and_pagination_bounds(config, tmp_path):
    with TestClient(create_app(config.model_copy(update={'http_ingest': None}))) as client:
        assert read(client, 'restores').status_code == 404
        assert not (tmp_path / 'http.sqlite').exists()
    with TestClient(create_app(config)) as client:
        assert client.get('/api/http/restores').status_code == 401
        assert client.get('/api/http/restores', headers={'Authorization': 'Bearer '+HTTP_TOKEN}).status_code == 401
        assert read(client, 'restores').json() == dict(items=[], page=1, limit=20, total=0, total_pages=1)
        for params in ({'page': 0}, {'page': 1000001}, {'limit': 0}, {'limit': 101}):
            assert read(client, 'restores', **params).status_code == 422
        seed(client.app.state.http_store, [marker(i) for i in range(23)])
        response = read(client, 'restores', page=2)
        assert response.status_code == 200
        data = response.json()
        assert data['total'] == 23 and len(data['items']) == 3
        assert data['items'][0]['backup_id'] == 'rp-test-002'
        assert 'private-http-path' not in response.text and 'http_sha256' not in response.text
        assert client.post('/api/http/restores', json={}).status_code == 405


@pytest.mark.parametrize('change', [dict(schema_version=True), dict(schema_version=2),
    dict(restore_id='secret-path'), dict(backup_id='../bad'), dict(stream_count=True), dict(stream_count=-1),
    dict(marked_at='2026-10-02T12:00:00'), dict(snapshot_at='2026-10-01T03:00:00+03:00'),
    dict(verification_scope='full_host'), dict(marked_at=['private-data'])])
def test_invalid_record_fails_closed(config, change):
    with TestClient(create_app(config)) as client:
        seed(client.app.state.http_store, [marker(**change)])
        response = read(client, 'restores')
        assert response.status_code == 503
        assert response.json() == {'detail': 'HTTP restore history unavailable'}


def test_malformed_json_and_storage_errors_are_sanitized(config, monkeypatch):
    with TestClient(create_app(config)) as client:
        store = client.app.state.http_store
        with store.connection(write=True) as db:
            db.execute('INSERT INTO http_analysis_meta VALUES(?,?)', ('restore:broken', 'private-malformed-json'))
        response = read(client, 'restores')
        assert response.status_code == 503 and 'private-malformed' not in response.text
        def fail(**kwargs):
            raise sqlite3.OperationalError('/private/db-path')
        monkeypatch.setattr(store, 'restores', fail)
        response = read(client, 'restores')
        assert response.status_code == 503 and '/private' not in response.text
        assert client.get('/health').status_code == 200
