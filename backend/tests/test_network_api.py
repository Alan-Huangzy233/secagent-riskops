"""Network source authentication, opt-in isolation and durable read boundaries."""
from copy import deepcopy
from dataclasses import asdict
import hashlib
from pathlib import Path
import secrets
import time
from types import SimpleNamespace

from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from app.live_api import create_app
from app.telemetry.config import LiveConfig, hash_operator_password
from app.telemetry.network_parse import SourceProfile
from app.telemetry.network_protocol import encode, journal_entry, validate_ack

NET_TOKEN = 'synthetic-network-token-12345678901234567890'
SSH_TOKEN = 'synthetic-ssh-token-12345678901234567890'
HTTP_TOKEN = 'synthetic-http-token-12345678901234567890'
PASSWORD: str = secrets.token_urlsafe(24)


def profile(source='net-a', digest='a'):
    return SourceProfile(source_id=source, ruleset_sha256=digest * 64,
        log_labels=('[UFW BLOCK]',), rejection_labels=('[UFW BLOCK]',),
        local_input_labels=('[UFW BLOCK]',), local_input_interfaces=('eth0',),
        logging_limit='rate_limited', retention='unknown')


def payload(index=0, *, before=None, selected=None):
    selected = selected or profile()
    now = time.time_ns() // 1000
    entry = journal_entry({'_TRANSPORT': 'kernel', '_BOOT_ID': '1' * 32,
        '__CURSOR': f'opaque-cursor-{index}', '__REALTIME_TIMESTAMP': str(now),
        '__MONOTONIC_TIMESTAMP': str(1_000_000 + index),
        'MESSAGE': f'[UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.9 DST=192.0.2.20 '
                   f'LEN=60 PROTO=TCP SPT=45000 DPT={8000+index} WINDOW=1024 RES=0x00 SYN URGP=0'}, selected)
    return {'version': 1, 'source_id': selected.source_id, 'profile_revision': selected.revision,
        'batch_id': f'batch-{index}', 'collected_at_us': now, 'cursor_before': before,
        'cursor_after': f'opaque-cursor-{index}', 'entries': [entry], 'reports': [], 'caught_up': True}


@pytest.fixture(scope='module')
def password_hash():
    return hash_operator_password(PASSWORD)


@pytest.fixture
def config(tmp_path, password_hash):
    return LiveConfig(database_path=str(tmp_path / 'ssh.sqlite'), notifications_enabled=False,
        sources=[{'id': 'ssh-a', 'hostname': 'ssh.example.invalid',
                  'token_sha256': hashlib.sha256(SSH_TOKEN.encode()).hexdigest()}],
        operator_username='operator', operator_password_pbkdf2=password_hash,
        http_ingest={'database_path': str(tmp_path / 'http.sqlite'), 'sources': [
            {'id': 'web-a', 'hostname': 'web.example.invalid', 'services': ['public'],
             'token_sha256': hashlib.sha256(HTTP_TOKEN.encode()).hexdigest()}]},
        network_ingest={'database_path': str(tmp_path / 'network.sqlite'), 'sources': [
            {'id': 'net-a', 'hostname': 'network.example.invalid', 'profiles': [asdict(profile())],
             'token_sha256': hashlib.sha256(NET_TOKEN.encode()).hexdigest()}]})


def app(config):
    return create_app(config, control=SimpleNamespace(block_listener=None), ai=SimpleNamespace())


def post(client, body, token=NET_TOKEN):
    return client.post('/api/network/batches', content=encode(body),
        headers={'Authorization': 'Bearer '+token, 'Content-Type': 'application/json'})


def read(client, endpoint, **params):
    return client.get('/api/network/'+endpoint, params=params, auth=('operator', PASSWORD))


def test_disabled_creates_no_network_database_and_status_is_explicit(config):
    config = config.model_copy(update={'network_ingest': None, 'http_ingest': None})
    with TestClient(app(config)) as client:
        assert post(client, payload()).status_code == 404
        assert read(client, 'events', source_id='net-a').status_code == 404
        assert read(client, 'status').json() == {'enabled': False}
    assert not (Path(config.database_path).parent / 'network.sqlite').exists()


def test_independent_tokens_operator_reads_and_no_cross_source_write(config):
    with TestClient(app(config)) as client:
        for token in (SSH_TOKEN, HTTP_TOKEN, 'not-valid'):
            assert post(client, payload(), token).status_code == 401
        assert post(client, payload(selected=profile('net-b'))).status_code == 403
        assert post(client, payload(selected=profile(digest='b'))).status_code == 422
        for endpoint in ('status', 'sources', 'events', 'batches'):
            assert client.get('/api/network/'+endpoint, params={'source_id': 'net-a'}).status_code == 401
            assert client.get('/api/network/'+endpoint, params={'source_id': 'net-a'},
                headers={'Authorization': 'Bearer '+NET_TOKEN}).status_code == 401
        assert client.post('/api/telemetry/batches', json={},
            headers={'Authorization': 'Bearer '+NET_TOKEN}).status_code == 401
        assert read(client, 'events', source_id='not-enrolled').status_code == 404
        assert read(client, 'sources').json()['items'][0]['status'] == 'never_seen'


@pytest.mark.parametrize('bad', ['ssh_token', 'http_token', 'ssh_path', 'http_path',
                                   'source', 'profile_source', 'profile_duplicate', 'cap_bool'])
def test_configuration_rejects_shared_credentials_paths_and_profiles(config, bad):
    values = config.model_dump()
    network = values['network_ingest']
    source = network['sources'][0]
    if bad in ('ssh_token', 'http_token'):
        source['token_sha256'] = (values['sources'][0] if bad == 'ssh_token'
            else values['http_ingest']['sources'][0])['token_sha256']
    elif bad in ('ssh_path', 'http_path'):
        network['database_path'] = (values['database_path'] if bad == 'ssh_path'
                                   else values['http_ingest']['database_path'])
    elif bad == 'source':
        network['sources'] = [source, source]
    elif bad == 'profile_source':
        source['profiles'][0]['source_id'] = 'other'
    elif bad == 'profile_duplicate':
        source['profiles'] = source['profiles'] * 2
    elif bad == 'cap_bool':
        network['max_batches'] = True
    with pytest.raises(ValidationError):
        LiveConfig.model_validate(values)


def test_replay_restart_and_operator_pagination_return_committed_evidence(config):
    first, second = payload(0), payload(1, before='opaque-cursor-0')
    with TestClient(app(config)) as client:
        response = post(client, first)
        assert response.status_code == 200, response.text
        receipt = response.json()
        validate_ack(receipt, first)
        assert post(client, first).json() == receipt
        page = read(client, 'events', source_id='net-a', limit=1).json()
        assert len(page['items']) == 1
        assert post(client, second).status_code == 200
        frozen = read(client, 'events', source_id='net-a', after=page['next_after'],
                      snapshot=page['snapshot']).json()
        assert frozen['items'] == []
        assert len(read(client, 'events', source_id='net-a').json()['items']) == 2
        assert read(client, 'events', source_id='net-a', limit=201).status_code == 422
        assert read(client, 'status').json()['analysis_enabled'] is True
        assert read(client, 'sources').json()['items'][0]['status'] == 'current'
    with TestClient(app(config)) as client:
        assert post(client, first).json() == receipt
        assert len(read(client, 'batches', source_id='net-a').json()['items']) == 2
        changed = deepcopy(first)
        changed['collected_at_us'] += 1
        assert post(client, changed).status_code == 409
        assert post(client, payload(2)).status_code == 409


def test_strict_json_size_and_safe_validation_errors(config):
    with TestClient(app(config)) as client:
        headers = {'Authorization': 'Bearer '+NET_TOKEN, 'Content-Type': 'application/json'}
        raw = encode(payload())
        duplicate = raw[:-1] + b',"version":1}'
        assert client.post('/api/network/batches', content=duplicate, headers=headers).status_code == 422
        assert client.post('/api/network/batches', content=b'x' * (1024 * 1024 + 1),
                           headers=headers).status_code == 413
        invalid = payload()
        invalid['entries'][0]['event']['MESSAGE'] = 'synthetic-private-metadata'
        response = post(client, invalid)
        assert response.status_code == 422 and 'synthetic-private-metadata' not in response.text
        assert read(client, 'events', source_id='net-a').json()['items'] == []


def test_storage_capacity_preserves_previous_ack_and_emits_no_new_ack(config):
    values = config.model_dump()
    values['network_ingest']['max_batches'] = 1
    config = LiveConfig.model_validate(values)
    with TestClient(app(config)) as client:
        first = payload()
        ack = post(client, first).json()
        assert ack['durable'] is True
        failed = post(client, payload(1, before='opaque-cursor-0'))
        assert failed.status_code == 503 and 'durable' not in failed.json()
        assert post(client, first).json() == ack
        assert len(read(client, 'batches', source_id='net-a').json()['items']) == 1


def test_storage_failure_is_safe_and_returns_no_ack(config, monkeypatch):
    with TestClient(app(config)) as client:
        def fail(*args):
            raise OSError('synthetic-private-path')
        monkeypatch.setattr(client.app.state.network_store, 'ingest', fail)
        response = post(client, payload())
        assert response.status_code == 503
        assert 'durable' not in response.json() and 'synthetic-private-path' not in response.text


def test_rejected_record_duplicate_stays_visible_as_degraded(config):
    first = payload()
    first['entries'] = [journal_entry({'_TRANSPORT': 'kernel', '_BOOT_ID': '1' * 32,
        '__CURSOR': first['cursor_after'], '__REALTIME_TIMESTAMP': str(first['collected_at_us']),
        '__MONOTONIC_TIMESTAMP': '1000000',
        'MESSAGE': '[UFW BLOCK] IN=eth0 OUT= SRC=invalid DST=192.0.2.20 PROTO=TCP'}, profile())]
    repeated = deepcopy(first)
    repeated.update(batch_id='repeated-rejection', cursor_before=first['cursor_after'])
    with TestClient(app(config)) as client:
        assert post(client, first).json()['rejected'] == 1
        ack = post(client, repeated).json()
        assert ack['rejected'] == 0 and ack['duplicates'] == 1
        source = read(client, 'sources').json()['items'][0]
        assert source['status'] == 'degraded' and source['rejected_total'] == 1
