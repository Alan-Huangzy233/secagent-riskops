"""Authenticated console integration over temporary derived observations only."""
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import secrets
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from app.live_api import create_app
from app.telemetry.config import LiveConfig, hash_operator_password
from app.telemetry.joint_case_contract import AnchorRequest, CaseScope
from app.telemetry.joint_case_store import JointCaseStore
from app.telemetry.joint_reconcile import reconcile_step
from test_joint_reader import sources as sources, store_digest, read
from test_network_detection import profile, REMOTE

PASSWORD: str = secrets.token_urlsafe(24)


@pytest.fixture(scope='module')
def password_hash():
    return hash_operator_password(PASSWORD)


@pytest.fixture
def setup(sources, tmp_path, password_hash, monkeypatch):
    net, ssh, mapping, anchor, _ = sources
    result = read(sources)
    scope = CaseScope((mapping,), result.projection.to_dict()['anchor']['producer_id'])
    derived = JointCaseStore.create(tmp_path/'derived'/'cases.sqlite', scope)
    derived.register((AnchorRequest(anchor['incident_id'], anchor['revision']),))
    derived.begin_cycle()
    reconcile_step(derived, net.path, ssh.path)
    config = LiveConfig(database_path=str(ssh.path), notifications_enabled=False,
        sources=[{'id': 'auth-a', 'hostname': 'ssh.example.invalid', 'token_sha256': 'a'*64}],
        operator_username='operator', operator_password_pbkdf2=password_hash,
        network_ingest={'database_path': str(net.path), 'sources': [
            {'id': profile().source_id, 'hostname': 'net.example.invalid',
             'token_sha256': hashlib.sha256(b'synthetic-network-source').hexdigest(),
             'profiles': [asdict(profile())]}]},
        joint_cases={'database_path': str(derived.path), 'scope': json.loads(scope.to_json())})
    # Source workers are independently tested. Freeze authored source data here
    # so GET effects can be measured without unrelated concurrent retention.
    monkeypatch.setattr('app.telemetry.network_worker.NetworkWorker.start', lambda self: None)
    monkeypatch.setattr('app.telemetry.network_worker.NetworkWorker.close', lambda self: None)
    return config, derived, sources, result.projection.case_id


def app(config):
    return create_app(config, control=SimpleNamespace(block_listener=None), ai=SimpleNamespace())


def get(client, path, **params):
    return client.get('/api/joint/'+path, params=params, auth=('operator', PASSWORD))


def test_disabled_does_not_create_joint_store_or_call_query(setup, monkeypatch):
    config, derived, _, _ = setup
    config = config.model_copy(update={'joint_cases': None})
    before = store_digest(derived.path)
    monkeypatch.setattr('app.telemetry.joint_api.open_query',
                        lambda *a, **kw: pytest.fail('disabled route opened a derived database'))
    with TestClient(app(config)) as client:
        assert get(client, 'status').json() == {'enabled': False}
        assert get(client, 'cases').status_code == 404
        assert get(client, 'cases/JNT-'+'a'*32, revision=1).status_code == 404
    assert store_digest(derived.path) == before


def test_every_route_requires_operator_and_exposes_no_mutation(setup):
    config, _, _, case_id = setup
    with TestClient(app(config)) as client:
        for path in ('status', 'cases', 'cases/'+case_id, 'cases/'+case_id+'/timeline'):
            endpoint = '/api/joint/'+path
            assert client.get(endpoint, params={'revision': 1}).status_code == 401
            assert client.get(endpoint, params={'revision': 1},
                headers={'Authorization': 'Bearer source-token-not-an-operator'}).status_code == 401
            assert client.post(endpoint, json={}, auth=('operator', PASSWORD)).status_code == 405


def test_gets_only_read_derived_store_and_keep_sources_and_history(setup, monkeypatch):
    config, derived, sources, case_id = setup
    with TestClient(app(config)) as client:
        paths = (derived.path, sources[0].path, sources[1].path)
        before = [store_digest(path) for path in paths]
        def forbidden(*a, **kw):
            pytest.fail('GET tried to refresh sources, initialize storage or run a process')
        monkeypatch.setattr('app.telemetry.joint_reader.read_joint_evidence', forbidden)
        monkeypatch.setattr('app.telemetry.joint_reconcile.read_joint_evidence', forbidden)
        monkeypatch.setattr(JointCaseStore, 'open', forbidden)
        monkeypatch.setattr(JointCaseStore, 'create', forbidden)
        monkeypatch.setattr('subprocess.run', forbidden)
        assert get(client, 'status').json()['enabled'] is True
        listing = get(client, 'cases', ip=REMOTE)
        assert listing.status_code == 200, listing.text
        body = listing.json()
        assert body['total'] == len(body['items']) == 1
        row = body['items'][0]
        assert row['case_id'] == case_id and row['revision'] == 1
        assert row['peer_ip'] == REMOTE
        detail = get(client, 'cases/'+case_id, revision=row['revision'])
        assert detail.status_code == 200, detail.text
        assert detail.json()['projection']['state'] == 'linked'
        timeline = get(client, 'cases/'+case_id+'/timeline', revision=1, limit=2)
        assert timeline.status_code == 200, timeline.text
        assert len(timeline.json()['items']) == 2
        assert get(client, 'cases', ip='203.0.113.254').json()['total'] == 0
        assert get(client, 'cases', ip=REMOTE, snapshot=body['snapshot']).json()['items'] == body['items']
        assert [store_digest(path) for path in paths] == before
        assert str(Path(derived.path).parent) not in listing.text+detail.text+timeline.text


@pytest.mark.parametrize('params', [
    {'limit': 51}, {'page': 0}, {'ip': 'not-an-ip'}, {'ip': '198.51.100.0/24'},
    {'start': 'yesterday'}, {'start': '2026-10-27T00:00:00'},
    {'start': '2026-10-28T00:00:00Z', 'end': '2026-10-27T00:00:00Z'},
    {'state': 'safe'}, {'asset_id': 'a'*129},
])
def test_invalid_filters_fail_without_success_shaped_empty_results(setup, params):
    with TestClient(app(setup[0])) as client:
        assert get(client, 'cases', **params).status_code == 422


def test_snapshot_is_filter_bound_and_revision_is_required(setup):
    config, _, _, case_id = setup
    with TestClient(app(config)) as client:
        snapshot = get(client, 'cases').json()['snapshot']
        assert get(client, 'cases', snapshot=snapshot, ip=REMOTE).status_code == 409
        assert get(client, 'cases/'+case_id).status_code == 422
        assert get(client, 'cases/'+case_id+'/timeline').status_code == 422
        assert get(client, 'cases/'+case_id, revision=999).status_code == 404
        assert get(client, 'cases/'+case_id+'/timeline', revision=999).status_code == 404


def test_missing_derived_store_does_not_initialize_and_does_not_break_health(setup, tmp_path):
    config, _, _, _ = setup
    missing = tmp_path/'missing-parent'/'private-joint.sqlite'
    joint = config.joint_cases.model_copy(update={'database_path': str(missing)})
    config = config.model_copy(update={'joint_cases': joint})
    with TestClient(app(config)) as client:
        response = get(client, 'status')
        assert response.status_code == 503
        assert response.json() == {'detail': 'joint_store_unavailable'}
        assert client.get('/health').json() == {'status': 'ok'}
    assert not missing.parent.exists()


@pytest.mark.parametrize('checkpoint', ['absent', 'malformed', 'mismatched', 'public', 'symlink'])
def test_refresh_metadata_failure_does_not_hide_saved_cases_or_write_files(setup, checkpoint, monkeypatch):
    from app.telemetry.joint_case_query import open_query
    from app.telemetry.joint_config import JointRefreshConfig, compile_joint_config
    from app.telemetry.joint_refresh_state import new_state, reserved_paths, save_state
    config, derived, sources, case_id = setup
    config = config.model_copy(update={'joint_cases': config.joint_cases.model_copy(update={
        'refresh': JointRefreshConfig(enabled=True)})})
    spec = compile_joint_config(config)
    _, metadata = reserved_paths(spec)
    if checkpoint == 'malformed':
        metadata.write_text('{broken')
        metadata.chmod(0o600)
    elif checkpoint in ('mismatched', 'public'):
        value = new_state(spec, open_query(spec.database_path, spec.scope, spec.limits).status())
        if checkpoint == 'mismatched':
            value['binding']['query_epoch'] = '0'*32
        save_state(spec, value)
        if checkpoint == 'public':
            metadata.chmod(0o644)
    elif checkpoint == 'symlink':
        metadata.symlink_to(sources[0].path)
    with TestClient(app(config)) as client:
        paths = (derived.path, sources[0].path, sources[1].path)
        before = [store_digest(path) for path in paths]
        entries = set(Path(derived.path).parent.iterdir())
        content = metadata.read_bytes() if metadata.exists() else None
        def forbidden(*a, **kw):
            pytest.fail('status read tried to start or mutate an update')
        monkeypatch.setattr('app.telemetry.joint_refresh.tick', forbidden)
        monkeypatch.setattr('app.telemetry.joint_refresh_state.save_state', forbidden)
        monkeypatch.setattr('app.telemetry.joint_refresh_state.writer_lock', forbidden)
        response = get(client, 'status')
        assert response.status_code == 200, response.text
        refresh = response.json()['refresh']
        assert refresh['enabled'] and refresh['stale']
        assert refresh['last_success_at'] is None
        assert refresh['state'] == ('not_started' if checkpoint == 'absent' else 'unavailable')
        assert get(client, 'cases').json()['total'] == 1
        assert get(client, 'cases/'+case_id, revision=1).status_code == 200
        assert [store_digest(path) for path in paths] == before
        assert set(Path(derived.path).parent.iterdir()) == entries
        assert (metadata.read_bytes() if metadata.exists() else None) == content
        assert str(Path(derived.path).parent) not in response.text


def test_status_reads_worker_checkpoint_without_refreshing_again(setup, monkeypatch):
    from app.telemetry.joint_cli import run
    from app.telemetry.joint_config import JointRefreshConfig, compile_joint_config
    from app.telemetry.joint_refresh_state import reserved_paths
    config, derived, _, _ = setup
    config = config.model_copy(update={'joint_cases': config.joint_cases.model_copy(update={
        'refresh': JointRefreshConfig(enabled=True)})})
    assert run(config, 'tick')['last_success_at'] is None
    finished = run(config, 'tick')
    assert finished['last_success_at'] is not None and not finished['stale']
    _, metadata = reserved_paths(compile_joint_config(config))
    content = metadata.read_bytes()
    before = store_digest(derived.path)
    with TestClient(app(config)) as client:
        monkeypatch.setattr('app.telemetry.joint_refresh.tick',
                            lambda *a, **kw: pytest.fail('GET started another worker'))
        for _ in range(2):
            response = get(client, 'status')
            assert response.json()['refresh']['last_success_at'] == finished['last_success_at']
            assert response.json()['refresh']['state'] == 'waiting'
        assert metadata.read_bytes() == content and store_digest(derived.path) == before
