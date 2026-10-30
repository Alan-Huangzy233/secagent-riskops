"""Local-only authenticated preview integration over synthetic saved observations."""
import json
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from app.live_api import create_app
from app.telemetry.ai_summary import Aliases
from app.telemetry.joint_ai_preview import JointPreviewError
from app.telemetry.joint_ai_summary import JointSummaryError
from app.telemetry.joint_case_store import JointCaseStore
from test_joint_api import PASSWORD, get, password_hash as password_hash, setup as setup, sources as sources
from test_joint_reader import store_digest


def application(config, *, aliases=True):
    ai = SimpleNamespace(aliases=Aliases(b'synthetic-preview-alias-material!')) if aliases else SimpleNamespace()
    return create_app(config, control=SimpleNamespace(block_listener=None), ai=ai)


def test_preview_requires_operator_and_explicit_revision(setup):
    config, _, _, case_id = setup
    path = '/api/joint/cases/'+case_id+'/ai/preview'
    with TestClient(application(config)) as client:
        assert client.get(path, params={'revision': 1}).status_code == 401
        assert client.get(path, params={'revision': 1},
                          headers={'Authorization': 'Bearer synthetic-source'}).status_code == 401
        assert client.post(path, json={'revision': 1}, auth=('operator', PASSWORD)).status_code == 405
        for params in ({}, {'revision': 0}, {'revision': 2**31}):
            assert client.get(path, params=params, auth=('operator', PASSWORD)).status_code == 422
        assert get(client, 'cases/'+case_id+'/ai/preview', revision=999).status_code == 404
        assert get(client, 'cases/not-a-case/ai/preview', revision=1).status_code == 422


def test_preview_is_read_only_aliased_bounded_and_never_calls_model_or_queue(setup, monkeypatch):
    config, derived, source_stores, case_id = setup
    with TestClient(application(config)) as client:
        paths = (derived.path, source_stores[0].path, source_stores[1].path)
        before = [store_digest(path) for path in paths]
        entries = set(Path(derived.path).parent.iterdir())
        def forbidden(*a, **kw):
            pytest.fail('local preview attempted a write, source read, job or model call')
        monkeypatch.setattr('app.telemetry.joint_reader.read_joint_evidence', forbidden)
        monkeypatch.setattr('app.telemetry.joint_reconcile.read_joint_evidence', forbidden)
        monkeypatch.setattr('app.telemetry.joint_refresh.tick', forbidden)
        monkeypatch.setattr('app.telemetry.joint_refresh_state.save_state', forbidden)
        monkeypatch.setattr('app.telemetry.joint_refresh_state.writer_lock', forbidden)
        monkeypatch.setattr(JointCaseStore, 'open', forbidden)
        monkeypatch.setattr(JointCaseStore, 'create', forbidden)
        monkeypatch.setattr('app.telemetry.ai_triage.Service.preview', forbidden)
        monkeypatch.setattr('app.telemetry.ai_triage.Service.status', forbidden)
        monkeypatch.setattr('subprocess.run', forbidden)
        response = get(client, 'cases/'+case_id+'/ai/preview', revision=1)
        assert response.status_code == 200, response.text
        assert response.headers['cache-control'] == 'no-store'
        body = response.json()
        assert body['preview']['mode'] == 'local'
        assert body['preview']['external_calls'] is False
        assert body['dossier_version'] == 'joint-local-envelope-v1'
        assert body['case']['dossier_version'] == 'joint-v1'
        assert body['case']['review_state'] == 'unknown'  # scheduler not enabled
        assert body['meta']['case_id'] == case_id
        assert body['meta']['case_revision'] == body['meta']['current_revision'] == 1
        assert {row['kind'] for row in body['case']['evidence']} == {'network_tcp', 'ssh'}
        assert 0 < len(body['case']['evidence']) <= 40
        assert set(body['local_refs']) == {row['event_id'] for row in body['case']['evidence']}
        outbound = json.dumps(body['case'])
        assert case_id not in outbound
        for ref in body['local_refs'].values():
            assert ref['source_id'] not in outbound
            assert ref['event_id'] not in outbound
        assert all(str(path) not in response.text for path in paths)
        assert [store_digest(path) for path in paths] == before
        assert set(Path(derived.path).parent.iterdir()) == entries
        assert get(client, 'cases/'+case_id+'/ai/preview', revision=1).json()['case'] == body['case']


def test_alias_key_absent_does_not_initialize_service(setup, monkeypatch):
    def forbidden(*a, **kw):
        pytest.fail('unavailable alias configuration opened evidence')
    monkeypatch.setattr('app.telemetry.joint_api.preview', forbidden)
    with TestClient(application(setup[0], aliases=False)) as client:
        response = get(client, 'cases/'+setup[3]+'/ai/preview', revision=1)
        assert response.status_code == 503
        assert response.json() == {'detail': 'joint_ai_preview_unavailable'}


@pytest.mark.parametrize('error,code,status', [
    (JointPreviewError(), 'joint_preview_changed', 409),
    (JointSummaryError('joint_ai_capacity_exceeded'), 'joint_ai_capacity_exceeded', 422),
    (RuntimeError('synthetic-private-path-and-evidence'), 'joint_ai_preview_unavailable', 503),
])
def test_preview_failures_return_only_fixed_codes(setup, monkeypatch, error, code, status):
    def fail(*a, **kw):
        raise error
    monkeypatch.setattr('app.telemetry.joint_api.preview', fail)
    with TestClient(application(setup[0])) as client:
        response = get(client, 'cases/'+setup[3]+'/ai/preview', revision=1)
        assert response.status_code == status
        assert response.json() == {'detail': code}
