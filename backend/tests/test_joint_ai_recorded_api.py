"""Authenticated recording playback over authored, disposable joint evidence."""

import json
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from app.live_api import create_app
from app.telemetry.joint_ai_recorded import make_tape
from app.telemetry.joint_ai_service import Service, Settings
from test_joint_ai_service import fake_result
from test_joint_ai_workflow_api import (
    AUTH, HEADERS, TOKEN, preview, submit,
    workflow as workflow, setup as setup, sources as sources,
    password_hash as password_hash,
)
from test_joint_reader import store_digest


def recorded_world(world, tmp_path, *, outcome="response", response=None):
    case = world.service.preview(world.case_id, 1)["case"]
    tape = make_tape([{
        "case": case,
        "outcome": outcome,
        "response_text": (response if response is not None else fake_result(case))
        if outcome == "response" else None,
    }])
    path = tmp_path / "synthetic-responses.json"
    path.write_text(json.dumps(tape))
    path.chmod(0o600)
    service = Service(
        world.service.spec,
        Settings(mode="recorded", database_path=world.service.settings.database_path,
                 recording_path=path),
        aliases=world.service.aliases,
    )
    app = create_app(
        world.config,
        control=SimpleNamespace(block_listener=None, csrf_token=TOKEN),
        ai=SimpleNamespace(aliases=service.aliases), joint_ai=service,
    )
    return SimpleNamespace(**{**vars(world), "service": service, "app": app}), path


def test_recorded_api_preserves_sources_and_history_without_credentials_or_calls(
    workflow, tmp_path, monkeypatch
):
    def forbidden(*args, **kwargs):
        pytest.fail("recording playback attempted external work")

    monkeypatch.setattr("app.agents.triage_api.APITriage.__init__", forbidden)
    monkeypatch.setattr("app.agents.triage_api.read_key", forbidden)
    monkeypatch.setattr("app.telemetry.joint_refresh.tick", forbidden)
    # Preserve an older offline job when the execution mode changes.
    p = workflow.service.preview(workflow.case_id, 1)
    old = workflow.service.enqueue(workflow.case_id, 1, p["preview_key"], "operator")
    workflow.service.run_once()
    w, recording = recorded_world(workflow, tmp_path)
    with TestClient(w.app) as client:
        paths = [w.derived.path, w.stores[0].path, w.stores[1].path]
        before = [store_digest(path) for path in paths]
        status = client.get("/api/joint/ai/status", auth=AUTH).json()
        assert status["mode"] == "recorded" and status["external_calls"] is False
        assert status["csrf_token"] == TOKEN
        assert str(recording) not in json.dumps(status)
        bundle = preview(client, w)
        assert bundle["execution"]["mode"] == "recorded"
        assert submit(client, w, p["preview_key"]).status_code == 409
        queued = submit(client, w, bundle["preview_key"])
        assert queued.status_code == 202
        identity = queued.json()["id"]
        assert identity != old["id"]
        assert submit(client, w, bundle["preview_key"]).json()["id"] == identity
        assert w.service.run_once()
        response = client.get("/api/joint/ai/jobs/" + identity, auth=AUTH)
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        job = response.json()
        assert job["execution_mode"] == job["local"]["meta"]["execution_mode"] == "recorded"
        result = job["result"]
        assert result["metadata"]["execution_mode"] == "recorded"
        assert result["metadata"]["recording_sha256"] == job["local"]["meta"]["recording_sha256"]
        assert result["metadata"]["recorded_generation_cost"] == "unknown"
        assert result["metadata"]["provenance_verified"] is False
        assert result["metadata"]["evidence_validation"]["free_text_requires_review"]
        assert result["usd"] == 0
        assert str(recording) not in response.text
        history = client.get(f"/api/joint/cases/{w.case_id}/ai/history", auth=AUTH).json()["items"]
        assert {row["execution_mode"] for row in history} == {"recorded", "offline"}
        assert all(not {"case", "local", "recording_sha256"} & row.keys() for row in history)
        assert client.get("/api/joint/ai/jobs/" + old["id"], auth=AUTH).json()["execution_mode"] == "offline"
        assert [store_digest(path) for path in paths] == before
        with w.service.jobs.connection() as db:
            assert db.execute("SELECT count(*) FROM ai_calls").fetchone()[0] == 0
            assert db.execute("SELECT count(*) FROM ai_meta WHERE name IN ('total_limit','daily_limit')").fetchone()[0] == 0
    restored = Service(w.service.spec, w.service.settings, aliases=w.service.aliases)
    assert restored.job(identity)["result"] == result
    assert len(restored.history(w.case_id)) == 2


def test_recorded_api_keeps_auth_csrf_and_server_side_preview_binding(workflow, tmp_path):
    w, _ = recorded_world(workflow, tmp_path)
    with TestClient(w.app) as client:
        base = f"/api/joint/cases/{w.case_id}/ai"
        key = preview(client, w)["preview_key"]
        for path in ("/api/joint/ai/status", base + "/history", base + "/preview?revision=1"):
            assert client.get(path).status_code == 401
        body = {"revision": 1, "preview_key": key}
        assert client.post(base, json=body, headers=HEADERS).status_code == 401
        assert client.post(base, json=body, auth=AUTH).status_code == 403
        assert client.post(base, json=body, auth=AUTH,
                           headers={**HEADERS, "origin": "https://other.example.invalid"}).status_code == 403
        for extra in ({"mode": "api"}, {"recording_path": "/synthetic/other.json"},
                      {"response_text": "forged"}, {"case": {}}, {"recording_sha256": "a" * 64}):
            assert client.post(base, json={**body, **extra}, headers=HEADERS, auth=AUTH).status_code == 422
        assert w.service.history(w.case_id) == []


def test_recorded_unavailability_has_no_fake_result_or_internal_details(workflow, tmp_path):
    w, recording = recorded_world(workflow, tmp_path, outcome="unavailable")
    with TestClient(w.app) as client:
        identity = submit(client, w, preview(client, w)["preview_key"]).json()["id"]
        for _ in range(w.service.settings.max_attempts):
            assert w.service.run_once()
        assert not w.service.run_once()
        response = client.get("/api/joint/ai/jobs/" + identity, auth=AUTH)
        assert response.json()["state"] == "failed"
        assert response.json()["result"] is None
        assert response.json()["error_code"] == "joint_ai_recording_unavailable"
        assert str(recording) not in response.text
        assert len(w.service.history(w.case_id)) == 1


def test_private_configuration_loads_recorded_mode_without_exposing_paths(workflow, tmp_path, monkeypatch):
    w, recording = recorded_world(workflow, tmp_path)
    config = tmp_path / "joint-config.json"
    config.write_text(w.service.settings.model_dump_json())
    config.chmod(0o600)
    monkeypatch.setenv("RISKOPS_JOINT_AI_CONFIG", str(config))
    loaded = Service.from_environment(w.service.spec, aliases=w.service.aliases)
    assert loaded.enabled and loaded.status()["mode"] == "recorded"
    assert loaded.config_sha == w.service.config_sha
    assert loaded.preview(w.case_id, 1)["preview_key"] == w.service.preview(w.case_id, 1)["preview_key"]
    assert str(recording) not in json.dumps(loaded.status())
    assert str(config) not in json.dumps(loaded.status())
    assert loaded.history(w.case_id) == []
