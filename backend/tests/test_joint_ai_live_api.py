"""Authenticated manual API mode; every transport and credential is synthetic."""
import json
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from app.live_api import create_app
from app.telemetry import joint_ai_service as service_module
from app.telemetry.config import LiveConfig
from app.telemetry.joint_ai_service import Service
from test_joint_ai_live_service import (
    world as world, saved as saved, scheduled as scheduled, configured as configured,
    sources as sources, store_clock as store_clock, no_network as no_network,
    reopen, rows,
)
from test_joint_api import PASSWORD, password_hash as password_hash


AUTH = ("operator", PASSWORD)
TOKEN = "synthetic-joint-manual-api-csrf"
HEADERS = {"x-riskops-csrf": TOKEN, "origin": "http://testserver"}


@pytest.fixture
def workflow(world, configured, password_hash, monkeypatch):
    w = world
    source, _ = configured
    config = LiveConfig(database_path=source.database_path, notifications_enabled=False,
        sources=[{"id": "auth-a", "hostname": "ssh.example.invalid", "token_sha256": "b" * 64}],
        operator_username="operator", operator_password_pbkdf2=password_hash,
        network_ingest={"database_path": source.network_ingest.database_path,
                        "sources": [item.model_dump() for item in source.network_ingest.sources]},
        joint_cases={**source.joint_cases.model_dump(), "refresh": w.spec.refresh.model_dump()})
    monkeypatch.setattr(Service, "start", lambda self: None)
    monkeypatch.setattr(type(w.ssh), "start", lambda self: None)
    monkeypatch.setattr("app.telemetry.network_worker.NetworkWorker.start", lambda self: None)
    monkeypatch.setattr("app.telemetry.network_worker.NetworkWorker.close", lambda self: None)
    w.app = create_app(config, control=SimpleNamespace(block_listener=None, csrf_token=TOKEN),
                       ai=w.ssh, joint_ai=w.service)
    return w


def preview(client, w):
    response = client.get(f"/api/joint/cases/{w.case_id}/ai/preview", params={"revision": 1}, auth=AUTH)
    assert response.status_code == 200, response.text
    return response.json()


def submit(client, w, key, **kwargs):
    return client.post(f"/api/joint/cases/{w.case_id}/ai", auth=AUTH, headers=HEADERS,
                       json={"revision": 1, "preview_key": key, **kwargs})


def test_get_never_calls_model_and_authenticated_manual_post_exposes_only_checked_result(workflow, monkeypatch):
    w = workflow
    reads = []
    actual = service_module.read_key
    monkeypatch.setattr(service_module, "read_key", lambda *args: reads.append(args) or actual(*args))
    with TestClient(w.app) as client:
        status = client.get("/api/joint/ai/status", auth=AUTH)
        assert status.status_code == 200 and status.headers["cache-control"] == "no-store"
        assert status.json()["external_calls"] is True
        assert status.json()["model"] == "synthetic-model"
        assert status.json()["budget"] == w.ssh.jobs.budget()
        first = preview(client, w)
        assert first["execution"]["execution_binding"] == status.json()["execution_binding"]
        history = client.get(f"/api/joint/cases/{w.case_id}/ai/history", auth=AUTH)
        assert history.status_code == 200 and history.json()["items"] == []
        assert reads == [] and w.requests == []
        response = submit(client, w, first["preview_key"])
        assert response.status_code in (200, 202), response.text
        job = response.json()
        assert job["execution_mode"] == "api" and job["state"] == "queued"
        assert reads == [] and w.requests == []
        again = submit(client, w, first["preview_key"])
        assert again.json()["id"] == job["id"]
        assert w.service.run_once()
        response = client.get("/api/joint/ai/jobs/" + job["id"], auth=AUTH)
        assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
        result = response.json()
        assert result["state"] == "complete" and result["result"]["metadata"]["execution_mode"] == "api"
        assert result["result"]["usd"] == 0.00016
        assert not {"lease_token", "lease_until", "run_id", "call_id"} & result.keys()
        serialized = json.dumps(result)
        for private in ("response_json", "synthetic-not-a-real-key", "https://model.example.invalid",
                        str(w.ssh.jobs.path), str(w.ssh.settings.keys_file), str(w.settings.database_path)):
            assert private not in serialized
        saved_history = client.get(f"/api/joint/cases/{w.case_id}/ai/history", auth=AUTH).json()["items"]
        assert len(saved_history) == 1 and saved_history[0]["execution_mode"] == "api"
        assert set(saved_history[0]["result"]) == {"verdict", "confidence"}
        assert len(reads) == len(w.requests) == 1
        assert rows(w.service.jobs, "ai_calls") == [] and len(rows(w.ssh.jobs, "ai_calls")) == 1


def test_api_mode_preserves_operator_csrf_origin_and_exact_server_dossier_boundary(workflow, monkeypatch):
    w = workflow
    monkeypatch.setattr(service_module, "read_key", lambda *args: pytest.fail("rejected request read key"))
    with TestClient(w.app) as client:
        path = f"/api/joint/cases/{w.case_id}/ai"
        key = preview(client, w)["preview_key"]
        body = {"revision": 1, "preview_key": key}
        assert client.get("/api/joint/ai/status").status_code == 401
        assert client.get(path + "/history").status_code == 401
        assert client.post(path, json=body, headers=HEADERS).status_code == 401
        assert client.post(path, json=body, auth=AUTH).status_code == 403
        assert client.post(path, json=body, auth=AUTH,
            headers={**HEADERS, "origin": "https://other.example.invalid"}).status_code == 403
        assert client.post(path, json=body, auth=AUTH,
            headers={**HEADERS, "x-riskops-csrf": "synthetic-wrong"}).status_code == 403
        for field, value in (("case", {}), ("model", "other"), ("allow_external", True),
                             ("actor", "other"), ("approved_summary_version", "joint-summary-v1")):
            assert submit(client, w, key, **{field: value}).status_code == 422
        changed = submit(client, w, "f" * 64)
        assert changed.status_code == 409 and changed.json()["detail"] == "joint_ai_request_changed"
        assert w.requests == [] and rows(w.service.jobs, "ai_jobs") == []


def test_paused_api_read_history_and_preview_remain_available_but_post_is_fixed_conflict(workflow, monkeypatch):
    w = workflow
    with TestClient(w.app) as client:
        first = preview(client, w)
        job = submit(client, w, first["preview_key"]).json()
        paused = reopen(w, allow_external=False)
        client.app.state.joint_ai = paused
        monkeypatch.setattr(service_module, "read_key", lambda *args: pytest.fail("paused route key read"))
        status = client.get("/api/joint/ai/status", auth=AUTH).json()
        assert status["enabled"] and status["paused"] and not status["external_calls"]
        assert status["pause_reason"] == "joint_ai_external_calls_paused"
        current = preview(client, w)
        rejected = submit(client, w, current["preview_key"])
        assert rejected.status_code == 409 and rejected.json()["detail"] == "joint_ai_paused"
        history = client.get(f"/api/joint/cases/{w.case_id}/ai/history", auth=AUTH).json()
        assert history["items"][0]["id"] == job["id"]
        assert client.get("/api/joint/ai/jobs/" + job["id"], auth=AUTH).status_code == 200
        assert not paused.run_once() and paused.job(job["id"])["attempt_count"] == 0
        assert w.requests == []


def test_unknown_api_result_is_sanitized_and_history_get_does_not_retry(workflow):
    import httpx
    w = workflow
    w.response = httpx.Response(403, text="synthetic-private-provider-detail")
    with TestClient(w.app) as client:
        job = submit(client, w, preview(client, w)["preview_key"]).json()
        assert w.service.run_once()
        result = client.get("/api/joint/ai/jobs/" + job["id"], auth=AUTH)
        assert result.json()["state"] == "uncertain"
        assert result.json()["error_code"] == "provider_outcome_unknown"
        assert "synthetic-private-provider-detail" not in result.text
        for _ in range(2):
            assert client.get(f"/api/joint/cases/{w.case_id}/ai/history", auth=AUTH).status_code == 200
            assert not w.service.run_once()
        assert len(w.requests) == 1
        assert w.ssh.jobs.budget()["unresolved_calls"] == 1
