"""Opt-in local joint jobs over disposable evidence; no model or source writes."""

import json
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from app.live_api import create_app
from app.telemetry.ai_summary import Aliases
from app.telemetry.joint_ai_service import Service, Settings
from app.telemetry.joint_config import compile_joint_config
from test_joint_api import (
    PASSWORD,
    password_hash as password_hash,
    setup as setup,
    sources as sources,
)
from test_joint_reader import store_digest

AUTH = ("operator", PASSWORD)
TOKEN = "synthetic-local-csrf"
HEADERS = {"x-riskops-csrf": TOKEN, "origin": "http://testserver"}


@pytest.fixture
def workflow(setup, tmp_path, monkeypatch):
    monkeypatch.delenv("RISKOPS_JOINT_AI_CONFIG", raising=False)
    config, derived, stores, case_id = setup
    aliases = Aliases(b"synthetic-joint-workflow-api-key!")
    service = Service(
        compile_joint_config(config),
        Settings(database_path=tmp_path / "joint-jobs.sqlite"),
        aliases=aliases,
    )
    app = create_app(
        config,
        control=SimpleNamespace(block_listener=None, csrf_token=TOKEN),
        ai=SimpleNamespace(aliases=aliases),
        joint_ai=service,
    )
    return SimpleNamespace(
        config=config,
        derived=derived,
        stores=stores,
        case_id=case_id,
        service=service,
        app=app,
    )


def preview(client, world):
    response = client.get(
        f"/api/joint/cases/{world.case_id}/ai/preview",
        params={"revision": 1},
        auth=AUTH,
    )
    assert response.status_code == 200, response.text
    return response.json()


def submit(client, world, key):
    return client.post(
        f"/api/joint/cases/{world.case_id}/ai",
        json={"revision": 1, "preview_key": key},
        auth=AUTH,
        headers=HEADERS,
    )


def test_manual_local_workflow_persists_history_without_modifying_evidence(
    workflow, monkeypatch
):
    w = workflow

    def forbidden(*args, **kwargs):
        pytest.fail("local joint workflow attempted a model or source refresh")

    monkeypatch.setattr("app.agents.triage_api.APITriage.__init__", forbidden)
    monkeypatch.setattr("app.agents.triage_api.read_key", forbidden)
    monkeypatch.setattr("app.telemetry.joint_refresh.tick", forbidden)
    with TestClient(w.app) as client:
        paths = [w.derived.path, w.stores[0].path, w.stores[1].path]
        before = [store_digest(path) for path in paths]
        status = client.get("/api/joint/ai/status", auth=AUTH).json()
        assert status["enabled"] is True and status["mode"] == "offline"
        assert status["external_calls"] is False and status["csrf_token"] == TOKEN
        first = preview(client, w)
        assert first["execution"]["mode"] == "offline"
        assert first["case"]["dossier_version"] == "joint-v1"
        assert len(first["preview_key"]) == 64
        assert w.service.history(w.case_id) == []
        job = submit(client, w, first["preview_key"])
        assert job.status_code == 202, job.text
        job = job.json()
        assert (
            job["state"] == "queued"
            and job["case_id"] == w.case_id
            and job["case_revision"] == 1
        )
        assert submit(client, w, first["preview_key"]).json()["id"] == job["id"]
        assert w.service.run_once() is True
        result = client.get("/api/joint/ai/jobs/" + job["id"], auth=AUTH)
        assert (
            result.status_code == 200 and result.headers["cache-control"] == "no-store"
        )
        saved = result.json()
        assert saved["state"] == "review" and saved["result"]["verdict"] == "abstain"
        assert (
            saved["result"]["usd"] == 0
            and saved["result"]["metadata"]["offline"] is True
        )
        assert (
            saved["result"]["metadata"]["evidence_validation"]["revision"]
            == first["case"]["revision"]
        )
        assert saved["local"]["local_refs"] == first["local_refs"]
        assert not {"lease_token", "lease_until", "run_id", "call_id"} & saved.keys()
        history = client.get(
            f"/api/joint/cases/{w.case_id}/ai/history", auth=AUTH
        ).json()
        assert history["case_id"] == w.case_id and len(history["items"]) == 1
        row = history["items"][0]
        assert row["id"] == job["id"] and row["state"] == "review"
        assert not {"case", "local", "audit"} & row.keys()
        assert set(row["result"]) == {"verdict", "confidence"}
        assert [store_digest(path) for path in paths] == before
        assert w.service.jobs.budget()["charged_usd"] == 0
        assert w.service.jobs.budget()["reserved_usd"] == 0
    # A new service instance retains the same jobs; opening a page never submits.
    restored = Service(
        compile_joint_config(w.config), w.service.settings, aliases=w.service.aliases
    )
    assert restored.history(w.case_id)[0]["id"] == job["id"]
    assert restored.job(job["id"])["result"]["verdict"] == "abstain"


def test_workflow_auth_csrf_and_client_dossier_rejection(workflow):
    w = workflow
    with TestClient(w.app) as client:
        path = f"/api/joint/cases/{w.case_id}/ai"
        for route in (
            "/api/joint/ai/status",
            path + "/history",
            "/api/joint/ai/jobs/" + "a" * 32,
        ):
            assert client.get(route).status_code == 401
            assert (
                client.get(
                    route, headers={"Authorization": "Bearer synthetic-source"}
                ).status_code
                == 401
            )
        key = preview(client, w)["preview_key"]
        body = {"revision": 1, "preview_key": key}
        assert client.post(path, json=body, headers=HEADERS).status_code == 401
        assert client.post(path, json=body, auth=AUTH).status_code == 403
        assert (
            client.post(
                path,
                json=body,
                auth=AUTH,
                headers={**HEADERS, "origin": "https://other.example.invalid"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                path,
                json=body,
                auth=AUTH,
                headers={**HEADERS, "sec-fetch-site": "cross-site"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                path,
                content=json.dumps(body),
                auth=AUTH,
                headers={**HEADERS, "content-type": "text/plain"},
            ).status_code
            == 415
        )
        for change in (
            {"revision": True},
            {"revision": 0},
            {"revision": "1"},
            {"case": {}},
            {"preview_key": "invalid"},
        ):
            assert (
                client.post(
                    path, json={**body, **change}, auth=AUTH, headers=HEADERS
                ).status_code
                == 422
            )
        changed = submit(client, w, "0" * 64)
        assert changed.status_code == 409 and changed.json() == {
            "detail": "joint_ai_request_changed"
        }
        assert w.service.history(w.case_id) == []
        assert (
            client.get("/api/joint/ai/jobs/" + "a" * 32, auth=AUTH).status_code == 404
        )
        assert client.get("/api/joint/ai/jobs/invalid", auth=AUTH).status_code == 422
        assert (
            client.get("/api/joint/cases/invalid/ai/history", auth=AUTH).status_code
            == 422
        )


@pytest.mark.parametrize(
    "error,expected,status",
    [
        (ValueError("sensitive rejected material"), "joint_ai_request_changed", 409),
        (KeyError("sensitive database identity"), "joint_ai_record_not_found", 404),
        (OSError("sensitive local path"), "joint_ai_unavailable", 503),
    ],
)
def test_failures_expose_fixed_codes_only(
    workflow, monkeypatch, error, expected, status
):
    w = workflow

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(w.service, "enqueue", fail)
    with TestClient(w.app) as client:
        response = submit(client, w, "a" * 64)
        assert response.status_code == status and response.json() == {
            "detail": expected
        }


def test_default_off_leaves_existing_local_preview_and_creates_no_queue(
    setup, monkeypatch
):
    monkeypatch.delenv("RISKOPS_JOINT_AI_CONFIG", raising=False)
    config, _, _, case_id = setup

    def forbidden(*args, **kwargs):
        pytest.fail("disabled joint workflow constructed a queue")

    monkeypatch.setattr("app.telemetry.joint_ai_service.Jobs", forbidden)
    app = create_app(
        config,
        control=SimpleNamespace(block_listener=None, csrf_token=TOKEN),
        ai=SimpleNamespace(aliases=Aliases(b"synthetic-joint-disabled-alias!!")),
    )
    with TestClient(app) as client:
        status = client.get("/api/joint/ai/status", auth=AUTH).json()
        assert status["enabled"] is False and status["external_calls"] is False
        p = client.get(
            f"/api/joint/cases/{case_id}/ai/preview", params={"revision": 1}, auth=AUTH
        )
        assert p.status_code == 200 and "preview_key" not in p.json()
        assert client.post(
            f"/api/joint/cases/{case_id}/ai",
            json={"revision": 1, "preview_key": "a" * 64},
            auth=AUTH,
            headers=HEADERS,
        ).json() == {"detail": "joint_ai_disabled"}


def test_invalid_optional_configuration_keeps_collection_and_preview_available(
    setup, tmp_path, monkeypatch
):
    config, _, _, case_id = setup
    p = tmp_path / "invalid-optional.json"
    p.write_text("{invalid")
    p.chmod(0o600)
    monkeypatch.setenv("RISKOPS_JOINT_AI_CONFIG", str(p))
    app = create_app(
        config,
        control=SimpleNamespace(block_listener=None, csrf_token=TOKEN),
        ai=SimpleNamespace(aliases=Aliases(b"synthetic-joint-invalid-alias!!!")),
    )
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        s = client.get("/api/joint/ai/status", auth=AUTH).json()
        assert s["enabled"] is False and s["error"] is not None
        assert (
            client.get(
                f"/api/joint/cases/{case_id}/ai/preview",
                params={"revision": 1},
                auth=AUTH,
            ).status_code
            == 200
        )


def test_optional_worker_start_failure_does_not_break_existing_preview(
    setup, monkeypatch
):
    config, _, _, case_id = setup
    closed = []

    def fail():
        raise RuntimeError("private thread startup details")

    failed_worker = SimpleNamespace(start=fail, close=lambda: closed.append(True))
    monkeypatch.setenv("RISKOPS_JOINT_AI_CONFIG", "/synthetic-config-not-opened.json")
    monkeypatch.setattr(
        Service, "from_environment", lambda *args, **kwargs: failed_worker
    )
    app = create_app(
        config,
        control=SimpleNamespace(block_listener=None, csrf_token=TOKEN),
        ai=SimpleNamespace(aliases=Aliases(b"synthetic-joint-startup-alias-key")),
    )
    with TestClient(app) as client:
        assert closed == [True]
        assert client.get("/health").status_code == 200
        status = client.get("/api/joint/ai/status", auth=AUTH).json()
        assert (
            status["enabled"] is False
            and status["error"] == "joint_ai_worker_unavailable"
        )
        response = client.get(
            f"/api/joint/cases/{case_id}/ai/preview", params={"revision": 1}, auth=AUTH
        )
        assert response.status_code == 200 and "preview_key" not in response.json()


def test_loader_passes_private_component_paths_before_queue_initialization(
    setup, monkeypatch, tmp_path
):
    from app.live_api import _joint_ai_service

    config = setup[0]
    captured = {}
    private = {
        name: tmp_path / name
        for name in (
            "database_path",
            "context_file",
            "profile_path",
            "recording_path",
            "keys_file",
        )
    }
    ai = SimpleNamespace(
        aliases=Aliases(b"synthetic-joint-loader-alias-key!"),
        settings=SimpleNamespace(**private),
        jobs=SimpleNamespace(path=tmp_path / "other-ai.sqlite"),
    )
    control = SimpleNamespace(
        path=tmp_path / "control.sqlite",
        transport=SimpleNamespace(config_path=tmp_path / "ssh-config"),
    )
    for name in (
        "RISKOPS_JOINT_AI_CONFIG",
        "RISKOPS_CONFIG",
        "RISKOPS_AI_CONFIG",
        "RISKOPS_CONTROL_CONFIG",
    ):
        monkeypatch.setenv(name, str(tmp_path / name))

    def capture(spec, **kwargs):
        captured.update(kwargs)
        return Service(None)

    monkeypatch.setattr(Service, "from_environment", capture)
    assert _joint_ai_service(config, ai, control).enabled is False
    excluded = {str(p) for p in captured["excluded_paths"]}
    assert all(str(p) in excluded for p in private.values())
    assert all(
        str(tmp_path / name) in excluded
        for name in (
            "other-ai.sqlite",
            "control.sqlite",
            "ssh-config",
            "RISKOPS_CONFIG",
            "RISKOPS_AI_CONFIG",
            "RISKOPS_CONTROL_CONFIG",
        )
    )
    assert captured["aliases"] is ai.aliases
