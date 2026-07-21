from __future__ import annotations

from fastapi.testclient import TestClient

from app.api.app import app


def test_run_flow_and_inspect():
    client = TestClient(app)

    assert client.get("/health").json() == {"status": "ok"}

    run = client.post("/flows/run").json()
    assert run["alerts"] == 4
    assert run["groups"] == 2
    assert len(run["incidents"]) == 1
    assert run["action_plans"][0]["status"] == "proposed"
    assert run["action_plans"][0]["decision"] == "APPROVAL_REQUIRED"

    incident_id = run["incidents"][0]
    assert client.get(f"/incidents/{incident_id}").status_code == 200
    assert client.get("/incidents/INC-9999").status_code == 404

    assert client.get("/audit/verify").json() == {"chain_intact": True}
