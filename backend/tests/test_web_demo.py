"""The web demo: its data matches the published results, and its buttons run the real gate and executor."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from app.agents import model_triage
from app.api.app import SNAPSHOT, app
from app.evaluation import synthetic
from app.webdemo import respond, snapshot

ROOT = Path(__file__).resolve().parents[2]
client = TestClient(app)
DATA = json.loads(SNAPSHOT.read_text(encoding="utf-8"))


def post(path: str, body: dict):
    return client.post(path, json=body)


def test_the_page_is_served_with_a_strict_policy():
    page = client.get("/demo")
    assert page.status_code == 200 and "text/html" in page.headers["content-type"]
    assert "script-src 'self'" in page.headers["content-security-policy"]
    assert "unsafe-inline" not in page.headers["content-security-policy"]
    assert client.get("/demo/static/demo.js").status_code == 200
    assert client.get("/demo/static/index.html").status_code == 404
    assert client.get("/", follow_redirects=False).headers["location"] == "/demo"


def test_the_snapshot_agrees_with_the_published_results():
    """The page's numbers are computed independently of results.json; both must agree."""
    results = json.loads((ROOT / "docs/eval/results-synthetic-7d.json").read_text())
    surfaced, head = results["systems"]["pipeline, surfaced"], DATA["headline"]
    half, b1 = surfaced["detection"]["tau_0.5"], results["systems"]["B1 tuple dedup"]
    assert head["alerts"] == results["alerts"]["count"] == surfaced["reduction"]["input_alerts"]
    assert head["surfaced"] == surfaced["reduction"]["output_incidents"] == len(DATA["incidents"]) == 50
    assert head["reduction_pct"] == surfaced["reduction"]["reduction_pct"]
    assert head["incidents"] == results["systems"]["pipeline, every incident"]["reduction"]["output_incidents"]
    for key in ("detected", "episodes", "miss_rate", "miss_rate_ci95", "precision", "no_alert_episodes"):
        assert head[key] == half[key], key
    assert head["b1_incidents"] == b1["reduction"]["output_incidents"]
    assert head["b1_miss_rate"] == b1["detection"]["tau_0.5"]["miss_rate"]
    for name, row in results["pipeline_by_scenario"].items():
        assert DATA["by_scenario"][name] == {key: row[key] for key in ("episodes", "raised_an_alert",
                                                                        "detected_tau_0.5")}
    assert len(DATA["missed"]) == head["episodes"] - head["detected"]
    columns = list(zip(*DATA["hours"]))
    assert [sum(column) for column in columns] == [head["log_lines"], head["alerts"], head["incidents"],
                                                   head["surfaced"]]
    assert len(SNAPSHOT.read_bytes()) < 1_000_000


def test_every_verdict_on_the_page_is_a_recorded_call():
    tape = {json.loads(line)["prompt_sha256"]: json.loads(line)
            for line in (ROOT / "docs/eval/triage-tape-synthetic-7d.jsonl").read_text().splitlines()}
    for incident in DATA["incidents"]:
        recorded = tape[incident["model"]["prompt_sha256"]]
        assert (recorded["incident_id"], recorded["verdict"]) == (incident["id"], incident["model"]["verdict"])
    triage = json.loads((ROOT / "docs/eval/triage-synthetic-7d.json").read_text())
    rows = triage["agreement"][f"{model_triage.MODEL}, effort {model_triage.DEFAULT_EFFORT}"]
    for key in ("attacks_dismissed", "attack_incidents", "benign_dismissed", "benign_incidents"):
        assert DATA["triage"][key] == rows[key], key
    assert DATA["triage"]["usd_per_incident"] == triage["cost"]["usd_per_incident"]


def test_approving_runs_verifies_and_rolls_back_on_the_lab_copy():
    before = {path: path.read_bytes() for path in snapshot.LAB.rglob("*") if path.is_file()}
    verified = post("/demo/incidents/INC-A0004561/respond", {"approve": True}).json()
    assert verified["status"] == "verified" and verified["chain"]["ok"]
    assert [step["kind"] for step in verified["steps"]] == ["policy", "approval", "policy"]
    assert verified["steps"][0]["reason_code"] == "APPROVAL_REQUIRED"
    assert verified["steps"][2]["reason_code"] == "ALLOW_OK"
    rolled = post("/demo/incidents/INC-A0003598/respond", {"approve": True}).json()
    assert rolled["status"] == "rolled_back" and rolled["rollback"]["ok"]
    assert any(row["segment"] == "ROLLBACK" for row in rolled["timeline"])
    assert {path: path.read_bytes() for path in snapshot.LAB.rglob("*") if path.is_file()} == before


def test_the_same_click_gives_the_same_trail():
    first = post("/demo/incidents/INC-A0003598/respond", {"approve": True}).json()
    assert post("/demo/incidents/INC-A0003598/respond", {"approve": True}).json() == first


def test_without_approval_nothing_runs_and_without_a_lab_copy_the_executor_refuses():
    bare = post("/demo/incidents/INC-A0004561/respond", {"approve": False}).json()
    assert bare["status"] == "proposed" and "states" not in bare
    assert [step["reason_code"] for step in bare["steps"]] == ["APPROVAL_REQUIRED"]
    no_lab = post("/demo/incidents/INC-A0002072/respond", {"approve": True}).json()
    assert no_lab["steps"][-1]["kind"] == "refused" and "no lab copy of db-01" in no_lab["steps"][-1]["reason"]
    assert any(row["text"].startswith("AP-0001 refused on db-01") for row in no_lab["timeline"])


def test_incidents_without_a_plan_are_not_found():
    dismissed = next(i["id"] for i in DATA["incidents"] if i["model"]["verdict"] == "dismiss")
    assert post(f"/demo/incidents/{dismissed}/respond", {"approve": True}).status_code == 404
    assert post("/demo/incidents/INC-NOPE/respond", {"approve": True}).status_code == 404


@pytest.mark.parametrize("targets, valid_until, code", [
    ("bastion-01", None, "ALLOW_OK"),
    ("bastion-01, web-02", None, "ALLOW_OK"),
    ("web-01", None, "TARGET_NOT_IN_SCOPE"),
    ("", None, "SCOPE_EMPTY"),
    ("*.internal", None, "SCOPE_AMBIGUOUS"),
    ("*", None, "SCOPE_AMBIGUOUS"),
    ("bastion-01,", None, "SCOPE_AMBIGUOUS"),
    ("10.0.0.0/8", None, "SCOPE_AMBIGUOUS"),
    ("bastion-01", "end of November", "SCOPE_AMBIGUOUS"),
    ("bastion-01", "2026-01-01T00:00:00Z", "SCOPE_AMBIGUOUS"),  # ends before it starts
])
def test_a_typed_scope_is_judged_by_the_policy_engine(targets, valid_until, code):
    result = post("/demo/incidents/INC-A0004561/scope-check", {"targets": targets, "valid_until": valid_until})
    assert result.status_code == 200 and result.json()["reason_code"] == code


def test_typed_scopes_are_bounded():
    many = ",".join(f"h{n}" for n in range(respond.MAX_ENTRIES + 1))
    assert post("/demo/incidents/INC-A0004561/scope-check", {"targets": many}).status_code == 422
    assert post("/demo/incidents/INC-A0004561/scope-check", {"targets": "x" * 5000}).status_code == 422


def test_the_builder_runs_on_a_small_dataset(tmp_path):
    synthetic.write(synthetic.Config(days=1), tmp_path)
    built = snapshot.build(tmp_path)
    assert len(built["hours"]) == 24 and built["dataset"]["days"] == 1
    head = built["headline"]
    assert [sum(column) for column in zip(*built["hours"])] == [head["log_lines"], head["alerts"],
                                                                head["incidents"], head["surfaced"]]
    assert head["surfaced"] == len(built["incidents"]) and head["episodes"] == 10
    assert built["triage"]["judged"] == sum(i["model"] is not None for i in built["incidents"])
    assert snapshot.render(built) == snapshot.render(snapshot.build(tmp_path))
