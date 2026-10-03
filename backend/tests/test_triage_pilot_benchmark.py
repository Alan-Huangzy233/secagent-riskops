"""The fresh pilot comparison uses a closed corpus and the same three adapters."""
import json
from pathlib import Path

import httpx
import pytest

from app.agents import triage_evidence
from app.agents.triage_api import APIConfig, APITriage
from app.agents.triage_budget import BudgetLedger
from app.evaluation import triage_benchmark, triage_pilot_scenarios, triage_scenarios

ROOT = Path(__file__).resolve().parents[2]


def reference_response(row):
    case = row["case"]
    records = case["evidence"]
    value = {"verdict": row["expected_verdict"], "confidence": "high", "rationale": "Synthetic reference.",
             "evidence_ids": [r["event_id"] for r in records], "attack_techniques": [],
             "revision": case["revision"], "dismissal_basis": "none", "claims": []}

    def claim(kind, predicate):
        value["claims"].append({"kind": kind, "evidence_ids": [r["event_id"] for r in records if predicate(r)]})

    if value["verdict"] == "dismiss":
        if any(r["kind"] == "authorization" for r in records):
            value["dismissal_basis"] = "authorized_activity"
            claim("activity_authorized", lambda r: r["kind"] == "authorization")
        elif any(r["kind"] == "service_context" for r in records):
            value["dismissal_basis"] = "expected_http_operation"
            claim("http_operation_expected", lambda r: r["kind"] == "service_context")
        else:
            value["dismissal_basis"] = "known_user_retry"
            claim("authentication_succeeded", lambda r: r["kind"] == "auth_success")
            claim("account_owned", lambda r: r["kind"] == "account_context" and r["classification"] == "organisation")
            claim("source_familiar", lambda r: r["kind"] == "source_history" and r["familiarity"] == "familiar")
    return value


def test_new_manifest_supports_labels_and_has_no_old_ids_or_family_names():
    rows, frozen = triage_pilot_scenarios.verified_scenarios("holdout")
    previous = [r for split in triage_scenarios.FAMILIES for r in triage_scenarios.scenarios(split)]
    assert {r["family"] for r in rows}.isdisjoint({r["family"] for r in previous})
    assert {r["case"]["incident_id"] for r in rows}.isdisjoint({r["case"]["incident_id"] for r in previous})
    assert len(rows) == 36 and frozen["thresholds"] == triage_scenarios.THRESHOLDS
    for row in rows:
        result, details = triage_evidence.validate(json.dumps(reference_response(row)), row["case"])
        assert details["status"] == "valid", (row["family"], details)
        assert result["verdict"] == row["expected_verdict"]
        serialized = json.dumps(row["case"])
        assert row["family"] not in serialized and "expected_verdict" not in serialized


@pytest.mark.parametrize("profile", ["openai-luna-low", "deepseek-flash-low", "zai-glm-flash-low"])
def test_all_three_adapters_freeze_resume_and_replay_the_fresh_suite(tmp_path, profile):
    config = APIConfig.load(ROOT / "examples/model-triage" / (profile + ".json"))
    rows = {r["case"]["incident_id"]: r for r in triage_pilot_scenarios.scenarios("holdout")}
    sent = []

    def send(request):
        body = json.loads(request.content)
        messages = body.get("input", body.get("messages"))
        case = json.loads(messages[-1]["content"].split("\n", 1)[1])
        assert "expected_verdict" not in request.content.decode()
        sent.append(case)
        text = json.dumps(reference_response(rows[case["incident_id"]]))
        if config.api_format == "openai-responses":
            response = {"model": config.model, "status": "completed",
                        "output": [{"type": "message", "content": [{"type": "output_text", "text": text}]}],
                        "usage": {"input_tokens": 1000, "output_tokens": 100}}
        else:
            response = {"model": config.model, "choices": [{"finish_reason": "stop", "message": {"content": text}}],
                        "usage": {"prompt_tokens": 1000, "completion_tokens": 100}}
        return httpx.Response(200, json=response)

    tape = tmp_path / "calls.jsonl"
    client = APITriage(config, "synthetic-placeholder", ledger=BudgetLedger(tmp_path / "budget.db", "10"),
                      tape=tape, transport=httpx.MockTransport(send))
    suite = triage_pilot_scenarios.SUITE
    triage_benchmark.evaluate("holdout", tape, config=config, live=client, suite=suite, limit=3)
    result = triage_benchmark.evaluate("holdout", tape, config=config, live=client, suite=suite)
    assert result["proposed"]["correct"] == result["accepted"]["correct"] == 36
    assert result["passes_scenario_gates"] and not result["production_qualified"]
    assert len(sent) == 36
    assert triage_benchmark.evaluate("holdout", tape, config=config, suite=suite) == result
    with pytest.raises(ValueError, match="protocol changed"):
        triage_benchmark.evaluate("holdout", tape, config=config, live=client)
    with pytest.raises(ValueError, match="unknown built-in suite"):
        triage_benchmark.evaluate("holdout", tape, config=config, live=client, suite="custom-data")
    assert len(sent) == 36


def test_modified_corpus_is_rejected_before_model_requests(monkeypatch):
    monkeypatch.setattr(triage_pilot_scenarios, "manifest", lambda: {"edited": True})
    with pytest.raises(ValueError, match="reviewed manifest"):
        triage_benchmark._scenarios("holdout", triage_pilot_scenarios.SUITE)
