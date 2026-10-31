"""Offline replay integration and reporting boundaries, using authored data only."""
from copy import deepcopy
import json
import socket

import pytest

from app.agents import joint_triage as joint
from app.evaluation import joint_ai_replay as replay
from app.evaluation.joint_ai_scenarios import scenarios


def test_fake_contract_is_repeatable_without_network_or_live_qualification(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("network access is not part of this evaluation")
    monkeypatch.setattr(socket, "socket", forbidden)
    first, second = replay.make_tape(), replay.make_tape()
    assert first == second
    report = replay.evaluate(first)
    assert report == replay.evaluate(second)
    assert report["complete"] is True
    assert report["contract_oracle"] == {"applicable": True, "passed": True}
    assert report["replay_model_calls"] == report["replay_cost_usd"] == 0
    assert report["live_qualified"] is False and report["semantic_accuracy_measured"] is False
    assert report["validation"]["counts"]["valid"] > 0
    assert report["validation"]["counts"]["requires_review"] > 0
    assert report["by_track"]["boundary"]["proposed"]["total"] > 0
    assert replay.make_tape() == first  # no evaluator mutation of canonical inputs


def test_all_abstaining_recording_cannot_claim_full_policy_agreement():
    tape = replay.make_tape()
    tape["source"] = "local_recording"
    rows = scenarios()
    for record, row in zip(tape["records"], rows):
        record["response_text"] = json.dumps({
            "verdict": "abstain", "confidence": "low", "rationale": "Insufficient concern.",
            "revision": row["case"]["revision"], "evidence_ids": [],
            "attack_techniques": [], "claims": [],
        })
    report = replay.evaluate(tape)
    assert report["complete"] is True
    expected_matches = sum(r["expected_verdict"] == "abstain" for r in rows if r["track"] == "decision")
    for side in ("proposed", "accepted"):
        assert report[side]["matched"] == expected_matches
        assert report[side]["agreement"] < 1
        assert report[side]["matrix"]["escalate"]["escalate"] == 0
    assert report["contract_oracle"] == {"applicable": False, "passed": None}
    assert report["recorded_generation_cost"] == "unknown"
    assert report["live_qualified"] is False


def test_raw_proposed_escalation_is_not_hidden_by_guardrail_abstention():
    tape = replay.make_tape()
    report = replay.evaluate(tape)
    rejected = [r for r in report["cases"] if r["proposed"] == "escalate" and r["status"] == "requires_review"]
    assert rejected and all(r["accepted"] == "abstain" for r in rejected)
    assert all(r["reason_codes"] for r in rejected)
    assert all(r["free_text_requires_review"] for r in report["cases"])
    assert report["validation"]["dimensions"]["schema_valid"] < len(tape["records"])


def test_protocol_binds_prompt_schema_version_labels_and_case(monkeypatch):
    original = replay.protocol()
    with monkeypatch.context() as m:
        m.setattr(joint, "SYSTEM", joint.SYSTEM + " A revised prompt.")
        assert replay.protocol()["requests"] != original["requests"]
    with monkeypatch.context() as m:
        m.setattr(joint, "VALIDATOR_VERSION", "synthetic-next-validator")
        assert replay.protocol()["requests"] != original["requests"]
    with monkeypatch.context() as m:
        changed = deepcopy(joint.SCHEMA)
        changed["description"] = "Synthetic schema change"
        m.setattr(joint, "SCHEMA", changed)
        assert replay.protocol()["requests"] != original["requests"]
    rows = scenarios()
    rows[0]["expected_verdict"] = "abstain" if rows[0]["expected_verdict"] == "escalate" else "escalate"
    with monkeypatch.context() as m:
        m.setattr(replay, "scenarios", lambda: rows)
        assert replay.protocol()["corpus_sha256"] != original["corpus_sha256"]
    rows = scenarios()
    rows[0]["case"]["revision"] = "R-" + "f" * 24
    with monkeypatch.context() as m:
        m.setattr(replay, "scenarios", lambda: rows)
        assert replay.protocol()["requests"] != original["requests"]


def test_cli_fake_creation_and_two_replays_have_identical_private_reports(tmp_path, capsys):
    tape, first, second = (tmp_path / name for name in ("tape.json", "first.json", "second.json"))
    assert replay.main(["--make-fake-tape", str(tape)]) == 0
    assert replay.main(["--tape", str(tape), "--out", str(first)]) == 0
    assert replay.main(["--tape", str(tape), "--out", str(second)]) == 0
    assert first.read_bytes() == second.read_bytes()
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in (tape, first, second))
    messages = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert messages[0] == {"synthetic_tape_created": True, "model_calls": 0}
    assert messages[1]["contract_oracle"]["passed"] is True
    assert not messages[1]["live_qualified"]


def test_contract_oracle_catches_regression_in_validator(monkeypatch):
    tape = replay.make_tape()
    actual = joint.validate
    def broken(text, case):
        verdict, details = actual(text, case)
        return {**verdict, "verdict": "escalate"}, details
    monkeypatch.setattr(joint, "validate", broken)
    result = replay.evaluate(tape)
    assert result["complete"] is True
    assert result["contract_oracle"]["passed"] is False


@pytest.mark.parametrize("cite", [False, True])
def test_escalation_without_required_claim_is_not_counted_as_supported(cite):
    tape = replay.make_tape()
    tape["source"] = "local_recording"
    for record in tape["records"]:
        record.update(outcome="unavailable", response_text=None)
    row = scenarios()[0]
    value = {"verdict": "escalate", "confidence": "high", "rationale": "Unsupported escalation.",
             "revision": row["case"]["revision"], "attack_techniques": [], "claims": [],
             "evidence_ids": [row["case"]["evidence"][0]["event_id"]] if cite else []}
    tape["records"][0].update(outcome="response", response_text=json.dumps(value))
    report = replay.evaluate(tape)
    assert report["validation"]["dimensions"]["schema_valid"] == 1
    assert report["validation"]["dimensions"]["typed_support_passed"] == 0
    assert "missing_supported_claim" in report["cases"][0]["reason_codes"]


def test_overall_policy_agreement_does_not_mix_in_guardrail_or_prose_challenges():
    report = replay.evaluate(replay.make_tape())
    expected_count = sum(row["track"] == "decision" for row in scenarios())
    assert report["proposed"]["total"] == report["accepted"]["total"] == expected_count
    assert expected_count < len(report["cases"])
    assert report["proposed"] == report["by_track"]["decision"]["proposed"]
    assert report["accepted"] == report["by_track"]["decision"]["accepted"]
