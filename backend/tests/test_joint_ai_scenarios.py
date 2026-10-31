"""Independently authored oracles for offline synthetic joint response replay."""
from collections import Counter
from copy import deepcopy
import json
import re

import pytest

from app.agents import joint_triage
from app.evaluation import joint_ai_scenarios as corpus


def test_suite_has_distinct_bounded_cases_and_three_separate_tracks():
    rows = corpus.scenarios()
    assert corpus.SUITE == "joint-ai-synthetic-v1"
    assert len(rows) >= 20
    assert len({row["id"] for row in rows}) == len(rows)
    assert len({row["case"]["case_id"] for row in rows}) == len(rows)
    assert len({joint_triage.canonical(row["case"]) for row in rows}) == len(rows)
    assert Counter(row["track"] for row in rows).keys() == {"decision", "guardrail", "boundary"}
    keys = {"id", "family", "track", "case", "expected_verdict", "fake_response",
            "expected_status", "expected_accepted", "expected_reason_codes"}
    for row in rows:
        assert set(row) == keys
        assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", row["id"])
        assert len(row["id"]) <= 64
        assert row["expected_verdict"] in {"escalate", "abstain"}
        assert row["expected_accepted"] in {"escalate", "abstain"}
        assert row["expected_status"] in {"valid", "requires_review"}
        assert len(row["expected_reason_codes"]) == len(set(row["expected_reason_codes"]))
        assert isinstance(row["fake_response"], str)
        assert len(row["fake_response"].encode()) <= joint_triage.MAX_RESPONSE_BYTES
        assert not {"family", "track", "expected_verdict", "expected_accepted",
                    "expected_status", "fake_response"}.intersection(row["case"])
        joint_triage.parse_dossier(row["case"])


@pytest.mark.parametrize("row", corpus.scenarios(), ids=lambda row: row["id"])
def test_scripted_response_matches_independent_hand_authored_oracle(row):
    before = deepcopy(row)
    accepted, details = joint_triage.validate(row["fake_response"], row["case"])
    assert accepted["verdict"] == row["expected_accepted"]
    assert details["status"] == row["expected_status"]
    assert sorted(reason["code"] for reason in details["reasons"]) == sorted(row["expected_reason_codes"])
    assert details["free_text_requires_review"] is True
    assert row == before


def test_generator_does_not_ask_validator_to_derive_labels(monkeypatch):
    baseline = corpus.scenarios()

    def forbidden(*args, **kwargs):
        pytest.fail("scenario labels must not be derived from the validator")

    monkeypatch.setattr(joint_triage, "validate", forbidden)
    monkeypatch.setattr(joint_triage, "parse_dossier", forbidden)
    assert corpus.scenarios() == baseline


def test_every_call_and_case_returns_independent_nested_objects():
    baseline = corpus.scenarios()
    first, second = corpus.scenarios(), corpus.scenarios()
    first[0]["case"]["evidence"][0]["dst_port"] = 9999
    first[0]["case"]["limitations"].append("mutated")
    first[0]["expected_reason_codes"].append("mutated")
    first[0]["case"]["counts"]["network"]["included"] = 0
    assert first[1:] == baseline[1:]
    assert second == baseline == corpus.scenarios()


def test_decision_track_keeps_policy_labels_separate_from_guardrail_fallbacks():
    rows = corpus.scenarios()
    decisions = [row for row in rows if row["track"] == "decision"]
    assert {row["expected_verdict"] for row in decisions} == {"escalate", "abstain"}
    assert all(row["expected_status"] == "valid" for row in decisions)
    assert any(row["expected_verdict"] != row["expected_accepted"] for row in rows
               if row["track"] == "guardrail")
    by_id = {row["id"]: row for row in rows}
    assert by_id["partial-positive"]["case"]["input_complete"] is False
    assert by_id["truncated-positive"]["case"]["summary_complete"] is False
    assert by_id["network-only"]["case"]["counts"]["ssh"]["included"] == 0
    assert by_id["joint-success"]["case"]["evidence"][2]["event_type"] == "auth_success"


def test_narrative_boundary_cannot_be_mistaken_for_verified_explanation():
    rows = [row for row in corpus.scenarios() if row["track"] == "boundary"]
    assert {row["id"] for row in rows} == {
        "hostile-rationale", "contradictory-rationale", "unverified-attack-technique"}
    for row in rows:
        accepted, details = joint_triage.validate(row["fake_response"], row["case"])
        proposal = json.loads(row["fake_response"])
        assert details["status"] == "valid"
        assert details["free_text_requires_review"] is True
        assert details["proposal"]["rationale"] == proposal["rationale"]
        assert proposal["rationale"] not in accepted["rationale"]
        assert "remain unverified" in accepted["rationale"]


def test_guardrails_include_response_structure_and_evidence_scope_failures():
    guards = [row for row in corpus.scenarios() if row["track"] == "guardrail"]
    assert {code for row in guards for code in row["expected_reason_codes"]} >= {
        "invalid_response", "unknown_evidence", "stale_revision", "unsupported_claim",
        "evidence_not_current", "missing_supported_claim"}
    assert all(row["expected_accepted"] == "abstain" for row in guards)
    assert all(row["expected_status"] == "requires_review" for row in guards)
    assert {row["id"] for row in guards} >= {
        "cross-source-ports", "cross-destination-ports", "preauth-as-failure",
        "disconnect-as-failure", "failure-as-success", "success-no-account",
        "forbidden-action", "forbidden-dismiss", "extra-instructions",
        "duplicate-json-key", "truncated-json"}
