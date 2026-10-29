"""Local factual claims must not weaken whole-incident dismissal boundaries."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from app.agents import triage_evidence as evidence
from app.agents.model_triage import RecordedTriage, TriageCall
from app.agents.triage_api import APIConfig


def dossier(kind="http", context="route"):
    event = {"event_id": "OBS-1", "time": 1000, "source": "source-a", "host": "host-a"}
    if kind == "ssh":
        event.update(kind="auth_failure", account="service-a")
    else:
        event.update(kind="http_request", method="GET", path="/health", status=200)
    if context == "authorization":
        record = {"event_id": "CTX-1", "kind": "authorization", "source": "source-a",
                  "host": "host-a", "accounts": ["service-a"], "methods": ["GET"],
                  "paths": ["/health"], "valid_from": 900, "valid_until": 1100}
    else:
        record = {"event_id": "CTX-1", "kind": "service_context", "host": "host-a",
                  "expected_routes": [{"method": "GET", "path": "/health", "status": 200}]}
    return {"dossier_version": 3, "incident_id": "synthetic-claim-scope", "revision": "r1",
            "kind": kind, "evidence_status": "complete", "evidence": [record, event]}


def proposal(case, *, verdict="escalate", proof=None):
    claim_kind = ("activity_authorized" if case["evidence"][0]["kind"] == "authorization"
                  else "http_operation_expected")
    basis = "authorized_activity" if claim_kind == "activity_authorized" else "expected_http_operation"
    return {"verdict": verdict, "confidence": "high", "rationale": "Synthetic scoped evidence.",
            "evidence_ids": ["CTX-1", "OBS-1"], "attack_techniques": [], "revision": "r1",
            "dismissal_basis": basis if verdict == "dismiss" else "none",
            "claims": [{"kind": claim_kind, "evidence_ids": proof or ["CTX-1", "OBS-1"]}]}


def judge(case, value):
    result, details = evidence.validate(json.dumps(value), case)
    return result, {reason["code"] for reason in details["reasons"]}


def add_uncovered(case):
    event = {**case["evidence"][1], "event_id": "OBS-2"}
    event["account" if case["kind"] == "ssh" else "path"] = "outside-approved-scope"
    case["evidence"].append(event)


@pytest.mark.parametrize("kind,context", [("ssh", "authorization"), ("http", "authorization"), ("http", "route")])
def test_partial_context_supports_a_local_fact_but_not_dismissing_uncited_events(kind, context):
    case = dossier(kind, context)
    add_uncovered(case)
    value = proposal(case)
    # The uncited observation remains part of the whole-incident decision.
    assert "OBS-2" not in value["evidence_ids"]
    assert judge(case, value)[0]["verdict"] == "escalate"
    result, reasons = judge(case, proposal(case, verdict="dismiss"))
    assert result["verdict"] == "abstain"
    assert reasons == {"unsupported_dismissal"}


@pytest.mark.parametrize("context", ["route", "authorization"])
def test_expected_request_can_coexist_with_confirmed_exploitation(context):
    case = dossier(context=context)
    case["evidence"].append({"event_id": "EXPLOIT", "kind": "exploit_confirmation", "time": 1001,
                             "source": "source-a", "host": "host-a", "finding": "Synthetic confirmation"})
    value = proposal(case)
    value["evidence_ids"].append("EXPLOIT")
    value["claims"].append({"kind": "exploitation_confirmed", "evidence_ids": ["EXPLOIT"]})
    assert judge(case, value)[0]["verdict"] == "escalate"
    value.update(verdict="dismiss", dismissal_basis=("authorized_activity" if context == "authorization"
                                                     else "expected_http_operation"))
    assert judge(case, value)[1] == {"unsupported_dismissal"}
    # Even a matching source/host/time never makes an exploit an authorized request.
    value = proposal(case, proof=["CTX-1", "OBS-1", "EXPLOIT"])
    assert judge(case, value)[1] == {"unsupported_claim"}


@pytest.mark.parametrize("kind,context", [("ssh", "authorization"), ("http", "authorization"), ("http", "route")])
def test_context_only_retains_full_dossier_semantics(kind, context):
    case = dossier(kind, context)
    value = proposal(case, verdict="dismiss", proof=["CTX-1"])
    assert judge(case, value)[0]["verdict"] == "dismiss"
    add_uncovered(case)
    result, reasons = judge(case, value)
    assert result["verdict"] == "abstain"
    assert reasons == {"unsupported_claim", "unsupported_dismissal"}
    value.update(verdict="escalate", dismissal_basis="none")
    assert judge(case, value)[1] == {"unsupported_claim"}


@pytest.mark.parametrize("kind,context", [("ssh", "authorization"), ("http", "authorization"), ("http", "route")])
def test_every_observation_in_a_claim_needs_its_own_context_coverage(kind, context):
    case = dossier(kind, context)
    add_uncovered(case)
    value = proposal(case, proof=["CTX-1", "OBS-1", "OBS-2"])
    assert judge(case, value)[1] == {"unsupported_claim"}
    second = deepcopy(case["evidence"][0])
    second["event_id"] = "CTX-2"
    if context == "route":
        second["expected_routes"][0]["path"] = "outside-approved-scope"
    else:
        second["accounts" if kind == "ssh" else "paths"] = ["outside-approved-scope"]
    case["evidence"].append(second)
    # Context merely present in the dossier cannot repair the claim.
    assert judge(case, value)[1] == {"unsupported_claim"}
    value["claims"][0]["evidence_ids"].append("CTX-2")
    assert judge(case, value)[0]["verdict"] == "escalate"


@pytest.mark.parametrize("kind,field,wrong", [
    ("ssh", "source", "source-b"), ("ssh", "host", "host-b"),
    ("ssh", "account", "service-b"), ("ssh", "time", 899), ("ssh", "time", 1101),
    ("http", "source", "source-b"), ("http", "host", "host-b"),
    ("http", "method", "POST"), ("http", "path", "/admin"),
    ("http", "time", 899), ("http", "time", 1101),
])
def test_authorization_checks_each_scope_field_for_all_cited_observations(kind, field, wrong):
    case = dossier(kind, "authorization")
    case["evidence"].append({**case["evidence"][1], "event_id": "OBS-2", field: wrong})
    assert judge(case, proposal(case, proof=["CTX-1", "OBS-1", "OBS-2"]))[1] == {"unsupported_claim"}


@pytest.mark.parametrize("field,wrong", [("host", "host-b"), ("method", "POST"),
                                         ("path", "/admin"), ("status", 500)])
def test_expected_route_checks_each_scope_field_for_all_cited_requests(field, wrong):
    case = dossier()
    case["evidence"].append({**case["evidence"][1], "event_id": "OBS-2", field: wrong})
    assert judge(case, proposal(case, proof=["CTX-1", "OBS-1", "OBS-2"]))[1] == {"unsupported_claim"}


@pytest.mark.parametrize("kind,field,accepted", [
    ("ssh", "methods", True), ("ssh", "paths", True), ("ssh", "accounts", False),
    ("http", "methods", False), ("http", "paths", False), ("http", "accounts", True),
])
def test_empty_authorization_fields_do_not_create_cross_protocol_wildcards(kind, field, accepted):
    case = dossier(kind, "authorization")
    case["evidence"][0][field] = []
    result, reasons = judge(case, proposal(case, verdict="dismiss"))
    assert result["verdict"] == ("dismiss" if accepted else "abstain")
    assert reasons == (set() if accepted else {"unsupported_claim", "unsupported_dismissal"})


@pytest.mark.parametrize("kind,context", [("ssh", "authorization"), ("http", "authorization"), ("http", "route")])
def test_observations_alone_and_empty_observation_scope_cannot_prove_context(kind, context):
    case = dossier(kind, context)
    assert judge(case, proposal(case, proof=["OBS-1"]))[1] == {"unsupported_claim"}
    typed = evidence.Dossier.model_validate(case)
    claim_kind = proposal(case)["claims"][0]["kind"]
    assert not evidence._supports(claim_kind, [typed.evidence[0]], [])


@pytest.mark.parametrize("kind,context", [("ssh", "authorization"), ("http", "authorization"), ("http", "route")])
def test_unreferenced_success_blocks_dismissal_despite_a_valid_local_claim(kind, context):
    case = dossier(kind, context)
    case["evidence"].append({"event_id": "SUCCESS", "kind": "auth_success" if kind == "ssh" else "app_auth_success",
                             "time": 1001, "source": "source-a", "host": "host-a", "account": "service-a"})
    value = proposal(case, verdict="dismiss")
    assert "SUCCESS" not in value["evidence_ids"]
    assert judge(case, value)[1] == {"unsupported_dismissal"}


@pytest.mark.parametrize("quality", ["gapped", "truncated", "unknown", "stale"])
@pytest.mark.parametrize("kind,context", [("ssh", "authorization"), ("http", "authorization"), ("http", "route")])
def test_local_claims_do_not_bypass_evidence_freshness_and_completeness(kind, context, quality):
    case = dossier(kind, context)
    case["evidence_status"] = quality
    result, reasons = judge(case, proposal(case, verdict="dismiss"))
    assert result["verdict"] == "abstain" and "incomplete_evidence" in reasons
    assert ("stale_evidence" in reasons) == (quality == "stale")
    result, reasons = judge(case, proposal(case))
    assert result["verdict"] == ("abstain" if quality == "stale" else "escalate")


@pytest.mark.parametrize("change,reason", [("low-confidence", "uncertain_dismissal"),
                                           ("old-revision", "stale_revision"),
                                           ("missing-claim", "unsupported_dismissal")])
def test_scoped_dismissal_still_requires_confidence_current_revision_and_factual_claim(change, reason):
    case = dossier()
    value = proposal(case, verdict="dismiss")
    if change == "low-confidence":
        value["confidence"] = "low"
    elif change == "old-revision":
        value["revision"] = "r0"
    else:
        value["claims"] = []
    assert judge(case, value)[1] == {reason}


@pytest.mark.parametrize("change", ["validator", "prompt"])
def test_old_recordings_cannot_satisfy_the_new_validator_or_prompt_contract(tmp_path, monkeypatch, change):
    case = dossier()
    config = APIConfig.load(Path(__file__).resolve().parents[2] /
                            "examples/model-triage/openai-luna-low.json")
    assert evidence.VALIDATOR_VERSION == 3
    current_request = config.fingerprint(case)
    with monkeypatch.context() as earlier:
        if change == "validator":
            earlier.setattr(evidence, "VALIDATOR_VERSION", 2)
        else:
            earlier.setattr(evidence, "SYSTEM", evidence.SYSTEM + "\nPrior synthetic prompt contract.")
        prior_request = config.fingerprint(case)
    assert config.fingerprint(case) == current_request
    assert prior_request != current_request
    call = TriageCall(incident_id=case["incident_id"], prompt_sha256=prior_request,
                      verdict="escalate", confidence="high", rationale="Synthetic prior recording.",
                      evidence_ids=("OBS-1",), attack_techniques=(), model=config.model,
                      stop_reason="completed", input_tokens=1, output_tokens=1,
                      cache_creation_input_tokens=0, cache_read_input_tokens=0,
                      usd=0, latency_seconds=0)
    tape = tmp_path / "prior-protocol.jsonl"
    tape.write_text(json.dumps(call.to_record()) + "\n")
    replay = RecordedTriage(tape)
    assert replay.lookup(case, request_sha256=prior_request) == call
    assert replay.lookup(case, request_sha256=current_request) is None
