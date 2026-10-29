"""Synthetic-only boundaries for the isolated joint advisory contract."""
from copy import deepcopy
import json

import pytest

from app.agents import joint_triage as joint


def alias(prefix, number):
    return f"{prefix}-{number:024x}"


def fixture():
    common = {"asset": alias("A", 1), "peer": alias("P", 1)}
    evidence = [
        {**common, "kind": "network_tcp", "event_id": alias("E", n), "offset_us": n,
         "source": alias("S", 1), "destination": alias("D", 1), "dst_port": port,
         "protocol": "TCP", "direction": "local_input"}
        for n, port in ((1, 22), (2, 443))]
    evidence += [{**common, "kind": "ssh", "event_id": alias("E", 3), "offset_us": 3,
                  "source": alias("S", 2), "event_type": "auth_failure", "account": alias("U", 1)}]
    return {"dossier_version": joint.VERSION, "case_id": alias("J", 1), "revision": alias("R", 1),
            "kind": "network_ssh", **common, "association_state": "linked", "review_state": "current",
            "input_complete": True, "timeline_complete": True, "summary_complete": True,
            "coverage_complete": None, "temporal_association_available": True, "window_duration_us": 10,
            "counts": {"network": {"observed": 2, "retained": 2, "included": 2},
                       "ssh": {"observed": 1, "retained": 1, "included": 1}},
            "limitations": sorted(joint.BASE_LIMITATIONS), "evidence": evidence}


def proposal(case=None, kind="ssh_network_associated", ids=None, verdict="escalate"):
    case = fixture() if case is None else case
    if ids is None:
        ids = [r["event_id"] for r in case["evidence"]]
    return {"verdict": verdict, "confidence": "high", "rationale": "Synthetic advisory rationale.",
            "revision": case["revision"], "evidence_ids": [], "attack_techniques": [],
            "claims": [{"kind": kind, "evidence_ids": ids}] if ids else []}


def judged(case=None, value=None):
    case = fixture() if case is None else case
    return joint.validate(json.dumps(proposal(case) if value is None else value), case)


def codes(details):
    return {item["code"] for item in details["reasons"]}


def test_supported_association_is_an_advisory_and_original_prose_is_separate():
    result, details = judged()
    assert result["verdict"] == "escalate" and details["status"] == "valid"
    assert len(result["evidence_ids"]) == 3
    assert "Synthetic" not in result["rationale"]
    assert details["proposal"]["rationale"] == "Synthetic advisory rationale."
    assert details["free_text_requires_review"] is True
    assert details["validator_version"] == joint.VALIDATOR_VERSION
    assert details["dossier_version"] == joint.VERSION


@pytest.mark.parametrize("kind,indices", [
    ("network_observed", [0]), ("multiple_destination_ports", [0, 1]),
    ("ssh_failure_observed", [2]), ("ssh_network_associated", [0, 2]),
])
def test_precise_positive_claims(kind, indices):
    case = fixture()
    ids = [case["evidence"][i]["event_id"] for i in indices]
    result, details = judged(case, proposal(case, kind, ids))
    assert result["verdict"] == "escalate" and not details["reasons"]


@pytest.mark.parametrize("event_type", ["auth_success", "ssh_success"])
def test_account_bound_authentication_success(event_type):
    case = fixture()
    case["evidence"][2]["event_type"] = event_type
    value = proposal(case, "authentication_succeeded", [case["evidence"][2]["event_id"]])
    assert judged(case, value)[0]["verdict"] == "escalate"
    case["evidence"][2]["account"] = None
    result, details = judged(case, value)
    assert result["verdict"] == "abstain" and "unsupported_claim" in codes(details)


@pytest.mark.parametrize("kind,indices", [
    ("network_observed", [2]), ("network_observed", [0, 2]),
    ("multiple_destination_ports", [0]), ("multiple_destination_ports", [0, 1, 2]),
    ("ssh_failure_observed", [0]), ("ssh_failure_observed", [0, 2]),
    ("authentication_succeeded", [2]), ("authentication_succeeded", [0]),
    ("ssh_network_associated", [0, 1]), ("ssh_network_associated", [2]),
])
def test_wrong_or_insufficient_evidence_cannot_support_claim(kind, indices):
    case = fixture()
    value = proposal(case, kind, [case["evidence"][i]["event_id"] for i in indices])
    result, details = judged(case, value)
    assert result["verdict"] == "abstain" and "unsupported_claim" in codes(details)


@pytest.mark.parametrize("event_type", ["preauth_abort", "disconnect", "auth_success", "ssh_success"])
def test_preauth_disconnect_and_success_are_not_failure(event_type):
    case = fixture()
    case["evidence"][2]["event_type"] = event_type
    value = proposal(case, "ssh_failure_observed", [case["evidence"][2]["event_id"]])
    assert "unsupported_claim" in codes(judged(case, value)[1])


@pytest.mark.parametrize("field,prefix", [("source", "S"), ("destination", "D")])
def test_multiple_ports_cannot_combine_different_scopes(field, prefix):
    case = fixture()
    case["evidence"][1][field] = alias(prefix, 9)
    value = proposal(case, "multiple_destination_ports", [r["event_id"] for r in case["evidence"][:2]])
    assert "unsupported_claim" in codes(judged(case, value)[1])


def test_repeated_port_is_not_multiple_ports():
    case = fixture()
    case["evidence"][1]["dst_port"] = case["evidence"][0]["dst_port"]
    value = proposal(case, "multiple_destination_ports", [r["event_id"] for r in case["evidence"][:2]])
    assert "unsupported_claim" in codes(judged(case, value)[1])


@pytest.mark.parametrize("state", ["historical", "stale", "unavailable", "revalidation_required", "unknown"])
@pytest.mark.parametrize("kind,indices", [
    ("network_observed", [0]), ("ssh_failure_observed", [2]), ("ssh_network_associated", [0, 2]),
])
def test_noncurrent_evidence_requires_abstention(state, kind, indices):
    case = fixture()
    case["review_state"] = state
    value = proposal(case, kind, [case["evidence"][i]["event_id"] for i in indices])
    result, details = judged(case, value)
    assert result["verdict"] == "abstain" and "evidence_not_current" in codes(details)
    value["verdict"] = "abstain"
    assert judged(case, value)[1]["status"] == "valid"


@pytest.mark.parametrize("state", ["stale", "retracted"])
@pytest.mark.parametrize("kind,indices", [
    ("network_observed", [0]), ("ssh_failure_observed", [2]), ("ssh_network_associated", [0, 2]),
])
def test_bad_anchor_cannot_escalate_even_if_review_state_claims_current(state, kind, indices):
    case = fixture()
    case["association_state"] = state
    assert case["review_state"] == "current"
    value = proposal(case, kind, [case["evidence"][i]["event_id"] for i in indices])
    result, details = judged(case, value)
    assert result["verdict"] == "abstain" and "evidence_not_current" in codes(details)


@pytest.mark.parametrize("state", ["stale", "retracted"])
def test_bad_anchor_abstention_can_keep_local_facts_but_not_joint_claim(state):
    case = fixture()
    case["association_state"] = state
    value = proposal(case, "network_observed", [case["evidence"][0]["event_id"]], verdict="abstain")
    value["claims"].append({"kind": "ssh_failure_observed", "evidence_ids": [case["evidence"][2]["event_id"]]})
    result, details = judged(case, value)
    assert result["verdict"] == "abstain" and details["status"] == "valid"
    assert set(result["evidence_ids"]) == {case["evidence"][i]["event_id"] for i in (0, 2)}
    value["claims"].append({"kind": "ssh_network_associated", "evidence_ids": result["evidence_ids"]})
    result, details = judged(case, value)
    assert result["verdict"] == "abstain" and codes(details) == {"unsupported_claim"}
    assert result["evidence_ids"] == []


@pytest.mark.parametrize("state", ["linked", "partial"])
@pytest.mark.parametrize("verdict", ["escalate", "abstain"])
def test_current_usable_association_accepts_supported_joint_claim(state, verdict):
    case = fixture()
    case["association_state"] = state
    if state == "partial":
        case["input_complete"] = False
        case["limitations"].append("projection_input_incomplete")
    result, details = judged(case, proposal(case, verdict=verdict))
    assert result["verdict"] == verdict and details["status"] == "valid"


@pytest.mark.parametrize("limit", ["network_anchor_span_exceeded", "network_clock_unverifiable"])
@pytest.mark.parametrize("verdict", ["escalate", "abstain"])
def test_unverifiable_temporal_relation_cannot_support_joint_claim(limit, verdict):
    case = fixture()
    case["limitations"].append(limit)
    assert "unsupported_claim" in codes(judged(case, proposal(case, verdict=verdict))[1])


def test_temporal_unavailable_keeps_local_order_but_forbids_association():
    case = fixture()
    case["temporal_association_available"] = False
    case["window_duration_us"] = None
    case["association_state"] = "partial"
    case["evidence"] = case["evidence"][:2]
    case["counts"]["ssh"] = {"observed": 0, "retained": 0, "included": 0}
    case["limitations"].append("temporal_association_unavailable")
    assert "unsupported_claim" in codes(judged(case)[1])
    value = proposal(case, "network_observed", [case["evidence"][0]["event_id"]])
    assert judged(case, value)[0]["verdict"] == "escalate"


def test_partial_evidence_can_support_positive_facts_but_never_complete_coverage():
    case = fixture()
    case["association_state"] = "partial"
    case["input_complete"] = False
    case["timeline_complete"] = False
    case["summary_complete"] = False
    case["counts"]["network"].update(observed=5, retained=4)
    case["limitations"] += ["projection_input_incomplete", "timeline_truncated", "summary_truncated"]
    value = proposal(case, "network_observed", [case["evidence"][0]["event_id"]])
    assert judged(case, value)[0]["verdict"] == "escalate"
    assert joint.parse_dossier(case).coverage_complete is None


def test_empty_dossier_allows_only_abstention():
    case = fixture()
    case["evidence"] = []
    case["counts"] = {name: {"observed": 0, "retained": 0, "included": 0} for name in ("network", "ssh")}
    case["association_state"] = "partial"
    case["temporal_association_available"] = False
    case["window_duration_us"] = None
    case["limitations"] += ["network_evidence_unavailable", "temporal_association_unavailable"]
    value = proposal(case, verdict="abstain")
    assert judged(case, value)[1]["status"] == "valid"
    value["verdict"] = "escalate"
    assert {"missing_observed_evidence", "missing_supported_claim"} <= codes(judged(case, value)[1])


def test_top_level_citation_without_typed_claim_cannot_escalate():
    case = fixture()
    value = proposal(case)
    value["evidence_ids"] = [case["evidence"][0]["event_id"]]
    value["claims"] = []
    assert "missing_supported_claim" in codes(judged(case, value)[1])


def test_unknown_citation_or_exact_revision_mismatch_fails_without_echoing_data():
    case = fixture()
    value = proposal(case)
    value["revision"] = alias("R", 9)
    value["claims"][0]["evidence_ids"].append(alias("E", 99))
    result, details = judged(case, value)
    assert result["verdict"] == "abstain"
    assert {"unknown_evidence", "stale_revision"} <= codes(details)
    assert alias("E", 99) not in json.dumps(details["reasons"])


@pytest.mark.parametrize("field,value", [
    ("verdict", "dismiss"), ("verdict", "block"), ("confidence", True),
    ("rationale", ""), ("rationale", "  "), ("rationale", "x" * 4001),
    ("revision", "raw-private-revision"), ("evidence_ids", ["raw-private-id"]),
    ("attack_techniques", ["x" * 33]), ("attack_techniques", ["T1234"] * 2),
    ("claims", [{"kind": "exploitation_confirmed", "evidence_ids": [alias("E", 1)]}]),
    ("claims", [{"kind": "network_observed", "evidence_ids": []}]),
    ("claims", [{"kind": "network_observed", "evidence_ids": [alias("E", 1)], "action": "block"}]),
])
def test_invalid_response_schema_is_fixed_error(field, value):
    case = fixture()
    raw = proposal(case)
    raw[field] = value
    result, details = judged(case, raw)
    assert result["verdict"] == "abstain" and codes(details) == {"invalid_response"}
    assert details["proposal"] is None


def test_duplicate_response_citations_are_rejected():
    case = fixture()
    value = proposal(case)
    value["claims"][0]["evidence_ids"] *= 2
    assert codes(judged(case, value)[1]) == {"invalid_response"}


@pytest.mark.parametrize("raw", [
    '{"verdict":"abstain","verdict":"escalate"}',
    '{"outer":{"untrusted_marker":1,"untrusted_marker":2}}', '{"untrusted_marker":NaN}', '{"untrusted_marker":Infinity}',
    '{"untrusted_marker":-Infinity}', 'null', '[]', 'true', '"string"', '{',
    ' ' * (joint.MAX_RESPONSE_BYTES + 1), '[' * 2000 + ']' * 2000,
])
def test_malformed_duplicate_nonfinite_and_oversized_json_fails_closed(raw):
    result, details = joint.validate(raw, fixture())
    assert result["verdict"] == "abstain" and codes(details) == {"invalid_response"}
    assert "untrusted_marker" not in json.dumps(details)


def test_extra_fields_and_missing_fields_are_rejected():
    value = proposal()
    value["action"] = "block"
    assert codes(judged(value=value)[1]) == {"invalid_response"}
    del value["action"]
    del value["revision"]
    assert codes(judged(value=value)[1]) == {"invalid_response"}


@pytest.mark.parametrize("field,value", [
    ("dossier_version", 3), ("kind", "ssh"), ("case_id", "private-case"),
    ("asset", alias("P", 1)), ("peer", "192.0.2.1"), ("coverage_complete", True),
    ("input_complete", 1), ("timeline_complete", 1), ("summary_complete", "true"),
    ("window_duration_us", True), ("window_duration_us", -1), ("window_duration_us", None),
    ("window_duration_us", 2), ("review_state", "trusted"), ("association_state", "safe"),
])
def test_invalid_dossier_fields_never_echo_input(field, value):
    case = fixture()
    case[field] = value
    with pytest.raises(ValueError, match="^invalid_joint_dossier$"):
        joint.parse_dossier(case)


@pytest.mark.parametrize("field,value", [
    ("offset_us", -1), ("offset_us", 1.0), ("offset_us", True),
    ("dst_port", 0), ("dst_port", 65536), ("dst_port", True),
    ("protocol", "UDP"), ("direction", "forward"),
    ("event_id", "raw-event"), ("asset", alias("A", 2)), ("peer", alias("P", 2)),
])
def test_invalid_network_record_boundaries(field, value):
    case = fixture()
    case["evidence"][0][field] = value
    with pytest.raises(ValueError, match="^invalid_joint_dossier$"):
        joint.parse_dossier(case)


@pytest.mark.parametrize("field,value", [("event_type", "login"), ("account", "raw-user"), ("account", 5)])
def test_invalid_ssh_record_boundaries(field, value):
    case = fixture()
    case["evidence"][2][field] = value
    with pytest.raises(ValueError, match="^invalid_joint_dossier$"):
        joint.parse_dossier(case)


@pytest.mark.parametrize("change", ["missing_baseline", "unknown", "duplicate", "missing_summary", "false_summary"])
def test_limitations_cannot_be_removed_forged_or_disagree_with_completeness(change):
    case = fixture()
    if change == "missing_baseline":
        case["limitations"].pop()
    elif change == "unknown":
        case["limitations"].append("private-untrusted-text")
    elif change == "duplicate":
        case["limitations"].append(case["limitations"][0])
    elif change == "missing_summary":
        case["counts"]["network"]["retained"] = 3
        case["counts"]["network"]["observed"] = 3
        case["summary_complete"] = False
    else:
        case["limitations"].append("summary_truncated")
    with pytest.raises(ValueError, match="^invalid_joint_dossier$"):
        joint.parse_dossier(case)


@pytest.mark.parametrize("field,value", [("observed", 1), ("retained", 1), ("included", 1),
                                         ("observed", True), ("observed", -1), ("observed", 1000001)])
def test_counts_are_strict_ordered_and_match_included_records(field, value):
    case = fixture()
    case["counts"]["network"][field] = value
    with pytest.raises(ValueError, match="^invalid_joint_dossier$"):
        joint.parse_dossier(case)


def test_duplicate_evidence_identity_and_extra_raw_fields_rejected():
    case = fixture()
    case["evidence"][1]["event_id"] = case["evidence"][0]["event_id"]
    with pytest.raises(ValueError, match="^invalid_joint_dossier$"):
        joint.parse_dossier(case)
    case = fixture()
    case["evidence"][0]["raw_message"] = "synthetic untrusted log"
    with pytest.raises(ValueError, match="^invalid_joint_dossier$"):
        joint.parse_dossier(case)


def test_model_instances_cannot_bypass_plain_data_boundary_or_revalidation():
    case = fixture()
    parsed = joint.parse_dossier(case)
    with pytest.raises(ValueError, match="^invalid_joint_dossier$"):
        joint.parse_dossier(parsed)
    case["evidence"][0] = parsed.evidence[0]
    with pytest.raises(ValueError, match="^invalid_joint_dossier$"):
        joint.parse_dossier(case)
    object.__setattr__(parsed.evidence[0], "dst_port", -1)
    with pytest.raises(ValueError):
        joint.Dossier.model_validate(parsed)


def test_dossier_byte_record_and_cyclic_input_bounds():
    case = fixture()
    case["raw"] = "x" * joint.MAX_DOSSIER_BYTES
    with pytest.raises(ValueError, match="^invalid_joint_dossier$"):
        joint.parse_dossier(case)
    case = fixture()
    case["evidence"] = [deepcopy(case["evidence"][0]) for _ in range(41)]
    with pytest.raises(ValueError, match="^invalid_joint_dossier$"):
        joint.parse_dossier(case)
    case = fixture()
    case["raw"] = case
    with pytest.raises(ValueError, match="^invalid_joint_dossier$"):
        joint.parse_dossier(case)


def test_hash_is_canonical_and_input_is_unchanged():
    case = fixture()
    before = deepcopy(case)
    first = judged(case)[1]["dossier_sha256"]
    second = judged(dict(reversed(list(case.items()))))[1]["dossier_sha256"]
    assert first == second and case == before
    case["evidence"][0]["dst_port"] = 80
    assert judged(case)[1]["dossier_sha256"] != first


@pytest.mark.parametrize("change", ["linked_without_ssh", "unmatched_with_ssh", "linked_incomplete",
                                     "linked_timeline_truncated", "unavailable_with_ssh", "false_network_empty"])
def test_association_state_cannot_contradict_retained_evidence(change):
    case = fixture()
    if change == "linked_without_ssh":
        case["evidence"] = case["evidence"][:2]
        case["counts"]["ssh"] = {"observed": 0, "retained": 0, "included": 0}
    elif change == "unmatched_with_ssh":
        case["association_state"] = "unmatched"
    elif change == "linked_incomplete":
        case["input_complete"] = False
        case["limitations"].append("projection_input_incomplete")
    elif change == "linked_timeline_truncated":
        case["counts"]["network"]["observed"] = 3
        case["timeline_complete"] = False
        case["limitations"].append("timeline_truncated")
    elif change == "unavailable_with_ssh":
        case["association_state"] = "partial"
        case["temporal_association_available"] = False
        case["window_duration_us"] = None
        case["limitations"].append("temporal_association_unavailable")
    else:
        case["limitations"].append("network_evidence_unavailable")
    with pytest.raises(ValueError, match="^invalid_joint_dossier$"):
        joint.parse_dossier(case)


def test_unmatched_network_observation_can_be_reviewed_without_claiming_safety():
    case = fixture()
    case["evidence"] = case["evidence"][:2]
    case["counts"]["ssh"] = {"observed": 0, "retained": 0, "included": 0}
    case["association_state"] = "unmatched"
    value = proposal(case, "network_observed", [case["evidence"][0]["event_id"]])
    assert judged(case, value)[0]["verdict"] == "escalate"
