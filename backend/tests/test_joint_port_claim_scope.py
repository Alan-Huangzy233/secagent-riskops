"""Synthetic evidence groups cannot be combined into a multi-port claim."""
from copy import deepcopy
import json

import pytest

from app.agents import joint_triage as joint


def _alias(prefix, number):
    return f"{prefix}-{number:024x}"


def _case(groups=(((1, 1), (22, 443)),)):
    common = {"asset": _alias("A", 1), "peer": _alias("P", 1)}
    records = []
    for (source, destination), ports in groups:
        for port in ports:
            number = len(records) + 1
            records.append({
                **common, "kind": "network_tcp", "event_id": _alias("E", number),
                "offset_us": number, "source": _alias("S", source),
                "destination": _alias("D", destination), "dst_port": port,
                "protocol": "TCP", "direction": "local_input",
            })
    network_count = len(records)
    records.append({
        **common, "kind": "ssh", "event_id": _alias("E", network_count + 1),
        "offset_us": network_count + 1, "source": _alias("S", 9),
        "event_type": "auth_failure", "account": _alias("U", 1),
    })
    return {
        "dossier_version": joint.VERSION, "case_id": _alias("J", 1),
        "revision": _alias("R", 1), "kind": "network_ssh", **common,
        "association_state": "linked", "review_state": "current",
        "input_complete": True, "timeline_complete": True, "summary_complete": True,
        "coverage_complete": None, "temporal_association_available": True,
        "window_duration_us": len(records), "limitations": sorted(joint.BASE_LIMITATIONS),
        "counts": {
            "network": {"observed": network_count, "retained": network_count, "included": network_count},
            "ssh": {"observed": 1, "retained": 1, "included": 1},
        },
        "evidence": records,
    }


def _claim(case, indices, kind="multiple_destination_ports"):
    return {"kind": kind, "evidence_ids": [case["evidence"][i]["event_id"] for i in indices]}


def _proposal(case, claims, *, verdict="escalate", top_level_ids=()):
    return {
        "verdict": verdict, "confidence": "high", "rationale": "Synthetic bounded observation.",
        "revision": case["revision"], "evidence_ids": list(top_level_ids),
        "attack_techniques": [], "claims": claims,
    }


def _judge(case, claims, **kwargs):
    # Every claim test uses a dossier accepted by the public schema first.
    joint.parse_dossier(case)
    return joint.validate(json.dumps(_proposal(case, claims, **kwargs)), case)


def _assert_valid(result, details, verdict="escalate"):
    assert result["verdict"] == verdict
    assert details["status"] == "valid"
    assert details["reasons"] == []


def _assert_unsupported(result, details, index=0):
    assert result["verdict"] == "abstain"
    assert result["evidence_ids"] == []
    assert details["status"] == "requires_review"
    assert details["reasons"] == [{"code": "unsupported_claim", "claim_index": index}]


@pytest.mark.parametrize("ports", [(22, 443), (22, 22, 443), (22, 443, 8443)])
def test_distinct_ports_with_one_identity_are_supported(ports):
    case = _case((((1, 1), ports),))
    claim = _claim(case, range(len(ports)))
    result, details = _judge(case, [claim])
    _assert_valid(result, details)
    assert set(result["evidence_ids"]) == set(claim["evidence_ids"])


@pytest.mark.parametrize("second_identity", [(2, 1), (1, 2), (2, 2)])
@pytest.mark.parametrize("verdict", ["escalate", "abstain"])
def test_distinct_ports_across_groups_are_unsupported(second_identity, verdict):
    case = _case((((1, 1), (22,)), (second_identity, (443,))))
    _assert_unsupported(*_judge(case, [_claim(case, [0, 1])], verdict=verdict))


@pytest.mark.parametrize("count", [2, 3])
def test_repeated_observations_of_one_port_do_not_establish_multiple_ports(count):
    case = _case((((1, 1), (443,) * count),))
    _assert_unsupported(*_judge(case, [_claim(case, range(count))]))


@pytest.mark.parametrize("second_identity", [(2, 1), (1, 2)])
def test_claim_can_select_one_group_from_a_dossier_with_other_groups(second_identity):
    case = _case((((1, 1), (22, 443)), (second_identity, (8080, 8443))))
    first_group = _claim(case, [0, 1])
    # Extra top-level references identify observations but do not enlarge a claim's proof.
    top_level_ids = [row["event_id"] for row in case["evidence"]]
    _assert_valid(*_judge(case, [first_group], top_level_ids=top_level_ids))
    _assert_unsupported(*_judge(case, [_claim(case, [0, 1, 2, 3])]))


@pytest.mark.parametrize("second_identity", [(2, 1), (1, 2)])
def test_each_group_can_support_a_separate_claim(second_identity):
    case = _case((((1, 1), (22, 443)), (second_identity, (8080, 8443))))
    claims = [_claim(case, [0, 1]), _claim(case, [2, 3])]
    _assert_valid(*_judge(case, claims))
    # One supported claim cannot hide an additional claim that crosses groups.
    claims.append(_claim(case, [1, 2]))
    _assert_unsupported(*_judge(case, claims), index=2)


def test_ports_elsewhere_in_dossier_cannot_supply_missing_claim_support():
    case = _case((((1, 1), (22, 443)),))
    _assert_unsupported(*_judge(case, [_claim(case, [0])],
                              top_level_ids=[row["event_id"] for row in case["evidence"]]))


def test_ssh_evidence_requires_its_own_claim():
    case = _case()
    _assert_unsupported(*_judge(case, [_claim(case, [0, 1, 2])]))
    _assert_valid(*_judge(case, [
        _claim(case, [0, 1]), _claim(case, [2], "ssh_failure_observed"),
    ]))


@pytest.mark.parametrize("field,prefix", [("asset", "A"), ("peer", "P")])
def test_cross_asset_or_peer_records_are_rejected_before_claim_validation(field, prefix):
    case = _case()
    case["evidence"][1][field] = _alias(prefix, 2)
    with pytest.raises(ValueError, match="^invalid_joint_dossier$"):
        joint.validate(json.dumps(_proposal(case, [_claim(case, [0, 1])])), case)


@pytest.mark.parametrize("state", ["linked", "partial"])
def test_baseline_clock_uncertainty_does_not_forbid_supported_association(state):
    case = _case()
    case["association_state"] = state
    assert "clock_alignment_unknown" in case["limitations"]
    _assert_valid(*_judge(case, [_claim(case, [0, 2], "ssh_network_associated")]))


@pytest.mark.parametrize("limit", ["network_anchor_span_exceeded", "network_clock_unverifiable"])
def test_temporal_blocker_forbids_association_but_preserves_local_port_claim(limit):
    case = _case()
    case["limitations"].append(limit)
    _assert_unsupported(*_judge(case, [_claim(case, [0, 2], "ssh_network_associated")]))
    _assert_valid(*_judge(case, [_claim(case, [0, 1])]))


@pytest.mark.parametrize("location", ["claim", "top_level"])
def test_unknown_reference_is_not_repaired_by_an_otherwise_valid_port_group(location):
    case = _case()
    claims = [_claim(case, [0, 1])]
    unknown = _alias("E", 99)
    top_level = []
    if location == "claim":
        claims[0]["evidence_ids"].append(unknown)
    else:
        top_level.append(unknown)
    result, details = _judge(case, claims, top_level_ids=top_level)
    assert result["verdict"] == "abstain" and result["evidence_ids"] == []
    assert details["reasons"] == [{"code": "unknown_evidence"}]
    assert unknown not in json.dumps(details["reasons"])


def test_validation_does_not_modify_groups_or_model_proposal():
    case = _case((((1, 1), (22, 443)), ((1, 2), (8080, 8443))))
    claims = [_claim(case, [0, 1]), _claim(case, [2, 3])]
    originals = deepcopy((case, claims))
    _assert_valid(*_judge(case, claims))
    assert (case, claims) == originals
