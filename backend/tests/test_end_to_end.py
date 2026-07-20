"""End-to-end test mapping directly to the charter's Initial Success Criteria."""
from __future__ import annotations

from app.orchestrator import run_flow
from app.schemas.enums import ActionPlanStatus, Disposition, PolicyEffect
from app.samples import sample_sources
from app.policy.reason_codes import ReasonCode


def test_walking_skeleton_hits_all_success_criteria(services):
    svc, result = run_flow(sample_sources(), svc=services)

    # 1 + 3: ingest, normalize, group, score.
    assert len(result.ingest.alerts) == 4
    assert len(result.ingest.groups) == 2

    # 2: raw input preserved as verifiable evidence.
    assert all(svc.evidence.verify(e.content_hash) for e in result.ingest.evidences)

    # 4 + 5: evidence-grounded triage -> inspectable incident.
    assert len(result.incidents) == 1
    incident = result.incidents[0]
    assert incident.triage_ref is not None
    assert "T1110" in incident.attack_techniques

    ssh_outcome = next(o for o in result.outcomes if o.incident)
    assert ssh_outcome.recommendation.disposition == Disposition.ESCALATE
    assert ssh_outcome.recommendation.evidence_ids  # grounded

    # 6: mapped to at least one control and a risk candidate.
    assert ssh_outcome.control_mapping is not None
    assert ssh_outcome.control_mapping.control_id == "AC-7"
    assert ssh_outcome.risk is not None

    # 7: ActionPlan created but NOT executed (policy gate denies).
    plan = ssh_outcome.action_plan
    assert plan is not None
    assert plan.status == ActionPlanStatus.PROPOSED
    assert ssh_outcome.policy_decision.effect == PolicyEffect.DENY
    assert ssh_outcome.policy_decision.reason_code == ReasonCode.APPROVAL_REQUIRED

    # Flow parks awaiting human approval; audit chain intact.
    assert result.flow_status == "waiting_for_approval"
    assert svc.audit.verify_chain() is True


def test_low_risk_group_is_monitored_not_escalated(services):
    _, result = run_flow(sample_sources(), svc=services)
    suri = next(o for o in result.outcomes if o.signature == "suspicious_outbound_tls")
    assert suri.incident is None
    assert suri.recommendation.disposition == Disposition.MONITOR
