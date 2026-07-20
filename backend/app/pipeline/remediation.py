"""Remediation stage: draft an ActionPlan, then let policy decide execution.

This is where "AI proposes; policy decides; typed executors act" becomes code.
The plan is created but execution is gated: an ActionRequest is submitted to the
independent policy engine, and only an ALLOW would let a typed executor run. At
the default autonomy level the decision is DENY, so nothing executes.
"""
from __future__ import annotations

from ..core.clock import isoformat
from ..schemas.enums import ActionPlanStatus, PolicyEffect
from ..schemas.models import (
    ActionPlan,
    ActionRequest,
    AssessmentScope,
    Incident,
    PolicyDecision,
    TriageRecommendation,
)
from ..services import Services
from ..tools.registry import get_action_spec


def build_action_plan(svc: Services, incident: Incident, rec: TriageRecommendation) -> ActionPlan | None:
    if not rec.recommended_action_types:
        return None
    spec = get_action_spec(rec.recommended_action_types[0])
    if spec is None:
        return None

    plan = ActionPlan(
        action_plan_id=svc.ids.next("AP"),
        title=spec.title,
        action_type=spec.action_type,
        risk_level=spec.risk_level,
        status=ActionPlanStatus.PROPOSED,
        target={"asset_id": incident.asset_id},
        parameters=dict(spec.default_parameters),
        rollback=spec.rollback,
        requires_approval=True,
        created_from=incident.incident_id,
        evidence_ids=incident.evidence_ids,
        created_at=isoformat(svc.clock.now()),
    )
    svc.repo.save("action_plans", plan.action_plan_id, plan)
    return plan


def evaluate_execution(
    svc: Services, plan: ActionPlan, scope: AssessmentScope, actor: str
) -> tuple[PolicyDecision, ActionPlan]:
    """Ask the policy engine whether this plan may execute now. Fail closed."""
    request = ActionRequest(
        request_id=svc.ids.next("REQ"),
        actor=actor,
        action_type=plan.action_type,
        risk_level=plan.risk_level,
        target=plan.target.get("asset_id", ""),
        action_plan_id=plan.action_plan_id,
        has_approval=False,
        at=isoformat(svc.clock.now()),
        # Untrusted assertions the policy engine must ignore:
        claimed={"note": "auto-remediation suggested by triage agent", "pre_approved": True},
    )
    decision = svc.policy.evaluate(request, scope)
    svc.repo.save("policy_decisions", request.request_id, decision)
    svc.audit.record(
        "policy.decision",
        actor,
        subject_ref=plan.action_plan_id,
        payload={"effect": decision.effect.value, "reason_code": decision.reason_code},
    )

    # The plan only advances to EXECUTED on an explicit ALLOW; otherwise it stays
    # a proposal awaiting approval. No executor is invoked here.
    if decision.effect == PolicyEffect.DENY:
        plan = plan.model_copy(update={"status": ActionPlanStatus.PROPOSED})
    svc.repo.save("action_plans", plan.action_plan_id, plan)
    return decision, plan
