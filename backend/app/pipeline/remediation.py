"""Remediation stage: draft an ActionPlan, then let policy decide execution.

This is where "AI proposes; policy decides; typed executors act" becomes code.
A plan is drafted from a recommendation. Execution is gated: an ActionRequest
is submitted to the independent policy engine, and only an ALLOW lets a typed
executor run. Whether the request carries an approval is decided here, from a
recorded Approval bound to the plan's hash and the scope's policy hash, never
from anything a caller or a model asserts.

After an executor runs, the result is verified by re-reading the target, and a
failed verification rolls the change back without waiting for a person; the
rollback is verified as well. Each step goes into the audit chain with the
hashes, checks and states it rests on, so the whole sequence can be rebuilt
from the chain alone.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..core.clock import isoformat
from ..core.hashing import canonical_json, policy_hash
from ..schemas.enums import ActionPlanStatus, PolicyEffect
from ..schemas.models import (
    ActionPlan,
    ActionRequest,
    Approval,
    AssessmentScope,
    Incident,
    PolicyDecision,
    TriageRecommendation,
)
from ..services import Services
from ..tools.harden_ssh import ExecutorRefused
from ..tools.registry import get_action_spec


def plan_hash(plan: ActionPlan) -> str:
    """Digest of what a plan would do; its status is not part of it."""
    return policy_hash({"action_plan_id": plan.action_plan_id, "action_type": plan.action_type,
                        "risk_level": plan.risk_level.value, "target": plan.target,
                        "parameters": plan.parameters, "rollback": plan.rollback})


def draft_plan(svc: Services, action_type: str, asset_id: str, *, created_from: str,
               evidence_ids: list[str]) -> ActionPlan | None:
    spec = get_action_spec(action_type)
    if spec is None:
        return None
    plan = ActionPlan(
        action_plan_id=svc.ids.next("AP"),
        title=spec.title,
        action_type=spec.action_type,
        risk_level=spec.risk_level,
        status=ActionPlanStatus.PROPOSED,
        target={"asset_id": asset_id},
        parameters=dict(spec.default_parameters),
        rollback=spec.rollback,
        requires_approval=True,
        created_from=created_from,
        evidence_ids=evidence_ids,
        created_at=isoformat(svc.clock.now()),
    )
    svc.repo.save("action_plans", plan.action_plan_id, plan)
    svc.audit.record("plan.created", "system", subject_ref=plan.action_plan_id,
                     payload={"action_type": plan.action_type, "target": asset_id,
                              "risk_level": plan.risk_level.value, "parameters": plan.parameters,
                              "created_from": created_from, "plan_hash": plan_hash(plan)})
    return plan


def playbook(case: dict, verdict: str) -> list[tuple[str, str, list[str]]]:
    """Fixed response rules for an incident the triage agent escalated.

    The model decides only escalate, dismiss or abstain; which action follows
    is decided here. A password login that succeeded from a source never seen
    logging in as that account before means the password was guessed, so the
    host should stop accepting passwords: ``harden_ssh_access`` on that host.
    Returns (action type, host, evidence ids).
    """
    if verdict != "escalate":
        return []
    actions: dict[str, list[str]] = {}
    for login in case.get("successful_logins", []):
        if not login["source_had_logged_in_as_account_before"]:
            actions.setdefault(login["host"], []).append(login["event_id"])
    return [("harden_ssh_access", host, evidence) for host, evidence in sorted(actions.items())]


def build_action_plan(svc: Services, incident: Incident, rec: TriageRecommendation) -> ActionPlan | None:
    if not rec.recommended_action_types:
        return None
    return draft_plan(svc, rec.recommended_action_types[0], incident.asset_id,
                      created_from=incident.incident_id, evidence_ids=incident.evidence_ids)


def record_approval(svc: Services, plan: ActionPlan, scope: AssessmentScope, approver: str,
                    decision: str = "approved") -> Approval:
    """Record a decision on this exact plan under this exact scope."""
    if decision not in ("approved", "rejected"):
        raise ValueError(f"unknown decision {decision!r}")
    if approver not in scope.allowed_actors:
        raise ValueError(f"{approver!r} is not a permitted actor in {scope.scope_id}")
    approval = Approval(
        approval_id=svc.ids.next("APR"), subject_ref=plan.action_plan_id, decision=decision,
        approver=approver, plan_hash=plan_hash(plan), policy_hash=scope.policy_hash,
        decided_at=isoformat(svc.clock.now()),
    )
    svc.repo.save("approvals", approval.approval_id, approval)
    svc.audit.record("approval.recorded", approver, subject_ref=plan.action_plan_id,
                     payload={"approval_id": approval.approval_id, "decision": decision, "approver": approver,
                              "plan_hash": approval.plan_hash, "policy_hash": approval.policy_hash})
    return approval


def valid_approval(svc: Services, plan: ActionPlan, scope: AssessmentScope) -> Approval | None:
    """The latest decision on this plan under this scope, if it approves the plan as it is now."""
    decisions = [Approval(**row) for row in svc.repo.list("approvals")
                 if row["subject_ref"] == plan.action_plan_id and row["policy_hash"] == scope.policy_hash]
    if not decisions:
        return None
    latest = max(decisions, key=lambda approval: approval.approval_id)
    if latest.decision != "approved" or latest.plan_hash != plan_hash(plan):
        return None
    return latest


def evaluate_execution(
    svc: Services, plan: ActionPlan, scope: AssessmentScope, actor: str
) -> tuple[PolicyDecision, ActionPlan]:
    """Ask the policy engine whether this plan may execute now. Fail closed."""
    approval = valid_approval(svc, plan, scope)
    request = ActionRequest(
        request_id=svc.ids.next("REQ"),
        actor=actor,
        action_type=plan.action_type,
        risk_level=plan.risk_level,
        target=plan.target.get("asset_id", ""),
        action_plan_id=plan.action_plan_id,
        has_approval=approval is not None,
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
        payload={"effect": decision.effect.value, "reason_code": decision.reason_code,
                 "scope_id": scope.scope_id, "policy_hash": scope.policy_hash, "plan_hash": plan_hash(plan),
                 "approval_id": approval.approval_id if approval else None},
    )

    # A DENY leaves the plan a proposal; an ALLOW marks it approved. Neither
    # invokes an executor here.
    status = ActionPlanStatus.APPROVED if decision.effect == PolicyEffect.ALLOW else ActionPlanStatus.PROPOSED
    plan = plan.model_copy(update={"status": status})
    svc.repo.save("action_plans", plan.action_plan_id, plan)
    return decision, plan


@dataclass
class Execution:
    plan: ActionPlan
    decision: PolicyDecision
    approval: Approval | None = None
    refused: str | None = None
    change: object | None = None  # tools.harden_ssh.Change
    verification: object | None = None  # tools.harden_ssh.Verification
    rollback: dict | None = None
    states: dict[str, dict] = field(default_factory=dict)  # before / after / restored


def _set_status(svc: Services, plan: ActionPlan, status: ActionPlanStatus) -> ActionPlan:
    plan = plan.model_copy(update={"status": status})
    svc.repo.save("action_plans", plan.action_plan_id, plan)
    return plan


def execute_plan(svc: Services, plan: ActionPlan, scope: AssessmentScope, actor: str, executor) -> Execution:
    """Policy gate, then execute, verify, and roll back on a failed verification."""
    decision, plan = evaluate_execution(svc, plan, scope, actor)
    outcome = Execution(plan, decision, valid_approval(svc, plan, scope))
    if decision.effect != PolicyEffect.ALLOW:
        return outcome
    name = f"executor.{plan.action_type}"
    target = plan.target.get("asset_id")
    try:
        if executor.action_type != plan.action_type or executor.asset_id != target:
            raise ExecutorRefused(f"executor for {executor.action_type} on {executor.asset_id} "
                                  f"cannot run {plan.action_type} on {target}")
        outcome.states["before"] = executor.state()
        change = executor.apply(plan.action_plan_id, plan.parameters)
    except ExecutorRefused as error:
        outcome.refused = str(error)
        svc.audit.record("execution.refused", name, subject_ref=plan.action_plan_id,
                         payload={"target": target, "reason": str(error)})
        return outcome
    svc.evidence.put((executor.root / change.backup).read_bytes())
    svc.evidence.put(executor.config.read_bytes())
    outcome.change, outcome.states["after"] = change, executor.state()
    outcome.plan = _set_status(svc, plan, ActionPlanStatus.EXECUTED)
    svc.audit.record("execution.applied", name, subject_ref=plan.action_plan_id,
                     payload={"target": target, "requested_by": actor, "file": change.file,
                              "before_sha256": change.before_sha256, "after_sha256": change.after_sha256,
                              "backup": change.backup, "edits": list(change.edits), "diff": list(change.diff),
                              "state_before": outcome.states["before"], "state_after": outcome.states["after"],
                              "reload": "skipped: lab copy, no daemon"})

    verification = executor.verify(plan.parameters)
    outcome.verification = verification
    report = verification.to_dict()
    svc.audit.record("execution.verified", "verifier.sshd_config", subject_ref=plan.action_plan_id,
                     payload={"target": target, **report,
                              "report_ref": svc.evidence.put(canonical_json(report).encode("utf-8"))})
    if verification.ok:
        outcome.plan = _set_status(svc, outcome.plan, ActionPlanStatus.VERIFIED)
        return outcome

    restored = executor.rollback(change)
    outcome.states["restored"] = executor.state()
    same_state = outcome.states["restored"] == outcome.states["before"]
    outcome.rollback = {**restored, "state_matches_before": same_state,
                        "ok": restored["matches_before"] and same_state}
    svc.audit.record("rollback.applied", name, subject_ref=plan.action_plan_id,
                     payload={"target": target, "reason": "verification failed",
                              "failed_checks": [check for check in report["checks"] if not check["ok"]],
                              "backup": change.backup, "restored_sha256": restored["restored_sha256"]})
    svc.audit.record("rollback.verified", "verifier.sshd_config", subject_ref=plan.action_plan_id,
                     payload={"target": target, "ok": outcome.rollback["ok"],
                              "file_matches_before": restored["matches_before"],
                              "state_matches_before": same_state, "state_restored": outcome.states["restored"]})
    outcome.plan = _set_status(svc, outcome.plan, ActionPlanStatus.ROLLED_BACK)
    return outcome
