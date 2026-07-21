"""End-to-end walking-skeleton flow.

Ties the stages together as one auditable Flow and returns a structured result.
This is the concrete realisation of the charter's eight "Initial Success
Criteria": ingest -> evidence -> normalize/group/score -> triage -> incident ->
control + risk -> ActionPlan (created, not executed) -> replayable audit trail.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .authorization import make_scope
from .core.clock import Clock, FixedClock
from .pipeline import grc, remediation, soc
from .pipeline.ingest import IngestResult, RawSource, ingest
from .schemas.enums import AutonomyLevel, FlowStatus
from .schemas.models import (
    ActionPlan,
    AssessmentScope,
    ControlMapping,
    Incident,
    PolicyDecision,
    Risk,
    TriageRecommendation,
)
from .services import Services

DEFAULT_ACTOR = "security-operator"


@dataclass
class GroupOutcome:
    group_id: str
    signature: str
    risk_score: int
    risk_band: str
    recommendation: TriageRecommendation
    incident: Incident | None = None
    control_mapping: ControlMapping | None = None
    risk: Risk | None = None
    action_plan: ActionPlan | None = None
    policy_decision: PolicyDecision | None = None


@dataclass
class FlowResult:
    flow_id: str
    flow_status: str
    ingest: IngestResult
    outcomes: list[GroupOutcome] = field(default_factory=list)

    @property
    def incidents(self) -> list[Incident]:
        return [o.incident for o in self.outcomes if o.incident]

    @property
    def action_plans(self) -> list[ActionPlan]:
        return [o.action_plan for o in self.outcomes if o.action_plan]


def default_scope(clock: Clock) -> AssessmentScope:
    return make_scope(
        "SCOPE-DEMO",
        autonomy_level=AutonomyLevel.SUGGEST_ONLY,
        allowed_actors=(DEFAULT_ACTOR,),
        target_allowlist=("web-01", "*.example.internal"),
    )


def run_flow(
    sources: list[RawSource],
    *,
    svc: Services | None = None,
    scope: AssessmentScope | None = None,
    actor: str = DEFAULT_ACTOR,
) -> tuple[Services, FlowResult]:
    svc = svc or Services.create(clock=FixedClock(datetime(2026, 7, 6, 21, 15, tzinfo=timezone.utc)))
    scope = scope or default_scope(svc.clock)
    rt = svc.runtime

    flow = rt.start_flow("soc_investigation", "Ingest and triage authorized sample alerts")

    # --- Ingest -----------------------------------------------------------
    ingest_task = rt.add_task(flow, "Ingest and normalize alerts")
    ingest_step = rt.add_step(flow, ingest_task, "ingest_sources", "deterministic")
    result = ingest(svc, sources)
    rt.tool_call(flow, ingest_step, "ingest.run",
                 input={"sources": [s.name for s in sources]},
                 output={"alerts": len(result.alerts), "groups": len(result.groups)},
                 evidence_ids=[e.evidence_id for e in result.evidences])
    for group in result.groups:
        rt.add_artifact(flow, "alert_group", group.group_id)

    # --- Per-group triage / GRC / remediation -----------------------------
    outcomes: list[GroupOutcome] = []
    any_awaiting_approval = False

    for group in result.groups:
        triage_task = rt.add_task(flow, f"Triage {group.group_id}")
        triage_step = rt.add_step(flow, triage_task, "ai_triage", "agent")
        rec, incident = soc.triage_group(svc, group)
        rt.tool_call(flow, triage_step, "soc.triage_group",
                     input={"group_id": group.group_id},
                     output={"disposition": rec.disposition.value, "confidence": rec.confidence},
                     evidence_ids=rec.evidence_ids, agent_run_ref=rec.produced_by)

        outcome = GroupOutcome(
            group_id=group.group_id, signature=group.signature,
            risk_score=group.risk_score, risk_band=group.risk_band.value,
            recommendation=rec,
        )

        if incident is not None:
            flow.related_incident_id = incident.incident_id
            rt.add_artifact(flow, "incident", incident.incident_id)
            outcome.incident = incident

            grc_task = rt.add_task(flow, f"Map {incident.incident_id} to controls and risk")
            grc_step = rt.add_step(flow, grc_task, "grc_mapping", "deterministic")
            mapping, risk = grc.map_incident(svc, incident, group.signature)
            rt.tool_call(flow, grc_step, "grc.map_incident",
                         input={"incident_id": incident.incident_id},
                         output={"control": mapping.control_id if mapping else None,
                                 "risk_id": risk.risk_id})
            outcome.control_mapping = mapping
            outcome.risk = risk

            rem_task = rt.add_task(flow, f"Plan remediation for {incident.incident_id}")
            plan_step = rt.add_step(flow, rem_task, "build_action_plan", "deterministic")
            plan = remediation.build_action_plan(svc, incident, rec)
            if plan is not None:
                rt.add_artifact(flow, "action_plan", plan.action_plan_id)
                gate_step = rt.add_step(flow, rem_task, "policy_gate", "policy")
                decision, plan = remediation.evaluate_execution(svc, plan, scope, actor)
                rt.tool_call(flow, gate_step, "policy.evaluate",
                             input={"action_plan_id": plan.action_plan_id,
                                    "action_type": plan.action_type},
                             output={"effect": decision.effect.value,
                                     "reason_code": decision.reason_code})
                outcome.action_plan = plan
                outcome.policy_decision = decision
                any_awaiting_approval = True

        outcomes.append(outcome)

    final_status = FlowStatus.WAITING_FOR_APPROVAL if any_awaiting_approval else FlowStatus.COMPLETED
    flow = rt.set_flow_status(flow, final_status)

    return svc, FlowResult(
        flow_id=flow.flow_id,
        flow_status=final_status.value,
        ingest=result,
        outcomes=outcomes,
    )
