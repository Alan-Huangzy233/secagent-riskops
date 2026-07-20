"""SOC stage: run triage behind the agent boundary, create incidents.

The triage agent proposes a disposition; a deterministic skeptic check then
requires evidence and a minimum confidence before an escalation may become an
incident. The agent never creates the incident itself.
"""
from __future__ import annotations

from ..core.clock import isoformat
from ..schemas.enums import Disposition, RunStatus
from ..schemas.models import AgentRun, AlertGroup, Incident, TriageRecommendation
from ..services import Services

_MIN_ESCALATION_CONFIDENCE = 0.5


def _run_triage_agent(svc: Services, group: AlertGroup) -> tuple[AgentRun, TriageRecommendation]:
    started = isoformat(svc.clock.now())
    agent = svc.registry.resolve("soc.triage")
    result = agent.run({"alert_group": group.model_dump()})
    finished = isoformat(svc.clock.now())

    run = AgentRun(
        agent_run_id=svc.ids.next("AR"),
        agent_name=agent.name,
        agent_version=agent.version,
        input_refs=[group.group_id],
        output=result.output,
        confidence=result.confidence,
        evidence_ids=result.evidence_ids,
        status=RunStatus.OK,
        started_at=started,
        finished_at=finished,
    )
    svc.repo.save("agent_runs", run.agent_run_id, run)

    recommendation = TriageRecommendation(
        disposition=Disposition(result.output["disposition"]),
        confidence=result.confidence,
        rationale=result.rationale,
        evidence_ids=result.evidence_ids,
        attack_techniques=result.output.get("attack_techniques", []),
        recommended_action_types=result.output.get("recommended_action_types", []),
        produced_by=run.agent_run_id,
    )
    return run, recommendation


def _skeptic_allows_escalation(rec: TriageRecommendation) -> bool:
    """Deterministic validation before an AI escalation becomes an incident."""
    return bool(rec.evidence_ids) and rec.confidence >= _MIN_ESCALATION_CONFIDENCE


def triage_group(svc: Services, group: AlertGroup) -> tuple[TriageRecommendation, Incident | None]:
    _run, rec = _run_triage_agent(svc, group)

    if rec.disposition != Disposition.ESCALATE or not _skeptic_allows_escalation(rec):
        return rec, None

    incident = Incident(
        incident_id=svc.ids.next("INC"),
        title=f"{group.signature} on {group.asset_id}",
        severity=group.severity,
        asset_id=group.asset_id,
        alert_group_ids=[group.group_id],
        evidence_ids=group.evidence_ids,
        triage_ref=rec.produced_by,
        attack_techniques=rec.attack_techniques,
        created_at=isoformat(svc.clock.now()),
    )
    svc.repo.save("incidents", incident.incident_id, incident)
    return rec, incident
