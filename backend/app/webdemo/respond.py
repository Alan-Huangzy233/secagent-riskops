"""What the page's buttons do: real policy decisions and real runs on lab copies.

Each request starts from nothing: a fresh audit chain, a fresh copy of the lab
host in a temporary directory, and a clock that starts fifteen minutes after
the incident ends and steps one second per reading, so the same click always
produces the same trail. The model verdict is the recorded one from the
snapshot; nothing here calls a model.

A host with no lab copy is refused by the executor after the policy allows the
plan. That is the executor's own boundary, and the page shows it as such.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
import shutil
import tempfile

from .. import audit_timeline
from ..authorization import make_scope
from ..core.clock import SteppingClock
from ..pipeline import remediation
from ..policy.engine import scope_problems
from ..schemas.enums import AutonomyLevel, FlowStatus
from ..services import Services
from ..tools.harden_ssh import ExecutorRefused, HardenSshExecutor
from .snapshot import LAB

OPERATOR = "security-operator"
MAX_ENTRIES, MAX_LENGTH = 12, 120


class NotFound(LookupError):
    pass


def _incident(snapshot: dict, incident_id: str) -> dict:
    for incident in snapshot["incidents"]:
        if incident["id"] == incident_id:
            return incident
    raise NotFound(incident_id)


def _scope(snapshot: dict, **overrides):
    start = datetime.fromisoformat(snapshot["dataset"]["start"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(snapshot["dataset"]["end"].replace("Z", "+00:00")) + timedelta(days=7)
    fields = dict(autonomy_level=AutonomyLevel.EXECUTE_AFTER_APPROVAL, allowed_actors=(OPERATOR,),
                  target_allowlist=tuple(snapshot["dataset"]["hosts"]),
                  valid_from=start.isoformat().replace("+00:00", "Z"), valid_until=end.isoformat().replace("+00:00", "Z"))
    fields.update(overrides)
    return make_scope(fields.pop("scope_id", "SCOPE-SYNTHETIC-ORG"), **fields)


def _services(incident: dict) -> Services:
    ended = datetime.fromisoformat(incident["last"].replace("Z", "+00:00"))
    return Services.create(clock=SteppingClock(ended + timedelta(minutes=15)))


def _decision(decision) -> dict:
    return {"effect": decision.effect.value, "reason_code": decision.reason_code, "message": decision.message}


def respond(snapshot: dict, incident_id: str, *, approve: bool, lab: Path = LAB) -> dict:
    """Run the incident's plan through the policy gate and, if approved, the executor."""
    incident = _incident(snapshot, incident_id)
    action, model = incident["action"], incident["model"]
    if action is None or model is None:
        raise NotFound(f"{incident_id} has no response plan")
    svc = _services(incident)
    rt, scope = svc.runtime, _scope(snapshot)
    flow = rt.start_flow("remediation", f"Respond to {incident_id}")
    step = rt.add_step(flow, rt.add_task(flow, f"Respond to {incident_id}"), "model_triage", "agent")
    svc.audit.record("agent.run", "agent.model_triage", flow_id=flow.flow_id, subject_ref=incident_id,
                     payload={"model": model["model"], "prompt_sha256": model["prompt_sha256"],
                              "verdict": model["verdict"], "confidence": model["confidence"],
                              "evidence_ids": model["evidence_ids"], "rationale": model["rationale"],
                              "replayed_from": "docs/eval/triage-tape-synthetic-7d.jsonl"})
    rt.tool_call(flow, step, "playbook.select", input={"incident_id": incident_id, "verdict": model["verdict"]},
                 output={"actions": [[action["type"], action["host"]]]})
    plan = remediation.draft_plan(svc, action["type"], action["host"], created_from=incident_id,
                                  evidence_ids=action["evidence_ids"])
    result: dict = {"incident_id": incident_id, "approved": approve, "steps": [],
                    "plan": {"id": plan.action_plan_id, "action_type": plan.action_type,
                             "target": action["host"], "risk_level": plan.risk_level.value,
                             "parameters": plan.parameters, "plan_hash": remediation.plan_hash(plan),
                             "scope_id": scope.scope_id}}
    decision, plan = remediation.evaluate_execution(svc, plan, scope, OPERATOR)
    result["steps"].append({"kind": "policy", "when": "before any approval", **_decision(decision)})
    if approve:
        approval = remediation.record_approval(svc, plan, scope, OPERATOR)
        result["steps"].append({"kind": "approval", "approver": approval.approver,
                                "approval_id": approval.approval_id, "plan_hash": approval.plan_hash})
        with tempfile.TemporaryDirectory(prefix="riskops-lab-") as scratch:
            host = Path(scratch) / action["host"]
            if action["lab_copy"]:
                shutil.copytree(lab / action["host"], host)
            else:
                host.mkdir()
            try:
                executor = HardenSshExecutor(host, action["host"])
            except ExecutorRefused:
                decision, plan = remediation.evaluate_execution(svc, plan, scope, OPERATOR)
                reason = f"no lab copy of {action['host']} in this demo; the executor runs only on marked lab copies"
                svc.audit.record("execution.refused", f"executor.{plan.action_type}", subject_ref=plan.action_plan_id,
                                 payload={"target": action["host"], "reason": reason})
                result["steps"].append({"kind": "policy", "when": "after approval", **_decision(decision)})
                result["steps"].append({"kind": "refused", "reason": reason})
            else:
                outcome = remediation.execute_plan(svc, plan, scope, OPERATOR, executor)
                plan = outcome.plan
                result["steps"].append({"kind": "policy", "when": "after approval", **_decision(outcome.decision)})
                result["states"] = outcome.states
                result["diff"] = list(outcome.change.diff)
                result["verification"] = outcome.verification.to_dict()
                result["rollback"] = outcome.rollback
        result["status"] = plan.status.value
    else:
        result["status"] = plan.status.value
    rt.set_flow_status(flow, FlowStatus.COMPLETED)
    rows = [event.model_dump() for event in svc.audit.events()]
    ok, message = audit_timeline.verify(rows)
    result["chain"] = {"ok": ok, "message": message, "events": len(rows)}
    result["timeline"] = [{"n": n, "time": row["recorded_at"], "segment": audit_timeline.SEGMENTS.get(row["event_type"]),
                           "actor": row["actor"], "text": audit_timeline.describe(row)}
                          for n, row in enumerate(rows, start=1)]
    result["export"] = rows
    return result


def _entries(value: str) -> tuple[str, ...]:
    """Comma-separated entries, trimmed; a blank entry is kept so the engine can refuse it."""
    if len(value) > MAX_ENTRIES * MAX_LENGTH:
        raise ValueError("too long")
    parts = tuple(part.strip() for part in value.split(",")) if value.strip() != "" else ()
    if len(parts) > MAX_ENTRIES:
        raise ValueError(f"at most {MAX_ENTRIES} entries")
    return parts


def scope_check(snapshot: dict, incident_id: str, *, targets: str, valid_until: str | None) -> dict:
    """Evaluate the incident's plan, as approved, under a scope the visitor typed."""
    incident = _incident(snapshot, incident_id)
    if incident["action"] is None:
        raise NotFound(f"{incident_id} has no response plan")
    if valid_until is not None and len(valid_until) > MAX_LENGTH:
        raise ValueError("valid_until is too long")
    overrides = {"scope_id": "SCOPE-TYPED", "target_allowlist": _entries(targets)}
    if valid_until is not None:
        overrides["valid_until"] = valid_until
    scope = _scope(snapshot, **overrides)
    svc = _services(incident)
    plan = remediation.draft_plan(svc, incident["action"]["type"], incident["action"]["host"],
                                  created_from=incident_id, evidence_ids=incident["action"]["evidence_ids"])
    remediation.record_approval(svc, plan, scope, OPERATOR)
    decision, _ = remediation.evaluate_execution(svc, plan, scope, OPERATOR)
    return {"target": incident["action"]["host"], "scope": {"target_allowlist": list(scope.target_allowlist),
                                                           "valid_until": scope.valid_until},
            "problems": scope_problems(scope), **_decision(decision)}
