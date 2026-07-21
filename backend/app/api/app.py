"""FastAPI surface over the walking skeleton.

A thin read/act layer: run the sample flow, then inspect the resulting
incidents, action plans, policy decisions, and the audit trail. State lives in a
process-lifetime Services instance (SQLite-backed) so GET endpoints see what a
run produced.
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException

from ..orchestrator import default_scope, run_flow
from ..samples import sample_sources
from ..services import Services
from ..storage.repository import SqliteRepository

app = FastAPI(title="SecAgent RiskOps", version="0.2.0",
              description="MVP walking skeleton: ingest -> triage -> incident -> GRC -> gated remediation.")

_services: Services | None = None


def get_services() -> Services:
    global _services
    if _services is None:
        _services = Services.create(repo=SqliteRepository())
    return _services


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/flows/run")
def run_sample_flow() -> dict[str, object]:
    """Ingest and process the bundled sample alerts."""
    svc = get_services()
    _, result = run_flow(sample_sources(), svc=svc, scope=default_scope(svc.clock))
    return {
        "flow_id": result.flow_id,
        "flow_status": result.flow_status,
        "alerts": len(result.ingest.alerts),
        "groups": len(result.ingest.groups),
        "incidents": [i.incident_id for i in result.incidents],
        "action_plans": [
            {"id": p.action_plan_id, "status": p.status.value,
             "decision": o.policy_decision.reason_code}
            for o, p in ((o, o.action_plan) for o in result.outcomes) if p
        ],
    }


@app.get("/flows/{flow_id}")
def get_flow(flow_id: str) -> dict:
    return _require(get_services(), "flows", flow_id)


@app.get("/incidents")
def list_incidents() -> list[dict]:
    return get_services().repo.list("incidents")


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str) -> dict:
    return _require(get_services(), "incidents", incident_id)


@app.get("/action-plans/{action_plan_id}")
def get_action_plan(action_plan_id: str) -> dict:
    return _require(get_services(), "action_plans", action_plan_id)


@app.get("/audit")
def list_audit() -> list[dict]:
    return [e.model_dump() for e in get_services().audit.events()]


@app.get("/audit/verify")
def verify_audit() -> dict[str, bool]:
    return {"chain_intact": get_services().audit.verify_chain()}


def _require(svc: Services, collection: str, obj_id: str) -> dict:
    obj = svc.repo.get(collection, obj_id)
    if obj is None:
        raise HTTPException(status_code=404, detail=f"{collection[:-1]} {obj_id} not found")
    return obj
