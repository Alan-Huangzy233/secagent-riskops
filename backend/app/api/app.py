"""FastAPI surface over the walking skeleton, and the web demo.

A thin read/act layer: run the sample flow, then inspect the resulting
incidents, action plans, policy decisions, and the audit trail. State lives in a
process-lifetime Services instance (SQLite-backed) so GET endpoints see what a
run produced.

``/demo`` is a read-only page that replays one labelled synthetic week from a
precomputed snapshot. Its two POST endpoints run the real policy engine, and
the executor on a temporary lab copy, per request; they keep no state.
"""
from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel, Field

from ..orchestrator import default_scope, run_flow
from ..samples import sample_sources
from ..services import Services
from ..storage.repository import SqliteRepository
from ..webdemo import respond as demo
from ..webdemo.snapshot import ROOT

STATIC = Path(__file__).resolve().parents[1] / "webdemo" / "static"
SNAPSHOT = ROOT / "docs" / "eval" / "web-demo-synthetic-7d.json"
STATIC_FILES = {"demo.css": "text/css", "demo.js": "text/javascript"}
PAGE_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                               "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
}

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


@lru_cache(maxsize=1)
def demo_snapshot() -> dict:
    return json.loads(SNAPSHOT.read_text(encoding="utf-8"))


class RespondRequest(BaseModel):
    approve: bool = False


class ScopeRequest(BaseModel):
    targets: str = Field(default="", max_length=demo.MAX_ENTRIES * demo.MAX_LENGTH)
    valid_until: str | None = Field(default=None, max_length=demo.MAX_LENGTH)


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse("/demo")


@app.get("/demo", include_in_schema=False)
def demo_page() -> FileResponse:
    return FileResponse(STATIC / "index.html", media_type="text/html", headers=PAGE_HEADERS)


@app.get("/demo/static/{name}", include_in_schema=False)
def demo_static(name: str) -> FileResponse:
    if name not in STATIC_FILES:
        raise HTTPException(status_code=404, detail="not found")
    return FileResponse(STATIC / name, media_type=STATIC_FILES[name], headers=PAGE_HEADERS)


@app.get("/demo/snapshot.json")
def demo_data() -> FileResponse:
    """The precomputed synthetic week the page replays."""
    return FileResponse(SNAPSHOT, media_type="application/json", headers=PAGE_HEADERS)


@app.post("/demo/incidents/{incident_id}/respond")
def demo_respond(incident_id: str, request: RespondRequest) -> dict:
    """Run the incident's plan through the policy gate and, when approved, on a lab copy."""
    try:
        return demo.respond(demo_snapshot(), incident_id, approve=request.approve)
    except demo.NotFound as error:
        raise HTTPException(status_code=404, detail=f"no response plan for {error}") from None


@app.post("/demo/incidents/{incident_id}/scope-check")
def demo_scope_check(incident_id: str, request: ScopeRequest) -> dict:
    """Evaluate the approved plan under a scope the visitor typed."""
    try:
        return demo.scope_check(demo_snapshot(), incident_id, targets=request.targets,
                                valid_until=request.valid_until)
    except demo.NotFound as error:
        raise HTTPException(status_code=404, detail=f"no response plan for {error}") from None
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None


def _require(svc: Services, collection: str, obj_id: str) -> dict:
    obj = svc.repo.get(collection, obj_id)
    if obj is None:
        raise HTTPException(status_code=404, detail=f"{collection[:-1]} {obj_id} not found")
    return obj
