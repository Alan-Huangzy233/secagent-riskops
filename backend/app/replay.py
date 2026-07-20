"""Replay a completed flow from retained raw evidence.

Replay pulls the original bytes back out of the content-addressed evidence
vault (verifying their hash), reconstructs the ingest sources, and re-runs the
same deterministic pipeline under the same fixed clock. Because IDs and
timestamps are deterministic, a faithful replay reproduces the stored objects
exactly — charter success criterion 8.
"""
from __future__ import annotations

from .core.clock import Clock
from .orchestrator import FlowResult, default_scope, run_flow
from .pipeline.ingest import RawSource
from .schemas.models import AssessmentScope
from .services import Services

# Collections whose contents must be identical between the original run and its
# replay for the replay to be considered faithful.
VERIFIED_COLLECTIONS = (
    "evidence", "alerts", "alert_groups", "agent_runs",
    "incidents", "control_mappings", "risks", "action_plans", "policy_decisions",
)


def reconstruct_sources(original: Services) -> list[RawSource]:
    sources: list[RawSource] = []
    for ev in original.repo.list("evidence"):
        ref = ev["storage_ref"]
        if not original.evidence.verify(ref):
            raise ValueError(f"Evidence integrity check failed for {ev['evidence_id']}")
        sources.append(RawSource(
            name=ev["source"],
            source_type=ev["source_type"],
            media_type=ev["media_type"],
            data=original.evidence.get(ref),
        ))
    return sources


def replay(original: Services, clock: Clock, scope: AssessmentScope | None = None) -> tuple[Services, FlowResult]:
    sources = reconstruct_sources(original)
    svc = Services.create(clock=clock)
    scope = scope or default_scope(clock)
    return run_flow(sources, svc=svc, scope=scope, actor="security-operator")


def diff_collections(a: Services, b: Services) -> dict[str, str]:
    """Return {collection: reason} for any collection that differs."""
    mismatches: dict[str, str] = {}
    for name in VERIFIED_COLLECTIONS:
        rows_a = a.repo.list(name)
        rows_b = b.repo.list(name)
        if rows_a != rows_b:
            mismatches[name] = f"{len(rows_a)} vs {len(rows_b)} rows or differing content"
    return mismatches
