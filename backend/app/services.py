"""Platform services bundle.

Groups the cross-cutting services (storage, evidence vault, audit, clock, IDs,
policy engine, agent registry, workflow runtime) so the pipeline can be
constructed once and threaded through each stage. A fixed clock makes a run
fully deterministic, which is what replay relies on.
"""
from __future__ import annotations

from dataclasses import dataclass

from .agents.contract import AgentRegistry
from .agents.triage import TriageAgent
from .core.clock import Clock, SystemClock
from .core.ids import IdFactory
from .policy.engine import PolicyEngine
from .runtime.workflow import WorkflowRuntime
from .storage.audit_log import AuditLog
from .storage.evidence_store import EvidenceStore
from .storage.repository import InMemoryRepository, Repository


@dataclass
class Services:
    repo: Repository
    evidence: EvidenceStore
    audit: AuditLog
    clock: Clock
    ids: IdFactory
    policy: PolicyEngine
    registry: AgentRegistry
    runtime: WorkflowRuntime

    @classmethod
    def create(cls, repo: Repository | None = None, clock: Clock | None = None) -> "Services":
        repo = repo or InMemoryRepository()
        clock = clock or SystemClock()
        ids = IdFactory()
        audit = AuditLog(clock, ids)
        registry = AgentRegistry()
        registry.register(TriageAgent())
        return cls(
            repo=repo,
            evidence=EvidenceStore(),
            audit=audit,
            clock=clock,
            ids=ids,
            policy=PolicyEngine(clock),
            registry=registry,
            runtime=WorkflowRuntime(repo, audit, clock, ids),
        )
