"""Field-level domain contracts for the MVP walking skeleton.

These are the concrete Pydantic realisations of the objects named in
``docs/data-model.md``. Only the subset the end-to-end slice needs is modelled;
the shape mirrors the documented relationships so later modules can extend it.

Design invariants encoded here:
- Every AI output carries ``confidence`` and ``evidence_ids`` (charter rule).
- Every security conclusion links to evidence.
- Authorization objects are immutable once approved (``model_config frozen``).
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .enums import (
    ActionPlanStatus,
    AutonomyLevel,
    Disposition,
    PolicyEffect,
    RiskBand,
    RiskLevel,
    RunStatus,
    Severity,
)


# --------------------------------------------------------------------------- #
# Evidence and assets
# --------------------------------------------------------------------------- #
class Evidence(BaseModel):
    evidence_id: str
    kind: str = "raw_alert"
    content_hash: str  # sha256:... of the raw bytes (integrity / TM-03)
    media_type: str
    size_bytes: int
    source: str
    source_type: str | None = None  # parser hint, enables replay reconstruction
    captured_at: str
    storage_ref: str


class Asset(BaseModel):
    asset_id: str
    hostname: str | None = None
    criticality: Severity = Severity.LOW
    tags: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# SOC: alerts, groups, triage, incidents
# --------------------------------------------------------------------------- #
class Alert(BaseModel):
    alert_id: str
    source: str
    signature: str
    title: str
    asset_id: str
    host: str | None = None
    severity: Severity
    event_time: str
    dedup_key: str
    evidence_ids: list[str] = Field(default_factory=list)


class AlertGroup(BaseModel):
    group_id: str
    dedup_key: str
    signature: str
    asset_id: str
    severity: Severity
    count: int
    alert_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    first_seen: str
    last_seen: str
    risk_score: int = 0
    risk_band: RiskBand = RiskBand.INFORMATIONAL


class AgentRun(BaseModel):
    """A record of one agent invocation behind the AgentContract boundary."""

    agent_run_id: str
    agent_name: str
    agent_version: str
    input_refs: list[str] = Field(default_factory=list)
    output: dict[str, Any] = Field(default_factory=dict)
    confidence: float
    evidence_ids: list[str] = Field(default_factory=list)
    status: RunStatus = RunStatus.OK
    started_at: str
    finished_at: str


class TriageRecommendation(BaseModel):
    disposition: Disposition
    confidence: float
    rationale: str
    evidence_ids: list[str]
    attack_techniques: list[str] = Field(default_factory=list)
    recommended_action_types: list[str] = Field(default_factory=list)
    produced_by: str  # agent_run_id


class Incident(BaseModel):
    incident_id: str
    title: str
    severity: Severity
    status: str = "open"
    asset_id: str
    alert_group_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    triage_ref: str | None = None  # agent_run_id
    attack_techniques: list[str] = Field(default_factory=list)
    created_at: str


# --------------------------------------------------------------------------- #
# GRC: findings, controls, risks
# --------------------------------------------------------------------------- #
class Finding(BaseModel):
    finding_id: str
    asset_id: str
    title: str
    severity: Severity
    confidence: float
    source_tool: str
    evidence_ids: list[str] = Field(default_factory=list)
    remediation: str


class Control(BaseModel):
    control_id: str
    framework: str
    control_ref: str
    title: str


class ControlMapping(BaseModel):
    mapping_id: str
    incident_id: str
    control_id: str
    confidence: float
    rationale: str
    evidence_ids: list[str] = Field(default_factory=list)


class Risk(BaseModel):
    risk_id: str
    title: str
    statement: str
    likelihood: Severity
    impact: Severity
    inherent_band: RiskBand
    owner: str | None = None
    treatment_status: str = "open"
    residual_band: RiskBand | None = None
    related_incident_id: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Remediation
# --------------------------------------------------------------------------- #
class ActionPlan(BaseModel):
    action_plan_id: str
    title: str
    action_type: str
    risk_level: RiskLevel
    status: ActionPlanStatus = ActionPlanStatus.DRAFT
    target: dict[str, Any] = Field(default_factory=dict)
    parameters: dict[str, Any] = Field(default_factory=dict)
    rollback: str
    requires_approval: bool = True
    created_from: str | None = None  # finding_id / incident_id
    evidence_ids: list[str] = Field(default_factory=list)
    created_at: str


class Approval(BaseModel):
    approval_id: str
    subject_ref: str  # action_plan_id
    decision: str  # approved / rejected
    approver: str
    policy_hash: str
    decided_at: str


# --------------------------------------------------------------------------- #
# Authorization / policy
# --------------------------------------------------------------------------- #
class AssessmentScope(BaseModel):
    """Immutable, approved authorization context.

    ``frozen`` enforces the "immutable, versioned scope" rule in code: a change
    means a new version + a new ``policy_hash``, never an in-place edit.
    """

    model_config = {"frozen": True}

    scope_id: str
    scope_version: int
    policy_hash: str
    approved: bool
    autonomy_level: AutonomyLevel
    allowed_actors: tuple[str, ...] = ()
    target_allowlist: tuple[str, ...] = ()
    valid_from: str | None = None
    valid_until: str | None = None


class ActionRequest(BaseModel):
    """A request to perform a typed action, submitted to the policy engine.

    ``claimed`` holds free-text fields that may originate from model output or
    untrusted content. The policy engine must never read it for a decision;
    it exists only so the audit trail can show what was asserted.
    """

    request_id: str
    actor: str
    action_type: str
    risk_level: RiskLevel
    target: str
    action_plan_id: str | None = None
    has_approval: bool = False
    at: str | None = None  # decision time (ISO); None -> treat as invalid window
    claimed: dict[str, Any] = Field(default_factory=dict)


class PolicyDecision(BaseModel):
    effect: PolicyEffect
    reason_code: str
    message: str
    request_ref: str
    policy_hash: str
    evaluated_at: str
