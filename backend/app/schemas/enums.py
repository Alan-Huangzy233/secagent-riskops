"""Enumerations shared across the domain model."""
from __future__ import annotations

from enum import IntEnum, StrEnum


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskBand(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskLevel(StrEnum):
    """Risk class of a remediation action (drives approval requirements)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Disposition(StrEnum):
    ESCALATE = "escalate"
    MONITOR = "monitor"
    SUPPRESS_CANDIDATE = "suppress_candidate"
    FALSE_POSITIVE = "false_positive"


class AutonomyLevel(IntEnum):
    REPORT_ONLY = 0
    SUGGEST_ONLY = 1
    CREATE_PATCH = 2
    EXECUTE_AFTER_APPROVAL = 3
    AUTO_FIX_LOW_RISK = 4
    LAB_FULL_AUTONOMY = 5


class FlowStatus(StrEnum):
    CREATED = "created"
    QUEUED = "queued"
    RUNNING = "running"
    WAITING_FOR_APPROVAL = "waiting_for_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    OK = "ok"
    ERROR = "error"


class ActionPlanStatus(StrEnum):
    DRAFT = "draft"
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    VERIFIED = "verified"
    ROLLED_BACK = "rolled_back"


class PolicyEffect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
