"""The policy engine: a pure, deterministic decision function.

This is the load-bearing security control. It is independent of any agent, it
reads only structured/validated fields, and it fails closed. The engine never
inspects ``ActionRequest.claimed`` — free-text assertions that may come from
model output or untrusted content carry no authority here (TM-02, TM-14).

Evaluation is a fixed sequence of gates with deny precedence; the first failing
gate produces the decision, so reason codes are predictable and testable.
"""
from __future__ import annotations

from ..core.clock import Clock, isoformat
from ..schemas.enums import AutonomyLevel, PolicyEffect, RiskLevel
from ..schemas.models import ActionRequest, AssessmentScope, PolicyDecision
from .reason_codes import ReasonCode


def _target_allowed(target: str, allowlist: tuple[str, ...]) -> bool:
    """Exact match, or a single leading ``*.`` wildcard. Deny by default."""
    for entry in allowlist:
        if entry == target:
            return True
        if entry.startswith("*.") and target.endswith(entry[1:]) and target != entry[2:]:
            return True
    return False


def _min_autonomy(risk_level: RiskLevel, has_approval: bool) -> AutonomyLevel:
    """Lowest autonomy level that may execute this action."""
    if risk_level == RiskLevel.LOW and not has_approval:
        return AutonomyLevel.AUTO_FIX_LOW_RISK  # 4: unattended low-risk auto-fix
    return AutonomyLevel.EXECUTE_AFTER_APPROVAL  # 3: execute only after approval


class PolicyEngine:
    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def evaluate(self, request: ActionRequest, scope: AssessmentScope) -> PolicyDecision:
        code = self._decide(request, scope)
        effect = PolicyEffect.ALLOW if code == ReasonCode.ALLOW_OK else PolicyEffect.DENY
        return PolicyDecision(
            effect=effect,
            reason_code=code.value,
            message=_MESSAGES[code],
            request_ref=request.request_id,
            policy_hash=scope.policy_hash,
            evaluated_at=isoformat(self._clock.now()),
        )

    def _decide(self, request: ActionRequest, scope: AssessmentScope) -> ReasonCode:
        # Gate 1 — scope must be an approved authorization.
        if not scope.approved:
            return ReasonCode.SCOPE_NOT_APPROVED

        # Gate 2 — scope must be bound to a canonical policy hash.
        if not scope.policy_hash:
            return ReasonCode.SCOPE_UNBOUND

        # Gate 3/4 — the decision must fall inside the validity window.
        if request.at is None or (scope.valid_from and request.at < scope.valid_from):
            return ReasonCode.SCOPE_WINDOW_INVALID
        if scope.valid_until and request.at > scope.valid_until:
            return ReasonCode.SCOPE_EXPIRED

        # Gate 5 — actor must be explicitly permitted.
        if request.actor not in scope.allowed_actors:
            return ReasonCode.ACTOR_NOT_PERMITTED

        # Gate 6 — target must match the allowlist (discovery never expands it).
        if not _target_allowed(request.target, scope.target_allowlist):
            return ReasonCode.TARGET_NOT_IN_SCOPE

        # Gate 7 — risky actions require a real approval record.
        requires_approval = request.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH)
        if requires_approval and not request.has_approval:
            return ReasonCode.APPROVAL_REQUIRED

        # Gate 8 — configured autonomy must reach the level this action needs.
        if scope.autonomy_level < _min_autonomy(request.risk_level, request.has_approval):
            return ReasonCode.AUTONOMY_LEVEL_INSUFFICIENT

        return ReasonCode.ALLOW_OK


_MESSAGES: dict[ReasonCode, str] = {
    ReasonCode.ALLOW_OK: "Action permitted by policy.",
    ReasonCode.SCOPE_NOT_APPROVED: "Scope is not approved; blank/ambiguous scope fails closed.",
    ReasonCode.SCOPE_UNBOUND: "Scope is not bound to a canonical policy hash.",
    ReasonCode.SCOPE_WINDOW_INVALID: "No valid decision time or before the scope validity window.",
    ReasonCode.SCOPE_EXPIRED: "Authorization window has expired.",
    ReasonCode.ACTOR_NOT_PERMITTED: "Actor is not on the scope actor allowlist.",
    ReasonCode.TARGET_NOT_IN_SCOPE: "Target is not covered by the scope allowlist.",
    ReasonCode.APPROVAL_REQUIRED: "Action risk requires an explicit approval record.",
    ReasonCode.AUTONOMY_LEVEL_INSUFFICIENT: "Configured autonomy level is below what this action requires.",
}
