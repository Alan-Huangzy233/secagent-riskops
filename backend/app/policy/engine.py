"""The policy engine: a pure, deterministic decision function.

This is the load-bearing security control. It is independent of any agent, it
reads only structured/validated fields, and it fails closed. The engine never
inspects ``ActionRequest.claimed`` — free-text assertions that may come from
model output or untrusted content carry no authority here (TM-02, TM-14).

Evaluation is a fixed sequence of gates with deny precedence; the first failing
gate produces the decision, so reason codes are predictable and testable.

A scope is read literally. Before any request is compared with it, the engine
checks that the scope can be read one way only: it names at least one actor and
one target, every entry is a plain name, a target wildcard is a single leading
``*.`` over at least two labels, and its window is made of real timestamps with
a zone. Anything else is refused as ``SCOPE_EMPTY`` or ``SCOPE_AMBIGUOUS``,
whatever the scope's ``approved`` flag says.
"""
from __future__ import annotations

from datetime import datetime
import re

from ..core.clock import Clock, isoformat
from ..schemas.enums import AutonomyLevel, PolicyEffect, RiskLevel
from ..schemas.models import ActionRequest, AssessmentScope, PolicyDecision
from .reason_codes import ReasonCode


_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME = re.compile(rf"{_LABEL}(?:\.{_LABEL})*")
_WILDCARD = re.compile(rf"\*\.{_LABEL}(?:\.{_LABEL})+")  # *.example.internal, never *.internal
_ACTOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@:-]{0,127}")


def _hostname(value: str) -> bool:
    return len(value) <= 253 and _HOSTNAME.fullmatch(value) is not None


def _instant(value: str | None) -> datetime | None:
    """An ISO-8601 timestamp with a zone, or None. Text is never compared as text."""
    if not isinstance(value, str):
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    return moment if moment.tzinfo is not None else None


def scope_problems(scope: AssessmentScope) -> list[str]:
    """Why a scope cannot be read one way only; empty when it can.

    Blank and ambiguous scopes are refused before any request is compared
    with them, so a mistake in writing a scope can only ever deny.
    """
    problems = [f"actor {entry!r} is not a plain name" for entry in scope.allowed_actors
                if not isinstance(entry, str) or not _ACTOR.fullmatch(entry)]
    for entry in scope.target_allowlist:
        if not isinstance(entry, str) or not (_hostname(entry) or _WILDCARD.fullmatch(entry)):
            problems.append(f"target {entry!r} is not a host name or a '*.' wildcard over two or more labels")
    start, end = scope.valid_from, scope.valid_until
    if start is not None and _instant(start) is None:
        problems.append(f"valid_from {start!r} is not a timestamp with a zone")
    if end is not None and _instant(end) is None:
        problems.append(f"valid_until {end!r} is not a timestamp with a zone")
    if _instant(start) and _instant(end) and _instant(start) >= _instant(end):
        problems.append("valid_from is not before valid_until")
    return problems


def _target_allowed(target: str, allowlist: tuple[str, ...]) -> bool:
    """Exact match, or a single leading ``*.`` wildcard. Deny by default."""
    if not _hostname(target):
        return False
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

        # Gate 3 — a blank scope names nobody and nothing; it never means "anyone, anything".
        if not scope.allowed_actors or not scope.target_allowlist:
            return ReasonCode.SCOPE_EMPTY

        # Gate 4 — every entry must be readable one way only.
        if scope_problems(scope):
            return ReasonCode.SCOPE_AMBIGUOUS

        # Gate 5/6 — the decision must fall inside the validity window.
        at = _instant(request.at)
        if at is None or (scope.valid_from and at < _instant(scope.valid_from)):
            return ReasonCode.SCOPE_WINDOW_INVALID
        if scope.valid_until and at > _instant(scope.valid_until):
            return ReasonCode.SCOPE_EXPIRED

        # Gate 7 — actor must be explicitly permitted.
        if request.actor not in scope.allowed_actors:
            return ReasonCode.ACTOR_NOT_PERMITTED

        # Gate 8 — target must match the allowlist (discovery never expands it).
        if not _target_allowed(request.target, scope.target_allowlist):
            return ReasonCode.TARGET_NOT_IN_SCOPE

        # Gate 9 — risky actions require a real approval record.
        requires_approval = request.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH)
        if requires_approval and not request.has_approval:
            return ReasonCode.APPROVAL_REQUIRED

        # Gate 10 — configured autonomy must reach the level this action needs.
        if scope.autonomy_level < _min_autonomy(request.risk_level, request.has_approval):
            return ReasonCode.AUTONOMY_LEVEL_INSUFFICIENT

        return ReasonCode.ALLOW_OK


_MESSAGES: dict[ReasonCode, str] = {
    ReasonCode.ALLOW_OK: "Action permitted by policy.",
    ReasonCode.SCOPE_NOT_APPROVED: "Scope is not approved.",
    ReasonCode.SCOPE_UNBOUND: "Scope is not bound to a canonical policy hash.",
    ReasonCode.SCOPE_EMPTY: "Scope names no actor or no target; a blank scope never means unrestricted.",
    ReasonCode.SCOPE_AMBIGUOUS: "Scope has an entry that can be read more than one way; it fails closed.",
    ReasonCode.SCOPE_WINDOW_INVALID: "No valid decision time or before the scope validity window.",
    ReasonCode.SCOPE_EXPIRED: "Authorization window has expired.",
    ReasonCode.ACTOR_NOT_PERMITTED: "Actor is not on the scope actor allowlist.",
    ReasonCode.TARGET_NOT_IN_SCOPE: "Target is not covered by the scope allowlist.",
    ReasonCode.APPROVAL_REQUIRED: "Action risk requires an explicit approval record.",
    ReasonCode.AUTONOMY_LEVEL_INSUFFICIENT: "Configured autonomy level is below what this action requires.",
}
