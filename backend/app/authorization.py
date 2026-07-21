"""Build immutable, hash-bound assessment scopes.

A scope's ``policy_hash`` is a canonical digest of its policy-relevant fields.
Any material change produces a different hash, which is what binds an approval
to the exact policy it approved (roadmap v0.1.9; TM-05, TM-14).
"""
from __future__ import annotations

from .core.hashing import policy_hash
from .schemas.enums import AutonomyLevel
from .schemas.models import AssessmentScope


def make_scope(
    scope_id: str,
    *,
    scope_version: int = 1,
    autonomy_level: AutonomyLevel = AutonomyLevel.SUGGEST_ONLY,
    allowed_actors: tuple[str, ...] = (),
    target_allowlist: tuple[str, ...] = (),
    valid_from: str | None = None,
    valid_until: str | None = None,
    approved: bool = True,
) -> AssessmentScope:
    policy_relevant = {
        "scope_version": scope_version,
        "autonomy_level": int(autonomy_level),
        "allowed_actors": sorted(allowed_actors),
        "target_allowlist": sorted(target_allowlist),
        "valid_from": valid_from,
        "valid_until": valid_until,
    }
    return AssessmentScope(
        scope_id=scope_id,
        scope_version=scope_version,
        policy_hash=policy_hash(policy_relevant),
        approved=approved,
        autonomy_level=autonomy_level,
        allowed_actors=allowed_actors,
        target_allowlist=target_allowlist,
        valid_from=valid_from,
        valid_until=valid_until,
    )
