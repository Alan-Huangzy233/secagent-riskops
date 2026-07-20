"""Stable policy decision reason codes.

These strings are part of the audit contract (roadmap v0.1.9). They must stay
stable across releases so downstream tooling and tests can assert on them.
"""
from __future__ import annotations

from enum import StrEnum


class ReasonCode(StrEnum):
    ALLOW_OK = "ALLOW_OK"

    # Fail-closed authorization gates, in evaluation order.
    SCOPE_NOT_APPROVED = "SCOPE_NOT_APPROVED"
    SCOPE_UNBOUND = "SCOPE_UNBOUND"  # missing/blank policy hash
    SCOPE_WINDOW_INVALID = "SCOPE_WINDOW_INVALID"  # no decision time / before valid_from
    SCOPE_EXPIRED = "SCOPE_EXPIRED"
    ACTOR_NOT_PERMITTED = "ACTOR_NOT_PERMITTED"
    TARGET_NOT_IN_SCOPE = "TARGET_NOT_IN_SCOPE"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    AUTONOMY_LEVEL_INSUFFICIENT = "AUTONOMY_LEVEL_INSUFFICIENT"
