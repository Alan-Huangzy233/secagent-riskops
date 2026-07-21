"""Typed executor/tool registry.

Executors accept typed operations with validated parameters — never arbitrary
instructions from model output or retrieved content (System Architecture,
Tool and Target Boundary). The walking skeleton registers action *specs* only;
no executor actually runs, because the policy gate blocks execution at the
default autonomy level.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..schemas.enums import RiskLevel


@dataclass(frozen=True)
class ActionSpec:
    action_type: str
    title: str
    risk_level: RiskLevel
    rollback: str
    default_parameters: dict[str, Any] = field(default_factory=dict)


ACTION_CATALOG: dict[str, ActionSpec] = {
    "harden_ssh_access": ActionSpec(
        action_type="harden_ssh_access",
        title="Harden SSH access (disable root login, enforce key auth)",
        risk_level=RiskLevel.MEDIUM,
        rollback="Restore the previous sshd_config from the pre-change backup and reload sshd.",
        default_parameters={"disable_root_login": True, "enforce_key_auth": True},
    ),
    "add_security_headers": ActionSpec(
        action_type="add_security_headers",
        title="Add baseline HTTP security headers",
        risk_level=RiskLevel.LOW,
        rollback="Remove the added header directives and reload the web server.",
        default_parameters={
            "headers": ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]
        },
    ),
}


def get_action_spec(action_type: str) -> ActionSpec | None:
    return ACTION_CATALOG.get(action_type)
