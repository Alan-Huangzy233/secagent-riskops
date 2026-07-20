"""Deterministic triage agent.

Stands in for a model-backed SOC triage agent behind the AgentContract seam.
It consumes an already-scored AlertGroup plus its evidence and proposes a
disposition. Every recommendation is evidence-grounded: it refuses to escalate
without at least one evidence reference, which keeps AI output tied to retained
inputs rather than invention (charter design principle 1).
"""
from __future__ import annotations

from typing import Any

from ..reference import ATTACK_TECHNIQUES
from ..schemas.enums import Disposition, RiskBand
from .contract import AgentContract, AgentResult


class TriageAgent(AgentContract):
    name = "soc.triage"
    version = "0.2.0"

    def run(self, context: dict[str, Any]) -> AgentResult:
        group = context["alert_group"]
        evidence_ids: list[str] = list(group.get("evidence_ids", []))
        signature: str = group["signature"]
        band = RiskBand(group["risk_band"])
        count = int(group["count"])

        techniques = ATTACK_TECHNIQUES.get(signature, [])

        # Evidence-grounded gate: no evidence -> cannot escalate.
        if not evidence_ids:
            return AgentResult(
                output={"disposition": Disposition.MONITOR.value,
                        "attack_techniques": techniques,
                        "recommended_action_types": []},
                confidence=0.3,
                evidence_ids=[],
                rationale="No linked evidence; defaulting to monitor.",
            )

        if signature == "ssh_failed_password" and count >= 3:
            return AgentResult(
                output={"disposition": Disposition.ESCALATE.value,
                        "attack_techniques": techniques,
                        "recommended_action_types": ["harden_ssh_access"]},
                confidence=0.85,
                evidence_ids=evidence_ids,
                rationale=(f"{count} repeated SSH authentication failures for the same "
                           f"source/host indicate credential brute force (T1110)."),
            )

        if band in (RiskBand.HIGH, RiskBand.CRITICAL):
            return AgentResult(
                output={"disposition": Disposition.ESCALATE.value,
                        "attack_techniques": techniques,
                        "recommended_action_types": []},
                confidence=0.7,
                evidence_ids=evidence_ids,
                rationale=f"Risk band {band.value} warrants analyst escalation.",
            )

        return AgentResult(
            output={"disposition": Disposition.MONITOR.value,
                    "attack_techniques": techniques,
                    "recommended_action_types": []},
            confidence=0.6,
            evidence_ids=evidence_ids,
            rationale=f"Risk band {band.value}; monitor and enrich before escalation.",
        )
