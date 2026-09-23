"""Alert reduction: dedup -> correlate -> score, the claim the evaluation measures.

``reduce_alerts`` turns the alert stream into incidents. Every incident is kept,
with its alerts, evidence and the reasons behind its score; ``surfaced`` says
whether it reaches an analyst. The reduction figure counts surfaced incidents
against input alerts, and the miss rate counts attacks that no surfaced incident
covers.
"""
from __future__ import annotations

from dataclasses import dataclass

from .correlate import DEFAULT_GAP_SECONDS, correlate
from .dedup import AlertGroup, deduplicate
from .score import SURFACE_THRESHOLD, assess, known_sources

__all__ = ["AlertGroup", "Incident", "reduce_alerts", "deduplicate", "correlate", "assess"]


@dataclass(frozen=True)
class Incident:
    incident_id: str
    alert_ids: tuple[str, ...]
    rules: tuple[str, ...]
    src_ips: tuple[str, ...]
    hosts: tuple[str, ...]
    first_ts: str
    last_ts: str
    evidence: tuple[str, ...]
    score: int
    priority: str | None
    surfaced: bool
    reasons: tuple[str, ...]

    def to_dict(self) -> dict:
        return {name: list(value) if isinstance(value, tuple) else value
                for name, value in self.__dict__.items()}


def reduce_alerts(alerts: list[dict], records: list[dict], *, gap_seconds: int = DEFAULT_GAP_SECONDS,
                  threshold: int = SURFACE_THRESHOLD) -> list[Incident]:
    """``records`` is the normalized log stream the alerts were raised from."""
    by_id = {row["event_id"]: row for row in records}
    baseline = known_sources(records)
    incidents = []
    for groups in correlate(deduplicate(alerts), gap_seconds=gap_seconds):
        evidence = sorted({record for group in groups for record in group.evidence})
        verdict = assess([by_id[record] for record in evidence], baseline, threshold=threshold)
        incidents.append(Incident(
            incident_id=f"INC-{groups[0].group_id}",
            alert_ids=tuple(sorted(alert for group in groups for alert in group.alert_ids)),
            rules=tuple(sorted({group.rule_id for group in groups})),
            src_ips=tuple(sorted({group.src_ip for group in groups})),
            hosts=tuple(sorted({host for group in groups for host in group.hosts})),
            first_ts=min(group.first_ts for group in groups), last_ts=max(group.last_ts for group in groups),
            evidence=tuple(evidence), score=verdict.score, priority=verdict.priority,
            surfaced=verdict.surfaced, reasons=verdict.reasons))
    return incidents
