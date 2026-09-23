"""Stage 1: collapse re-raised alerts into one alert group per detection.

A scheduled rule raises the same detection again on every run while an attack
keeps producing records. Two alerts are the same detection when they come from
the same rule, source address and set of hosts *and* share at least one log
record. Sharing a record is the test, not a time window, so a detection is never
split by a pause shorter than the rule's own lookback and two unrelated bursts
from one address are never glued together by a guessed interval.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class AlertGroup:
    group_id: str
    rule_id: str
    src_ip: str
    hosts: tuple[str, ...]
    alert_ids: tuple[str, ...]
    evidence: tuple[str, ...]
    first_ts: str
    last_ts: str


class _Sets:
    """Union-find over integer indices."""

    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, left: int, right: int) -> None:
        left, right = self.find(left), self.find(right)
        if left != right:
            self.parent[max(left, right)] = min(left, right)

    def components(self) -> list[list[int]]:
        grouped: dict[int, list[int]] = {}
        for item in range(len(self.parent)):
            grouped.setdefault(self.find(item), []).append(item)
        return [grouped[root] for root in sorted(grouped)]


def deduplicate(alerts: Iterable[dict]) -> list[AlertGroup]:
    """Return alert groups in the order of their first alert."""
    alerts = sorted(alerts, key=lambda alert: alert["alert_id"])
    sets = _Sets(len(alerts))
    owner: dict[tuple, int] = {}
    for index, alert in enumerate(alerts):
        key = (alert["rule_id"], alert["src_ip"], tuple(alert["hosts"]))
        for record in alert["evidence"]:
            seen = owner.setdefault((key, record), index)
            if seen != index:
                sets.union(seen, index)
    groups = []
    for members in sets.components():
        chosen = [alerts[index] for index in members]
        first = chosen[0]
        groups.append(AlertGroup(
            group_id=first["alert_id"], rule_id=first["rule_id"], src_ip=first["src_ip"],
            hosts=tuple(first["hosts"]), alert_ids=tuple(alert["alert_id"] for alert in chosen),
            evidence=tuple(sorted({record for alert in chosen for record in alert["evidence"]})),
            first_ts=min(alert["first_ts"] for alert in chosen), last_ts=max(alert["last_ts"] for alert in chosen)))
    return groups
