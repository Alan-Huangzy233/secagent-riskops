"""The comparison systems of EVALUATION.md §4, run on the same alert stream.

Each returns incidents as ``{"alert_ids": [...], "surfaced": True}``. None of
them scores, so every group they form reaches the analyst. The time of an alert
is when it was raised (``fired_at``).
"""
from __future__ import annotations

from datetime import datetime

WINDOW_SECONDS = 600


def _at(alert: dict) -> float:
    return datetime.fromisoformat(alert["fired_at"].replace("Z", "+00:00")).timestamp()


def _ordered(alerts: list[dict]) -> list[dict]:
    return sorted(alerts, key=lambda alert: (_at(alert), alert["alert_id"]))


def b0_passthrough(alerts: list[dict]) -> list[dict]:
    """One incident per alert: the analyst's status quo."""
    return [{"alert_ids": [alert["alert_id"]], "surfaced": True} for alert in _ordered(alerts)]


def b1_tuple_dedup(alerts: list[dict], window_seconds: int = WINDOW_SECONDS) -> list[dict]:
    """Group on (rule_id, src_ip, hosts); a gap longer than the window starts a new group."""
    open_groups: dict[tuple, tuple[int, float]] = {}
    groups: list[list[str]] = []
    for alert in _ordered(alerts):
        key, at = (alert["rule_id"], alert["src_ip"], tuple(alert["hosts"])), _at(alert)
        current = open_groups.get(key)
        if current is None or at - current[1] > window_seconds:
            groups.append([])
            current = (len(groups) - 1, at)
        groups[current[0]].append(alert["alert_id"])
        open_groups[key] = (current[0], at)
    return [{"alert_ids": ids, "surfaced": True} for ids in groups]


def b2_window_aggregation(alerts: list[dict], window_seconds: int = WINDOW_SECONDS) -> list[dict]:
    """Tumbling windows keyed on the rule alone."""
    buckets: dict[tuple[str, int], list[str]] = {}
    for alert in _ordered(alerts):
        buckets.setdefault((alert["rule_id"], int(_at(alert) // window_seconds)), []).append(alert["alert_id"])
    # Buckets keep the order in which the time-ordered stream first opened them.
    return [{"alert_ids": ids, "surfaced": True} for ids in buckets.values()]
