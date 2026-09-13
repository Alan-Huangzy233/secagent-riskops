"""Pure rolling-window correlation for normalized SSH log records.

Thresholds count log records, not independent SSH connections or sessions. A
record can support multiple rules. Windows that share evidence are returned as
one match, so that match's evidence can span longer than ``window_seconds``;
every constituent window still independently satisfies the rule.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import math
from typing import Any

from .sshd_parse import FAILURE_KINDS


RULE_VERSION = 1
MAX_WINDOW_SECONDS = 2 * 60 * 60
_FAILURE_TYPES = FAILURE_KINDS | {"ssh_failure"}
_SUCCESS_TYPES = {"auth_success", "ssh_success"}


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    rule_version: int
    window_seconds: int
    evidence: list[dict[str, Any]]
    reason: str


@dataclass(frozen=True)
class _Event:
    row: dict[str, Any]
    key: tuple[str, str]
    source: str
    peer: str
    at: float
    kind: str
    user: str | None


@dataclass(frozen=True)
class _FailureRule:
    rule_id: str
    window: int
    records: int
    users: int = 0
    sources: int = 1


_LOCAL_RULES = (
    _FailureRule("slow_scan", MAX_WINDOW_SECONDS, 12),
    _FailureRule("multi_account", MAX_WINDOW_SECONDS, 6, users=3),
)
_CROSS_SOURCE_RULE = _FailureRule("cross_source", 30 * 60, 6, sources=2)


def _text(row: dict[str, Any], *names: str) -> str | None:
    for name in names:
        value = row.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _normalize(events: list[dict[str, Any]]) -> list[_Event]:
    normalized = []
    seen: set[tuple[str, str]] = set()
    for row in events:
        source, event_id = _text(row, "source_id"), _text(row, "event_id")
        peer = _text(row, "src_ip", "peer_ip")
        kind = _text(row, "event_type", "event_kind")
        if not source or not event_id or not peer or not kind:
            continue
        raw_time = row.get("event_ts")
        if isinstance(raw_time, bool):
            continue
        try:
            at = float(raw_time)
        except (TypeError, ValueError, OverflowError):
            continue
        if not math.isfinite(at) or (source, event_id) in seen:
            continue
        seen.add((source, event_id))
        normalized.append(_Event(row, (source, event_id), source, peer, at, kind,
                                 _text(row, "ssh_user", "username")))
    return sorted(normalized, key=lambda event: (event.at, event.key))


def _failure_matches(events: list[_Event], triggers: set[tuple[str, str]],
                     rule: _FailureRule) -> list[RuleMatch]:
    # Keep only interval bounds during the scan. Copying each dense window's
    # evidence separately would otherwise make a large batch quadratic.
    intervals: list[list[int]] = []
    users: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    left = triggered = 0
    for right, event in enumerate(events):
        if event.user is not None:
            users[event.user] += 1
        sources[event.source] += 1
        triggered += event.key in triggers
        while event.at - events[left].at > rule.window:
            expired = events[left]
            if expired.user is not None:
                users[expired.user] -= 1
                if not users[expired.user]:
                    del users[expired.user]
            sources[expired.source] -= 1
            if not sources[expired.source]:
                del sources[expired.source]
            triggered -= expired.key in triggers
            left += 1
        if (not triggered or right - left + 1 < rule.records
                or len(users) < rule.users or len(sources) < rule.sources):
            continue
        if intervals and left <= intervals[-1][1]:
            intervals[-1][1] = right
            intervals[-1][2] += 1
        else:
            intervals.append([left, right, 1])

    condition = f"At least {rule.records} failed SSH log records"
    if rule.users:
        condition += f" involving at least {rule.users} nonempty usernames"
    if rule.sources > 1:
        condition += f" across at least {rule.sources} sources"
    condition += f" in a {rule.window // 60}-minute rolling window."
    return [RuleMatch(
        rule.rule_id, RULE_VERSION, rule.window,
        [dict(event.row) for event in events[start:end + 1]],
        f"{condition} {count} qualifying window(s) linked by shared evidence; "
        f"{end - start + 1} log records retained.",
    ) for start, end, count in intervals]


def _success_matches(events: list[_Event], triggers: set[tuple[str, str]]) -> list[RuleMatch]:
    window, minimum = 30 * 60, 3
    failures = [event for event in events if event.kind in _FAILURE_TYPES]
    successes = [event for event in events if event.kind in _SUCCESS_TYPES]
    # Failure interval bounds are monotonic as success times advance. Adjacent
    # matches merge only when they share an actual failure record.
    components: list[tuple[int, int, list[_Event]]] = []
    left = right = triggered = 0
    for success in successes:
        # Strictly earlier: equal-timestamp failures cannot establish that a
        # successful authentication followed them.
        while right < len(failures) and failures[right].at < success.at:
            triggered += failures[right].key in triggers
            right += 1
        while left < right and failures[left].at < success.at - window:
            triggered -= failures[left].key in triggers
            left += 1
        if right - left < minimum or not (triggered or success.key in triggers):
            continue
        if components and left < components[-1][1]:
            start, _, matched_successes = components[-1]
            matched_successes.append(success)
            components[-1] = (start, right, matched_successes)
        else:
            components.append((left, right, [success]))

    matches = []
    for start, end, matched_successes in components:
        evidence = sorted(failures[start:end] + matched_successes,
                          key=lambda event: (event.at, event.key))
        matches.append(RuleMatch(
            "success_after_failures", RULE_VERSION, window,
            [dict(event.row) for event in evidence],
            f"Authentication succeeded strictly after at least {minimum} failed "
            f"SSH log records in the preceding {window // 60} minutes on the same "
            f"source. {len(matched_successes)} qualifying window(s) linked by shared "
            f"evidence; {len(evidence)} log records retained.",
        ))
    return matches


def detect_matches(events: list[dict[str, Any]],
                   trigger_keys: set[tuple[str, str]], *, include_burst: bool = False) -> list[RuleMatch]:
    """Find new or rebuilt matches that contain at least one trigger record.

    Input records need ``source_id``, ``event_id`` and numeric ``event_ts``, plus
    normalized ``event_type``, ``src_ip`` and optional ``ssh_user``. The equivalent
    ``event_kind``, ``peer_ip`` and ``username`` fields are also accepted. Raw
    ``record_json`` is retained as evidence but is never reparsed here. Missing
    peers/identities or invalid timestamps cannot participate in correlation.

    Duplicate (source_id, event_id) records are counted once; this is journal
    record identity deduplication, not connection/session deduplication. Window
    lower bounds are inclusive. Success must strictly follow its failures.
    Caller order and input dictionaries are preserved without mutation.
    """
    if not trigger_keys:
        return []
    normalized = _normalize(events)
    local: dict[tuple[str, str], list[_Event]] = defaultdict(list)
    peers: dict[str, list[_Event]] = defaultdict(list)
    for event in normalized:
        if event.kind in _FAILURE_TYPES | _SUCCESS_TYPES:
            local[(event.source, event.peer)].append(event)
        if event.kind in _FAILURE_TYPES:
            peers[event.peer].append(event)
    matches = []
    for group in sorted(local):
        records = local[group]
        failures = [event for event in records if event.kind in _FAILURE_TYPES]
        rules = (_FailureRule("burst", 300, 3), *_LOCAL_RULES) if include_burst else _LOCAL_RULES
        for rule in rules:
            matches.extend(_failure_matches(failures, trigger_keys, rule))
        matches.extend(_success_matches(records, trigger_keys))
    for peer in sorted(peers):
        matches.extend(_failure_matches(peers[peer], trigger_keys, _CROSS_SOURCE_RULE))
    return matches
