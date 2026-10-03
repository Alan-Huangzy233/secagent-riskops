"""Offline HTTP request-pattern rules with evidence, not compromise verdicts.

Inputs are normalized access records. All three rules describe attempts or
patterns; even a 2xx response cannot establish that an exploit succeeded.
Findings are grouped within a source, configured service and connection peer.
This module has no network, database, model or response-execution dependency.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Iterable

from .http_parse import HttpEvent


RULE_VERSION = 1
WINDOW_SECONDS = 300
SCAN_MIN_RECORDS = 20
SCAN_MIN_PATHS = 10
SCAN_DENIED_PERCENT = 80
_DENIED = {403, 404}
_RESOURCE_NAMES = {".git", ".svn", ".hg", ".htpasswd", "wp-config.php",
                   "wp-config.php.bak", "wp-config.php.old"}


@dataclass(frozen=True)
class WebFinding:
    rule_id: str
    rule_version: int
    source_id: str
    service_id: str
    client_ip: str
    first_seen: str
    last_seen: str
    window_seconds: int
    evidence_ids: tuple[str, ...]
    reason: str


def unique_events(events: Iterable[HttpEvent]) -> list[HttpEvent]:
    """Re-delivery is idempotent; conflicting identities fail in either order."""
    unique: dict[tuple[str, str], HttpEvent] = {}
    for event in events:
        if not isinstance(event, HttpEvent):
            raise ValueError("HTTP detection requires normalized events")
        if event.key in unique and unique[event.key] != event:
            raise ValueError("conflicting HTTP evidence identity")
        unique[event.key] = event
    return sorted(unique.values(), key=lambda event: (event.event_ts, event.key))


def _segments(event: HttpEvent) -> list[str]:
    # Backslash is conservatively treated as a separator. Case folding is only
    # used for the resource heuristic, never to claim the server resolved it.
    return event.decoded_path.replace("\\", "/").split("/")


def _sensitive(event: HttpEvent) -> bool:
    return any(part.casefold() in _RESOURCE_NAMES or part.casefold() == ".env"
               or part.casefold().startswith(".env.") for part in _segments(event))


def _traversal(event: HttpEvent) -> bool:
    return ".." in _segments(event)


def _finding(rule: str, rows: list[HttpEvent], reason: str) -> WebFinding:
    first, last = rows[0], rows[-1]
    return WebFinding(rule, RULE_VERSION, first.source_id, first.service_id,
                      first.client_ip, first.timestamp, last.timestamp, WINDOW_SECONDS,
                      tuple(row.event_id for row in rows), reason)


def _point_findings(rows: list[HttpEvent], rule: str, predicate, description: str) -> list[WebFinding]:
    # Each row independently matches. Group nearby matches for review; unlike
    # a scan window this group may span more than five minutes in total.
    groups: list[list[HttpEvent]] = []
    for event in rows:
        if not predicate(event):
            continue
        if not groups or event.event_ts - groups[-1][-1].event_ts > WINDOW_SECONDS:
            groups.append([])
        groups[-1].append(event)
    return [_finding(rule, group, f"{description} {len(group)} matching request record(s); "
                     "adjacent matches within 300 seconds grouped. This does not prove compromise.")
            for group in groups]


def _scan_findings(rows: list[HttpEvent]) -> list[WebFinding]:
    # One monotonic sliding window; retain interval bounds, not a copy of each
    # dense window. Materialize evidence once after overlapping windows merge.
    intervals: list[list[int]] = []
    paths: Counter[str] = Counter()
    left = denied = 0
    for right, event in enumerate(rows):
        paths[event.decoded_path] += 1
        denied += event.status in _DENIED
        while event.event_ts - rows[left].event_ts > WINDOW_SECONDS:
            expired = rows[left]
            paths[expired.decoded_path] -= 1
            if not paths[expired.decoded_path]:
                del paths[expired.decoded_path]
            denied -= expired.status in _DENIED
            left += 1
        records = right - left + 1
        if (records < SCAN_MIN_RECORDS or len(paths) < SCAN_MIN_PATHS
                or denied * 100 < SCAN_DENIED_PERCENT * records):
            continue
        if intervals and left <= intervals[-1][1]:
            intervals[-1][1] = right
            intervals[-1][2] += 1
        else:
            intervals.append([left, right, 1])
    return [_finding("http_multi_path_scan", rows[start:end + 1],
                     f"At least {SCAN_MIN_RECORDS} requests across {SCAN_MIN_PATHS} distinct query-free "
                     f"decoded paths, with at least {SCAN_DENIED_PERCENT}% HTTP 403/404 responses in a "
                     f"{WINDOW_SECONDS}-second window. {count} qualifying window(s) linked by shared "
                     "evidence; automation or a crawler can also produce this pattern.")
            for start, end, count in intervals]


def detect_web(events: Iterable[HttpEvent]) -> list[WebFinding]:
    """Batch/replay entry point. It is not a persistent live streaming engine."""
    groups: dict[tuple[str, str, str], list[HttpEvent]] = defaultdict(list)
    for event in unique_events(events):
        groups[event.source_id, event.service_id, event.client_ip].append(event)
    findings = []
    for key in sorted(groups):
        rows = groups[key]
        findings.extend(_point_findings(rows, "http_sensitive_resource", _sensitive,
                                       "A request path names a known sensitive resource."))
        findings.extend(_point_findings(rows, "http_path_traversal", _traversal,
                                       "A request path contains a parent-directory segment after bounded decoding."))
        findings.extend(_scan_findings(rows))
    return sorted(findings, key=lambda item: (item.first_seen, item.source_id, item.service_id,
                                             item.client_ip, item.rule_id, item.evidence_ids))
