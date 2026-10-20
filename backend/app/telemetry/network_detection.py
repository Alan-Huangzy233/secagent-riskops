"""Bounded offline firewall observations; advisory patterns, never verdicts.

The caller supplies a finite observation context, not a complete traffic history.
No collector, storage, SSH allowlist, response action or model is invoked here.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
import hashlib
import ipaddress
import json
import re
from typing import Iterable

from .network_parse import NetworkEvent, validate_event


RULE_ID = "network_tcp_multi_port_probe"
RULE_VERSION = 1
WINDOW_SECONDS = 300
MIN_DISTINCT_PORTS = 10
MAX_INPUT_RECORDS = 10_000
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_MAINTENANCE_WINDOWS = 64
MAX_MAINTENANCE_PORTS = 1024
_BASE_COVERAGE = {"offline_context_only", "observations_are_lower_bounds",
                  "apparent_source_not_identity"}
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


@dataclass(frozen=True)
class MaintenanceWindow:
    """Previously approved context, not approval acquisition or an exemption.

    The caller is responsible for authenticating the approval. Exact addresses,
    source, TCP ports and a UTC interval of at most 24 hours bound its meaning.
    Matching evidence stays in findings; this module never suppresses a notice.
    """

    authorization_id: str
    source_id: str
    src_ip: str
    dst_ip: str
    protocol: str
    dst_ports: frozenset[int]
    starts_at_us: int
    ends_at_us: int
    reason: str

    def __post_init__(self) -> None:
        for value in (self.authorization_id, self.source_id):
            if not isinstance(value, str) or not _ID.fullmatch(value):
                raise ValueError("invalid_network_maintenance")
        for value in (self.src_ip, self.dst_ip):
            try:
                if (not isinstance(value, str) or len(value) > 45 or "%" in value
                        or str(ipaddress.ip_address(value)) != value
                        or getattr(ipaddress.ip_address(value), "ipv4_mapped", None)):
                    raise ValueError
            except ValueError:
                raise ValueError("invalid_network_maintenance") from None
        if ipaddress.ip_address(self.src_ip).version != ipaddress.ip_address(self.dst_ip).version:
            raise ValueError("invalid_network_maintenance")
        if (self.protocol != "TCP" or not isinstance(self.dst_ports, frozenset)
                or not 1 <= len(self.dst_ports) <= MAX_MAINTENANCE_PORTS
                or any(type(port) is not int or not 0 <= port <= 65535 for port in self.dst_ports)
                or type(self.starts_at_us) is not int or type(self.ends_at_us) is not int
                or not 0 <= self.starts_at_us < self.ends_at_us <= 2**63 - 1
                or self.ends_at_us - self.starts_at_us > 86_400_000_000
                or not isinstance(self.reason, str) or not 1 <= len(self.reason) <= 256
                or not self.reason.strip()
                or any(ord(char) < 32 or ord(char) == 127 for char in self.reason)):
            raise ValueError("invalid_network_maintenance")


@dataclass(frozen=True)
class MaintenanceMatch:
    authorization_id: str
    reason: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class NetworkFinding:
    finding_id: str
    rule_id: str
    rule_version: int
    source_id: str
    boot_id: str
    source_profile_revision: str
    src_ip: str
    dst_ip: str
    first_monotonic_us: int
    last_monotonic_us: int
    first_journal_realtime_us: int
    last_journal_realtime_us: int
    window_seconds: int
    distinct_dst_ports: tuple[int, ...]
    evidence_ids: tuple[str, ...]
    qualifying_windows: int
    coverage: tuple[str, ...]
    maintenance_context: tuple[MaintenanceMatch, ...]


@dataclass(frozen=True)
class NetworkReport:
    findings: tuple[NetworkFinding, ...]
    input_count: int
    unique_count: int
    duplicate_count: int
    eligible_count: int
    excluded_count: int
    coverage: tuple[str, ...]


def _maintenance_windows(windows: Iterable[MaintenanceWindow]) -> tuple[MaintenanceWindow, ...]:
    unique: dict[str, MaintenanceWindow] = {}
    for count, window in enumerate(windows, 1):
        if count > MAX_MAINTENANCE_WINDOWS:
            raise ValueError("network_maintenance_limit")
        if not isinstance(window, MaintenanceWindow):
            raise ValueError("invalid_network_maintenance")
        window.__post_init__()
        previous = unique.get(window.authorization_id)
        if previous is not None and previous != window:
            raise ValueError("conflicting_network_maintenance")
        unique[window.authorization_id] = window
    return tuple(unique[key] for key in sorted(unique))


def _eligible(event: NetworkEvent) -> bool:
    return (event.transport == "kernel" and event.direction == "local_input"
            and event.observation_point == "local_input" and event.rejection_related
            and event.protocol == "TCP" and event.src_port is not None
            and event.dst_port is not None and event.tcp_flags is not None
            and "SYN" in event.tcp_flags and not event.tcp_flags & {"ACK", "RST", "FIN"})


def _clock_warnings(events: list[NetworkEvent]) -> set[tuple[str, str]]:
    """Wall time cannot change the monotonic rule window within a single boot."""
    previous: dict[tuple[str, str], NetworkEvent] = {}
    affected = set()
    for event in events:
        key = event.source_id, event.boot_id
        before = previous.get(key)
        if before is not None:
            wall_delta = event.journal_realtime_us - before.journal_realtime_us
            mono_delta = event.journal_monotonic_us - before.journal_monotonic_us
            if abs(wall_delta - mono_delta) > 1_000_000:
                affected.add(key)
        previous[key] = event
    return affected


def _maintenance_context(rows: list[NetworkEvent], windows: tuple[MaintenanceWindow, ...],
                         *, clock_uncertain: bool) -> tuple[MaintenanceMatch, ...]:
    if clock_uncertain:
        return ()
    first = rows[0]
    matches = []
    for window in windows:
        if ((first.source_id, first.src_ip, first.dst_ip, first.protocol)
                != (window.source_id, window.src_ip, window.dst_ip, window.protocol)):
            continue
        evidence = tuple(row.event_id for row in rows
                         if row.dst_port in window.dst_ports
                         and window.starts_at_us <= row.journal_realtime_us <= window.ends_at_us)
        if evidence:
            matches.append(MaintenanceMatch(window.authorization_id, window.reason, evidence))
    return tuple(matches)


def _finding(rows: list[NetworkEvent], qualifying_windows: int,
             windows: tuple[MaintenanceWindow, ...], clock_uncertain: bool) -> NetworkFinding:
    first, last = rows[0], rows[-1]
    evidence = tuple(row.event_id for row in rows)
    identity = (RULE_ID, RULE_VERSION, first.source_id, first.boot_id,
                first.source_profile_revision, first.src_ip, first.dst_ip, evidence)
    finding_id = hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()
    coverage = _BASE_COVERAGE | {code for row in rows for code in row.coverage}
    if clock_uncertain:
        coverage.add("journal_clock_discontinuity")
    return NetworkFinding(
        finding_id, RULE_ID, RULE_VERSION, first.source_id, first.boot_id,
        first.source_profile_revision, first.src_ip, first.dst_ip,
        first.journal_monotonic_us, last.journal_monotonic_us,
        first.journal_realtime_us, last.journal_realtime_us, WINDOW_SECONDS,
        tuple(sorted({row.dst_port for row in rows})), evidence, qualifying_windows,
        tuple(sorted(coverage)),
        _maintenance_context(rows, windows, clock_uncertain=clock_uncertain),
    )


def _scan(rows: list[NetworkEvent], windows: tuple[MaintenanceWindow, ...],
          clock_uncertain: bool) -> list[NetworkFinding]:
    # Sliding counts and interval coalescing avoid materializing each dense
    # qualifying window. Each retained evidence row is copied only once.
    ports: Counter[int] = Counter()
    left = 0
    intervals: list[tuple[int, int, int]] = []
    for right, event in enumerate(rows):
        ports[event.dst_port] += 1
        while event.journal_monotonic_us - rows[left].journal_monotonic_us > WINDOW_SECONDS * 1_000_000:
            port = rows[left].dst_port
            ports[port] -= 1
            if not ports[port]:
                del ports[port]
            left += 1
        if len(ports) < MIN_DISTINCT_PORTS:
            continue
        if intervals and left <= intervals[-1][1]:
            start, _, count = intervals[-1]
            intervals[-1] = (start, right, count + 1)
        else:
            intervals.append((left, right, 1))
    return [_finding(rows[start:end + 1], count, windows, clock_uncertain)
            for start, end, count in intervals]


def detect_network(events: Iterable[NetworkEvent], *,
                   maintenance: Iterable[MaintenanceWindow] = ()) -> NetworkReport:
    """Analyze a bounded offline context, returning all evidence and limitations.

    More than 10,000 input records (including duplicates), 16 MiB of normalized
    JSON, invalid events or conflicting identities abort with ValueError before
    any report is returned. Callers must report failure, never substitute an
    empty/safe assessment. This does not implement persistence or late-arrival
    reconciliation; subsequent batches need the future durable correlator.
    """
    windows = _maintenance_windows(maintenance)
    unique: dict[tuple[str, str], NetworkEvent] = {}
    input_count = byte_count = 0
    coverage = set(_BASE_COVERAGE)
    for event in events:
        input_count += 1
        if input_count > MAX_INPUT_RECORDS:
            raise ValueError("network_context_limit")
        validate_event(event)
        byte_count += len(json.dumps(asdict(event), sort_keys=True, default=sorted,
                                     separators=(",", ":")).encode("utf-8"))
        if byte_count > MAX_INPUT_BYTES:
            raise ValueError("network_context_limit")
        before = unique.get(event.key)
        if before is not None and before.content_hash != event.content_hash:
            raise ValueError("conflicting_network_evidence")
        unique[event.key] = event
        coverage.update(event.coverage)
    ordered = sorted(unique.values(), key=lambda row: (
        row.source_id, row.boot_id, row.journal_monotonic_us, row.event_id))
    clock_affected = _clock_warnings(ordered)
    if clock_affected:
        coverage.add("journal_clock_discontinuity")
    groups: dict[tuple[str, ...], list[NetworkEvent]] = defaultdict(list)
    eligible_count = 0
    for event in ordered:
        if _eligible(event):
            eligible_count += 1
            groups[(event.source_id, event.boot_id, event.source_profile_revision,
                    event.src_ip, event.dst_ip)].append(event)
    findings = []
    for key in sorted(groups):
        findings.extend(_scan(groups[key], windows, key[:2] in clock_affected))
    return NetworkReport(tuple(findings), input_count, len(unique), input_count - len(unique),
                         eligible_count, len(unique) - eligible_count, tuple(sorted(coverage)))
