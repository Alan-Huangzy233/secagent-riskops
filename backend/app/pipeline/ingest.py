"""Ingestion: retain raw evidence, normalize, deduplicate, group, score.

Deterministic and evidence-first: every parsed alert links to the
content-addressed evidence blob it came from before any interpretation.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from ..core.clock import isoformat
from ..reference import (
    CRITICALITY_BONUS,
    SEVERITY_WEIGHT,
    ASSET_CRITICALITY,
    band_for_score,
)
from ..schemas.enums import Severity
from ..schemas.models import Alert, AlertGroup, Evidence
from ..services import Services

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}
_DEFAULT_YEAR = 2026

_SSH_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+(?P<host>\S+)\s+"
    r"sshd\[\d+\]:\s+Failed password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

_SURICATA_SEVERITY = {1: Severity.HIGH, 2: Severity.MEDIUM, 3: Severity.LOW}


@dataclass
class RawSource:
    name: str
    source_type: str  # "linux_auth" | "suricata_eve"
    media_type: str
    data: bytes


@dataclass
class IngestResult:
    evidences: list[Evidence]
    alerts: list[Alert]
    groups: list[AlertGroup]


def _syslog_iso(mon: str, day: str, time: str) -> str:
    return f"{_DEFAULT_YEAR:04d}-{_MONTHS[mon]:02d}-{int(day):02d}T{time}Z"


def _asset_criticality(asset_id: str) -> Severity:
    return ASSET_CRITICALITY.get(asset_id, Severity.LOW)


def store_evidence(svc: Services, source: RawSource) -> Evidence:
    """Persist raw bytes content-addressed, and record Evidence metadata."""
    storage_ref = svc.evidence.put(source.data)
    evidence = Evidence(
        evidence_id=svc.ids.next("EVID"),
        kind="raw_alert",
        content_hash=storage_ref,
        media_type=source.media_type,
        size_bytes=len(source.data),
        source=source.name,
        source_type=source.source_type,
        captured_at=isoformat(svc.clock.now()),
        storage_ref=storage_ref,
    )
    svc.repo.save("evidence", evidence.evidence_id, evidence)
    return evidence


def _parse_linux_auth(svc: Services, data: bytes, evidence_id: str) -> list[Alert]:
    alerts: list[Alert] = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        m = _SSH_RE.match(line.strip())
        if not m:
            continue
        host = m.group("host")
        ip = m.group("ip")
        alerts.append(Alert(
            alert_id=svc.ids.next("ALERT"),
            source="linux_auth",
            signature="ssh_failed_password",
            title=f"Failed SSH password for {m.group('user')} from {ip}",
            asset_id=host,
            host=host,
            severity=Severity.MEDIUM,
            event_time=_syslog_iso(m.group("mon"), m.group("day"), m.group("time")),
            dedup_key=f"ssh_failed_password:{host}:{ip}",
            evidence_ids=[evidence_id],
        ))
    return alerts


def _parse_suricata_eve(svc: Services, data: bytes, evidence_id: str) -> list[Alert]:
    alerts: list[Alert] = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if rec.get("event_type") != "alert":
            continue
        alert_meta = rec.get("alert", {})
        sev = _SURICATA_SEVERITY.get(int(alert_meta.get("severity", 3)), Severity.LOW)
        src_ip = rec.get("src_ip", "unknown")
        dest_ip = rec.get("dest_ip", "unknown")
        sig_id = alert_meta.get("signature_id", "0")
        alerts.append(Alert(
            alert_id=svc.ids.next("ALERT"),
            source="suricata_eve",
            signature="suspicious_outbound_tls",
            title=alert_meta.get("signature", "Suricata alert"),
            asset_id=src_ip,
            host=src_ip,
            severity=sev,
            event_time=rec.get("timestamp", "").replace("+0000", "Z"),
            dedup_key=f"suspicious_outbound_tls:{sig_id}:{src_ip}:{dest_ip}",
            evidence_ids=[evidence_id],
        ))
    return alerts


_PARSERS = {
    "linux_auth": _parse_linux_auth,
    "suricata_eve": _parse_suricata_eve,
}


def _score(group_severity: Severity, count: int, asset_id: str) -> tuple[int, str]:
    base = SEVERITY_WEIGHT[group_severity]
    count_bonus = min(count, 5) * 5
    asset_bonus = CRITICALITY_BONUS[_asset_criticality(asset_id)]
    score = min(100, base + count_bonus + asset_bonus)
    return score, band_for_score(score).value


def ingest(svc: Services, sources: list[RawSource]) -> IngestResult:
    evidences: list[Evidence] = []
    alerts: list[Alert] = []

    for source in sources:
        parser = _PARSERS.get(source.source_type)
        if parser is None:
            raise ValueError(f"No parser for source_type {source.source_type!r}")
        evidence = store_evidence(svc, source)
        evidences.append(evidence)
        alerts.extend(parser(svc, source.data, evidence.evidence_id))

    # Deduplicate + group by dedup_key (deterministic order of first appearance).
    grouped: dict[str, list[Alert]] = {}
    order: list[str] = []
    for alert in alerts:
        if alert.dedup_key not in grouped:
            grouped[alert.dedup_key] = []
            order.append(alert.dedup_key)
        grouped[alert.dedup_key].append(alert)

    groups: list[AlertGroup] = []
    for key in order:
        members = grouped[key]
        first = members[0]
        severity = max((a.severity for a in members), key=lambda s: SEVERITY_WEIGHT[s])
        evidence_ids = sorted({eid for a in members for eid in a.evidence_ids})
        score, band = _score(severity, len(members), first.asset_id)
        group = AlertGroup(
            group_id=svc.ids.next("AG"),
            dedup_key=key,
            signature=first.signature,
            asset_id=first.asset_id,
            severity=severity,
            count=len(members),
            alert_ids=[a.alert_id for a in members],
            evidence_ids=evidence_ids,
            first_seen=min(a.event_time for a in members),
            last_seen=max(a.event_time for a in members),
            risk_score=score,
            risk_band=band,
        )
        for alert in members:
            svc.repo.save("alerts", alert.alert_id, alert)
        svc.repo.save("alert_groups", group.group_id, group)
        groups.append(group)

    return IngestResult(evidences=evidences, alerts=alerts, groups=groups)
