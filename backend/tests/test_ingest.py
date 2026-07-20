from __future__ import annotations

from app.pipeline.ingest import ingest
from app.schemas.enums import RiskBand, Severity


def test_ingest_normalizes_dedups_groups_and_scores(services, sources):
    result = ingest(services, sources)

    # 3 SSH failures + 1 Suricata alert = 4 normalized alerts.
    assert len(result.alerts) == 4
    # Deduplicated into 2 groups by (signature, host, source).
    assert len(result.groups) == 2

    ssh = next(g for g in result.groups if g.signature == "ssh_failed_password")
    assert ssh.count == 3
    assert ssh.asset_id == "web-01"
    # medium(45) + count(15) + web-01 criticality(10) = 70 -> HIGH.
    assert ssh.risk_score == 70
    assert ssh.risk_band == RiskBand.HIGH

    suri = next(g for g in result.groups if g.signature == "suspicious_outbound_tls")
    assert suri.count == 1
    assert suri.severity == Severity.MEDIUM
    # medium(45) + count(5) + unknown asset(0) = 50 -> MEDIUM.
    assert suri.risk_score == 50
    assert suri.risk_band == RiskBand.MEDIUM


def test_raw_input_is_preserved_as_content_addressed_evidence(services, sources):
    result = ingest(services, sources)
    assert len(result.evidences) == 2
    for ev in result.evidences:
        assert ev.content_hash.startswith("sha256:")
        assert ev.content_hash == ev.storage_ref
        assert services.evidence.verify(ev.storage_ref)


def test_every_alert_links_to_evidence(services, sources):
    result = ingest(services, sources)
    for alert in result.alerts:
        assert alert.evidence_ids, "alert must reference retained evidence"
