"""Deterministic reference knowledge used by the pipeline.

Small, explicit stand-ins for what will become the Asset registry, ATT&CK
enrichment, and GRC control library. Kept deterministic so scoring, triage, and
mapping are reproducible under replay.
"""
from __future__ import annotations

from .schemas.enums import RiskBand, Severity

# --- Asset criticality -----------------------------------------------------
ASSET_CRITICALITY: dict[str, Severity] = {
    "web-01": Severity.MEDIUM,
}

# --- Scoring weights -------------------------------------------------------
SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.INFO: 5,
    Severity.LOW: 20,
    Severity.MEDIUM: 45,
    Severity.HIGH: 70,
    Severity.CRITICAL: 90,
}
CRITICALITY_BONUS: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 0,
    Severity.MEDIUM: 10,
    Severity.HIGH: 20,
    Severity.CRITICAL: 30,
}


def band_for_score(score: int) -> RiskBand:
    if score >= 80:
        return RiskBand.CRITICAL
    if score >= 60:
        return RiskBand.HIGH
    if score >= 40:
        return RiskBand.MEDIUM
    if score >= 20:
        return RiskBand.LOW
    return RiskBand.INFORMATIONAL


# --- ATT&CK enrichment -----------------------------------------------------
# Keyed by normalized signature.
ATTACK_TECHNIQUES: dict[str, list[str]] = {
    "ssh_failed_password": ["T1110"],  # Brute Force
    "suspicious_outbound_tls": ["T1071.001"],  # Application Layer Protocol: Web
}

# --- GRC control library (subset) -----------------------------------------
CONTROL_LIBRARY: dict[str, dict[str, str]] = {
    "AC-7": {"framework": "NIST SP 800-53", "control_ref": "AC-7",
             "title": "Unsuccessful Logon Attempts"},
    "SI-4": {"framework": "NIST SP 800-53", "control_ref": "SI-4",
             "title": "System Monitoring"},
}

# Map a normalized signature to the control it provides evidence for.
SIGNATURE_TO_CONTROL: dict[str, str] = {
    "ssh_failed_password": "AC-7",
    "suspicious_outbound_tls": "SI-4",
}
