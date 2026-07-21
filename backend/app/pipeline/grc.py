"""GRC stage: map an incident to a control and a risk-register candidate.

The mapping assists analysis; it does not certify compliance or accept risk.
Every mapping carries confidence and evidence references.
"""
from __future__ import annotations

from ..reference import CONTROL_LIBRARY, SIGNATURE_TO_CONTROL
from ..schemas.enums import RiskBand, Severity
from ..schemas.models import Control, ControlMapping, Incident, Risk
from ..services import Services

_BAND_BY_SEVERITY = {
    Severity.INFO: RiskBand.INFORMATIONAL,
    Severity.LOW: RiskBand.LOW,
    Severity.MEDIUM: RiskBand.MEDIUM,
    Severity.HIGH: RiskBand.HIGH,
    Severity.CRITICAL: RiskBand.CRITICAL,
}


def map_incident(svc: Services, incident: Incident, signature: str) -> tuple[ControlMapping | None, Risk]:
    mapping: ControlMapping | None = None
    control_id = SIGNATURE_TO_CONTROL.get(signature)
    if control_id and control_id in CONTROL_LIBRARY:
        meta = CONTROL_LIBRARY[control_id]
        control = Control(control_id=control_id, framework=meta["framework"],
                          control_ref=meta["control_ref"], title=meta["title"])
        svc.repo.save("controls", control.control_id, control)
        mapping = ControlMapping(
            mapping_id=svc.ids.next("MAP"),
            incident_id=incident.incident_id,
            control_id=control.control_id,
            confidence=0.8,
            rationale=f"Incident evidences control {control.control_ref} ({control.title}).",
            evidence_ids=incident.evidence_ids,
        )
        svc.repo.save("control_mappings", mapping.mapping_id, mapping)

    band = _BAND_BY_SEVERITY[incident.severity]
    risk = Risk(
        risk_id=svc.ids.next("RISK"),
        title=f"Exposure from {incident.title}",
        statement=(f"Observed activity ({', '.join(incident.attack_techniques) or 'n/a'}) "
                   f"on {incident.asset_id} could lead to compromise if unaddressed."),
        likelihood=Severity.MEDIUM,
        impact=incident.severity,
        inherent_band=band,
        related_incident_id=incident.incident_id,
        evidence_ids=incident.evidence_ids,
    )
    svc.repo.save("risks", risk.risk_id, risk)
    return mapping, risk
