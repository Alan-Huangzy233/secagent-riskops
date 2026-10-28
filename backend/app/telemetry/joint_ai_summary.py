"""Pure, bounded summaries of a pinned joint observation; no model or store I/O.

The caller supplies a trusted server-side observation and explicit freshness
context. This is not an HTTP/body parser or a live source adapter. Only ``case``
is a candidate for a separately approved future request; references and metadata
remain local. Existing SSH summary permissions do not cover this contract.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
import json
import re

from ..agents.joint_triage import Dossier
from .ai_summary import Aliases
from .joint_case_contract import AnchorRequest, CaseScope, ValidatedRead, validate_read

VERSION = "joint-summary-v1"
ENVELOPE_VERSION = "joint-local-envelope-v1"
MAX_RECORDS = 40
MAX_BYTES = 64 * 1024
MAX_LOCAL_BYTES = 256 * 1024
_HEX = re.compile(r"[0-9a-f]{32}\Z")
_CASE = re.compile(r"JOINT-[0-9a-f]{32}\Z")
_REFRESH = {"fresh", "pending", "unavailable", "needs_review", "not_eligible"}
_BASE_LIMITATIONS = {
    "source_coverage_unknown", "cross_store_not_atomic", "shared_ip_not_identity",
    "clock_alignment_unknown", "retained_incidents_only", "observed_counts_lower_bounds",
}


class JointSummaryError(ValueError):
    """Fixed codes only; never expose source values or validation input."""

    def __init__(self, code="invalid_joint_ai_input"):
        if code not in {"invalid_joint_ai_input", "joint_ai_capacity_exceeded",
                        "joint_ai_rejected_observation"}:
            raise ValueError("invalid_joint_ai_error_code")
        self.code = code
        super().__init__(code)


def _int(value, lower, upper):
    if type(value) is not int or not lower <= value <= upper:
        raise JointSummaryError()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False)


@dataclass(frozen=True)
class SnapshotContext:
    """Trusted context for one saved revision, not a claim of source coverage.

    A future store adapter must capture and validate these values with the saved
    observation. ``freshness`` must be assessed explicitly; a previous successful
    read alone does not establish it. Restore epochs invalidate old summaries.
    """

    store_id: str
    query_epoch: str
    case_id: str
    case_revision: int
    current_revision: int
    refresh_state: str
    refresh_error: bool
    freshness: str
    revalidation_pending: bool

    def __post_init__(self):
        for value in (self.store_id, self.query_epoch):
            if type(value) is not str or not _HEX.fullmatch(value):
                raise JointSummaryError()
        if type(self.case_id) is not str or not _CASE.fullmatch(self.case_id):
            raise JointSummaryError()
        _int(self.case_revision, 1, 2**63 - 1)
        _int(self.current_revision, self.case_revision, 2**63 - 1)
        if type(self.refresh_state) is not str or self.refresh_state not in _REFRESH:
            raise JointSummaryError()
        if type(self.freshness) is not str or self.freshness not in {"current", "stale", "unknown"}:
            raise JointSummaryError()
        if type(self.refresh_error) is not bool or type(self.revalidation_pending) is not bool:
            raise JointSummaryError()


def _review_state(context, projection):
    if context.revalidation_pending:
        return "revalidation_required"
    if context.case_revision != context.current_revision:
        return "historical"
    if projection["state"] in {"stale", "retracted"} or context.freshness == "stale":
        return "stale"
    if context.refresh_state != "fresh" or context.refresh_error:
        return "unavailable"
    return "current" if context.freshness == "current" else "unknown"


def _select(timeline, limit):
    """Round-robin prefixes retain both domains when the cap permits it."""
    groups = [[row for row in timeline if row["kind"] == kind] for kind in ("network", "ssh")]
    selected = []
    for index in range(max(map(len, groups), default=0)):
        for group in groups:
            if index < len(group) and len(selected) < limit:
                selected.append(group[index])
        if len(selected) == limit:
            break
    return sorted(selected, key=lambda row: (row["event_ts_us"], row["kind"],
                                            row["source_id"], row["event_id"]))


def build(observation: ValidatedRead, scope: CaseScope, context: SnapshotContext,
          aliases: Aliases, *, record_limit=MAX_RECORDS, byte_limit=MAX_BYTES,
          local_byte_limit=MAX_LOCAL_BYTES) -> dict:
    """Revalidate the whole supplied revision, then derive an aliased dossier.

    Limits are lowerable. A byte overflow rejects the summary; it never silently
    discards references or promotes a bounded sample to complete coverage.
    """
    try:
        return _build(observation, scope, context, aliases, record_limit=record_limit,
                      byte_limit=byte_limit, local_byte_limit=local_byte_limit)
    except JointSummaryError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OverflowError, RecursionError):
        raise JointSummaryError() from None


def _build(observation, scope, context, aliases, *, record_limit, byte_limit, local_byte_limit):
    _int(record_limit, 1, MAX_RECORDS)
    _int(byte_limit, 1, MAX_BYTES)
    _int(local_byte_limit, 1, MAX_LOCAL_BYTES)
    if (type(observation) is not ValidatedRead or type(scope) is not CaseScope
            or type(context) is not SnapshotContext or type(aliases) is not Aliases):
        raise JointSummaryError()
    if type(aliases.secret) is not bytes or not 32 <= len(aliases.secret) <= 128:
        raise JointSummaryError()
    alias = Aliases(aliases.secret)
    # Reconstruct frozen values too: an object instance is not an authenticity
    # guarantee, and Python callers can bypass normal dataclass construction.
    context = SnapshotContext(**asdict(context))
    scope = CaseScope.from_json(scope.to_json())
    observation = ValidatedRead(**asdict(observation))
    projection = json.loads(observation.projection_json)
    anchor = projection["anchor"]
    checked = validate_read(scope, AnchorRequest(anchor["incident_id"], anchor["revision"]),
                            observation.to_joint_read())
    if checked.state == "rejected":
        raise JointSummaryError("joint_ai_rejected_observation")
    if context.case_id != checked.case_id:
        raise JointSummaryError()

    timeline = projection["timeline"]
    selected = _select(timeline, record_limit)
    retained = Counter(row["kind"] for row in timeline)
    included = Counter(row["kind"] for row in selected)
    observed = {"network": sum(projection["counts"]["network"].values()),
                "ssh": sum(item["evidence"] for item in projection["counts"]["ssh"].values())}
    counts = {kind: {"observed": observed[kind], "retained": retained[kind],
                     "included": included[kind]} for kind in ("network", "ssh")}
    summary_complete = len(selected) == len(timeline)
    temporal = projection["temporal_association_available"]
    if temporal:
        origin = projection["window"]["start_us"]
        duration = projection["window"]["end_us"] - origin
    else:
        origin = min((row["event_ts_us"] for row in timeline), default=0)
        duration = None

    asset, peer = alias("A", projection["asset_id"]), alias("P", anchor["src_ip"])
    evidence, references = [], {}
    for row in selected:
        event_id = alias("E", [VERSION, row["kind"], row["source_id"], row["event_id"]])
        event = {"event_id": event_id, "offset_us": row["event_ts_us"] - origin,
                 "source": alias("S", row["source_id"]), "asset": asset, "peer": peer}
        if row["kind"] == "network":
            event.update(kind="network_tcp", destination=alias("D", row["dst_ip"]),
                         dst_port=row["dst_port"], protocol=row["protocol"], direction=row["direction"])
        else:
            event.update(kind="ssh", event_type=row["event_type"],
                         account=alias("U", row["account"]) if row["account"] is not None else None)
        evidence.append(event)
        references[event_id] = {"kind": row["kind"], "source_id": row["source_id"],
                                "event_id": row["event_id"], "incident_refs": row["incident_refs"]}

    limitations = set(_BASE_LIMITATIONS)
    for present, code in ((not projection["input_complete"], "projection_input_incomplete"),
                          (not projection["timeline_complete"], "timeline_truncated"),
                          (not summary_complete, "summary_truncated"),
                          (not temporal, "temporal_association_unavailable")):
        if present:
            limitations.add(code)
    # Only fixed classifications leave this adapter. Source-specific coverage
    # codes can be locally supplied strings and must not become prompt content.
    uncertainties = projection["uncertainties"]
    for prefix, code in (("network:", "network_coverage_limited"), ("ssh:", "ssh_coverage_limited")):
        if any(value.startswith(prefix) for value in uncertainties):
            limitations.add(code)
    for old, new in (("network_anchor_time_span_exceeded", "network_anchor_span_exceeded"),
                     ("single_network_observation_clock_unverifiable", "network_clock_unverifiable"),
                     ("network_evidence_unavailable", "network_evidence_unavailable")):
        if old in uncertainties:
            limitations.add(new)
    case = {"dossier_version": "joint-v1", "case_id": alias("J", [context.store_id, checked.case_id]),
            "revision": "R-" + "0" * 24, "kind": "network_ssh", "asset": asset, "peer": peer,
            "association_state": projection["state"], "review_state": _review_state(context, projection),
            "input_complete": projection["input_complete"], "timeline_complete": projection["timeline_complete"],
            "summary_complete": summary_complete, "coverage_complete": None,
            "temporal_association_available": temporal, "window_duration_us": duration,
            "counts": counts, "limitations": sorted(limitations), "evidence": evidence}
    case["revision"] = alias("R", [VERSION, scope.sha256, asdict(context),
                                     checked.projection_sha256, record_limit, case])
    Dossier.model_validate(case)
    if len(_canonical(case).encode("ascii")) > byte_limit:
        raise JointSummaryError("joint_ai_capacity_exceeded")
    result = {"dossier_version": ENVELOPE_VERSION, "case": case, "local_refs": references, "meta": {
        "summary_version": VERSION, "scope_sha256": scope.sha256,
        "store_id": context.store_id, "query_epoch": context.query_epoch,
        "case_id": checked.case_id, "case_revision": context.case_revision,
        "current_revision": context.current_revision, "projection_sha256": checked.projection_sha256,
        "snapshot_context": asdict(context), "record_limit": record_limit,
        "sampling": "round_robin_domain_prefixes_then_chronological",
        "time_origin_us": origin, "time_basis": "association_window_start" if temporal else "retained_minimum",
        "coverage": "unknown; supplied projection completeness is not source coverage",
        "outbound_candidate": "case only; no production transport approved",
    }}
    private = {key: result[key] for key in ("dossier_version", "local_refs", "meta")}
    if len(_canonical(private).encode("ascii")) > local_byte_limit:
        raise JointSummaryError("joint_ai_capacity_exceeded")
    return result
