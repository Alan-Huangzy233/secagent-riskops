"""Bounded, allowlisted dossiers. Raw fields and reference mappings stay local."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime
import hashlib
import hmac
import json
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from ..agents.triage_evidence import (
    AccountContext, Authorization, Dossier, ServiceContext, SourceHistory,
)

VERSION = 1
ContextRecord = Annotated[AccountContext | SourceHistory | Authorization | ServiceContext,
                          Field(discriminator="kind")]


class Inventory(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    version: int = Field(default=1, ge=1, le=1)
    records: list[ContextRecord] = Field(default_factory=list, max_length=500)


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def inventory(path: Path | None) -> tuple[list[dict], str]:
    if path is None:
        return [], hashlib.sha256(b"no trusted inventory").hexdigest()
    if path.stat().st_mode & 0o077 or path.stat().st_size > 256 * 1024:
        raise ValueError("trusted context file must be private and bounded")
    parsed = Inventory.model_validate_json(path.read_bytes())
    records = [r.model_dump() for r in parsed.records]
    if len({r["event_id"] for r in records}) != len(records):
        raise ValueError("duplicate trusted context IDs")
    return records, hashlib.sha256(canonical(records).encode()).hexdigest()


class Aliases:
    def __init__(self, secret: bytes):
        if len(secret) < 32:
            raise ValueError("alias secret is too short")
        self.secret = secret

    def __call__(self, kind: str, value) -> str:
        digest = hmac.new(self.secret, canonical([kind, value]).encode(), "sha256").hexdigest()
        return kind + "-" + digest[:24]


def _timestamp(value) -> int:
    if isinstance(value, str):
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
    if type(value) not in (int, float):
        raise ValueError("unsupported timestamp")
    return int(value)


def build(snapshot: dict, aliases: Aliases, context: list[dict], context_sha: str,
          *, http_paths: tuple[str, ...] = ()) -> dict:
    """Consume an authenticated server snapshot, never a browser-supplied dossier.

    Live snapshots currently contain SSH only. The HTTP adapter accepts normalized
    records for offline/future source integration; it does not parse raw requests.
    """
    events, local_refs, reasons = [], {}, list(snapshot.get("completeness_reasons", []))
    shift = 1_000_000_000 - _timestamp(snapshot["first_seen"])
    observed_hosts, observed_accounts, observed_peers = set(), set(), set()

    def path(value):
        # Only explicitly approved exact paths may stay readable. Other strings,
        # including queries/credentials, are entirely opaque, not just URL-stripped.
        return value if value in http_paths else "/" + aliases("path", value)

    for row in snapshot["records"][:40]:
        kind = row.get("event_type")
        host, peer, user = row.get("source_id"), row.get("src_ip"), row.get("ssh_user")
        is_http = snapshot["kind"] == "http" and kind == "http_request"
        is_auth = snapshot["kind"] == "ssh" and kind in ("auth_failure", "invalid_user", "auth_success")
        if not host or not peer or not (is_http or (is_auth and user)):
            reasons.append("unsupported_or_incomplete_record")
            continue
        event_id = aliases("E", [host, row["event_id"]])
        event = {"event_id": event_id, "kind": kind, "time": _timestamp(row["timestamp"]) + shift,
                 "source": aliases("P", peer), "host": aliases("H", host)}
        if is_http:
            if not isinstance(row.get("path"), str):
                reasons.append("unsupported_or_incomplete_record")
                continue
            event.update(method=row["method"], path=path(row["path"]), status=row["status"], user_agent="")
            if row["path"] not in http_paths:
                reasons.append("http_path_withheld")
        else:
            event["account"] = aliases("U", user)
            observed_accounts.add((host, user))
        observed_hosts.add(host)
        observed_peers.add((host, peer))
        events.append(event)
        local_refs[event_id] = {"source_id": host, "event_id": row["event_id"]}
    if not events:
        raise ValueError("no supported observed evidence; manual review required")
    evidence = list(events)
    known_accounts = set()
    for raw in context:
        if raw["host"] not in observed_hosts:
            continue
        kind = raw["kind"]
        if kind in ("account_context", "source_history") and (raw["host"], raw["account"]) not in observed_accounts:
            continue
        if kind in ("source_history", "authorization") and (raw["host"], raw["source"]) not in observed_peers:
            continue
        if len(evidence) >= 95:
            reasons.append("context_truncated")
            break
        item = deepcopy(raw)
        item["event_id"] = aliases("C", raw)
        item["host"] = aliases("H", raw["host"])
        if "account" in raw:
            item["account"] = aliases("U", raw["account"])
        if "source" in raw:
            item["source"] = aliases("P", raw["source"])
        for field in ("window_start", "window_end", "valid_from", "valid_until"):
            if field in item:
                item[field] += shift
        if kind == "authorization":
            item["accounts"] = [aliases("U", a) for a in raw["accounts"]]
            item["paths"] = [path(p) for p in raw["paths"]]
        if kind == "service_context":
            item["expected_routes"] = [{**route, "path": path(route["path"])} for route in raw["expected_routes"]]
        if kind == "account_context":
            known_accounts.add((raw["host"], raw["account"]))
        evidence.append(item)
        local_refs[item["event_id"]] = {"trusted_context_id": raw["event_id"], "context_sha256": context_sha}
    for host, user in sorted(observed_accounts - known_accounts):
        if len(evidence) >= 100:
            reasons.append("context_truncated")
            break
        evidence.append({"event_id": aliases("C", ["unknown-account", host, user]), "kind": "account_context",
                         "host": aliases("H", host), "account": aliases("U", user), "classification": "unknown"})
    if snapshot["evidence_count"] > len(snapshot["records"]) or len(snapshot["records"]) > 40:
        reasons.append("sample_truncated")
    reasons = sorted(set(reasons))
    state = "complete"
    if reasons:
        state = "gapped" if "collection_gap" in reasons else (
            "truncated" if any("truncated" in r for r in reasons) else "unknown")
    case = {"dossier_version": 3, "incident_id": aliases("I", snapshot["incident_id"]),
            "revision": "pending", "kind": snapshot["kind"], "evidence_status": state, "evidence": evidence}
    # The private snapshot revision changes even when new records are outside the sample.
    case["revision"] = aliases("R", [VERSION, snapshot["revision"], case, context_sha, http_paths])
    Dossier.model_validate(case)
    return {"case": case, "local_refs": local_refs,
            "meta": {"summary_version": VERSION, "adapter": "bounded-telemetry-v1",
                     "context_sha256": context_sha, "evidence_count": snapshot["evidence_count"],
                     "observed_included": len(events), "completeness_reasons": reasons,
                     "withheld_fields": ["raw_message", "hostname", "raw_ip", "raw_account",
                                         "raw_event_id", "user_agent", "unapproved_http_path"],
                     "timestamps": "relative to incident start with a fixed synthetic epoch"}}
