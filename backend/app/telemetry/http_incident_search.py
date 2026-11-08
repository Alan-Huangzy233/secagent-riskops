"""Bounded exact connection-peer lookup over retained HTTP review cases.

Search is a read-only view of existing analysis. Count and page share a database
snapshot; separate page requests may change as analysis or retention advances.
"""
from __future__ import annotations

from contextlib import closing
import ipaddress
import json
from pathlib import Path
import re
import sqlite3
import time

from .http_incidents import stamp

MAX_PEER_CASES = 10_000
MAX_RECORD_BYTES = 64 * 1024
MAX_SELECTED_BYTES = 2 * 1024 * 1024
MAX_VM_STEPS = 1_000_000
PROGRESS_INTERVAL = 1000
MAX_SECONDS = 2.0
BUSY_MILLISECONDS = 250
LIMITATIONS = ("retained_cases_only", "connection_peer_only", "analysis_coverage_limited", "pages_may_change")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
INVALID = "invalid_http_incident_search"


class HttpIncidentSearchUnavailable(RuntimeError):
    """A complete, bounded result could not be read safely."""

    def __init__(self):
        super().__init__("http_incident_search_unavailable")


def canonical_ip(value):
    try:
        if not isinstance(value, str) or not value or len(value) > 45 or "%" in value:
            raise ValueError
        address = ipaddress.ip_address(value)
        return str(getattr(address, "ipv4_mapped", None) or address)
    except ValueError:
        raise ValueError(INVALID) from None


def _scope(ip, source_id, service_id, focus, page, limit):
    peer = canonical_ip(ip)
    if any(value is not None and (not isinstance(value, str) or not _ID.fullmatch(value))
           for value in (source_id, service_id)):
        raise ValueError(INVALID)
    if (focus not in ("all", "attention", "low", "retracted") or type(page) is not int
            or not 1 <= page <= 1_000_000 or type(limit) is not int or not 1 <= limit <= 200):
        raise ValueError(INVALID)
    return {"ip": peer, "source_id": source_id, "service_id": service_id, "focus": focus}


def _reject_nonfinite(_value):
    raise ValueError("nonfinite HTTP incident JSON")


def _decode(row):
    payload = json.loads(row["payload_json"], parse_constant=_reject_nonfinite)
    # Reject finite-number overflow and escaped lone surrogates too: otherwise
    # response serialization can fail after the safe query-error boundary.
    json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    if not isinstance(payload, dict) or not isinstance(payload.get("assessment"), dict):
        raise HttpIncidentSearchUnavailable()
    assessment = payload["assessment"]
    for field in ("incident_id", "source_id", "service_id", "client_ip", "coverage"):
        if not isinstance(payload.get(field), str) or payload[field] != row[field]:
            raise HttpIncidentSearchUnavailable()
    if (payload.get("protocol") != "http" or payload.get("window_start") != stamp(row["hour"])
            or payload.get("window_end") != stamp(row["hour"] + 3600)
            or type(payload.get("revision")) is not int or payload["revision"] != row["revision"]
            or type(payload.get("active")) is not bool or int(payload["active"]) != row["active"]
            or type(assessment.get("surfaced")) is not bool or int(assessment["surfaced"]) != row["surfaced"]
            or type(assessment.get("score")) is not int or assessment["score"] != row["score"]
            or payload.get("updated_at") != stamp(row["updated_at"])):
        raise HttpIncidentSearchUnavailable()
    return payload


def search_cases(store, *, ip, source_id=None, service_id=None, focus="all", page=1, limit=50):
    query = _scope(ip, source_id, service_id, focus, page, limit)
    started = time.monotonic()
    steps = 0

    def expired():
        return time.monotonic() - started > MAX_SECONDS

    def progress():
        nonlocal steps
        steps += PROGRESS_INTERVAL
        return int(steps > MAX_VM_STEPS or expired())

    where, params = ["client_ip=?"], [query["ip"]]
    for field in ("source_id", "service_id"):
        if query[field] is not None:
            where.append(field + "=?")
            params.append(query[field])
    if focus == "attention":
        where.append("surfaced=1 AND active=1")
    elif focus == "low":
        where.append("surfaced=0 AND active=1")
    elif focus == "retracted":
        where.append("active=0")
    clause = " AND ".join(where)
    table = "http_incidents INDEXED BY http_incidents_peer"
    try:
        # Opening a missing database must not create one or run migrations.
        uri = Path(store.path).resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=BUSY_MILLISECONDS / 1000,
                                    isolation_level=None)) as db:
            db.row_factory = sqlite3.Row
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_RECORD_BYTES + 4096)
            db.set_progress_handler(progress, PROGRESS_INTERVAL)
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            # Bound even selective service/focus searches for a very hot peer.
            candidates = db.execute("SELECT count(*) FROM (SELECT 1 FROM " + table +
                                    " WHERE client_ip=? LIMIT ?)", (query["ip"], MAX_PEER_CASES + 1)).fetchone()[0]
            if candidates > MAX_PEER_CASES or expired():
                raise HttpIncidentSearchUnavailable()
            total = db.execute("SELECT count(*) FROM " + table + " WHERE " + clause, params).fetchone()[0]
            pages = max(1, (total + limit - 1) // limit)
            page = min(page, pages)
            offset = (page - 1) * limit
            rows = db.execute("SELECT incident_id,source_id,service_id,client_ip,hour,revision,score,surfaced,"
                              "active,coverage,updated_at,payload_json FROM " + table + " WHERE " + clause +
                              " ORDER BY hour DESC,seq DESC LIMIT ? OFFSET ?", (*params, limit, offset))
            items, selected_bytes = [], 0
            for row in rows:
                raw = row["payload_json"]
                if not isinstance(raw, str):
                    raise HttpIncidentSearchUnavailable()
                size = len(raw.encode("utf-8"))
                selected_bytes += size
                if size > MAX_RECORD_BYTES or selected_bytes > MAX_SELECTED_BYTES or expired():
                    raise HttpIncidentSearchUnavailable()
                items.append(_decode(row))
            if len(items) != min(limit, total - offset) or expired():
                raise HttpIncidentSearchUnavailable()
            return {"items": items, "page": page, "total_pages": pages, "total": total,
                    "query": query, "limitations": list(LIMITATIONS)}
    except (sqlite3.Error, ValueError, TypeError, KeyError, OverflowError, OSError, RecursionError):
        raise HttpIncidentSearchUnavailable() from None
