"""Bounded, read-only search of retained normalized network observations.

The high-water sequence excludes later receipts, even after retention deletes
rows. It cannot preserve deleted history: every page explicitly limits coverage.
Cursors are checksummed navigation state, not an authorization boundary.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager, suppress
from datetime import datetime, timezone
import hashlib
import hmac
import ipaddress
import json
from pathlib import Path
import re
import sqlite3
import time

from .network_parse import MAX_REALTIME_US
from .network_protocol import decode, event_from_dict
from .network_store import APPLICATION_ID, SCHEMA_VERSION, _expected_schema_sql

MAX_CANDIDATES = 10_000
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_RECORD_BYTES = 16 * 1024
MAX_SCHEMA_OBJECTS = 64
MAX_SCHEMA_SQL_BYTES = 16 * 1024
MAX_CURSOR_BYTES = 512
MAX_VM_STEPS = 1_000_000
PROGRESS_STEPS = 1000
DEADLINE_SECONDS = 2.0
BUSY_SECONDS = 0.25
MAX_WINDOW_US = 7 * 86_400_000_000
MAX_SEQUENCE = (1 << 63) - 1
LIMITATIONS = (
    "retained_observations_only", "history_may_be_incomplete", "logging_coverage_limited",
    "observed_source_ip_only", "late_receipts_excluded",
)
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}"
                   r"(?:\.[0-9]{1,6})?(?:[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])\Z")
_TOKEN = re.compile(r"[A-Za-z0-9_-]+\Z")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# Bound the projection before event_json crosses the SQLite/Python boundary.
# Separate seeks avoid rescanning earlier rows, including equal-time ties.
_SEARCH_COLUMNS = """
SELECT seq,journal_realtime_us,collected_at_us,received_at_us,
       CASE WHEN typeof(event_id)='text' AND length(CAST(event_id AS BLOB))=64
            THEN event_id END AS event_id,
       CASE WHEN typeof(event_json)='text'
                 AND length(CAST(event_json AS BLOB)) BETWEEN 2 AND ?
            THEN event_json END AS event_json
FROM network_events INDEXED BY network_events_source_time
"""
_SAME_TIME_SQL = (_SEARCH_COLUMNS + "WHERE source_id=? AND journal_realtime_us=? AND seq>? AND seq<=? "
                  "ORDER BY journal_realtime_us,seq LIMIT ?")
_SEARCH_SQL = (_SEARCH_COLUMNS + "WHERE source_id=? AND journal_realtime_us>? AND journal_realtime_us<=? "
               "AND seq<=? ORDER BY journal_realtime_us,seq LIMIT ?")


class NetworkSearchInvalid(ValueError):
    """Fixed public input error; submitted values never enter its message."""

    code = "invalid_network_search"

    def __init__(self):
        super().__init__(self.code)


class NetworkSearchUnavailable(RuntimeError):
    """Fixed public storage/budget error; never returns partial search results."""

    code = "network_search_unavailable"

    def __init__(self):
        super().__init__(self.code)


def _endpoint(value):
    try:
        if type(value) is str:
            if len(value) > 40 or not _TIME.fullmatch(value):
                raise NetworkSearchInvalid()
            value = datetime.fromisoformat(value.replace("z", "+00:00").replace("Z", "+00:00"))
        if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
            raise NetworkSearchInvalid()
        value = value.astimezone(timezone.utc)
        delta = value - _EPOCH
        stamp = delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds
        if not 0 <= stamp <= MAX_REALTIME_US:
            raise NetworkSearchInvalid()
        return stamp, value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    except (ValueError, TypeError, OverflowError):
        raise NetworkSearchInvalid() from None


def _query(source_id, ip, start, end, limit):
    if (type(source_id) is not str or not _ID.fullmatch(source_id)
            or type(ip) is not str or not 1 <= len(ip) <= 45 or "%" in ip
            or type(limit) is not int or not 1 <= limit <= 100):
        raise NetworkSearchInvalid()
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        raise NetworkSearchInvalid() from None
    first, start = _endpoint(start)
    last, end = _endpoint(end)
    if not 0 <= last - first <= MAX_WINDOW_US:
        raise NetworkSearchInvalid()
    query = {"source_id": source_id, "ip": ip, "start": start, "end": end}
    binding = hashlib.sha256(_json([source_id, ip, first, last, limit])).hexdigest()
    return query, first, last, binding


def _json(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _cursor(binding, snapshot, boundary):
    data = _json([1, binding, snapshot, boundary])
    checksum = hashlib.sha256(data).digest()[:16]
    return base64.urlsafe_b64encode(checksum + data).rstrip(b"=").decode("ascii")


def _parse_cursor(token, binding, first, last):
    if (type(token) is not str or not 1 <= len(token) <= MAX_CURSOR_BYTES
            or not _TOKEN.fullmatch(token)):
        raise NetworkSearchInvalid()
    try:
        raw = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
        checksum, data = raw[:16], raw[16:]
        if not hmac.compare_digest(checksum, hashlib.sha256(data).digest()[:16]):
            raise NetworkSearchInvalid()
        value = json.loads(data)
        if (type(value) is not list or len(value) != 4 or type(value[0]) is not int or value[0] != 1
                or value[1] != binding or type(value[2]) is not int or not 0 <= value[2] <= MAX_SEQUENCE):
            raise NetworkSearchInvalid()
        snapshot, boundary = value[2:]
        if boundary is not None and (
            type(boundary) is not list or len(boundary) != 2
            or any(type(item) is not int for item in boundary)
            or not first <= boundary[0] <= last or not 1 <= boundary[1] <= snapshot
        ):
            raise NetworkSearchInvalid()
        if _cursor(binding, snapshot, boundary) != token:
            raise NetworkSearchInvalid()
        return snapshot, boundary
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise NetworkSearchInvalid() from None


class _Budget:
    def __init__(self):
        self.deadline = time.monotonic() + DEADLINE_SECONDS
        self.steps = 0
        self.bytes_read = 0

    def check(self):
        if self.steps >= MAX_VM_STEPS or time.monotonic() >= self.deadline:
            raise NetworkSearchUnavailable()

    def progress(self):
        self.steps += PROGRESS_STEPS
        return int(self.steps >= MAX_VM_STEPS or time.monotonic() >= self.deadline)

    def consume(self, size):
        self.bytes_read += size
        self.check()
        if self.bytes_read > MAX_JSON_BYTES:
            raise NetworkSearchUnavailable()


@contextmanager
def _snapshot(store, budget):
    db = None
    try:
        budget.check()
        file = Path(store.path).resolve(strict=True)
        if not file.is_file():
            raise NetworkSearchUnavailable()
        db = sqlite3.connect(file.as_uri() + "?mode=ro", uri=True, isolation_level=None,
                             timeout=BUSY_SECONDS)
        db.row_factory = sqlite3.Row
        # Also cap SQLite's value allocation/result size, including schema reads.
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, max(MAX_RECORD_BYTES, MAX_SCHEMA_SQL_BYTES) * 2)
        db.set_progress_handler(budget.progress, PROGRESS_STEPS)
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("BEGIN")
        yield db
        budget.check()
    except (sqlite3.Error, OSError, UnicodeError):
        raise NetworkSearchUnavailable() from None
    finally:
        if db is not None:
            with suppress(sqlite3.Error):
                db.set_progress_handler(None, 0)
                db.rollback()
            with suppress(sqlite3.Error):
                db.close()


def _validate_schema(db, budget):
    """Exact known schema, with bounded objects/SQL before Python allocation."""
    if (db.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
            or db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION):
        raise NetworkSearchUnavailable()
    rows = db.execute(
        "SELECT type,CASE WHEN length(CAST(name AS BLOB))<=128 THEN name END AS name,"
        "CASE WHEN length(CAST(sql AS BLOB))<=? THEN sql END AS sql "
        "FROM sqlite_master LIMIT ?", (MAX_SCHEMA_SQL_BYTES, MAX_SCHEMA_OBJECTS + 1)).fetchall()
    if len(rows) > MAX_SCHEMA_OBJECTS:
        raise NetworkSearchUnavailable()
    actual = {}
    tables = set()
    for row in rows:
        budget.check()
        if row["name"] is None or row["type"] not in ("table", "index"):
            raise NetworkSearchUnavailable()
        if row["type"] == "table":
            tables.add(row["name"])
        if row["name"] == "sqlite_sequence" or row["name"].startswith("sqlite_autoindex_"):
            continue
        if row["sql"] is None:
            raise NetworkSearchUnavailable()
        actual[row["type"], row["name"]] = re.sub(r"\s+", " ", row["sql"].strip())
    expected = _expected_schema_sql(SCHEMA_VERSION)
    if (actual != expected or tables != {name for kind, name in expected if kind == "table"} | {"sqlite_sequence"}):
        raise NetworkSearchUnavailable()
    row = db.execute("SELECT CASE WHEN length(CAST(value AS BLOB))<=8 THEN value END "
                     "FROM network_meta WHERE key='schema_version'").fetchone()
    if row is None or row[0] != str(SCHEMA_VERSION):
        raise NetworkSearchUnavailable()
    budget.check()


def _highwater(db):
    # sqlite_sequence retains the global AUTOINCREMENT high-water after expiry.
    rows = db.execute("SELECT seq FROM sqlite_sequence WHERE name='network_events' LIMIT 2").fetchall()
    if len(rows) > 1:
        raise NetworkSearchUnavailable()
    value = rows[0][0] if rows else 0
    if type(value) is not int or not 0 <= value <= MAX_SEQUENCE:
        raise NetworkSearchUnavailable()
    latest = db.execute("SELECT seq FROM network_events ORDER BY seq DESC LIMIT 1").fetchone()
    if latest is not None and (type(latest[0]) is not int or not 1 <= latest[0] <= value):
        raise NetworkSearchUnavailable()
    return value


def _event(row, source_id, budget):
    raw = row["event_json"]
    if raw is None or row["event_id"] is None:
        raise NetworkSearchUnavailable()
    raw = raw.encode("utf-8")
    budget.consume(len(raw))
    try:
        result = decode(raw)
        event = event_from_dict(result)
    except (ValueError, TypeError, RecursionError):
        raise NetworkSearchUnavailable() from None
    if (event.source_id != source_id or event.event_id != row["event_id"]
            or event.journal_realtime_us != row["journal_realtime_us"]
            or type(row["seq"]) is not int or not 1 <= row["seq"] <= MAX_SEQUENCE
            or any(type(row[key]) is not int or not 0 <= row[key] <= MAX_REALTIME_US
                   for key in ("journal_realtime_us", "collected_at_us", "received_at_us"))):
        raise NetworkSearchUnavailable()
    return {**result, **{key: row[key] for key in ("seq", "collected_at_us", "received_at_us")}}


def _page(db, budget, query, first, last, limit, binding, snapshot, boundary):
    lower_time, lower_seq = boundary if boundary is not None else (first, 0)
    items = []
    candidates = 0
    seeks = (
        (_SAME_TIME_SQL, (query["source_id"], lower_time, lower_seq, snapshot)),
        (_SEARCH_SQL, (query["source_id"], lower_time, last, snapshot)),
    )
    for sql, parameters in seeks:
        budget.check()
        rows = db.execute(sql, (MAX_RECORD_BYTES, *parameters, MAX_CANDIDATES + 1))
        try:
            while True:
                budget.check()
                row = rows.fetchone()
                if row is None:
                    break
                candidates += 1
                if candidates > MAX_CANDIDATES:
                    raise NetworkSearchUnavailable()
                event = _event(row, query["source_id"], budget)
                if event["src_ip"] != query["ip"]:
                    continue
                if len(items) == limit:
                    previous = items[-1]
                    token = _cursor(binding, snapshot, [previous["journal_realtime_us"], previous["seq"]])
                    return items, token
                items.append(event)
        finally:
            rows.close()
    return items, None


def search_events(store, *, source_id, ip, start, end, limit=50, cursor=None):
    """Search exact observed src_ip in an inclusive, at-most-seven-day UTC window.

    No counts, retention scans, writes or initialization. The deadline bounds
    cooperative SQLite/Python work; filesystem I/O is not preemptible and a lock
    wait may add up to BUSY_SECONDS. Exhaustion always discards the whole page.
    """
    query, first, last, binding = _query(source_id, ip, start, end, limit)
    requested = None if cursor is None else _parse_cursor(cursor, binding, first, last)
    budget = _Budget()
    with _snapshot(store, budget) as db:
        _validate_schema(db, budget)
        highwater = _highwater(db)
        snapshot, boundary = (highwater, None) if requested is None else requested
        if snapshot > highwater:
            raise NetworkSearchInvalid()
        page_cursor = _cursor(binding, snapshot, boundary)
        items, next_cursor = _page(db, budget, query, first, last, limit, binding, snapshot, boundary)
        budget.check()
        result = {"items": items, "next_cursor": next_cursor, "page_cursor": page_cursor,
                  "query": query, "snapshot": snapshot, "limitations": list(LIMITATIONS)}
    return result
