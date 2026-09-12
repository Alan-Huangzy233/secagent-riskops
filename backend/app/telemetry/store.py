"""Durable, read-only SSH telemetry, isolated from the demonstration workflow.

One SQLite transaction acknowledges each batch. Source identity is supplied by
the authenticated API, never inferred from a log message. Raw events expire;
compact event/batch receipts and incident evidence survive raw-event retention.
This module never invokes the agent, policy engine, or a remediation executor.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from .sshd_parse import FAILURE_KINDS, parse_sshd


_WINDOW_SECONDS = 300
_FAILURE_THRESHOLD = 3
_EVIDENCE_RESPONSE_LIMIT = 20
_SSH_PREFIX = re.compile(
    r"^(?:\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+)?"
    r"sshd(?:-session|-auth)?(?:\[\d+\])?:\s*"
)
_SSH_IDENTIFIERS = {"sshd", "sshd-session", "sshd-auth"}
_SSH_UNITS = {"ssh.service", "sshd.service"}
# Message shapes that count toward the failure threshold, plus the vocabulary
# this column used before parse_sshd so a restored older database still detects.
_FAILURE_TYPES = tuple(sorted(FAILURE_KINDS | {"ssh_failure"}))
_SUCCESS_TYPES = ("auth_success", "ssh_success")
_FAILURE_SQL = ",".join("?" * len(_FAILURE_TYPES))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _bounded_text(value: Any, name: str, maximum: int, *, empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or (not empty and not value.strip()):
        raise ValueError(f"{name} must be {'an optional' if empty else 'a nonempty'} string of at most {maximum} characters")
    if "\x00" in value:
        raise ValueError(f"{name} must not contain a NUL character")
    return value


def _classify(message: str, identifier: str, unit: str) -> tuple[str, str | None, str | None]:
    """Map one journal message to (event_kind, peer_ip, username).

    Only sshd messages reach parse_sshd. Everything else the exporter ships
    (systemd-logind, per-user managers, cron) is labelled non_sshd, so "other"
    keeps its narrow meaning -- an sshd line no rule matched -- and a nonzero
    "other" count stays a real signal that sshd printed a shape we do not read.
    """
    if identifier in _SSH_IDENTIFIERS or (
            not identifier and (unit in _SSH_UNITS or _SSH_PREFIX.match(message))):
        text = _SSH_PREFIX.sub("", message, count=1)
    else:
        return "non_sshd", None, None
    parsed = parse_sshd(text)
    peer = parsed["peer_ip"]
    if peer is not None:
        try:
            # Canonicalise so one peer correlates as one peer, and drop an
            # address whose shape matched but which is not a real IP.
            peer = str(ipaddress.ip_address(peer))
        except ValueError:
            peer = None
    return parsed["event_kind"], peer, parsed["username"]


def _normalize(record: dict[str, Any], now: datetime) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise ValueError("each record must be an object")
    event_id = _bounded_text(record.get("event_id"), "event_id", 2048)
    timestamp = _bounded_text(record.get("timestamp"), "timestamp", 80)
    try:
        at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if at.tzinfo is None or at.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        at = at.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise ValueError("timestamp must be a valid timezone-aware ISO timestamp") from exc
    # A bad source clock must not create incidents far into the future.
    if at > now + timedelta(minutes=10):
        raise ValueError("timestamp is more than ten minutes in the future")
    message = _bounded_text(record.get("message"), "message", 65536, empty=True)
    unit = _bounded_text(record.get("unit") or "", "unit", 256, empty=True)
    identifier = _bounded_text(record.get("identifier") or "", "identifier", 256, empty=True)
    priority = record.get("priority")
    if priority is not None and (isinstance(priority, bool) or not isinstance(priority, (str, int))):
        raise ValueError("priority must be a string, integer, or null")
    if priority is not None and str(priority) not in {str(i) for i in range(8)}:
        raise ValueError("priority must be between 0 and 7")
    raw = dict(event_id=event_id, timestamp=_iso(at), message=message, unit=unit,
               priority=priority, identifier=identifier)
    kind, peer, username = _classify(message, identifier, unit)
    return {**raw, "record_hash": _hash(_json(raw)), "message_hash": _hash(message),
            "event_type": kind, "src_ip": peer, "ssh_user": username, "event_ts": at.timestamp()}


class TelemetryStore:
    """A filesystem-backed store; each operation owns its database connection."""

    def __init__(self, path: str | Path, retention_days: int = 14) -> None:
        if str(path) == ":memory:":
            raise ValueError("live telemetry requires a durable filesystem database")
        if isinstance(retention_days, bool) or not isinstance(retention_days, int) or retention_days < 1:
            raise ValueError("retention_days must be a positive integer")
        self.path = str(Path(path).expanduser().resolve())
        self.retention_days = retention_days
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._connection(transaction=False) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS sources (
                    source_id TEXT PRIMARY KEY, hostname TEXT NOT NULL,
                    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                    last_event_at TEXT, last_error TEXT, status TEXT NOT NULL,
                    accepted_total INTEGER NOT NULL DEFAULT 0,
                    duplicate_total INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS batches (
                    source_id TEXT NOT NULL, batch_id TEXT NOT NULL, payload_hash TEXT NOT NULL,
                    received_at TEXT NOT NULL, record_count INTEGER NOT NULL,
                    response_json TEXT NOT NULL, PRIMARY KEY (source_id, batch_id)
                );
                CREATE TABLE IF NOT EXISTS event_receipts (
                    source_id TEXT NOT NULL, event_id TEXT NOT NULL, record_hash TEXT NOT NULL,
                    received_at TEXT NOT NULL, PRIMARY KEY (source_id, event_id)
                );
                CREATE TABLE IF NOT EXISTS events (
                    source_id TEXT NOT NULL, event_id TEXT NOT NULL, hostname TEXT NOT NULL,
                    timestamp TEXT NOT NULL, event_ts REAL NOT NULL, received_at TEXT NOT NULL,
                    event_type TEXT NOT NULL, src_ip TEXT, ssh_user TEXT,
                    record_json TEXT NOT NULL, incident_id TEXT,
                    PRIMARY KEY (source_id, event_id)
                );
                CREATE INDEX IF NOT EXISTS events_detection
                    ON events(source_id, src_ip, event_type, event_ts);
                CREATE INDEX IF NOT EXISTS events_paging
                    ON events(event_ts DESC, source_id, event_id);
                CREATE INDEX IF NOT EXISTS events_source_paging
                    ON events(source_id, event_ts DESC, event_id);
                -- The complete ordering above also covers timestamp retention.
                DROP INDEX IF EXISTS events_recent;
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY, source_id TEXT NOT NULL,
                    hostname TEXT NOT NULL, src_ip TEXT NOT NULL,
                    title TEXT NOT NULL, status TEXT NOT NULL,
                    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                    first_ts REAL NOT NULL, last_ts REAL NOT NULL,
                    failure_count INTEGER NOT NULL, created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL, merged_into TEXT
                );
                CREATE INDEX IF NOT EXISTS incidents_peer
                    ON incidents(source_id, src_ip, status, first_ts, last_ts);
                CREATE INDEX IF NOT EXISTS incidents_paging
                    ON incidents(last_ts DESC, incident_id) WHERE status!='merged';
                CREATE INDEX IF NOT EXISTS incidents_source_paging
                    ON incidents(source_id, last_ts DESC, incident_id) WHERE status!='merged';
                CREATE TABLE IF NOT EXISTS incident_evidence (
                    source_id TEXT NOT NULL, event_id TEXT NOT NULL,
                    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
                    event_ts REAL NOT NULL, snapshot_json TEXT NOT NULL,
                    PRIMARY KEY (source_id, event_id)
                );
                CREATE INDEX IF NOT EXISTS incident_evidence_incident
                    ON incident_evidence(incident_id, event_ts);
                CREATE TABLE IF NOT EXISTS maintenance (name TEXT PRIMARY KEY, value TEXT NOT NULL);
            """)

    @contextmanager
    def _connection(self, *, write: bool = False, transaction: bool = True) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA synchronous=FULL")
            if transaction:
                db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield db
            if transaction:
                db.commit()
        except BaseException:
            if transaction:
                db.rollback()
            raise
        finally:
            db.close()

    def healthcheck(self) -> bool:
        try:
            with self._connection() as db:
                return db.execute("SELECT count(*) FROM sources").fetchone()[0] >= 0
        except sqlite3.Error:
            return False

    def ingest(self, source_id: str, hostname: str, batch_id: str,
               records: list[dict[str, Any]], error: str | None = None) -> dict[str, Any]:
        source_id = _bounded_text(source_id, "source_id", 128)
        hostname = _bounded_text(hostname, "hostname", 255)
        batch_id = _bounded_text(batch_id, "batch_id", 256)
        if not isinstance(records, list) or len(records) > 500:
            raise ValueError("records must be a list of at most 500 objects")
        if error is not None:
            error = _bounded_text(error, "error", 8192, empty=True) or None
        now = _now()
        received_at = _iso(now)
        normalized = [_normalize(record, now) for record in records]
        # Bind receipts to normalized raw input, not classifier output. A later
        # parser release must still acknowledge an already committed batch.
        payload_hash = _hash(_json({"hostname": hostname,
                                   "record_hashes": [record["record_hash"] for record in normalized],
                                   "error": error}))
        with self._connection(write=True) as db:
            receipt = db.execute("SELECT * FROM batches WHERE source_id=? AND batch_id=?",
                                 (source_id, batch_id)).fetchone()
            if receipt and receipt["payload_hash"] != payload_hash:
                raise ValueError("batch_id was already used for different content")
            db.execute("""INSERT INTO sources(source_id,hostname,first_seen,last_seen,last_error,status)
                VALUES(?,?,?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET
                hostname=excluded.hostname,last_seen=excluded.last_seen,
                last_error=excluded.last_error,status=excluded.status""",
                (source_id, hostname, received_at, received_at, error, "error" if error else "ok"))
            if receipt:
                original = json.loads(receipt["response_json"])
                db.execute("UPDATE sources SET duplicate_total=duplicate_total+? WHERE source_id=?",
                           (len(records), source_id))
                return {**original, "accepted": 0, "duplicates": len(records),
                        "incident_ids": sorted({self._canonical_incident(db, item) for item in original["incident_ids"]}),
                        "replayed_batch": True, "last_seen": received_at}

            accepted = duplicates = 0
            failure_ids: list[str] = []
            for record in normalized:
                prior = db.execute("SELECT record_hash FROM event_receipts WHERE source_id=? AND event_id=?",
                                   (source_id, record["event_id"])).fetchone()
                if prior:
                    if prior["record_hash"] != record["record_hash"]:
                        raise ValueError("event_id was already used for different content")
                    duplicates += 1
                    continue
                db.execute("INSERT INTO event_receipts VALUES(?,?,?,?)",
                           (source_id, record["event_id"], record["record_hash"], received_at))
                snapshot = {**record, "source_id": source_id, "hostname": hostname,
                            "received_at": received_at}
                db.execute("""INSERT INTO events(source_id,event_id,hostname,timestamp,event_ts,
                    received_at,event_type,src_ip,ssh_user,record_json) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (source_id, record["event_id"], hostname, record["timestamp"], record["event_ts"],
                     received_at, record["event_type"], record["src_ip"], record["ssh_user"], _json(snapshot)))
                accepted += 1
                if record["event_type"] in FAILURE_KINDS and record["src_ip"] is not None:
                    failure_ids.append(record["event_id"])
            incident_ids: set[str] = set()
            for event_id in failure_ids:
                incident_id = self._detect(db, source_id, event_id, received_at)
                if incident_id:
                    incident_ids.add(incident_id)
            # Out-of-order input can join two prior windows. Return canonical IDs.
            incident_ids = {self._canonical_incident(db, item) for item in incident_ids}
            latest = max((record["timestamp"] for record in normalized), default=None)
            db.execute("""UPDATE sources SET accepted_total=accepted_total+?,
                duplicate_total=duplicate_total+?, last_event_at=CASE
                WHEN last_event_at IS NULL OR last_event_at < ? THEN ? ELSE last_event_at END
                WHERE source_id=?""", (accepted, duplicates, latest, latest, source_id))
            result = {"source_id": source_id, "batch_id": batch_id, "durable": True,
                      "accepted": accepted, "duplicates": duplicates,
                      "incident_ids": sorted(incident_ids), "last_seen": received_at,
                      "replayed_batch": False}
            db.execute("INSERT INTO batches VALUES(?,?,?,?,?,?)",
                       (source_id, batch_id, payload_hash, received_at, len(records), _json(result)))
            day = received_at[:10]
            last_cleanup = db.execute("SELECT value FROM maintenance WHERE name='last_cleanup'").fetchone()
            if not last_cleanup or last_cleanup[0] != day:
                self._cleanup(db, now)
            return result

    @staticmethod
    def _canonical_incident(db: sqlite3.Connection, incident_id: str) -> str:
        while True:
            row = db.execute("SELECT merged_into FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
            if not row or not row[0]:
                return incident_id
            incident_id = row[0]

    def _detect(self, db: sqlite3.Connection, source_id: str, event_id: str, now: str) -> str | None:
        event = db.execute("SELECT * FROM events WHERE source_id=? AND event_id=?",
                           (source_id, event_id)).fetchone()
        if event["incident_id"]:
            return self._canonical_incident(db, event["incident_id"])
        at = event["event_ts"]
        neighbors = db.execute(f"""SELECT * FROM events WHERE source_id=? AND src_ip=?
            AND event_type IN ({_FAILURE_SQL}) AND event_ts BETWEEN ? AND ? ORDER BY event_ts,event_id""",
            (source_id, event["src_ip"], *_FAILURE_TYPES,
             at - _WINDOW_SECONDS, at + _WINDOW_SECONDS)).fetchall()
        # Find a true rolling five-minute window containing this event, including
        # late arrivals. Three failures spread over a longer interval do not pass.
        best_left = best_right = 0
        left = 0
        for right, row in enumerate(neighbors):
            while row["event_ts"] - neighbors[left]["event_ts"] > _WINDOW_SECONDS:
                left += 1
            if neighbors[left]["event_ts"] <= at <= row["event_ts"] and right - left + 1 > best_right - best_left:
                best_left, best_right = left, right + 1
        best = neighbors[best_left:best_right]
        active = db.execute("""SELECT * FROM incidents WHERE source_id=? AND src_ip=? AND status='open'
            AND first_ts<=? AND last_ts>=? ORDER BY first_ts,incident_id""",
            (source_id, event["src_ip"], at + _WINDOW_SECONDS, at - _WINDOW_SECONDS)).fetchall()
        if not active and len(best) < _FAILURE_THRESHOLD:
            return None
        evidence = best if len(best) >= _FAILURE_THRESHOLD else [event]
        linked = {row["incident_id"] for row in evidence if row["incident_id"]}
        linked.update(row["incident_id"] for row in active)
        linked = {self._canonical_incident(db, item) for item in linked}
        if linked:
            incident_id = sorted(linked)[0]
            for other in linked - {incident_id}:
                db.execute("UPDATE incident_evidence SET incident_id=? WHERE incident_id=?", (incident_id, other))
                db.execute("UPDATE events SET incident_id=? WHERE incident_id=?", (incident_id, other))
                db.execute("UPDATE incidents SET status='merged',merged_into=?,updated_at=? WHERE incident_id=?",
                           (incident_id, now, other))
        else:
            incident_id = "SSH-" + uuid.uuid4().hex
            db.execute("""INSERT INTO incidents VALUES(?,?,?,?,?,'open',?,?,?,?,0,?,?,NULL)""",
                       (incident_id, source_id, event["hostname"], event["src_ip"],
                        f"Repeated SSH authentication failures on {event['hostname']} from {event['src_ip']}",
                        event["timestamp"], event["timestamp"], at, at, now, now))
        for row in evidence:
            db.execute("INSERT OR IGNORE INTO incident_evidence VALUES(?,?,?,?,?)",
                       (source_id, row["event_id"], incident_id, row["event_ts"], row["record_json"]))
            db.execute("UPDATE events SET incident_id=? WHERE source_id=? AND event_id=?",
                       (incident_id, source_id, row["event_id"]))
        stats = db.execute("SELECT count(*),min(event_ts),max(event_ts) FROM incident_evidence WHERE incident_id=?",
                           (incident_id,)).fetchone()
        db.execute("""UPDATE incidents SET failure_count=?,first_ts=?,last_ts=?,first_seen=?,last_seen=?,
            updated_at=? WHERE incident_id=?""",
            (stats[0], stats[1], stats[2], _iso(datetime.fromtimestamp(stats[1], timezone.utc)),
             _iso(datetime.fromtimestamp(stats[2], timezone.utc)), now, incident_id))
        return incident_id

    @staticmethod
    def _page(limit: int, offset: int) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError("offset must be a nonnegative integer")

    @staticmethod
    def _event(record: dict[str, Any]) -> dict[str, Any]:
        return {**record, "event_kind": record["event_type"], "peer_ip": record["src_ip"],
                "username": record["ssh_user"]}

    def _events(self, db: sqlite3.Connection, source_id: str | None,
                limit: int, offset: int) -> list[dict[str, Any]]:
        where, params = ("WHERE source_id=?", [source_id]) if source_id else ("", [])
        rows = db.execute(f"SELECT record_json,incident_id FROM events {where} ORDER BY event_ts DESC,source_id,event_id LIMIT ? OFFSET ?",
                          (*params, limit, offset)).fetchall()
        return [self._event({**json.loads(row["record_json"]), "incident_id": row["incident_id"]}) for row in rows]

    def list_events(self, source_id: str | None = None, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        self._page(limit, offset)
        with self._connection() as db:
            return self._events(db, source_id, limit, offset)

    @staticmethod
    def _pagination(total: int, limit: int, page: int) -> dict[str, int]:
        total_pages = max(1, (total + limit - 1) // limit)
        page = min(page, total_pages)
        return {"total": total, "total_pages": total_pages, "page": page,
                "limit": limit, "offset": (page - 1) * limit}

    def _page_number(self, limit: int, page: int) -> None:
        self._page(limit, 0)
        if isinstance(page, bool) or not isinstance(page, int) or page < 1:
            raise ValueError("page must be a positive integer")

    def paginate_events(self, source_id: str | None = None, limit: int = 100,
                        page: int = 1) -> dict[str, Any]:
        """Count and read one page from the same SQLite snapshot.

        The ordering indexes let SQLite skip old rows without sorting or loading
        their JSON. Page numbers beyond the available range resolve to the last
        page, including when retention removed rows since the previous request.
        """
        self._page_number(limit, page)
        where, params = ("WHERE source_id=?", (source_id,)) if source_id else ("", ())
        with self._connection() as db:
            total = db.execute(f"SELECT count(*) FROM events {where}", params).fetchone()[0]
            pagination = self._pagination(total, limit, page)
            return {"items": self._events(db, source_id, limit, pagination["offset"]), **pagination}

    def _incidents(self, db: sqlite3.Connection, source_id: str | None,
                   limit: int, offset: int) -> list[dict[str, Any]]:
        where, params = ("AND source_id=?", [source_id]) if source_id else ("", [])
        rows = db.execute(f"SELECT * FROM incidents WHERE status!='merged' {where} ORDER BY last_ts DESC,incident_id LIMIT ? OFFSET ?",
                          (*params, limit, offset)).fetchall()
        result = []
        for row in rows:
            evidence = db.execute("SELECT event_id,snapshot_json FROM incident_evidence WHERE incident_id=? ORDER BY event_ts,event_id LIMIT ?",
                                  (row["incident_id"], _EVIDENCE_RESPONSE_LIMIT)).fetchall()
            result.append({**dict(row), "peer_ip": row["src_ip"], "severity": "medium",
                           "evidence_count": row["failure_count"],
                           "evidence_truncated": row["failure_count"] > len(evidence),
                           "event_ids": [item["event_id"] for item in evidence],
                           "evidence_snapshots": [self._event(json.loads(item["snapshot_json"])) for item in evidence]})
        return result

    def list_incidents(self, source_id: str | None = None, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        self._page(limit, offset)
        with self._connection() as db:
            return self._incidents(db, source_id, limit, offset)

    def paginate_incidents(self, source_id: str | None = None, limit: int = 100,
                           page: int = 1) -> dict[str, Any]:
        self._page_number(limit, page)
        where, params = ("AND source_id=?", (source_id,)) if source_id else ("", ())
        with self._connection() as db:
            total = db.execute(f"SELECT count(*) FROM incidents WHERE status!='merged' {where}", params).fetchone()[0]
            pagination = self._pagination(total, limit, page)
            return {"items": self._incidents(db, source_id, limit, pagination["offset"]), **pagination}

    def list_sources(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        self._page(limit, offset)
        with self._connection() as db:
            rows = db.execute("SELECT * FROM sources ORDER BY source_id LIMIT ? OFFSET ?", (limit, offset)).fetchall()
            return [self._source(db, row) for row in rows]

    @staticmethod
    def _source(db: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        counts = db.execute(f"""SELECT count(*),
            coalesce(sum(event_type IN ({_FAILURE_SQL})),0),
            coalesce(sum(event_type IN (?,?)),0) FROM events WHERE source_id=?""",
            (*_FAILURE_TYPES, *_SUCCESS_TYPES, row["source_id"])).fetchone()
        incidents = db.execute("SELECT count(*) FROM incidents WHERE source_id=? AND status!='merged'", (row["source_id"],)).fetchone()[0]
        return {**dict(row), "event_count": counts[0], "ssh_failure_count": counts[1],
                "ssh_success_count": counts[2], "incident_count": incidents}

    def get_source(self, source_id: str) -> dict[str, Any] | None:
        with self._connection() as db:
            row = db.execute("SELECT * FROM sources WHERE source_id=?", (source_id,)).fetchone()
            return self._source(db, row) if row else None

    def _cleanup(self, db: sqlite3.Connection, now: datetime) -> dict[str, int]:
        cutoff = (now - timedelta(days=self.retention_days)).timestamp()
        deleted = db.execute("DELETE FROM events WHERE event_ts<?", (cutoff,)).rowcount
        db.execute("INSERT INTO maintenance VALUES('last_cleanup',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value",
                   (_iso(now)[:10],))
        return {"deleted_events": deleted, "deleted_batches": 0}

    def cleanup(self) -> dict[str, int]:
        """Expire raw rows; retain compact dedup receipts and incident snapshots."""
        with self._connection(write=True) as db:
            return self._cleanup(db, _now())

    def reparse_sshd(self) -> dict[str, int]:
        """Re-enrich retained records atomically without changing raw evidence.

        Run explicitly after a consistent backup with collection paused. Do not
        replay ingestion: receipts intentionally reject duplicate raw records.
        Existing incident IDs, receipts, original messages and hashes survive.
        """
        changed_events = changed_evidence = 0
        newly_detectable = []

        def enrich(snapshot: dict[str, Any]) -> dict[str, Any]:
            kind, peer, user = _classify(snapshot["message"], snapshot.get("identifier") or "",
                                         snapshot.get("unit") or "")
            updated = {**snapshot, "event_type": kind, "src_ip": peer, "ssh_user": user}
            for alias, value in (("event_kind", kind), ("peer_ip", peer), ("username", user)):
                if alias in updated:
                    updated[alias] = value
            return updated

        with self._connection(write=True) as db:
            rows = db.execute("SELECT source_id,event_id,event_type,src_ip,ssh_user,record_json,event_ts,incident_id FROM events ORDER BY source_id,event_id")
            while batch := rows.fetchmany(500):
                for row in batch:
                    old = json.loads(row["record_json"])
                    updated = enrich(old)
                    if old == updated and (row["event_type"], row["src_ip"], row["ssh_user"]) == (updated["event_type"], updated["src_ip"], updated["ssh_user"]):
                        continue
                    if row["incident_id"] and (row["src_ip"] != updated["src_ip"] or updated["event_type"] not in _FAILURE_TYPES):
                        raise ValueError("Parser changes an existing incident's peer or evidence classification; review before applying")
                    db.execute("UPDATE events SET event_type=?,src_ip=?,ssh_user=?,record_json=? WHERE source_id=? AND event_id=?",
                               (updated["event_type"], updated["src_ip"], updated["ssh_user"], _json(updated), row["source_id"], row["event_id"]))
                    changed_events += 1
                    if (updated["event_type"] in FAILURE_KINDS and updated["src_ip"] is not None
                            and (row["event_type"] not in _FAILURE_TYPES or row["src_ip"] != updated["src_ip"])):
                        newly_detectable.append((row["event_ts"], row["source_id"], row["event_id"]))
            rows = db.execute("SELECT source_id,event_id,snapshot_json FROM incident_evidence ORDER BY source_id,event_id")
            while batch := rows.fetchmany(500):
                for row in batch:
                    old = json.loads(row["snapshot_json"])
                    updated = enrich(old)
                    if old != updated:
                        if old.get("src_ip") != updated["src_ip"] or updated["event_type"] not in _FAILURE_TYPES:
                            raise ValueError("Parser changes retained incident evidence; review before applying")
                        db.execute("UPDATE incident_evidence SET snapshot_json=? WHERE source_id=? AND event_id=?",
                                   (_json(updated), row["source_id"], row["event_id"]))
                        changed_evidence += 1
            for _, source, event_id in sorted(newly_detectable):
                self._detect(db, source, event_id, _iso(_now()))
        return {"changed_events": changed_events, "changed_evidence": changed_evidence,
                "newly_detectable": len(newly_detectable)}
