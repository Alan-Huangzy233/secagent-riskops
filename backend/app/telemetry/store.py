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
from .detection import MAX_WINDOW_SECONDS, RuleMatch, detect_matches


_WINDOW_SECONDS = 300
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


def _compatible_evidence_kind(old: str, new: str) -> bool:
    """Parser upgrades must preserve the authentication outcome in evidence."""
    return ((old in _FAILURE_TYPES and new in _FAILURE_TYPES)
            or (old in _SUCCESS_TYPES and new in _SUCCESS_TYPES))


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
                CREATE INDEX IF NOT EXISTS events_username_paging
                    ON events(ssh_user, event_ts DESC, source_id, event_id);
                CREATE INDEX IF NOT EXISTS events_type_paging
                    ON events(event_type, event_ts DESC, source_id, event_id);
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
                CREATE INDEX IF NOT EXISTS events_peer_detection
                    ON events(src_ip, event_ts, source_id, event_id);
                CREATE TABLE IF NOT EXISTS incident_sources (
                    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
                    source_id TEXT NOT NULL, hostname TEXT NOT NULL,
                    PRIMARY KEY (incident_id, source_id)
                );
                CREATE INDEX IF NOT EXISTS incident_sources_source ON incident_sources(source_id, incident_id);
                CREATE TABLE IF NOT EXISTS incident_rules (
                    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
                    rule_id TEXT NOT NULL, rule_version INTEGER NOT NULL,
                    window_seconds INTEGER NOT NULL, reason TEXT NOT NULL,
                    PRIMARY KEY (incident_id, rule_id)
                );
                CREATE TABLE IF NOT EXISTS incident_details (
                    incident_id TEXT PRIMARY KEY REFERENCES incidents(incident_id),
                    success_count INTEGER NOT NULL, evidence_count INTEGER NOT NULL,
                    username_count INTEGER NOT NULL, usernames_json TEXT NOT NULL
                );
            """)
        # Additive migration: old IDs, receipts and raw evidence remain intact.
        with self._connection(write=True) as db:
            if not db.execute("SELECT 1 FROM maintenance WHERE name='detection_metadata_v1'").fetchone():
                for row in db.execute("SELECT incident_id FROM incidents WHERE status!='merged'").fetchall():
                    self._record_rule(db, row[0], RuleMatch("burst", 1, _WINDOW_SECONDS, [],
                        "同一来源、同一 IP，滚动 5 分钟内至少 3 条 SSH 认证失败日志。"))
                    self._refresh_incident(db, row[0])
                db.execute("INSERT INTO maintenance VALUES('detection_metadata_v1',?)", (_iso(_now()),))

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
            detection_rows: list[dict[str, Any]] = []
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
                if record["event_type"] in (*_FAILURE_TYPES, *_SUCCESS_TYPES) and record["src_ip"] is not None:
                    detection_rows.append(snapshot)
            incident_ids = self._detect_advanced(db, detection_rows, received_at)
            # Out-of-order input can join two prior windows. Return canonical IDs.
            incident_ids = {self._canonical_incident(db, item) for item in incident_ids}
            for incident_id in incident_ids:
                self._refresh_incident(db, incident_id)
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

    @staticmethod
    def _record_rule(db: sqlite3.Connection, incident_id: str, match: RuleMatch) -> None:
        db.execute("""INSERT INTO incident_rules VALUES(?,?,?,?,?)
            ON CONFLICT(incident_id,rule_id) DO UPDATE SET rule_version=excluded.rule_version,
            window_seconds=excluded.window_seconds,reason=excluded.reason""",
            (incident_id, match.rule_id, match.rule_version, match.window_seconds, match.reason))

    @staticmethod
    def _merge_incident(db: sqlite3.Connection, target: str, other: str, now: str) -> None:
        if target == other:
            return
        db.execute("UPDATE incident_evidence SET incident_id=? WHERE incident_id=?", (target, other))
        db.execute("UPDATE events SET incident_id=? WHERE incident_id=?", (target, other))
        db.execute("""INSERT OR IGNORE INTO incident_rules
            SELECT ?,rule_id,rule_version,window_seconds,reason FROM incident_rules WHERE incident_id=?""", (target, other))
        db.execute("UPDATE incidents SET status='merged',merged_into=?,updated_at=? WHERE incident_id=?",
                   (target, now, other))

    def _refresh_incident(self, db: sqlite3.Connection, incident_id: str) -> None:
        # Counts cover retained evidence, including after raw-event expiry. Read
        # JSON inside SQLite rather than materialising an unbounded preview.
        stats = db.execute(f"""SELECT count(*), min(event_ts), max(event_ts),
            coalesce(sum(json_extract(snapshot_json,'$.event_type') IN ({_FAILURE_SQL})),0),
            coalesce(sum(json_extract(snapshot_json,'$.event_type') IN (?,?)),0),
            count(DISTINCT nullif(json_extract(snapshot_json,'$.ssh_user'),''))
            FROM incident_evidence WHERE incident_id=?""", (*_FAILURE_TYPES, *_SUCCESS_TYPES, incident_id)).fetchone()
        if not stats[0]:
            row = db.execute("SELECT source_id,hostname FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
            db.execute("INSERT OR IGNORE INTO incident_sources VALUES(?,?,?)", (incident_id, row[0], row[1]))
            return
        usernames = [row[0] for row in db.execute("""SELECT DISTINCT json_extract(snapshot_json,'$.ssh_user') AS username
            FROM incident_evidence WHERE incident_id=? AND username IS NOT NULL AND username!=''
            ORDER BY username LIMIT 100""", (incident_id,))]
        db.execute("INSERT OR REPLACE INTO incident_details VALUES(?,?,?,?,?)",
                   (incident_id, stats[4], stats[0], stats[5], _json(usernames)))
        db.execute("DELETE FROM incident_sources WHERE incident_id=?", (incident_id,))
        db.execute("""INSERT INTO incident_sources SELECT ?,source_id,
            coalesce(max(json_extract(snapshot_json,'$.hostname')),source_id)
            FROM incident_evidence WHERE incident_id=? GROUP BY source_id""", (incident_id, incident_id))
        db.execute("""UPDATE incidents SET failure_count=?,first_ts=?,last_ts=?,first_seen=?,last_seen=?
            WHERE incident_id=?""", (stats[3], stats[1], stats[2],
            _iso(datetime.fromtimestamp(stats[1], timezone.utc)), _iso(datetime.fromtimestamp(stats[2], timezone.utc)), incident_id))

    def _apply_match(self, db: sqlite3.Connection, match: RuleMatch, now: str) -> str:
        evidence = match.evidence
        first = min(evidence, key=lambda row: (row["event_ts"], row["source_id"], row["event_id"]))
        linked = set()
        for row in evidence:
            prior = db.execute("SELECT incident_id FROM incident_evidence WHERE source_id=? AND event_id=?",
                               (row["source_id"], row["event_id"])).fetchone()
            if prior:
                linked.add(self._canonical_incident(db, prior[0]))
        if linked:
            # Preserve the oldest existing identity. Old batch acknowledgments
            # continue resolving through merged_into, even after restart.
            incident_id = min(linked, key=lambda item: tuple(db.execute(
                "SELECT created_at,incident_id FROM incidents WHERE incident_id=?", (item,)).fetchone()))
            for other in linked - {incident_id}:
                self._merge_incident(db, incident_id, other, now)
        else:
            incident_id = "SSH-" + uuid.uuid4().hex
            timestamp = _iso(datetime.fromtimestamp(first["event_ts"], timezone.utc))
            db.execute("INSERT INTO incidents VALUES(?,?,?,?,?,'open',?,?,?,?,0,?,?,NULL)",
                       (incident_id, first["source_id"], first["hostname"], first["src_ip"],
                        f"SSH authentication activity from {first['src_ip']}", timestamp, timestamp,
                        first["event_ts"], first["event_ts"], now, now))
        for row in evidence:
            db.execute("INSERT OR IGNORE INTO incident_evidence VALUES(?,?,?,?,?)",
                       (row["source_id"], row["event_id"], incident_id, row["event_ts"], row["record_json"]))
            db.execute("UPDATE events SET incident_id=? WHERE source_id=? AND event_id=?",
                       (incident_id, row["source_id"], row["event_id"]))
        self._record_rule(db, incident_id, match)
        db.execute("UPDATE incidents SET updated_at=? WHERE incident_id=?", (now, incident_id))
        return incident_id

    def _detect_advanced(self, db: sqlite3.Connection, triggers: list[dict[str, Any]], now: str) -> set[str]:
        by_peer: dict[str, list[dict[str, Any]]] = {}
        for row in triggers:
            by_peer.setdefault(row["src_ip"], []).append(row)
        changed: set[str] = set()
        for peer, rows in by_peer.items():
            # Only fetch the affected peer's temporal neighbourhoods. Separate
            # distant late arrivals instead of querying all intervening history.
            intervals: list[list[float]] = []
            for at in sorted(row["event_ts"] for row in rows):
                left, right = at - MAX_WINDOW_SECONDS, at + MAX_WINDOW_SECONDS
                if intervals and left <= intervals[-1][1]:
                    intervals[-1][1] = max(intervals[-1][1], right)
                else:
                    intervals.append([left, right])
            keys = {(row["source_id"], row["event_id"]) for row in rows}
            for left, right in intervals:
                candidates = [dict(row) for row in db.execute(f"""SELECT * FROM events
                    WHERE src_ip=? AND event_ts BETWEEN ? AND ? AND event_type IN ({_FAILURE_SQL},?,?)
                    ORDER BY event_ts,source_id,event_id""", (peer, left, right, *_FAILURE_TYPES, *_SUCCESS_TYPES))]
                for match in detect_matches(candidates, keys, include_burst=True):
                    changed.add(self._apply_match(db, match, now))
        return {self._canonical_incident(db, item) for item in changed}

    def rebuild_detections(self) -> dict[str, int]:
        """Re-evaluate retained raw rows transactionally; never replay ingestion.

        This explicit maintenance operation keeps all raw data and receipts,
        retains old incident identities (including merged aliases), and adds
        evidence only. Expired raw rows cannot be reconstructed from this call.
        """
        with self._connection(write=True) as db:
            before = [db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                      for table in ("incidents", "incident_evidence")]
            merged_before = db.execute("SELECT count(*) FROM incidents WHERE status='merged'").fetchone()[0]
            evaluated = 0
            now = _iso(_now())
            peers = db.execute(f"""SELECT DISTINCT src_ip FROM events WHERE src_ip IS NOT NULL
                AND event_type IN ({_FAILURE_SQL},?,?)""", (*_FAILURE_TYPES, *_SUCCESS_TYPES)).fetchall()
            for peer in peers:
                rows = [dict(row) for row in db.execute(f"""SELECT * FROM events WHERE src_ip=?
                    AND event_type IN ({_FAILURE_SQL},?,?) ORDER BY event_ts,source_id,event_id""",
                    (peer[0], *_FAILURE_TYPES, *_SUCCESS_TYPES))]
                evaluated += len(rows)
                changed = set()
                keys = {(row["source_id"], row["event_id"]) for row in rows}
                for match in detect_matches(rows, keys, include_burst=True):
                    changed.add(self._apply_match(db, match, now))
                for incident_id in {self._canonical_incident(db, item) for item in changed}:
                    self._refresh_incident(db, incident_id)
            return {"events_evaluated": evaluated,
                    "incidents_created": db.execute("SELECT count(*) FROM incidents").fetchone()[0] - before[0],
                    "incidents_merged": db.execute("SELECT count(*) FROM incidents WHERE status='merged'").fetchone()[0] - merged_before,
                    "evidence_added": db.execute("SELECT count(*) FROM incident_evidence").fetchone()[0] - before[1]}

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
                limit: int, offset: int, **filters) -> list[dict[str, Any]]:
        where, params = self._event_filter(source_id, **filters)
        rows = db.execute(f"SELECT record_json,incident_id FROM events {where} ORDER BY event_ts DESC,source_id,event_id LIMIT ? OFFSET ?",
                          (*params, limit, offset)).fetchall()
        return [self._event({**json.loads(row["record_json"]), "incident_id": row["incident_id"]}) for row in rows]

    def list_events(self, source_id: str | None = None, limit: int = 100, offset: int = 0, **filters) -> list[dict[str, Any]]:
        self._page(limit, offset)
        with self._connection() as db:
            return self._events(db, source_id, limit, offset, **filters)

    @staticmethod
    def _event_filter(source_id=None, *, ip=None, username=None, event_type=None,
                      q=None, start=None, end=None, snapshot=None):
        clauses, params = [], []
        for column, value in (("source_id", source_id), ("src_ip", ip),
                              ("ssh_user", username), ("event_type", event_type)):
            if value is not None:
                if not isinstance(value, str) or not value or len(value) > 256:
                    raise ValueError("Invalid search value")
                if column == "src_ip":
                    address = ipaddress.ip_address(value)
                    value = str(address)
                clauses.append(column + "=?")
                params.append(value)
        times = []
        for column, value, operator in (("event_ts", start, ">="), ("event_ts", end, "<=")):
            if value is not None:
                moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if moment.tzinfo is None:
                    raise ValueError("Search time requires timezone")
                stamp = moment.timestamp()
                clauses.append(column + operator + "?")
                params.append(stamp)
                times.append(stamp)
        if len(times) == 2 and times[0] > times[1]:
            raise ValueError("Search start must precede end")
        if q is not None:
            if not isinstance(q, str) or not 1 <= len(q) <= 256:
                raise ValueError("Invalid keyword")
            clauses.append("instr(json_extract(record_json,'$.message'),?)>0")
            params.append(q)
        if snapshot is not None:
            if not isinstance(snapshot, str) or not re.fullmatch(r"r1:[0-9]{1,19}", snapshot):
                raise ValueError("Invalid snapshot")
            bound = int(snapshot[3:])
            if bound > 9223372036854775807:
                raise ValueError("Invalid snapshot")
            clauses.append("EXISTS (SELECT 1 FROM event_receipts r WHERE r.source_id=events.source_id AND r.event_id=events.event_id AND r.rowid<=?)")
            params.append(bound)
        return ("WHERE " + " AND ".join(clauses) if clauses else ""), params

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
                        page: int = 1, **filters) -> dict[str, Any]:
        """Count and read one page from the same SQLite snapshot.

        The ordering indexes let SQLite skip old rows without sorting or loading
        their JSON. Page numbers beyond the available range resolve to the last
        page, including when retention removed rows since the previous request.
        """
        self._page_number(limit, page)
        with self._connection() as db:
            # Receipts outlive raw-event retention. Their monotonically appended
            # rowids exclude late arrivals even if they have old event times.
            if filters.get("snapshot") is None:
                filters["snapshot"] = "r1:" + str(db.execute("SELECT coalesce(max(rowid),0) FROM event_receipts").fetchone()[0])
            where, params = self._event_filter(source_id, **filters)
            total = db.execute(f"SELECT count(*) FROM events {where}", params).fetchone()[0]
            pagination = self._pagination(total, limit, page)
            return {"items": self._events(db, source_id, limit, pagination["offset"], **filters),
                    **pagination, "snapshot": filters["snapshot"]}

    def _incidents(self, db: sqlite3.Connection, source_id: str | None,
                   limit: int, offset: int, *, include_evidence: bool = True,
                   incident_id: str | None = None) -> list[dict[str, Any]]:
        where, params = self._incident_filter(source_id)
        if incident_id is not None:
            where += " AND incident_id=?"
            params += (incident_id,)
        rows = db.execute(f"SELECT * FROM incidents WHERE status!='merged' {where} ORDER BY last_ts DESC,incident_id LIMIT ? OFFSET ?",
                          (*params, limit, offset)).fetchall()
        result = []
        for row in rows:
            evidence = db.execute("SELECT source_id,event_id,snapshot_json FROM incident_evidence WHERE incident_id=? ORDER BY event_ts,source_id,event_id LIMIT ?",
                                  (row["incident_id"], _EVIDENCE_RESPONSE_LIMIT)).fetchall() if include_evidence else []
            sources = db.execute("SELECT source_id,hostname FROM incident_sources WHERE incident_id=? ORDER BY source_id", (row["incident_id"],)).fetchall()
            rules = [dict(rule) for rule in db.execute("SELECT rule_id,rule_version,window_seconds,reason FROM incident_rules WHERE incident_id=? ORDER BY rule_id", (row["incident_id"],))]
            detail = db.execute("SELECT * FROM incident_details WHERE incident_id=?", (row["incident_id"],)).fetchone()
            count = detail["evidence_count"] if detail else row["failure_count"]
            usernames = json.loads(detail["usernames_json"]) if detail else []
            result.append({**dict(row), "peer_ip": row["src_ip"],
                           "severity": "high" if any(rule["rule_id"] == "success_after_failures" for rule in rules) else "medium",
                           "source_ids": [source["source_id"] for source in sources] or [row["source_id"]],
                           "hostnames": [source["hostname"] for source in sources] or [row["hostname"]],
                           "rules": rules, "success_count": detail["success_count"] if detail else 0,
                           "username_count": detail["username_count"] if detail else 0,
                           "usernames": usernames, "usernames_truncated": bool(detail and detail["username_count"] > len(usernames)),
                           "evidence_count": count,
                           "evidence_truncated": count > len(evidence),
                           "evidence_refs": [{"source_id": item["source_id"], "event_id": item["event_id"]} for item in evidence],
                           "event_ids": [item["event_id"] for item in evidence],
                           "evidence_snapshots": [self._event(json.loads(item["snapshot_json"])) for item in evidence]})
        return result

    @staticmethod
    def _incident_filter(source_id: str | None) -> tuple[str, tuple]:
        if source_id is None:
            return "", ()
        return ("AND (source_id=? OR incident_id IN (SELECT incident_id FROM incident_sources WHERE source_id=?))",
                (source_id, source_id))

    def count_incidents(self) -> int:
        with self._connection() as db:
            return db.execute("SELECT count(*) FROM incidents WHERE status!='merged'").fetchone()[0]

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        with self._connection() as db:
            canonical = self._canonical_incident(db, incident_id)
            rows = self._incidents(db, None, 1, 0, include_evidence=False, incident_id=canonical)
            return {**rows[0], "requested_incident_id": incident_id} if rows else None

    def paginate_incident_evidence(self, incident_id: str, limit: int = 100,
                                   page: int = 1, source_id: str | None = None):
        self._page_number(limit, page)
        with self._connection() as db:
            canonical = self._canonical_incident(db, incident_id)
            if not db.execute("SELECT 1 FROM incidents WHERE incident_id=?", (canonical,)).fetchone():
                return None
            where, params = "incident_id=?", [canonical]
            if source_id:
                where += " AND source_id=?"
                params.append(source_id)
            total = db.execute("SELECT count(*) FROM incident_evidence WHERE " + where, params).fetchone()[0]
            pagination = self._pagination(total, limit, page)
            rows = db.execute("SELECT snapshot_json FROM incident_evidence WHERE " + where +
                              " ORDER BY event_ts,source_id,event_id LIMIT ? OFFSET ?",
                              (*params, limit, pagination["offset"])).fetchall()
            return {"items": [self._event(json.loads(row[0])) for row in rows], **pagination,
                    "incident_id": canonical, "requested_incident_id": incident_id}

    def list_incidents(self, source_id: str | None = None, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        self._page(limit, offset)
        with self._connection() as db:
            return self._incidents(db, source_id, limit, offset)

    def paginate_incidents(self, source_id: str | None = None, limit: int = 100,
                           page: int = 1, *, include_evidence: bool = True) -> dict[str, Any]:
        self._page_number(limit, page)
        where, params = self._incident_filter(source_id)
        with self._connection() as db:
            total = db.execute(f"SELECT count(*) FROM incidents WHERE status!='merged' {where}", params).fetchone()[0]
            pagination = self._pagination(total, limit, page)
            return {"items": self._incidents(db, source_id, limit, pagination["offset"], include_evidence=include_evidence), **pagination}

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
        where, params = TelemetryStore._incident_filter(row["source_id"])
        incidents = db.execute(f"SELECT count(*) FROM incidents WHERE status!='merged' {where}", params).fetchone()[0]
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
                    if row["incident_id"] and (row["src_ip"] != updated["src_ip"]
                            or not _compatible_evidence_kind(row["event_type"], updated["event_type"])):
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
                        if old.get("src_ip") != updated["src_ip"] or not _compatible_evidence_kind(old["event_type"], updated["event_type"]):
                            raise ValueError("Parser changes retained incident evidence; review before applying")
                        db.execute("UPDATE incident_evidence SET snapshot_json=? WHERE source_id=? AND event_id=?",
                                   (_json(updated), row["source_id"], row["event_id"]))
                        changed_evidence += 1
            dirty = set()
            triggers = []
            for _, source, event_id in sorted(newly_detectable):
                triggers.append(dict(db.execute("SELECT * FROM events WHERE source_id=? AND event_id=?", (source, event_id)).fetchone()))
            dirty.update(self._detect_advanced(db, triggers, _iso(_now())))
            if changed_evidence:
                dirty.update(row[0] for row in db.execute("SELECT incident_id FROM incidents WHERE status!='merged'"))
            for incident_id in {self._canonical_incident(db, item) for item in dirty}:
                self._refresh_incident(db, incident_id)
        return {"changed_events": changed_events, "changed_evidence": changed_evidence,
                "newly_detectable": len(newly_detectable)}
