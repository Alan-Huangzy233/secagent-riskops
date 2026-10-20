"""Isolated durable network observations and immutable delivery receipts.

This foundation has bounded fail-stop capacity. Event retention never deletes
identities or batch receipts; safely compacting those is a later protocol change.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import sqlite3
import time

from .network_parse import SourceProfile
from .network_protocol import encode, fingerprint, validate_batch


SCHEMA_VERSION = 1
APPLICATION_ID = 0x4E455431
MAX_PAGE_LIMIT = 200
RETENTION_BATCH = 1000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_TABLE_COLUMNS = {
    "network_meta": ("key", "value"),
    "network_sources": ("source_id", "profile_revision", "checkpoint", "first_received_at_us",
                        "received_at_us", "accepted_total", "rejected_total", "duplicate_total", "last_report_json"),
    "network_batches": ("seq", "source_id", "batch_id", "payload_hash", "received_at_us", "response_json"),
    "network_receipts": ("source_id", "event_id", "content_hash", "kind", "code", "record_hash",
                         "boot_id", "journal_cursor", "journal_realtime_us", "journal_monotonic_us",
                         "collected_at_us", "received_at_us"),
    "network_events": ("seq", "source_id", "event_id", "journal_realtime_us", "collected_at_us",
                       "received_at_us", "event_json"),
}
_INDEXES = {"network_batches_source", "network_events_source", "network_events_source_time", "network_events_expiry"}
_SCHEMA = """
CREATE TABLE network_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE network_sources (
    source_id TEXT PRIMARY KEY, profile_revision TEXT NOT NULL, checkpoint TEXT,
    first_received_at_us INTEGER NOT NULL, received_at_us INTEGER NOT NULL,
    accepted_total INTEGER NOT NULL, rejected_total INTEGER NOT NULL,
    duplicate_total INTEGER NOT NULL, last_report_json TEXT NOT NULL
);
CREATE TABLE network_batches (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, source_id TEXT NOT NULL, batch_id TEXT NOT NULL,
    payload_hash TEXT NOT NULL, received_at_us INTEGER NOT NULL, response_json TEXT NOT NULL,
    UNIQUE(source_id, batch_id)
);
CREATE INDEX network_batches_source ON network_batches(source_id, seq);
CREATE TABLE network_receipts (
    source_id TEXT NOT NULL, event_id TEXT NOT NULL, content_hash TEXT NOT NULL,
    kind TEXT NOT NULL, code TEXT, record_hash TEXT NOT NULL, boot_id TEXT NOT NULL,
    journal_cursor TEXT NOT NULL, journal_realtime_us INTEGER NOT NULL,
    journal_monotonic_us INTEGER NOT NULL, collected_at_us INTEGER NOT NULL,
    received_at_us INTEGER NOT NULL, PRIMARY KEY(source_id, event_id)
);
CREATE TABLE network_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, source_id TEXT NOT NULL, event_id TEXT NOT NULL,
    journal_realtime_us INTEGER NOT NULL, collected_at_us INTEGER NOT NULL,
    received_at_us INTEGER NOT NULL, event_json TEXT NOT NULL, UNIQUE(source_id, event_id)
);
CREATE INDEX network_events_source ON network_events(source_id, seq);
CREATE INDEX network_events_source_time ON network_events(source_id, journal_realtime_us, seq);
CREATE INDEX network_events_expiry ON network_events(received_at_us, seq);
"""


class NetworkStoreError(ValueError):
    """Safe storage code; never contains a submitted record or filesystem path."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _now_us() -> int:
    return time.time_ns() // 1000


def _json(value) -> str:
    return encode(value).decode("utf-8")


def _storage_error(error: sqlite3.Error) -> NetworkStoreError:
    code = getattr(error, "sqlite_errorcode", 0) & 0xFF
    if code == sqlite3.SQLITE_FULL:
        return NetworkStoreError("storage_capacity_exceeded")
    if code in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
        return NetworkStoreError("network_storage_busy")
    return NetworkStoreError("network_storage_unavailable")


class NetworkStore:
    def __init__(self, path: str | Path, *, retention_days: int = 14,
                 max_receipts: int = 100000, max_batches: int = 10000,
                 max_storage_bytes: int = 268435456):
        if (str(path) == ":memory:" or type(retention_days) is not int or not 1 <= retention_days <= 365
                or type(max_receipts) is not int or not 1 <= max_receipts <= 10_000_000
                or type(max_batches) is not int or not 1 <= max_batches <= 1_000_000
                or type(max_storage_bytes) is not int or not 1_048_576 <= max_storage_bytes <= 2**40):
            raise NetworkStoreError("invalid_network_store_configuration")
        self.path = str(Path(path).resolve())
        self.retention_days = retention_days
        self.max_receipts = self.max_events = max_receipts
        self.max_batches = max_batches
        self.max_storage_bytes = max_storage_bytes
        Path(self.path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(descriptor)
        with self.connection() as db:
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if tables:
                self._validate_schema(db)
            elif (db.execute("PRAGMA application_id").fetchone()[0]
                  or db.execute("PRAGMA user_version").fetchone()[0]
                  or db.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone()):
                raise NetworkStoreError("network_store_schema_mismatch")
            # Inspect the existing database before changing its journal mode.
            if db.execute("PRAGMA journal_mode=WAL").fetchone()[0] != "wal":
                raise NetworkStoreError("network_storage_unavailable")
            self._page_limit(db)
            if not tables:
                db.execute("BEGIN IMMEDIATE")
                try:
                    for statement in _SCHEMA.split(";"):
                        if statement.strip():
                            db.execute(statement)
                    db.execute("INSERT INTO network_meta VALUES('schema_version',?)", (str(SCHEMA_VERSION),))
                    db.execute(f"PRAGMA application_id={APPLICATION_ID}")
                    db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                    db.commit()
                except BaseException:
                    db.rollback()
                    raise
            self._validate_schema(db)
            self._checkpoint(db)

    @contextmanager
    def connection(self):
        db = None
        try:
            db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("PRAGMA cache_spill=OFF")
            db.execute("PRAGMA wal_autocheckpoint=0")
            yield db
        except sqlite3.Error as error:
            if db is not None:
                db.rollback()
            raise _storage_error(error) from None
        except BaseException:
            if db is not None:
                db.rollback()
            raise
        finally:
            if db is not None:
                db.close()

    def _validate_schema(self, db):
        objects = db.execute("SELECT type,name FROM sqlite_master").fetchall()
        tables = {row[1] for row in objects if row[0] == "table"}
        if (tables != set(_TABLE_COLUMNS) | {"sqlite_sequence"}
                or db.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
                or db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION
                or any(kind in ("trigger", "view") for kind, _ in objects)
                or {name for kind, name in objects if kind == "index" and not name.startswith("sqlite_autoindex_")}
                != _INDEXES):
            raise NetworkStoreError("network_store_schema_mismatch")
        for table, columns in _TABLE_COLUMNS.items():
            if tuple(row[1] for row in db.execute(f"PRAGMA table_info({table})")) != columns:
                raise NetworkStoreError("network_store_schema_mismatch")
        row = db.execute("SELECT value FROM network_meta WHERE key='schema_version'").fetchone()
        if row is None or row[0] != str(SCHEMA_VERSION):
            raise NetworkStoreError("network_store_schema_mismatch")

    def _page_limit(self, db):
        page_size = db.execute("PRAGMA page_size").fetchone()[0]
        # Reserve two thirds for WAL frames/headers, shared-memory index and
        # filesystem rounding. With spilling disabled, a transaction writes at
        # most one frame per dirty page, and must start with an empty WAL.
        limit = max(1, (self.max_storage_bytes // 3 - 65536) // page_size)
        actual = db.execute(f"PRAGMA max_page_count={limit}").fetchone()[0]
        if actual > limit:
            raise NetworkStoreError("storage_capacity_exceeded")

    def _disk_usage(self):
        sizes = {}
        for name, suffix in (("database", ""), ("wal", "-wal"), ("shared_memory", "-shm")):
            try:
                sizes[name] = Path(self.path + suffix).stat().st_size
            except FileNotFoundError:
                sizes[name] = 0
        return {**sizes, "total": sum(sizes.values())}

    def _checkpoint(self, db):
        busy, _, _ = db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if busy:
            raise NetworkStoreError("network_storage_busy")
        if self._disk_usage()["total"] > self.max_storage_bytes:
            raise NetworkStoreError("storage_capacity_exceeded")

    @staticmethod
    def _replay(db, batch, payload_hash):
        previous = db.execute("SELECT payload_hash,response_json FROM network_batches "
                              "WHERE source_id=? AND batch_id=?",
                              (batch["source_id"], batch["batch_id"])).fetchone()
        if previous is None:
            return None
        if previous["payload_hash"] != payload_hash:
            raise NetworkStoreError("network_batch_conflict")
        return json.loads(previous["response_json"])

    def ingest(self, batch: dict, profile: SourceProfile, *, now_us: int | None = None) -> dict:
        validate_batch(batch, profile)
        payload_hash = fingerprint(batch)
        now = _now_us() if now_us is None else now_us
        if type(now) is not int or not 0 <= now <= 253402300799999999:
            raise NetworkStoreError("invalid_network_receive_time")
        with self.connection() as db:
            replay = self._replay(db, batch, payload_hash)
            if replay is not None:
                return replay
            if batch["collected_at_us"] > now + 300_000_000:
                raise NetworkStoreError("network_collection_time_in_future")
            self._checkpoint(db)
            self._page_limit(db)
            db.execute("BEGIN IMMEDIATE")
            # A concurrent delivery may have committed while this caller waited.
            replay = self._replay(db, batch, payload_hash)
            if replay is not None:
                db.rollback()
                return replay
            if self._disk_usage()["wal"] > 32:
                raise NetworkStoreError("network_storage_busy")
            source = db.execute("SELECT checkpoint FROM network_sources WHERE source_id=?",
                                (batch["source_id"],)).fetchone()
            if batch["cursor_before"] != (source[0] if source else None):
                raise NetworkStoreError("network_cursor_conflict")
            db.execute("DELETE FROM network_events WHERE seq IN (SELECT seq FROM network_events "
                       "WHERE received_at_us<? ORDER BY received_at_us,seq LIMIT ?)",
                       (now - self.retention_days * 86_400_000_000, RETENTION_BATCH))
            counts = self._counts(db)
            if counts["batches"] >= self.max_batches:
                raise NetworkStoreError("network_capacity_exceeded")
            results = []
            accepted = rejected = duplicates = 0
            for entry in batch["entries"]:
                kind = "event" if "event" in entry else "rejection"
                item = entry[kind]
                identity = (batch["source_id"], item["event_id"])
                metadata = {key: item[key] for key in ("boot_id", "journal_cursor", "journal_realtime_us",
                                                     "journal_monotonic_us")}
                record_hash = fingerprint({"kind": kind, "record": item})
                previous = db.execute("SELECT content_hash,kind,code,record_hash FROM network_receipts "
                                      "WHERE source_id=? AND event_id=?", identity).fetchone()
                code = None if kind == "event" else item["code"]
                if previous is not None:
                    if (previous["content_hash"] != item["content_hash"] or previous["kind"] != kind
                            or previous["record_hash"] != record_hash):
                        raise NetworkStoreError("network_event_conflict")
                    duplicates += 1
                    result = "duplicate"
                    code = previous["code"]
                else:
                    if counts["receipts"] >= self.max_receipts or (kind == "event" and counts["events"] >= self.max_events):
                        raise NetworkStoreError("network_capacity_exceeded")
                    db.execute("INSERT INTO network_receipts VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                               (*identity, item["content_hash"], kind, code, record_hash,
                                metadata["boot_id"], metadata["journal_cursor"], metadata["journal_realtime_us"],
                                metadata["journal_monotonic_us"], batch["collected_at_us"], now))
                    counts["receipts"] += 1
                    if kind == "event":
                        db.execute("INSERT INTO network_events(source_id,event_id,journal_realtime_us,collected_at_us,"
                                   "received_at_us,event_json) VALUES(?,?,?,?,?,?)",
                                   (*identity, item["journal_realtime_us"], batch["collected_at_us"], now, _json(item)))
                        counts["events"] += 1
                        accepted += 1
                        result = "accepted"
                    else:
                        rejected += 1
                        result = "rejected"
                results.append({"event_id": item["event_id"], "content_hash": item["content_hash"],
                                "status": result, "code": code})
            response = {"version": 1, "source_id": batch["source_id"], "profile_revision": batch["profile_revision"],
                        "batch_id": batch["batch_id"], "payload_hash": payload_hash, "durable": True,
                        "cursor_before": batch["cursor_before"], "cursor_after": batch["cursor_after"],
                        "collected_at_us": batch["collected_at_us"], "received_at_us": now, "results": results,
                        "reports": batch["reports"], "caught_up": batch["caught_up"],
                        "accepted": accepted, "rejected": rejected, "duplicates": duplicates}
            response_json = _json(response)
            db.execute("INSERT INTO network_batches(source_id,batch_id,payload_hash,received_at_us,response_json) "
                       "VALUES(?,?,?,?,?)", (batch["source_id"], batch["batch_id"], payload_hash, now, response_json))
            db.execute("INSERT INTO network_sources VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET "
                       "profile_revision=excluded.profile_revision,checkpoint=excluded.checkpoint,"
                       "received_at_us=excluded.received_at_us,accepted_total=accepted_total+excluded.accepted_total,"
                       "rejected_total=rejected_total+excluded.rejected_total,duplicate_total=duplicate_total+excluded.duplicate_total,"
                       "last_report_json=excluded.last_report_json",
                       (batch["source_id"], batch["profile_revision"], batch["cursor_after"], now, now,
                        accepted, rejected, duplicates, response_json))
            db.commit()
            # A reader can postpone truncation after commit. The preallocated
            # reserve still bounds this one WAL; subsequent writes fail-stop.
            try:
                self._checkpoint(db)
            except NetworkStoreError:
                pass
        return response

    @staticmethod
    def _counts(db):
        return {name: db.execute(f"SELECT count(*) FROM network_{name}").fetchone()[0]
                for name in ("events", "receipts", "batches", "sources")}

    def _quota(self, db):
        counts = self._counts(db)
        disk = self._disk_usage()
        page_size = db.execute("PRAGMA page_size").fetchone()[0]
        page_count = db.execute("PRAGMA page_count").fetchone()[0]
        page_limit = max(1, (self.max_storage_bytes // 3 - 65536) // page_size)
        exhausted = []
        for name, maximum in (("events", self.max_events), ("receipts", self.max_receipts), ("batches", self.max_batches)):
            if counts[name] >= maximum:
                exhausted.append(name)
        if disk["total"] >= self.max_storage_bytes or page_count >= page_limit:
            exhausted.append("storage")
        return {"counts": counts, "limits": {"events": self.max_events, "receipts": self.max_receipts,
                                             "batches": self.max_batches, "storage_bytes": self.max_storage_bytes},
                "storage_bytes": disk["total"], "database_bytes": disk["database"], "wal_bytes": disk["wal"],
                "page_count": page_count, "page_limit": page_limit,
                "capacity_available": not exhausted, "exhausted": exhausted}

    def _retention_state(self, db, source_id=None):
        cutoff = _now_us() - self.retention_days * 86_400_000_000
        if source_id is None:
            accepted = db.execute("SELECT coalesce(sum(accepted_total),0) FROM network_sources").fetchone()[0]
            retained = db.execute("SELECT count(*) FROM network_events").fetchone()[0]
            incomplete = db.execute("SELECT 1 FROM network_events WHERE received_at_us<? LIMIT 1", (cutoff,)).fetchone()
        else:
            accepted = db.execute("SELECT coalesce(sum(accepted_total),0) FROM network_sources WHERE source_id=?",
                                  (source_id,)).fetchone()[0]
            retained = db.execute("SELECT count(*) FROM network_events WHERE source_id=?", (source_id,)).fetchone()[0]
            incomplete = db.execute("SELECT 1 FROM network_events WHERE source_id=? AND received_at_us<? LIMIT 1",
                                    (source_id, cutoff)).fetchone()
        expired = accepted - retained
        coverage = []
        if expired:
            coverage.append("event_history_expired")
        if incomplete:
            coverage.append("event_retention_incomplete")
        return {"expired_events": expired, "coverage": coverage}

    def page(self, source_id: str, *, after=0, limit=100, snapshot=None, batches=False):
        if (not isinstance(source_id, str) or not _ID.fullmatch(source_id)
                or type(after) is not int or not 0 <= after <= 2**63 - 1
                or type(limit) is not int or not 1 <= limit <= MAX_PAGE_LIMIT
                or (snapshot is not None and (type(snapshot) is not int or not 0 <= snapshot <= 2**63 - 1))
                or type(batches) is not bool):
            raise NetworkStoreError("invalid_network_page")
        table = "network_batches" if batches else "network_events"
        column = "response_json" if batches else "event_json"
        with self.connection() as db:
            db.execute("BEGIN")
            if snapshot is None:
                snapshot = db.execute(f"SELECT coalesce(max(seq),0) FROM {table} WHERE source_id=?",
                                      (source_id,)).fetchone()[0]
            columns = f"seq,{column}" if batches else f"seq,{column},collected_at_us,received_at_us"
            rows = db.execute(f"SELECT {columns} FROM {table} WHERE source_id=? AND seq>? AND seq<=? ORDER BY seq LIMIT ?",
                              (source_id, after, snapshot, limit + 1)).fetchall()
            items = []
            for row in rows[:limit]:
                item = {"seq": row["seq"], **json.loads(row[column])}
                if not batches:
                    item.update(collected_at_us=row["collected_at_us"], received_at_us=row["received_at_us"])
                items.append(item)
            return {"items": items, "snapshot": snapshot, "next_after": items[-1]["seq"] if items else after,
                    "has_more": len(rows) > limit, **self._retention_state(db, source_id), "quota": self._quota(db)}

    def sources(self):
        with self.connection() as db:
            return [{**{key: row[key] for key in row.keys() if key != "last_report_json"},
                     "last_report": json.loads(row["last_report_json"])}
                    for row in db.execute("SELECT * FROM network_sources ORDER BY source_id")]

    def status(self):
        with self.connection() as db:
            db.execute("BEGIN")
            return {"schema_version": SCHEMA_VERSION, "retention_days": self.retention_days,
                    "receipt_retention": "until_capacity_stop", **self._quota(db), **self._retention_state(db)}

    def healthcheck(self):
        try:
            with self.connection() as db:
                self._validate_schema(db)
            return True
        except (NetworkStoreError, OSError):
            return False
