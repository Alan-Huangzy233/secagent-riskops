"""Opt-in HTTP storage, analysis and retained evidence; no response actions."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

from pydantic import BaseModel, Field, StrictBool, field_validator
from typing import Literal

from .http_parse import normalize_http
from . import http_incidents

IDENTITY = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
ReportCode = Literal["rotation_gap", "file_truncated", "file_unavailable", "partial_line",
                     "line_too_long", "catching_up", "rotation_wait"]


class RejectedRecord(BaseModel):
    model_config = {"extra": "forbid"}
    event_id: str = Field(pattern=IDENTITY)
    code: Literal["invalid_record"]


class HttpBatch(BaseModel):
    model_config = {"extra": "forbid"}
    source_id: str = Field(pattern=IDENTITY)
    service_id: str = Field(pattern=IDENTITY)
    batch_id: str = Field(pattern=IDENTITY)
    records: list[dict] = Field(default_factory=list, max_length=200)
    rejected: list[RejectedRecord] = Field(default_factory=list, max_length=200)
    reports: list[ReportCode] = Field(default_factory=list, max_length=6)
    caught_up: StrictBool
    collected_at: str = Field(min_length=1, max_length=80)

    @field_validator("collected_at")
    @classmethod
    def collection_time(cls, value):
        try:
            at = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if at.utcoffset() is None or at.timestamp() > datetime.now(timezone.utc).timestamp() + 300:
                raise ValueError
            return at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except (ValueError, OverflowError, OSError):
            raise ValueError("Invalid HTTP collection timestamp") from None


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def fingerprint(value):
    return hashlib.sha256(encoded(value).encode()).hexdigest()


class HttpStore:
    def __init__(self, path: str | Path, retention_days: int = 14):
        if str(path) == ":memory:" or type(retention_days) is not int or not 1 <= retention_days <= 365:
            raise ValueError("HTTP storage requires a persistent path and bounded retention")
        self.path = str(Path(path).resolve())
        self.retention_days = retention_days
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if tables - {"http_batches", "http_receipts", "http_events", "http_streams", "sqlite_sequence"} - http_incidents.TABLES:
                raise ValueError("HTTP storage requires a separate database")
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS http_batches (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id TEXT NOT NULL, service_id TEXT NOT NULL, batch_id TEXT NOT NULL,
                    payload_hash TEXT NOT NULL, received_at TEXT NOT NULL, response_json TEXT NOT NULL,
                    UNIQUE(source_id, service_id, batch_id)
                );
                CREATE INDEX IF NOT EXISTS http_batches_stream ON http_batches(source_id, service_id, seq);
                CREATE TABLE IF NOT EXISTS http_receipts (
                    source_id TEXT NOT NULL, service_id TEXT NOT NULL, event_id TEXT NOT NULL,
                    record_hash TEXT NOT NULL, PRIMARY KEY(source_id, service_id, event_id)
                );
                CREATE TABLE IF NOT EXISTS http_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id TEXT NOT NULL, service_id TEXT NOT NULL, event_id TEXT NOT NULL,
                    event_ts REAL NOT NULL, record_json TEXT NOT NULL,
                    UNIQUE(source_id, service_id, event_id)
                );
                CREATE INDEX IF NOT EXISTS http_events_stream ON http_events(source_id, service_id, seq);
                CREATE INDEX IF NOT EXISTS http_events_expiry ON http_events(event_ts);
                CREATE TABLE IF NOT EXISTS http_streams (
                    source_id TEXT NOT NULL, service_id TEXT NOT NULL, received_at TEXT NOT NULL,
                    accepted_total INTEGER NOT NULL, rejected_total INTEGER NOT NULL,
                    last_batch_json TEXT NOT NULL, PRIMARY KEY(source_id, service_id)
                );
            """)
            http_incidents.initialize(db)

    @contextmanager
    def connection(self, write=False):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA synchronous=FULL")
            if write:
                db.execute("BEGIN IMMEDIATE")
            yield db
            if write:
                db.commit()
        except BaseException:
            if write:
                db.rollback()
            raise
        finally:
            db.close()

    def ingest(self, batch: HttpBatch):
        now = datetime.now(timezone.utc)
        if len(batch.records) + len(batch.rejected) > 200:
            raise ValueError("HTTP batch record limit")
        events = []
        for record in batch.records:
            if not isinstance(record.get("event_id"), str):
                raise ValueError("Invalid HTTP event identity")
            event = normalize_http({k: v for k, v in record.items() if k != "event_id"},
                                   source_id=batch.source_id, service_id=batch.service_id,
                                   event_id=record["event_id"])
            if event.event_ts > now.timestamp() + 300:
                raise ValueError("HTTP timestamp is in the future")
            events.append(asdict(event))
        rejected = [item.model_dump() for item in batch.rejected]
        # Fingerprint only the permitted, normalized fields; queries never persist.
        normalized = {**batch.model_dump(), "records": events, "rejected": rejected}
        payload_hash = fingerprint(normalized)
        stream = (batch.source_id, batch.service_id)
        with self.connection(write=True) as db:
            receipt = db.execute("SELECT payload_hash,response_json FROM http_batches "
                                 "WHERE source_id=? AND service_id=? AND batch_id=?",
                                 (*stream, batch.batch_id)).fetchone()
            if receipt:
                if receipt["payload_hash"] != payload_hash:
                    raise ValueError("Conflicting HTTP batch identity")
                return json.loads(receipt["response_json"])
            accepted = rejected_count = duplicates = 0
            for item, valid in [(row, True) for row in events] + [(row, False) for row in rejected]:
                identity = (*stream, item["event_id"])
                digest = fingerprint({"valid": valid, "record": item})
                previous = db.execute("SELECT record_hash FROM http_receipts WHERE source_id=? "
                                      "AND service_id=? AND event_id=?", identity).fetchone()
                if previous:
                    if previous[0] != digest:
                        raise ValueError("Conflicting HTTP event identity")
                    duplicates += 1
                    continue
                db.execute("INSERT INTO http_receipts VALUES(?,?,?,?)", (*identity, digest))
                if valid:
                    db.execute("INSERT INTO http_events(source_id,service_id,event_id,event_ts,record_json) "
                               "VALUES(?,?,?,?,?)", (*identity, item["event_ts"], encoded(item)))
                    accepted += 1
                else:
                    rejected_count += 1
            received_at = now.isoformat().replace("+00:00", "Z")
            response = {"source_id": batch.source_id, "service_id": batch.service_id,
                        "batch_id": batch.batch_id, "durable": True, "accepted": accepted,
                        "rejected": rejected_count, "rejected_records": rejected, "duplicates": duplicates,
                        "received_at": received_at, "collected_at": batch.collected_at, "reports": batch.reports,
                        "caught_up": batch.caught_up}
            db.execute("INSERT INTO http_batches(source_id,service_id,batch_id,payload_hash,received_at,response_json) "
                       "VALUES(?,?,?,?,?,?)", (*stream, batch.batch_id, payload_hash, received_at, encoded(response)))
            db.execute("INSERT INTO http_streams VALUES(?,?,?,?,?,?) ON CONFLICT(source_id,service_id) "
                       "DO UPDATE SET received_at=excluded.received_at, accepted_total=accepted_total+excluded.accepted_total, "
                       "rejected_total=rejected_total+excluded.rejected_total, last_batch_json=excluded.last_batch_json",
                       (*stream, received_at, accepted, rejected_count, encoded(response)))
            # Bound cleanup on every new batch. Compact receipts survive expiry.
            db.execute("DELETE FROM http_events WHERE seq IN (SELECT seq FROM http_events "
                       "WHERE event_ts<? ORDER BY event_ts LIMIT 1000)",
                       (now.timestamp() - self.retention_days * 86400,))
        return response  # Only after COMMIT; a failed transaction never produces an ACK.

    def page(self, source_id: str, service_id: str, *, after=0, limit=100, snapshot=None, batches=False):
        if not 0 <= after <= 2**63-1 or not 1 <= limit <= 200:
            raise ValueError("Invalid HTTP page")
        table = "http_batches" if batches else "http_events"
        column = "response_json" if batches else "record_json"
        with self.connection() as db:
            db.execute("BEGIN")
            if snapshot is None:
                snapshot = db.execute(f"SELECT coalesce(max(seq),0) FROM {table} "
                                      "WHERE source_id=? AND service_id=?", (source_id, service_id)).fetchone()[0]
            if not 0 <= snapshot <= 2**63-1:
                raise ValueError("Invalid HTTP snapshot")
            rows = db.execute(f"SELECT seq,{column} FROM {table} WHERE source_id=? AND service_id=? "
                              "AND seq>? AND seq<=? ORDER BY seq LIMIT ?",
                              (source_id, service_id, after, snapshot, limit + 1)).fetchall()
            return {"items": [{"seq": r[0], **json.loads(r[1])} for r in rows[:limit]],
                    "snapshot": snapshot, "next_after": rows[min(len(rows), limit)-1][0] if rows else after,
                    "has_more": len(rows) > limit}

    def streams(self):
        with self.connection() as db:
            return [{**dict(row), "last_batch": json.loads(row["last_batch_json"])}
                    for row in db.execute("SELECT * FROM http_streams ORDER BY source_id,service_id")]

    def healthcheck(self):
        with self.connection() as db:
            db.execute("SELECT 1 FROM http_batches LIMIT 1").fetchone()
            return True

    def analysis_status(self):
        with self.connection() as db:
            return http_incidents.status(db)

    def incidents(self, **kwargs):
        with self.connection() as db:
            db.execute("BEGIN")
            return http_incidents.list_cases(db, **kwargs)

    def incident(self, identity, revision=None):
        with self.connection() as db:
            return http_incidents.get_case(db, identity, revision)

    def evidence(self, identity, **kwargs):
        with self.connection() as db:
            db.execute("BEGIN")
            return http_incidents.evidence(db, identity, **kwargs)
