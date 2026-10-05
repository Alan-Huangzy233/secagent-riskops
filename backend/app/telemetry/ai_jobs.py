"""Durable manual-analysis queue and total/daily budget reservations."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time

from ..agents.model_triage import BudgetExceeded
from ..agents.triage_budget import CallUncertain
from .ai_summary import canonical


class Jobs:
    def __init__(self, path: Path, *, clock=time.time):
        self.path = path.resolve()
        self.clock = clock
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
        if path.stat().st_mode & 0o077:
            raise ValueError("analysis database must be private")
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS ai_meta (name TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS ai_jobs (
                    id TEXT PRIMARY KEY,incident_id TEXT NOT NULL,cache_key TEXT UNIQUE NOT NULL,
                    request_sha TEXT NOT NULL,config_sha TEXT NOT NULL,dossier_json TEXT NOT NULL,
                    local_json TEXT NOT NULL,actor TEXT NOT NULL,created REAL NOT NULL,updated REAL NOT NULL,
                    state TEXT NOT NULL,attempt_count INTEGER NOT NULL DEFAULT 0,
                    lease_token TEXT,lease_until REAL,call_id TEXT,run_id TEXT,result_json TEXT,error_code TEXT
                );
                CREATE INDEX IF NOT EXISTS ai_jobs_pending ON ai_jobs(state,created);
                CREATE INDEX IF NOT EXISTS ai_jobs_incident ON ai_jobs(incident_id,created);
                CREATE TABLE IF NOT EXISTS ai_attempts (
                    call_id TEXT PRIMARY KEY,job_id TEXT NOT NULL,number INTEGER NOT NULL,
                    started REAL NOT NULL,ended REAL,state TEXT NOT NULL,error_code TEXT
                );
                CREATE TABLE IF NOT EXISTS ai_calls (
                    id TEXT PRIMARY KEY,day TEXT NOT NULL,reserved INTEGER NOT NULL,
                    charged INTEGER,status TEXT NOT NULL,record TEXT,error TEXT
                );
                CREATE INDEX IF NOT EXISTS ai_calls_day ON ai_calls(day);
                CREATE TABLE IF NOT EXISTS ai_audit (
                    seq INTEGER PRIMARY KEY,job_id TEXT NOT NULL,at REAL NOT NULL,
                    actor TEXT NOT NULL,event TEXT NOT NULL,details TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ai_audit_job ON ai_audit(job_id,seq);
            """)
            db.execute("INSERT OR IGNORE INTO ai_meta VALUES('alias_secret',?)", (secrets.token_hex(32),))
            db.execute("INSERT OR IGNORE INTO ai_meta VALUES('halted','0')")

    @contextmanager
    def connection(self, *, write=False):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
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

    def secret(self) -> bytes:
        with self.connection() as db:
            return bytes.fromhex(db.execute("SELECT value FROM ai_meta WHERE name='alias_secret'").fetchone()[0])

    def _audit(self, db, job_id, event, *, actor="worker", **details):
        db.execute("INSERT INTO ai_audit(job_id,at,actor,event,details) VALUES(?,?,?,?,?)",
                   (job_id, self.clock(), actor, event, canonical(details)))

    def enqueue(self, incident_id, bundle, config_sha, request_sha, actor, *, queue_limit=100):
        key = hashlib.sha256(canonical([bundle["case"], config_sha]).encode()).hexdigest()
        with self.connection(write=True) as db:
            prior = db.execute("SELECT id FROM ai_jobs WHERE cache_key=?", (key,)).fetchone()
            if prior:
                return prior[0]
            if db.execute("SELECT count(*) FROM ai_jobs WHERE state IN ('queued','running','recoverable')").fetchone()[0] >= queue_limit:
                raise ValueError("analysis queue is full")
            job_id, now = secrets.token_hex(16), self.clock()
            db.execute("""INSERT INTO ai_jobs(id,incident_id,cache_key,request_sha,config_sha,dossier_json,
                local_json,actor,created,updated,state) VALUES(?,?,?,?,?,?,?,?,?,?,'queued')""",
                (job_id, incident_id, key, request_sha, config_sha, canonical(bundle["case"]),
                 canonical({"meta": bundle["meta"], "local_refs": bundle["local_refs"]}), actor, now, now))
            self._audit(db, job_id, "queued", actor=actor, revision=bundle["case"]["revision"])
            return job_id

    def _recover(self, db, max_attempts):
        rows = db.execute("SELECT * FROM ai_jobs WHERE state='running' AND lease_until<=? LIMIT 100",
                          (self.clock(),)).fetchall()
        for job in rows:
            call = db.execute("SELECT * FROM ai_calls WHERE id=?", (job["call_id"],)).fetchone()
            if call and call["charged"] is not None:
                state = "recoverable"
            elif call:
                state = "uncertain"
            else:
                state = "queued" if job["attempt_count"] < max_attempts else "failed"
            db.execute("UPDATE ai_jobs SET state=?,error_code='lease_expired',updated=? WHERE id=?",
                       (state, self.clock(), job["id"]))
            db.execute("UPDATE ai_attempts SET state=?,ended=?,error_code='lease_expired' WHERE call_id=?",
                       (state, self.clock(), job["call_id"]))
            self._audit(db, job["id"], "lease_recovered", state=state)

    def claim(self, *, lease_seconds=300, max_attempts=2):
        with self.connection(write=True) as db:
            self._recover(db, max_attempts)
            row = db.execute("SELECT * FROM ai_jobs WHERE state IN ('queued','recoverable') "
                             "ORDER BY created,id LIMIT 1").fetchone()
            if not row:
                return None
            job = dict(row)
            token, now = secrets.token_hex(16), self.clock()
            if row["state"] != "recoverable":
                number = row["attempt_count"] + 1
                run_id = str((self.path.parent / (self.path.name + ".attempts") / row["id"] / str(number)).resolve())
                call_id = hashlib.sha256(json.dumps([run_id, row["request_sha"]]).encode()).hexdigest()
                job.update(attempt_count=number, run_id=run_id, call_id=call_id)
                db.execute("INSERT INTO ai_attempts VALUES(?,?,?,?,NULL,'running',NULL)",
                           (call_id, row["id"], number, now))
            db.execute("""UPDATE ai_jobs SET state='running',lease_token=?,lease_until=?,updated=?,
                attempt_count=?,run_id=?,call_id=?,error_code=NULL WHERE id=?""",
                (token, now + lease_seconds, now, job["attempt_count"], job["run_id"], job["call_id"], job["id"]))
            self._audit(db, job["id"], "claimed", attempt=job["attempt_count"])
            job.update(state="running", lease_token=token, lease_until=now+lease_seconds)
            return job

    def cached_call(self, job):
        with self.connection() as db:
            row = db.execute("SELECT record FROM ai_calls WHERE id=? AND charged IS NOT NULL", (job["call_id"],)).fetchone()
            return json.loads(row[0]) if row else None

    def finish(self, job, state, *, record=None, error=None):
        with self.connection(write=True) as db:
            changed = db.execute("""UPDATE ai_jobs SET state=?,result_json=?,error_code=?,updated=?
                WHERE id=? AND lease_token=? AND state IN ('running','uncertain')""",
                (state, canonical(record) if record is not None else None, error, self.clock(),
                 job["id"], job["lease_token"])).rowcount
            if changed:
                db.execute("UPDATE ai_attempts SET state=?,ended=?,error_code=? WHERE call_id=?",
                           (state, self.clock(), error, job["call_id"]))
                self._audit(db, job["id"], state, error_code=error)

    def retry_unsubmitted(self, job, *, max_attempts=2):
        with self.connection() as db:
            submitted = db.execute("SELECT 1 FROM ai_calls WHERE id=?", (job["call_id"],)).fetchone()
        state = "uncertain" if submitted else ("queued" if job["attempt_count"] < max_attempts else "failed")
        self.finish(job, state, error="provider_unavailable")

    def get(self, job_id):
        with self.connection() as db:
            row = db.execute("SELECT * FROM ai_jobs WHERE id=?", (job_id,)).fetchone()
            if not row:
                return None
            job = dict(row)
            job["case"] = json.loads(job.pop("dossier_json"))
            job["local"] = json.loads(job.pop("local_json"))
            result = job.pop("result_json")
            job["result"] = json.loads(result) if result else None
            job["audit"] = [{**dict(r), "details": json.loads(r["details"])} for r in db.execute(
                "SELECT seq,at,actor,event,details FROM ai_audit WHERE job_id=? ORDER BY seq DESC LIMIT 50", (job_id,))]
            for key in ("lease_token", "lease_until", "run_id", "call_id"):
                job.pop(key, None)
            return job

    def history(self, incident_ids):
        with self.connection() as db:
            return [r[0] for r in db.execute("SELECT id FROM ai_jobs WHERE incident_id IN (SELECT value FROM json_each(?)) "
                                           "ORDER BY created DESC,id DESC LIMIT 20", (canonical(incident_ids),))]

    def feedback(self, job_id, verdict, note, actor):
        if verdict not in ("agree", "disagree", "needs_more") or not isinstance(note, str) or len(note) > 1000:
            raise ValueError("invalid review")
        with self.connection(write=True) as db:
            row = db.execute("SELECT state FROM ai_jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                raise KeyError("analysis job not found")
            if row[0] in ("queued", "running", "recoverable"):
                raise ValueError("analysis is still running")
            self._audit(db, job_id, "reviewed", actor=actor, verdict=verdict, note=note)

    def set_budget(self, total: int, daily: int):
        if not 0 < daily <= total:
            raise ValueError("positive daily budget must not exceed total budget")
        with self.connection(write=True) as db:
            for name, value in (("total_limit", total), ("daily_limit", daily)):
                db.execute("INSERT OR IGNORE INTO ai_meta VALUES(?,?)", (name, str(value)))
                if db.execute("SELECT value FROM ai_meta WHERE name=?", (name,)).fetchone()[0] != str(value):
                    raise ValueError("existing analysis budget limits changed; keep the original limits")

    def budget(self):
        day = datetime.fromtimestamp(self.clock(), timezone.utc).strftime("%Y-%m-%d")
        with self.connection() as db:
            meta = {r["name"]: r["value"] for r in db.execute(
                "SELECT name,value FROM ai_meta WHERE name IN ('total_limit','daily_limit','halted')")}
            charged, reserved, uncertain = db.execute("""SELECT coalesce(sum(charged),0),
                coalesce(sum(CASE WHEN charged IS NULL THEN reserved ELSE 0 END),0),
                coalesce(sum(CASE WHEN charged IS NULL THEN 1 ELSE 0 END),0) FROM ai_calls""").fetchone()
            today = db.execute("SELECT coalesce(sum(coalesce(charged,reserved)),0) FROM ai_calls WHERE day=?", (day,)).fetchone()[0]
        return {"total_usd": int(meta.get("total_limit", 0))/1e6, "daily_usd": int(meta.get("daily_limit", 0))/1e6,
                "charged_usd": charged/1e6, "reserved_usd": reserved/1e6, "today_committed_usd": today/1e6,
                "unresolved_calls": uncertain, "halted": meta.get("halted") == "1"}


class Ledger:
    """APITriage-compatible ledger bound to one claimed job attempt."""
    def __init__(self, jobs: Jobs, job: dict):
        self.jobs, self.job = jobs, job

    def reserve(self, call_id, amount):
        if call_id != self.job["call_id"] or type(amount) is not int or amount <= 0:
            raise ValueError("invalid analysis reservation")
        now = self.jobs.clock()
        day = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d")
        with self.jobs.connection(write=True) as db:
            previous = db.execute("SELECT * FROM ai_calls WHERE id=?", (call_id,)).fetchone()
            if previous:
                if previous["charged"] is not None:
                    return json.loads(previous["record"])
                raise CallUncertain("previous analysis outcome is unresolved")
            active = db.execute("SELECT 1 FROM ai_jobs WHERE id=? AND state='running' AND lease_token=? AND lease_until>?",
                                (self.job["id"], self.job["lease_token"], now)).fetchone()
            if not active:
                raise CallUncertain("analysis lease is no longer active")
            meta = {r["name"]: r["value"] for r in db.execute(
                "SELECT name,value FROM ai_meta WHERE name IN ('total_limit','daily_limit','halted')")}
            total = db.execute("SELECT coalesce(sum(coalesce(charged,reserved)),0) FROM ai_calls").fetchone()[0]
            today = db.execute("SELECT coalesce(sum(coalesce(charged,reserved)),0) FROM ai_calls WHERE day=?", (day,)).fetchone()[0]
            if (meta.get("halted") == "1" or total + amount > int(meta.get("total_limit",0))
                    or today + amount > int(meta.get("daily_limit",0))):
                raise BudgetExceeded("analysis total or daily budget exhausted")
            db.execute("INSERT INTO ai_calls VALUES(?,?,?,NULL,'reserved',NULL,NULL)", (call_id, day, amount))
            self.jobs._audit(db, self.job["id"], "budget_reserved", micro_usd=amount)
        return None

    def complete(self, call_id, charged, record):
        if call_id != self.job["call_id"] or type(charged) is not int or charged < 0:
            raise ValueError("invalid analysis settlement")
        with self.jobs.connection(write=True) as db:
            row = db.execute("SELECT * FROM ai_calls WHERE id=?", (call_id,)).fetchone()
            if row is None:
                raise ValueError("missing reservation")
            if row["charged"] is not None:
                if row["charged"] != charged or row["record"] != canonical(record):
                    raise ValueError("settlement changed")
                return
            db.execute("UPDATE ai_calls SET charged=?,status='complete',record=? WHERE id=?",
                       (charged, canonical(record), call_id))
            if charged > row["reserved"]:
                db.execute("UPDATE ai_meta SET value='1' WHERE name='halted'")
            self.jobs._audit(db, self.job["id"], "budget_settled", micro_usd=charged)

    def fail(self, call_id, code):
        if call_id != self.job["call_id"]:
            raise ValueError("wrong analysis call")
        with self.jobs.connection(write=True) as db:
            db.execute("UPDATE ai_calls SET status='uncertain',error=? WHERE id=? AND charged IS NULL",
                       (code, call_id))
            self.jobs._audit(db, self.job["id"], "call_uncertain", code=code)
