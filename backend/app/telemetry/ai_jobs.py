"""Durable manual-analysis queue and total/daily budget reservations."""
from __future__ import annotations

from contextlib import closing, contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import sqlite3
import stat
import time

from ..agents.model_triage import BudgetExceeded
from ..agents.triage_budget import CallUncertain
from .ai_summary import canonical


SHARED_QUEUE_KIND = "joint-shared-budget-v1"


class Jobs:
    def __init__(self, path: Path, *, clock=time.time, queue_kind="ssh", budget_owner: Jobs | None = None):
        if queue_kind not in ("ssh", "joint"):
            raise ValueError("invalid_analysis_queue_kind")
        self.queue_kind = queue_kind
        self.path = path.resolve()
        self.clock = clock
        self.budget_owner = budget_owner
        self._owner_binding = None
        if budget_owner is not None:
            if (queue_kind != "joint" or not isinstance(budget_owner, Jobs)
                    or budget_owner.queue_kind != "ssh" or budget_owner.budget_owner is not None
                    or self.path == budget_owner.path):
                raise ValueError("shared_budget_owner_mismatch")
            self._separate_storage()
            with self._owner_connection() as db:
                self._owner_binding = self._owner_identity(db)
            if path.exists() and path.samefile(budget_owner.path):
                raise ValueError("shared_budget_owner_mismatch")
        # Reject a foreign queue before mkdir/open/WAL/DDL can alter it.
        if path.exists():
            if not stat.S_ISREG(path.stat().st_mode) or path.stat().st_mode & 0o077:
                raise ValueError("analysis database must be private")
            if path.stat().st_size:
                # SQLite may create WAL/SHM read bookkeeping, but no queue
                # schema, data or budgets are modified by this preflight.
                with closing(sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True)) as db:
                    self._kind_guard(db, initialize=True)
                    self._shared_guard(db, initializing=True)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
        if path.stat().st_mode & 0o077:
            raise ValueError("analysis database must be private")
        with self.connection(write=True, initializing=True) as db:
            self._kind_guard(db, initialize=True)
            schema = """
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
            """
            for statement in schema.split(";"):
                if statement.strip():
                    db.execute(statement)
            db.execute("INSERT OR IGNORE INTO ai_meta VALUES('alias_secret',?)", (secrets.token_hex(32),))
            db.execute("INSERT OR IGNORE INTO ai_meta VALUES('halted','0')")
            db.execute("INSERT OR IGNORE INTO ai_meta VALUES('queue_kind',?)", (queue_kind,))
            if self._owner_binding is not None:
                # The marker and owner binding commit together. Older workers
                # reject this marker instead of looking for local paid calls.
                db.execute("UPDATE ai_meta SET value=? WHERE name='queue_kind'", (SHARED_QUEUE_KIND,))
                db.execute("INSERT OR IGNORE INTO ai_meta VALUES('shared_budget_owner',?)",
                           (canonical(self._owner_binding),))
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")

    def _kind_guard(self, db, *, initialize=False):
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
                  if not row[0].startswith("sqlite_")}
        if not tables and initialize:
            # A foreign view-only or branded empty database is not a new queue.
            objects = [row[0] for row in db.execute("SELECT name FROM sqlite_master")
                       if not row[0].startswith("sqlite_")]
            if (objects or db.execute("PRAGMA application_id").fetchone()[0] != 0
                    or db.execute("PRAGMA user_version").fetchone()[0] != 0):
                raise ValueError("analysis_queue_kind_mismatch")
            return
        required = {"ai_meta", "ai_jobs", "ai_attempts", "ai_calls", "ai_audit"}
        if tables != required:
            raise ValueError("analysis_queue_kind_mismatch")
        row = db.execute("SELECT value FROM ai_meta WHERE name='queue_kind'").fetchone()
        if row is not None:
            if self.queue_kind == "joint" and row[0] == SHARED_QUEUE_KIND:
                if self.budget_owner is None:
                    raise ValueError("shared_budget_owner_required")
                if db.execute("SELECT 1 FROM ai_meta WHERE name='shared_budget_owner'").fetchone() is None:
                    raise ValueError("shared_budget_owner_mismatch")
                return
            if row[0] != self.queue_kind:
                raise ValueError("analysis_queue_kind_mismatch")
            if self.budget_owner is not None:
                # Only a never-bound offline queue can be upgraded. A binding
                # with the old marker is inconsistent and must not be repaired.
                if (not initialize or db.execute("SELECT 1 FROM ai_meta WHERE name='shared_budget_owner'").fetchone()):
                    raise ValueError("shared_budget_owner_mismatch")
            return
        if not initialize or self.queue_kind != "ssh":
            raise ValueError("analysis_queue_kind_mismatch")
        # Only the existing manual SSH format may acquire its missing marker.
        # Preserve its alias key, calls, uncertain reservations and audit rows.
        alias_row = db.execute("SELECT value FROM ai_meta WHERE name='alias_secret'").fetchone()
        if alias_row is None or not isinstance(alias_row[0], str) or len(alias_row[0]) != 64:
            raise ValueError("analysis_queue_kind_mismatch")
        try:
            bytes.fromhex(alias_row[0])
            for (raw,) in db.execute("SELECT dossier_json FROM ai_jobs"):
                case = json.loads(raw)
                if (not isinstance(case, dict) or case.get("dossier_version") not in (None, 3)
                        or not isinstance(case.get("incident_id"), str)
                        or not isinstance(case.get("revision"), str)):
                    raise ValueError
        except (ValueError, TypeError):
            raise ValueError("analysis_queue_kind_mismatch") from None

    def _separate_storage(self):
        # SQLite may remove or overwrite side files during an open. Reject
        # overlaps before opening either database, including existing aliases.
        suffixes = ("", "-wal", "-shm", "-journal")
        local = [Path(str(self.path) + suffix) for suffix in suffixes]
        shared = [Path(str(self.budget_owner.path) + suffix) for suffix in suffixes]
        if {p.resolve() for p in local} & {p.resolve() for p in shared}:
            raise ValueError("shared_budget_owner_mismatch")
        def identities(paths):
            found = set()
            for path in paths:
                try:
                    info = path.stat()
                except FileNotFoundError:
                    # Idle SQLite connections may remove their side files.
                    continue
                except OSError:
                    raise ValueError("shared_budget_owner_unavailable") from None
                found.add((info.st_dev, info.st_ino))
            return found
        if identities(local) & identities(shared):
            raise ValueError("shared_budget_owner_mismatch")

    def _owner_identity(self, db):
        owner = self.budget_owner
        info = owner.path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                or owner.path.resolve() != owner.path):
            raise ValueError("shared_budget_owner_unavailable")
        meta = dict(db.execute("SELECT name,value FROM ai_meta WHERE name IN "
                               "('alias_secret','total_limit','daily_limit','halted')"))
        try:
            total, daily = int(meta["total_limit"]), int(meta["daily_limit"])
            if (str(total) != meta["total_limit"] or str(daily) != meta["daily_limit"]
                    or not 0 < daily <= total <= 2**63 - 1 or meta["halted"] not in ("0", "1")):
                raise ValueError
            alias = bytes.fromhex(meta["alias_secret"])
            if len(alias) != 32:
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise ValueError("shared_budget_not_configured") from None
        return {"version": 1, "path": str(owner.path), "device": info.st_dev,
                "inode": info.st_ino, "alias_sha256": hashlib.sha256(alias).hexdigest(),
                "total_limit": total, "daily_limit": daily}

    @contextmanager
    def _owner_connection(self, *, write=False):
        # The owner must exist. Never initialize a replacement or a second pool.
        owner = self.budget_owner
        db = None
        try:
            before = owner.path.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o077:
                raise ValueError("shared_budget_owner_unavailable")
            db = sqlite3.connect(owner.path.as_uri() + "?mode=rw", uri=True,
                                 timeout=30, isolation_level=None)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA synchronous=FULL")
            if write:
                db.execute("BEGIN IMMEDIATE")
            owner._kind_guard(db)
            owner._shared_guard(db)
            identity = self._owner_identity(db)
            if (identity["device"], identity["inode"]) != (before.st_dev, before.st_ino):
                raise ValueError("shared_budget_owner_mismatch")
            if self._owner_binding is not None and identity != self._owner_binding:
                raise ValueError("shared_budget_owner_mismatch")
            yield db
            if write:
                db.commit()
        except (OSError, sqlite3.Error):
            if db is not None and write:
                db.rollback()
            raise ValueError("shared_budget_owner_unavailable") from None
        except BaseException:
            if db is not None and write:
                db.rollback()
            raise
        finally:
            if db is not None:
                db.close()

    def _shared_guard(self, db, *, initializing=False):
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ai_meta'").fetchone():
            return  # Only a new queue can reach this branch after the kind guard.
        row = db.execute("SELECT value FROM ai_meta WHERE name='shared_budget_owner'").fetchone()
        if self.budget_owner is None:
            if row is not None:
                raise ValueError("shared_budget_owner_required")
            return
        if row is None and not initializing:
            raise ValueError("shared_budget_owner_mismatch")
        if row is not None and row[0] != canonical(self._owner_binding):
            raise ValueError("shared_budget_owner_mismatch")
        if (db.execute("SELECT 1 FROM ai_calls LIMIT 1").fetchone()
                or db.execute("SELECT 1 FROM ai_meta WHERE name IN ('total_limit','daily_limit')").fetchone()):
            raise ValueError("shared_budget_local_accounting")
        with self._owner_connection():
            pass

    @contextmanager
    def connection(self, *, write=False, initializing=False):
        if self.budget_owner is not None:
            self._separate_storage()
        db = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA synchronous=FULL")
            if write:
                db.execute("BEGIN IMMEDIATE")
            self._kind_guard(db, initialize=initializing)
            self._shared_guard(db, initializing=initializing)
            yield db
            if write:
                db.commit()
        except BaseException:
            if write:
                db.rollback()
            raise
        finally:
            db.close()

    @contextmanager
    def accounting(self, db, *, write=False):
        """Call only with the local queue connection held: joint then owner."""
        if self.budget_owner is None:
            yield db
        else:
            with self._owner_connection(write=write) as owner_db:
                yield owner_db

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
        rows = list(db.execute("SELECT * FROM ai_jobs WHERE state='running' AND lease_until<=? "
                               "ORDER BY created,id LIMIT 100", (self.clock(),)))
        if self.budget_owner is None:
            # A local receipt join skips unresolved calls without scanning them.
            rows.extend(db.execute("SELECT j.* FROM ai_jobs j JOIN ai_calls c ON c.id=j.call_id "
                                   "WHERE j.state='uncertain' AND c.charged IS NOT NULL "
                                   "ORDER BY j.created,j.id LIMIT 100"))
        else:
            # Owner receipts live elsewhere. Persist a bounded rotating scan so
            # old unresolved calls cannot starve later late-arriving receipts.
            cursor = db.execute("SELECT value FROM ai_meta WHERE name='receipt_recovery_cursor'").fetchone()
            position = cursor[0] if cursor else ""
            pending = list(db.execute("SELECT * FROM ai_jobs WHERE state='uncertain' AND id>? "
                                      "ORDER BY id LIMIT 100", (position,)))
            if not pending and position:
                pending = list(db.execute("SELECT * FROM ai_jobs WHERE state='uncertain' ORDER BY id LIMIT 100"))
            if pending:
                db.execute("INSERT INTO ai_meta VALUES('receipt_recovery_cursor',?) "
                           "ON CONFLICT(name) DO UPDATE SET value=excluded.value", (pending[-1]["id"],))
            rows.extend(pending)
        if not rows:
            return
        with self.accounting(db) as account:
            for job in rows:
                call = account.execute("SELECT * FROM ai_calls WHERE id=?", (job["call_id"],)).fetchone()
                if call and call["charged"] is not None:
                    state = "recoverable"
                elif job["state"] == "uncertain":
                    continue  # Only a durable receipt can reopen an uncertain job.
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
            Ledger(self, job)._attempt(db)
            with self.accounting(db) as account:
                row = account.execute("SELECT record FROM ai_calls WHERE id=? AND charged IS NOT NULL",
                                      (job["call_id"],)).fetchone()
                return json.loads(row[0]) if row else None

    def _finish(self, db, job, state, *, record=None, error=None):
        changed = db.execute("""UPDATE ai_jobs SET state=?,result_json=?,error_code=?,updated=?
            WHERE id=? AND lease_token=? AND call_id=? AND request_sha=?
            AND state IN ('running','uncertain')""",
            (state, canonical(record) if record is not None else None, error, self.clock(),
             job["id"], job["lease_token"], job["call_id"], job["request_sha"])).rowcount
        if changed:
            db.execute("UPDATE ai_attempts SET state=?,ended=?,error_code=? WHERE call_id=?",
                       (state, self.clock(), error, job["call_id"]))
            self._audit(db, job["id"], state, error_code=error)

    def finish(self, job, state, *, record=None, error=None):
        with self.connection(write=True) as db:
            self._finish(db, job, state, record=record, error=error)

    def retry_unsubmitted(self, job, *, max_attempts=2):
        with self.connection(write=True) as db:
            Ledger(self, job)._attempt(db)
            with self.accounting(db) as account:
                submitted = account.execute("SELECT 1 FROM ai_calls WHERE id=?", (job["call_id"],)).fetchone()
            state = "uncertain" if submitted else ("queued" if job["attempt_count"] < max_attempts else "failed")
            self._finish(db, job, state, error="provider_unavailable")

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
        if self.budget_owner is not None:
            raise ValueError("shared_budget_owner_controls_limits")
        if type(total) is not int or type(daily) is not int or not 0 < daily <= total <= 2**63 - 1:
            raise ValueError("positive daily budget must not exceed total budget")
        with self.connection(write=True) as db:
            for name, value in (("total_limit", total), ("daily_limit", daily)):
                db.execute("INSERT OR IGNORE INTO ai_meta VALUES(?,?)", (name, str(value)))
                if db.execute("SELECT value FROM ai_meta WHERE name=?", (name,)).fetchone()[0] != str(value):
                    raise ValueError("existing analysis budget limits changed; keep the original limits")

    def budget(self):
        if self.budget_owner is not None:
            # Validate the persisted binding before returning the common totals.
            with self.connection() as db, self.accounting(db) as account:
                return self._budget(account, self.budget_owner.clock())
        with self.connection() as db:
            return self._budget(db, self.clock())

    def _budget(self, db, now):
        day = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d")
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
    """Ledger bound to one attempt; shared charges commit before local audit.

    A shared reservation is committed while the joint queue write lock remains
    held. Recovery takes that same lock and consults the owner before retrying.
    No cross-database commit is needed: only the owner stores financial state.
    """
    def __init__(self, jobs: Jobs, job: dict):
        self.jobs, self.job = jobs, dict(job)

    def _attempt(self, db, *, active=False):
        job = self.job
        row = db.execute("""SELECT j.state,j.lease_token,j.lease_until,j.call_id
            FROM ai_jobs j JOIN ai_attempts a ON a.job_id=j.id
            WHERE j.id=? AND j.request_sha=? AND a.call_id=? AND a.number=?""",
            (job["id"], job["request_sha"], job["call_id"], job["attempt_count"])).fetchone()
        if row is None:
            raise ValueError("invalid analysis attempt")
        if active and (row["state"] != "running" or row["lease_token"] != job["lease_token"]
                       or row["call_id"] != job["call_id"] or row["lease_until"] <= self.jobs.clock()):
            raise CallUncertain("analysis lease is no longer active")

    def _call(self, call_id):
        if not isinstance(call_id, str) or call_id != self.job["call_id"]:
            raise ValueError("wrong analysis call")

    def reserve(self, call_id, amount):
        self._call(call_id)
        if type(amount) is not int or not 0 < amount <= 2**63 - 1:
            raise ValueError("invalid analysis reservation")
        with self.jobs.connection(write=True) as db:
            self._attempt(db)
            with self.jobs.accounting(db, write=True) as account:
                previous = account.execute("SELECT * FROM ai_calls WHERE id=?", (call_id,)).fetchone()
                if previous:
                    if previous["reserved"] != amount:
                        raise ValueError("reservation changed")
                    if previous["charged"] is not None:
                        return json.loads(previous["record"])
                    raise CallUncertain("previous analysis outcome is unresolved")
                self._attempt(db, active=True)
                now = (self.jobs.budget_owner or self.jobs).clock()
                day = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d")
                meta = dict(account.execute("SELECT name,value FROM ai_meta "
                                             "WHERE name IN ('total_limit','daily_limit','halted')"))
                total = account.execute("SELECT coalesce(sum(coalesce(charged,reserved)),0) FROM ai_calls").fetchone()[0]
                today = account.execute("SELECT coalesce(sum(coalesce(charged,reserved)),0) FROM ai_calls WHERE day=?", (day,)).fetchone()[0]
                if (meta.get("halted") == "1" or total + amount > int(meta.get("total_limit", 0))
                        or today + amount > int(meta.get("daily_limit", 0))):
                    raise BudgetExceeded("analysis total or daily budget exhausted")
                account.execute("INSERT INTO ai_calls VALUES(?,?,?,NULL,'reserved',NULL,NULL)", (call_id, day, amount))
            self.jobs._audit(db, self.job["id"], "budget_reserved", micro_usd=amount)
        return None

    def complete(self, call_id, charged, record):
        self._call(call_id)
        if type(charged) is not int or not 0 <= charged <= 2**63 - 1 or type(record) is not dict:
            raise ValueError("invalid analysis settlement")
        try:
            encoded = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            encoded.encode()  # Reject invalid text without dropping large paid receipts.
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise ValueError("invalid analysis settlement") from None
        with self.jobs.connection(write=True) as db:
            self._attempt(db)
            with self.jobs.accounting(db, write=True) as account:
                row = account.execute("SELECT * FROM ai_calls WHERE id=?", (call_id,)).fetchone()
                if row is None:
                    raise ValueError("missing reservation")
                if row["charged"] is not None:
                    if row["charged"] != charged or row["record"] != encoded:
                        raise ValueError("settlement changed")
                    return
                account.execute("UPDATE ai_calls SET charged=?,status='complete',record=? WHERE id=?",
                                (charged, encoded, call_id))
                if charged > row["reserved"]:
                    account.execute("UPDATE ai_meta SET value='1' WHERE name='halted'")
            self.jobs._audit(db, self.job["id"], "budget_settled", micro_usd=charged)

    def fail(self, call_id, code):
        self._call(call_id)
        if not isinstance(code, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) is None:
            raise ValueError("invalid analysis failure")
        with self.jobs.connection(write=True) as db:
            self._attempt(db)
            with self.jobs.accounting(db, write=True) as account:
                row = account.execute("SELECT * FROM ai_calls WHERE id=?", (call_id,)).fetchone()
                if row is None:
                    raise ValueError("missing reservation")
                if row["charged"] is not None:
                    return
                if row["status"] == "uncertain":
                    if row["error"] != code:
                        raise ValueError("failure changed")
                    return
                account.execute("UPDATE ai_calls SET status='uncertain',error=? WHERE id=?", (code, call_id))
            self.jobs._audit(db, self.job["id"], "call_uncertain", code=code)
