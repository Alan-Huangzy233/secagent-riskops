"""Durable, shared reservations for paid evaluations (amounts are integer micro-USD).

A reservation is committed before network I/O. An interrupted or failed call
keeps its entire reservation; it is never automatically retried or refunded.
Completed results are kept here too, so a crash before tape append is recoverable.
"""
from __future__ import annotations

from contextlib import contextmanager
from decimal import Decimal, ROUND_CEILING
import json
import os
from pathlib import Path
import sqlite3

from .model_triage import BudgetExceeded


class CallUncertain(RuntimeError):
    """A previous attempt may have been billed; do not repeat it automatically."""


def micro_usd(value: Decimal | str | float) -> int:
    amount = Decimal(str(value))
    if not amount.is_finite() or amount < 0:
        raise ValueError("USD amount must be finite and non-negative")
    return int((amount * 1_000_000).to_integral_value(rounding=ROUND_CEILING))


class BudgetLedger:
    def __init__(self, path: Path, budget_usd: Decimal | str | float):
        self.path = path
        amount = Decimal(str(budget_usd))
        if not amount.is_finite() or amount <= 0:
            raise ValueError("budget must be finite and positive")
        ceiling = int(amount * 1_000_000)
        if ceiling <= 0:
            raise ValueError("budget must be positive")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Create privately before SQLite opens it; never reset an existing ledger.
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(descriptor)
        with self._transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS budget (id INTEGER PRIMARY KEY CHECK(id=1), "
                       "ceiling INTEGER NOT NULL, halted INTEGER NOT NULL DEFAULT 0)")
            db.execute("CREATE TABLE IF NOT EXISTS calls (id TEXT PRIMARY KEY, reserved INTEGER NOT NULL, "
                       "charged INTEGER, status TEXT NOT NULL, record TEXT, error TEXT)")
            db.execute("INSERT OR IGNORE INTO budget(id, ceiling) VALUES (1, ?)", (ceiling,))
            if db.execute("SELECT ceiling FROM budget WHERE id=1").fetchone()[0] != ceiling:
                raise ValueError("this ledger already has a different budget; keep the original ceiling")

    @contextmanager
    def _transaction(self):
        db = sqlite3.connect(self.path, timeout=30)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def reserve(self, call_id: str, amount: int) -> dict | None:
        if amount <= 0:
            raise ValueError("reservation must be positive")
        with self._transaction() as db:
            previous = db.execute("SELECT status, record FROM calls WHERE id=?", (call_id,)).fetchone()
            if previous:
                if previous[0] == "complete":
                    return json.loads(previous[1])
                raise CallUncertain("an earlier attempt is unresolved; its reservation is retained")
            ceiling, halted = db.execute("SELECT ceiling, halted FROM budget WHERE id=1").fetchone()
            used = db.execute("SELECT COALESCE(SUM(COALESCE(charged, reserved)), 0) FROM calls").fetchone()[0]
            if halted or used + amount > ceiling:
                raise BudgetExceeded("shared budget cannot cover the next call's reservation")
            db.execute("INSERT INTO calls(id, reserved, status) VALUES (?, ?, 'pending')", (call_id, amount))
        return None

    def complete(self, call_id: str, charged: int, record: dict):
        if charged < 0:
            raise ValueError("charge cannot be negative")
        with self._transaction() as db:
            row = db.execute("SELECT reserved, status FROM calls WHERE id=?", (call_id,)).fetchone()
            if row is None or row[1] != "pending":
                raise ValueError("call does not have a pending reservation")
            db.execute("UPDATE calls SET charged=?, status='complete', record=? WHERE id=?",
                       (charged, json.dumps(record, sort_keys=True), call_id))
            if charged > row[0]:
                # Usage exceeded the configured bound. Preserve the charge and
                # prevent any further spending until a human investigates.
                db.execute("UPDATE budget SET halted=1 WHERE id=1")

    def fail(self, call_id: str, code: str):
        with self._transaction() as db:
            db.execute("UPDATE calls SET status='uncertain', error=? WHERE id=? AND status='pending'",
                       (code, call_id))

    def summary(self) -> dict:
        with self._transaction() as db:
            ceiling, halted = db.execute("SELECT ceiling, halted FROM budget WHERE id=1").fetchone()
            charged, reserved, unresolved, total = db.execute(
                "SELECT COALESCE(SUM(charged), 0), "
                "COALESCE(SUM(CASE WHEN charged IS NULL THEN reserved ELSE 0 END), 0), "
                "SUM(CASE WHEN charged IS NULL THEN 1 ELSE 0 END), COUNT(*) FROM calls").fetchone()
        return {"budget_usd": ceiling / 1_000_000, "charged_usd": charged / 1_000_000,
                "reserved_usd": reserved / 1_000_000,
                "available_usd": max(0, ceiling - charged - reserved) / 1_000_000,
                "unresolved_calls": unresolved or 0, "attempts": total, "halted": bool(halted)}
