"""Bounded read-only SQLite access for explicit joint-evidence requests.

No store constructors, migrations or retained-source writes. The deadline is
cooperative (SQLite VM and Python checkpoints), not an OS/filesystem timeout.
A lock wait already in progress can overrun it by up to the configured 250 ms.
"""
from __future__ import annotations

from contextlib import contextmanager, suppress
from dataclasses import dataclass
import math
from pathlib import Path
import sqlite3
import time

from .joint_evidence import MAX_INPUT_BYTES, MAX_RECORDS

ERROR_CODES = frozenset({
    'adapter_invalid_request', 'adapter_limit_exceeded', 'evidence_invalid',
    'network_revision_missing', 'source_unavailable', 'source_busy',
    'source_schema_unavailable', 'query_deadline_exceeded',
})


class EvidenceReadError(RuntimeError):
    """A fixed public code: no database path, SQL, raw evidence or credentials."""

    def __init__(self, code: str):
        if code not in ERROR_CODES:
            raise ValueError('invalid_evidence_read_error_code')
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ReadLimits:
    record_limit: int = MAX_RECORDS
    candidate_limit: int = 200
    byte_limit: int = MAX_INPUT_BYTES
    deadline_seconds: float = 5.0
    lock_wait_seconds: float = 0.25
    batch_size: int = 200

    def __post_init__(self):
        for value, maximum in ((self.record_limit, MAX_RECORDS),
                               (self.candidate_limit, 200),
                               (self.byte_limit, MAX_INPUT_BYTES),
                               (self.batch_size, 200)):
            if type(value) is not int or not 1 <= value <= maximum:
                raise EvidenceReadError('adapter_invalid_request')
        for value, maximum in ((self.deadline_seconds, 5), (self.lock_wait_seconds, .25)):
            if type(value) not in (int, float) or not 0 < value <= maximum or not math.isfinite(value):
                raise EvidenceReadError('adapter_invalid_request')


class ReadBudget:
    def __init__(self, limits: ReadLimits | None = None, *, clock=None):
        if limits is not None and type(limits) is not ReadLimits:
            raise EvidenceReadError('adapter_invalid_request')
        self.limits = limits or ReadLimits()
        self._clock = clock or time.monotonic
        self._deadline = self._clock() + self.limits.deadline_seconds
        self.bytes_read = 0
        self.progress_calls = 0

    def check(self):
        if self._clock() >= self._deadline:
            raise EvidenceReadError('query_deadline_exceeded')

    def remaining(self):
        self.check()
        return max(0.0, self._deadline - self._clock())

    def consume_bytes(self, amount: int):
        self.check()
        if type(amount) is not int or amount < 0:
            raise EvidenceReadError('evidence_invalid')
        self.bytes_read += amount
        if self.bytes_read > self.limits.byte_limit:
            raise EvidenceReadError('adapter_limit_exceeded')

    def progress(self):
        self.progress_calls += 1
        return int(self._clock() >= self._deadline)


def _database_error(error, budget):
    try:
        budget.check()
    except EvidenceReadError as expired:
        return expired
    code = getattr(error, 'sqlite_errorcode', 0) & 255
    if code == sqlite3.SQLITE_INTERRUPT:
        return EvidenceReadError('query_deadline_exceeded')
    if code in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
        return EvidenceReadError('source_busy')
    message = str(error).lower()
    if any(text in message for text in ('no such table', 'no such column', 'no such index', 'no such function')):
        return EvidenceReadError('source_schema_unavailable')
    if 'malformed json' in message:
        return EvidenceReadError('evidence_invalid')
    return EvidenceReadError('source_unavailable')


@contextmanager
def snapshot(path: str | Path, budget: ReadBudget):
    """One source transaction; always release it before opening another source.

    mode=ro forbids creating the database. query_only also forbids accidental
    writes through this connection. Normal WAL reading may require existing or
    writable shared-memory sidecars; immutable=1 is deliberately not used.
    """
    db = None
    try:
        budget.check()
        if not isinstance(path, (str, Path)) or not str(path) or '\x00' in str(path):
            raise EvidenceReadError('adapter_invalid_request')
        try:
            str(path).encode('utf-8', errors='strict')
        except UnicodeError:
            raise EvidenceReadError('adapter_invalid_request') from None
        file = Path(path).expanduser().resolve(strict=True)
        if not file.is_file():
            raise EvidenceReadError('source_unavailable')
        db = sqlite3.connect(file.as_uri()+'?mode=ro', uri=True, isolation_level=None,
                             timeout=min(budget.limits.lock_wait_seconds, budget.remaining()))
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA query_only=ON')
        db.execute('PRAGMA trusted_schema=OFF')
        db.set_progress_handler(budget.progress, 1000)
        db.execute('BEGIN')
        yield db
        budget.check()
    except sqlite3.Error as error:
        raise _database_error(error, budget) from None
    except (OSError, RuntimeError) as error:
        if isinstance(error, EvidenceReadError):
            raise
        raise EvidenceReadError('source_unavailable') from None
    finally:
        if db is not None:
            with suppress(sqlite3.Error):
                db.set_progress_handler(None, 0)
                db.rollback()
            with suppress(sqlite3.Error):
                db.close()
