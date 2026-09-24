"""Collection integrity: what was not collected, and what arrived late.

Two different things are kept apart:

* a **gap** is an interval whose records may never arrive: collection began
  (only the exporter's recent window was read), the collector's cursor was lost,
  or the source journal had already rotated past it. A gap is written once, as a
  closed interval, and later batches never change or remove it.
* a **delay** means the records are still in the source journal and will be
  collected: the source could not be read, nothing arrived for a while (the
  collector or this API was down), a batch waited in the collector's spool, or
  the collector is working through a backlog. A delay stays open while it lasts
  and is closed by the first batch that shows it is over.

Everything is derived from what a batch already carries (its reports, record
times and ``collected_at``) and from the source's previous state, so older
collectors keep working and a rollback leaves nothing behind but unused tables.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import sqlite3
from typing import Any

# Report codes that describe a batch without saying the source failed. Any
# other code, including one this version does not know, means the source could
# not be read: an unknown condition is treated as a failure, not ignored.
CATCHING_UP = frozenset({"page_full", "batch_limited"})
INFORMATIONAL = frozenset({"coverage_start", "retention_gap", "message_truncated"}) | CATCHING_UP
SILENCE_SECONDS = 300
# After a reset the collector asks the exporter for the last ten minutes
# (``since_minutes`` in telemetry_collector.ssh_export).
RECOVERY_WINDOW_SECONDS = 600
DELIVERY_DELAY_SECONDS = 120
GAP, DELAY, NOTICE = "gap", "delay", "notice"

SCHEMA = """
CREATE TABLE IF NOT EXISTS collection_issues (
    issue_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id TEXT NOT NULL, kind TEXT NOT NULL, category TEXT NOT NULL,
    started_at TEXT, ended_at TEXT, detail TEXT NOT NULL,
    first_batch_id TEXT, last_batch_id TEXT, batches INTEGER NOT NULL DEFAULT 1,
    opened_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_collection_issues_source ON collection_issues(source_id, issue_id);
CREATE INDEX IF NOT EXISTS idx_collection_issues_open ON collection_issues(source_id, kind) WHERE ended_at IS NULL;
CREATE TABLE IF NOT EXISTS source_collection (
    source_id TEXT PRIMARY KEY,
    tracking_since TEXT NOT NULL,
    coverage_start TEXT,
    coverage_note TEXT,
    last_batch_at TEXT,
    caught_up INTEGER NOT NULL DEFAULT 1,
    last_delivery_lag_seconds REAL,
    updated_at TEXT NOT NULL
);
"""


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _seconds(start: str, end: str) -> float:
    return (_parse(end) - _parse(start)).total_seconds()


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _minutes(seconds: float) -> str:
    return f"{seconds / 60:.0f} min" if seconds < 5400 else f"{seconds / 3600:.1f} h"


def _insert(db: sqlite3.Connection, source_id: str, kind: str, category: str, started: str | None,
            ended: str | None, detail: str, batch_id: str | None, now: str) -> None:
    db.execute("""INSERT INTO collection_issues(source_id,kind,category,started_at,ended_at,detail,
        first_batch_id,last_batch_id,batches,opened_at,updated_at) VALUES(?,?,?,?,?,?,?,?,1,?,?)""",
               (source_id, kind, category, started, ended, detail, batch_id, batch_id, now, now))


def _open(db: sqlite3.Connection, source_id: str, kind: str, detail: str, batch_id: str, now: str) -> None:
    """Start a delay, or extend the one already open."""
    row = db.execute("SELECT issue_id FROM collection_issues WHERE source_id=? AND kind=? AND ended_at IS NULL "
                     "ORDER BY issue_id DESC LIMIT 1", (source_id, kind)).fetchone()
    if row is None:
        _insert(db, source_id, kind, DELAY, now, None, detail, batch_id, now)
    else:
        db.execute("UPDATE collection_issues SET last_batch_id=?, batches=batches+1, detail=?, updated_at=? "
                   "WHERE issue_id=?", (batch_id, detail, now, row[0]))


def _close(db: sqlite3.Connection, source_id: str, kind: str, now: str) -> None:
    db.execute("UPDATE collection_issues SET ended_at=?, updated_at=? WHERE source_id=? AND kind=? "
               "AND ended_at IS NULL", (now, now, source_id, kind))


def record_batch(db: sqlite3.Connection, *, source_id: str, batch_id: str, received_at: str,
                 previous: sqlite3.Row | None, reports: list[dict[str, Any]], record_times: list[str],
                 collected_at: str | None) -> None:
    """Update collection state for one newly committed batch (never for a replayed one)."""
    codes = {str(report.get("code", "")) for report in reports}
    messages = {str(report.get("code", "")): str(report.get("message", "")) for report in reports}
    first_record = min(record_times) if record_times else None
    last_seen = previous["last_seen"] if previous is not None else None
    last_event = previous["last_event_at"] if previous is not None else None
    state = db.execute("SELECT * FROM source_collection WHERE source_id=?", (source_id,)).fetchone()
    if state is None:
        if previous is None:
            coverage, note = None, None
        else:
            # The source was collected before integrity tracking existed; its
            # first batch is the earliest time anything is known about.
            coverage, note = previous["first_seen"], "estimated from the first batch; tracking started later"
        db.execute("INSERT INTO source_collection(source_id,tracking_since,coverage_start,coverage_note,"
                   "updated_at) VALUES(?,?,?,?,?)", (source_id, received_at, coverage, note, received_at))
        state = db.execute("SELECT * FROM source_collection WHERE source_id=?", (source_id,)).fetchone()

    if last_seen is not None:
        quiet = _seconds(last_seen, received_at)
        if quiet > SILENCE_SECONDS:
            _insert(db, source_id, "silence", DELAY, last_seen, received_at,
                    f"no batch for {_minutes(quiet)}: the collector or this API was not running. The source "
                    "journal kept the records, so they arrive late rather than being lost, unless it rotated "
                    "in the meantime (that would be recorded as a gap).", batch_id, received_at)

    # A reset re-reads the exporter's recent window, which starts ten minutes
    # before the export. Only the stretch between the last record already
    # collected and that window can be missing; if they overlap, nothing is.
    window_start = _iso(_parse(collected_at or received_at) - timedelta(seconds=RECOVERY_WINDOW_SECONDS))

    def reset(kind: str, why: str) -> None:
        if last_event is not None and _parse(window_start) > _parse(last_event):
            _insert(db, source_id, kind, GAP, last_event, window_start,
                    f"{why} Records between these times may be missing. {messages.get(kind, '')}".strip(),
                    batch_id, received_at)
        else:
            _insert(db, source_id, "cursor_reset", NOTICE, window_start, received_at,
                    f"{why} The recovered window reaches back past the last record already collected, so "
                    "nothing is missing; overlapping records were deduplicated.", batch_id, received_at)

    if "coverage_start" in codes:
        if last_event is None:
            start = first_record or received_at
            _insert(db, source_id, "coverage_start", GAP, None, start,
                    "collection began here; only the exporter's recent window was read, so anything earlier "
                    "is outside coverage.", batch_id, received_at)
            if state["coverage_start"] is None:
                db.execute("UPDATE source_collection SET coverage_start=?, coverage_note=NULL WHERE source_id=?",
                           (start, source_id))
        else:
            reset("cursor_lost", "The collector had no saved cursor for a source it had collected before and "
                  "restarted from the exporter's recent window.")
    if "retention_gap" in codes:
        reset("retention_gap", "The saved cursor was no longer in the source journal (rotated or vacuumed).")

    failed = sorted(codes - INFORMATIONAL - {""})
    if failed:
        _open(db, source_id, "source_error", f"the source could not be read ({', '.join(failed)}); its "
              "cursor did not move, so the records wait in its journal.", batch_id, received_at)
    else:
        _close(db, source_id, "source_error", received_at)

    behind = codes & CATCHING_UP
    if behind:
        _open(db, source_id, "catching_up", "the collector read a full page and more records are waiting; it "
              "is working through a backlog.", batch_id, received_at)
    elif not failed:
        _close(db, source_id, "catching_up", received_at)

    lag = None
    if collected_at:
        lag = max(0.0, _seconds(collected_at, received_at))
        if lag > DELIVERY_DELAY_SECONDS:
            _insert(db, source_id, "delivery_delay", DELAY, collected_at, received_at,
                    f"this batch waited {_minutes(lag)} in the collector's spool before this API accepted it.",
                    batch_id, received_at)
    if "message_truncated" in codes:
        _insert(db, source_id, "message_truncated", NOTICE, received_at, received_at,
                messages["message_truncated"], batch_id, received_at)

    db.execute("""UPDATE source_collection SET last_batch_at=?, caught_up=?,
        last_delivery_lag_seconds=coalesce(?, last_delivery_lag_seconds), updated_at=? WHERE source_id=?""",
               (received_at, 0 if behind or failed else 1, lag, received_at, source_id))


def _issue(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()}


def summary(db: sqlite3.Connection, source_id: str) -> dict[str, Any] | None:
    state = db.execute("SELECT * FROM source_collection WHERE source_id=?", (source_id,)).fetchone()
    if state is None:
        return None
    gaps = db.execute("SELECT count(*) FROM collection_issues WHERE source_id=? AND category=?",
                      (source_id, GAP)).fetchone()[0]
    last_gap = db.execute("SELECT * FROM collection_issues WHERE source_id=? AND category=? AND kind!='coverage_start' "
                          "ORDER BY issue_id DESC LIMIT 1", (source_id, GAP)).fetchone()
    open_rows = db.execute("SELECT kind FROM collection_issues WHERE source_id=? AND ended_at IS NULL "
                           "ORDER BY issue_id", (source_id,)).fetchall()
    delays = db.execute("SELECT count(*) FROM collection_issues WHERE source_id=? AND category=?",
                        (source_id, DELAY)).fetchone()[0]
    losses = db.execute("SELECT count(*) FROM collection_issues WHERE source_id=? AND category=? "
                        "AND kind!='coverage_start'", (source_id, GAP)).fetchone()[0]
    return {"tracking_since": state["tracking_since"], "coverage_start": state["coverage_start"],
            "coverage_note": state["coverage_note"], "gaps_since_coverage": losses, "gap_records": gaps,
            "last_gap": _issue(last_gap) if last_gap else None, "open": [row[0] for row in open_rows],
            "delays": delays, "caught_up": bool(state["caught_up"]), "last_batch_at": state["last_batch_at"],
            "last_delivery_lag_seconds": state["last_delivery_lag_seconds"]}


def issues(db: sqlite3.Connection, source_id: str | None, limit: int, offset: int) -> tuple[int, list[dict]]:
    where, params = ("WHERE source_id=?", (source_id,)) if source_id else ("", ())
    total = db.execute(f"SELECT count(*) FROM collection_issues {where}", params).fetchone()[0]
    rows = db.execute(f"SELECT * FROM collection_issues {where} ORDER BY issue_id DESC LIMIT ? OFFSET ?",
                      (*params, limit, offset)).fetchall()
    return total, [_issue(row) for row in rows]
