"""Durable console notifications. No external transport or incident mutation.

Producers coalesce by topic; the local inbox and outbox acknowledgement commit
together. A failed attempt is retried, including after a service restart.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import shutil
import sqlite3
import threading
import time

from . import scoring

SCHEMA = """
CREATE TABLE IF NOT EXISTS notification_outbox (
    topic TEXT PRIMARY KEY, kind TEXT NOT NULL, object_id TEXT,
    priority INTEGER NOT NULL, payload_json TEXT NOT NULL,
    revision INTEGER NOT NULL, state TEXT NOT NULL,
    due_at REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT, last_delivered_at REAL, updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS notification_due ON notification_outbox(state,due_at);
CREATE TABLE IF NOT EXISTS notification_inbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT, topic TEXT NOT NULL,
    revision INTEGER NOT NULL, kind TEXT NOT NULL, payload_json TEXT NOT NULL,
    delivered_at REAL NOT NULL, read_at REAL,
    UNIQUE(topic,revision)
);
CREATE INDEX IF NOT EXISTS notification_unread ON notification_inbox(id DESC) WHERE read_at IS NULL;
CREATE TABLE IF NOT EXISTS notification_meta (name TEXT PRIMARY KEY,value TEXT NOT NULL);
"""
COOLDOWN_SECONDS = 3600
SCAN_LIMIT = 200
DELIVERY_LIMIT = 50


def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _get(db, key, default=None):
    row = db.execute("SELECT value FROM notification_meta WHERE name=?", (key,)).fetchone()
    return json.loads(row[0]) if row else default


def _set(db, key, value):
    db.execute("INSERT INTO notification_meta VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value",
               (key, _json(value)))


def enqueue(db, topic, kind, payload, now, *, priority=0, object_id=None, cooldown=COOLDOWN_SECONDS):
    encoded = _json(payload)
    old = db.execute("SELECT * FROM notification_outbox WHERE topic=?", (topic,)).fetchone()
    if old and old["payload_json"] == encoded and old["state"] != "cancelled":
        return False
    due, attempts = now, 0
    if old:
        if old["state"] == "pending":
            due, attempts = old["due_at"], old["attempts"]
        elif old["last_delivered_at"] is not None:
            due = max(now, old["last_delivered_at"] + cooldown)
        if priority > old["priority"] or cooldown == 0:
            due = now
    db.execute("""INSERT INTO notification_outbox
        (topic,kind,object_id,priority,payload_json,revision,state,due_at,attempts,updated_at)
        VALUES(?,?,?,?,?,?,'pending',?,?,?) ON CONFLICT(topic) DO UPDATE SET
        priority=excluded.priority,payload_json=excluded.payload_json,revision=excluded.revision,
        state='pending',due_at=excluded.due_at,attempts=excluded.attempts,updated_at=excluded.updated_at""",
        (topic, kind, object_id, priority, encoded, old["revision"] + 1 if old else 1, due, attempts, now))
    return True


def incident(db, incident_id, now):
    row = db.execute("""SELECT i.incident_id,i.src_ip,i.last_seen,s.score,s.priority,s.reasons_json,d.evidence_count
        FROM incidents i JOIN incident_scores s USING(incident_id) JOIN incident_details d USING(incident_id)
        LEFT JOIN incident_triage t USING(incident_id)
        WHERE i.incident_id=? AND i.status!='merged' AND coalesce(t.state,'pending')='pending'
        AND s.version=? AND s.evidence_count=d.evidence_count AND s.surfaced=1""",
        (incident_id, scoring.VERSION)).fetchone()
    topic = "incident:" + incident_id
    if not row:
        db.execute("UPDATE notification_outbox SET state='cancelled' WHERE topic=? AND state='pending'", (topic,))
        return
    payload = {"title": "需要关注的 SSH 事件", **dict(row),
               "reasons": json.loads(row["reasons_json"]),
               "source_ids": [r[0] for r in db.execute(
                   "SELECT source_id FROM incident_sources WHERE incident_id=? ORDER BY source_id", (incident_id,))]}
    del payload["reasons_json"]
    enqueue(db, topic, "incident", payload, now, priority={"P1": 3, "P2": 2, "P3": 1}[row["priority"]],
            object_id=incident_id)


def _condition(db, topic, kind, problem, payload, now):
    previous = _get(db, "condition:" + topic, False)
    if problem or previous:
        enqueue(db, topic, kind, {**payload, "active": problem}, now,
                priority=2 if problem else 0, cooldown=COOLDOWN_SECONDS if problem else 0)
    _set(db, "condition:" + topic, problem)


def _sources(db, sources, heartbeat_timeout, now):
    for source in sources:
        row = db.execute("SELECT last_seen FROM sources WHERE source_id=?", (source,)).fetchone()
        last = datetime.fromisoformat(row[0].replace("Z", "+00:00")).timestamp() if row else None
        codes = [r[0] for r in db.execute("""SELECT kind FROM collection_issues
            WHERE source_id=? AND ended_at IS NULL AND kind='source_error' ORDER BY kind""", (source,))]
        if last is None:
            codes.append("never_seen")
        elif now - last > heartbeat_timeout:
            codes.append("offline")
        behind = db.execute("""SELECT started_at FROM collection_issues
            WHERE source_id=? AND kind='catching_up' AND ended_at IS NULL LIMIT 1""", (source,)).fetchone()
        if behind and behind[0] and now - datetime.fromisoformat(behind[0].replace("Z", "+00:00")).timestamp() > heartbeat_timeout:
            codes.append("catching_up")
        _condition(db, "source:" + source, "collection", bool(codes),
                   {"title": "采集异常" if codes else "采集已恢复", "source_id": source, "conditions": codes}, now)
    cursor = _get(db, "gap_cursor", 0)
    rows = db.execute("""SELECT issue_id,source_id,kind,started_at,ended_at FROM collection_issues
        WHERE issue_id>? AND category='gap' AND kind!='coverage_start'
        ORDER BY issue_id LIMIT ?""", (cursor, SCAN_LIMIT)).fetchall()
    for row in rows:
        # Existing history stays in the collection timeline; avoid an upgrade storm.
        opened = db.execute("SELECT opened_at FROM collection_issues WHERE issue_id=?", (row["issue_id"],)).fetchone()[0]
        if datetime.fromisoformat(opened.replace("Z", "+00:00")).timestamp() >= now - 86400:
            enqueue(db, "gap:" + str(row["issue_id"]), "collection", {"title": "发现采集缺口", **dict(row)}, now, priority=2)
    if rows:
        _set(db, "gap_cursor", rows[-1]["issue_id"])


def monitor_health(database, backup_directories, now, *, disk_usage=shutil.disk_usage):
    """Only metadata is read. Snapshot names follow backup_telemetry.py's atomic publication."""
    checks = []
    try:
        usage = disk_usage(Path(database).parent)
        low = usage.free < max(1024 ** 3, usage.total * .1)
        checks.append({"key": "capacity", "status": "low" if low else "ok",
                       "title": "磁盘可用空间不足" if low else "磁盘空间已恢复"})
    except OSError:
        checks.append({"key": "capacity", "status": "unknown", "title": "无法核实磁盘容量"})
    for index, directory in enumerate(backup_directories, 1):
        key = f"backup-{index}"
        try:
            latest = None
            for count, path in enumerate(Path(directory).iterdir()):
                if count >= 10000:
                    raise OSError("directory scan limit")
                if not re.fullmatch(r"live-\d{8}T\d{12}\.sqlite", path.name) or path.is_symlink() or not path.is_file():
                    continue
                stamp = datetime.strptime(path.stem[5:], "%Y%m%dT%H%M%S%f").replace(tzinfo=timezone.utc).timestamp()
                if stamp <= now + 300 and path.stat().st_size > 0:
                    latest = max(latest or stamp, stamp)
            stale = latest is None or now - latest > 36 * 3600
            checks.append({"key": key, "status": "stale" if stale else "ok",
                           "title": "本机备份缺失或超过 36 小时" if stale else "本机备份已恢复"})
        except (OSError, ValueError):
            checks.append({"key": key, "status": "unknown", "title": "无法核实本机备份"})
    return checks


def advance_briefing(store, now, *, batch_size=1000):
    """Read one bounded page without a write lock; checkpoint with compare-and-set.

    The received-at cutoff and keyset cursor give a stable population across
    restarts. Retention may remove older logs, which the report discloses.
    """
    today = datetime.fromtimestamp(now, timezone.utc).date()
    with store._connection() as db:
        work = _get(db, "briefing_work")
        last = _get(db, "briefing_date")
        if work is None:
            day = datetime.fromisoformat(last).date() + timedelta(days=1) if last else today - timedelta(days=1)
            earliest = today - timedelta(days=max(1, store.retention_days - 1))
            skipped = max(0, (earliest - day).days)
            day = max(day, earliest)
            if day >= today:
                return False
            work = {"date": day.isoformat(), "cutoff": now, "cursor": None, "counts": {}, "skipped_days": skipped}
        old_work = _get(db, "briefing_work")
        start = datetime.fromisoformat(work["date"]).replace(tzinfo=timezone.utc)
        end = start + timedelta(days=1)
        cutoff = datetime.fromtimestamp(work["cutoff"], timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        params = [start.timestamp(), end.timestamp(), cutoff]
        after = ""
        if work["cursor"]:
            stamp, source, event = work["cursor"]
            after = " AND event_ts<=? AND (event_ts<? OR source_id>? OR (source_id=? AND event_id>?))"
            params.extend([stamp, stamp, source, source, event])
        deadline = time.monotonic() + 5
        db.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
        rows = db.execute("SELECT event_ts,source_id,event_id,event_type FROM events "
                          "WHERE event_ts>=? AND event_ts<? AND received_at<=?" + after +
                          " ORDER BY event_ts DESC,source_id,event_id LIMIT ?", (*params, batch_size)).fetchall()
        counts = dict(work["counts"])
        for row in rows:
            counts[row["event_type"]] = counts.get(row["event_type"], 0) + 1
        more = len(rows) == batch_size
        next_work = {**work, "counts": counts, "cursor": list(rows[-1][:3]) if rows else work["cursor"]}
        if not more:
            new = db.execute("""SELECT count(*),coalesce(sum(s.surfaced=1),0),
                coalesce(sum(s.surfaced=0),0),coalesce(sum(s.incident_id IS NULL),0)
                FROM incidents i LEFT JOIN incident_scores s ON s.incident_id=i.incident_id
                AND s.version=? AND s.evidence_count=(SELECT evidence_count FROM incident_details WHERE incident_id=i.incident_id)
                WHERE i.status!='merged' AND julianday(i.created_at)>=julianday(?) AND julianday(i.created_at)<julianday(?)""",
                (scoring.VERSION, start.isoformat(), end.isoformat())).fetchone()
            gaps = db.execute("""SELECT count(*) FROM collection_issues WHERE category='gap'
                AND julianday(opened_at)>=julianday(?) AND julianday(opened_at)<julianday(?)""",
                (start.isoformat(), end.isoformat())).fetchone()[0]
    # The read transaction is closed before trying to acquire the write lock.
    with store._connection(write=True) as db:
        if _get(db, "briefing_work") != old_work or _get(db, "briefing_date") != last:
            return True
        _set(db, "briefing_error", None)
        if more:
            _set(db, "briefing_work", next_work)
        else:
            enqueue(db, "briefing:" + work["date"], "briefing", {
                "title": work["date"] + " 每日简报（UTC）", "date": work["date"],
                "start": start.isoformat(), "end": end.isoformat(), "generated_at": now,
                "data_as_of": work["cutoff"], "log_count": sum(counts.values()), "event_types": counts,
                "new_incidents": new[0], "attention": new[1], "low": new[2], "unscored": new[3],
                "collection_gaps": gaps, "skipped_days": work["skipped_days"],
                "note": "按日志发生时间统计汇总开始时已采集的日志；事件按创建时间统计，评分为生成简报时的状态。迟到日志、保留期限和采集缺口可能影响完整性。"}, now)
            _set(db, "briefing_date", work["date"])
            _set(db, "briefing_work", None)
    return more


def deliver_console(db, row, now):
    db.execute("""INSERT OR IGNORE INTO notification_inbox(topic,revision,kind,payload_json,delivered_at)
        VALUES(?,?,?,?,?)""", (row["topic"], row["revision"], row["kind"], row["payload_json"], now))


def tick(db, sources, heartbeat_timeout, now, *, health=(), deliver=deliver_console):
    cursor = _get(db, "incident_cursor", "")
    rows = db.execute("""SELECT i.incident_id FROM incidents i JOIN incident_scores s USING(incident_id)
        WHERE i.status!='merged' AND s.surfaced=1 AND i.incident_id>? ORDER BY i.incident_id LIMIT ?""",
        (cursor, SCAN_LIMIT)).fetchall()
    for row in rows:
        incident(db, row[0], now)
    _set(db, "incident_cursor", rows[-1][0] if len(rows) == SCAN_LIMIT else "")
    _sources(db, sources, heartbeat_timeout, now)
    for check in health:
        _condition(db, "health:" + check["key"], "health", check["status"] != "ok", check, now)
    _set(db, "health", list(health))
    sent = failed = 0
    due = db.execute("""SELECT * FROM notification_outbox WHERE state='pending' AND due_at<=?
        ORDER BY due_at,topic LIMIT ?""", (now, DELIVERY_LIMIT)).fetchall()
    for row in due:
        if row["kind"] == "incident":
            incident(db, row["object_id"], now)
            row = db.execute("SELECT * FROM notification_outbox WHERE topic=?", (row["topic"],)).fetchone()
            if row["state"] != "pending" or row["due_at"] > now:
                continue
        db.execute("SAVEPOINT notification_delivery")
        try:
            deliver(db, row, now)
            db.execute("""UPDATE notification_outbox SET state='delivered',last_delivered_at=?,
                attempts=0,last_error=NULL WHERE topic=?""", (now, row["topic"]))
        except Exception:
            db.execute("ROLLBACK TO notification_delivery")
            attempts = row["attempts"] + 1
            db.execute("UPDATE notification_outbox SET attempts=?,due_at=?,last_error=? WHERE topic=?",
                       (attempts, now + min(3600, 30 * 2 ** min(attempts - 1, 7)),
                        "站内通知写入失败，将自动重试", row["topic"]))
            failed += 1
        else:
            sent += 1
        finally:
            db.execute("RELEASE notification_delivery")
    _set(db, "last_run", now)
    _set(db, "last_error", None)
    return {"delivered": sent, "failed": failed}


def snapshot(db, *, page=1, limit=20, unread=False, kind=None):
    where, params = ["1=1"], []
    if unread:
        where.append("read_at IS NULL")
    if kind:
        where.append("kind=?")
        params.append(kind)
    clause = " AND ".join(where)
    total = db.execute("SELECT count(*) FROM notification_inbox WHERE " + clause, params).fetchone()[0]
    pages = max(1, (total + limit - 1) // limit)
    page = min(page, pages)
    rows = db.execute("SELECT * FROM notification_inbox WHERE " + clause + " ORDER BY id DESC LIMIT ? OFFSET ?",
                      (*params, limit, (page - 1) * limit)).fetchall()
    items = [{"id": row["id"], "kind": row["kind"], "payload": json.loads(row["payload_json"]),
              "delivered_at": row["delivered_at"], "read_at": row["read_at"]} for row in rows]
    return {"items": items, "total": total, "page": page, "total_pages": pages,
            "unread": db.execute("SELECT count(*) FROM notification_inbox WHERE read_at IS NULL").fetchone()[0],
            "pending": db.execute("SELECT count(*) FROM notification_outbox WHERE state='pending'").fetchone()[0],
            "retrying": db.execute("SELECT count(*) FROM notification_outbox WHERE state='pending' AND attempts>0").fetchone()[0],
            "last_run": _get(db, "last_run"), "last_error": _get(db, "last_error"),
            "health": _get(db, "health", []),
            "briefing_in_progress": (_get(db, "briefing_work") or {}).get("date"),
            "briefing_error": _get(db, "briefing_error")}


class NotificationWorker:
    def __init__(self, store, config, *, interval=30):
        self.store, self.config, self.interval = store, config, interval
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, name="console-notifications", daemon=True)

    def start(self):
        self.thread.start()

    def close(self):
        self.stop.set()
        self.thread.join(timeout=35)

    def _run(self):
        while not self.stop.is_set():
            delay = self.interval
            try:
                now = time.time()
                health = monitor_health(self.store.path, self.config.notification_backup_directories, now)
                result = self.store.run_notifications([s.id for s in self.config.sources], self.config.heartbeat_timeout_seconds,
                                                      now=now, health=health)
                if result["briefing_pending"]:
                    delay = min(self.interval, 1)
            except Exception:
                # A worker problem must never stop ingestion or leak exception content.
                try:
                    with self.store._connection(write=True) as db:
                        _set(db, "last_error", "通知任务暂时失败，将自动重试")
                except sqlite3.Error:
                    pass
            self.stop.wait(delay)
