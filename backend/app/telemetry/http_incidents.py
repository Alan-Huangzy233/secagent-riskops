"""Bounded, restartable HTTP analysis over committed access records.

Detection keeps the existing 300-second sliding rules. Review cases group one
source/service/peer per UTC hour, reading five minutes of context on both sides.
Scores describe request patterns, never successful exploitation.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import uuid

from .http_parse import HttpEvent
from .web_detection import detect_web

VERSION = "http-evidence-v1"
CORRELATION_VERSION = "http-peer-hour-v1"
RULES = {
    "http_sensitive_resource": (25, "敏感资源探测"),
    "http_path_traversal": (35, "目录穿越尝试"),
    "http_multi_path_scan": (30, "多路径扫描模式"),
}
CRITERIA = {
    "http_sensitive_resource": "解码后的路径段命中敏感资源名称；任何响应码均只作为探测迹象。",
    "http_path_traversal": "有限解码后的路径含父目录段；不能据此判断服务器是否返回文件。",
    "http_multi_path_scan": "300 秒内至少 20 次请求、10 个不同路径，且至少 80% 为 403/404；授权扫描也可能命中。",
}
MAX_CONTEXT_RECORDS = 5000
MAX_CONTEXT_BYTES = 4 * 1024 * 1024
TABLES = {"http_analysis_meta", "http_context", "http_windows", "http_incidents",
          "http_incident_revisions", "http_evidence", "http_evidence_membership", "http_notice_outbox"}
SCHEMA = """
CREATE TABLE IF NOT EXISTS http_analysis_meta(name TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS http_context(
    seq INTEGER PRIMARY KEY,source_id TEXT NOT NULL,service_id TEXT NOT NULL,
    client_ip TEXT NOT NULL,event_ts REAL NOT NULL,record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS http_context_peer ON http_context(source_id,service_id,client_ip,event_ts,seq);
CREATE INDEX IF NOT EXISTS http_context_expiry ON http_context(event_ts);
CREATE TABLE IF NOT EXISTS http_windows(
    source_id TEXT NOT NULL,service_id TEXT NOT NULL,client_ip TEXT NOT NULL,hour INTEGER NOT NULL,
    dirty INTEGER NOT NULL,coverage TEXT NOT NULL,updated_at REAL NOT NULL,
    PRIMARY KEY(source_id,service_id,client_ip,hour)
);
CREATE INDEX IF NOT EXISTS http_windows_dirty ON http_windows(dirty,updated_at);
CREATE INDEX IF NOT EXISTS http_windows_coverage ON http_windows(coverage,updated_at DESC);
CREATE TABLE IF NOT EXISTS http_incidents(
    seq INTEGER PRIMARY KEY AUTOINCREMENT,incident_id TEXT NOT NULL UNIQUE,
    source_id TEXT NOT NULL,service_id TEXT NOT NULL,client_ip TEXT NOT NULL,hour INTEGER NOT NULL,
    revision INTEGER NOT NULL,score INTEGER NOT NULL,surfaced INTEGER NOT NULL,active INTEGER NOT NULL,
    coverage TEXT NOT NULL,updated_at REAL NOT NULL,payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS http_incidents_page ON http_incidents(hour DESC,seq DESC);
CREATE INDEX IF NOT EXISTS http_incidents_stream ON http_incidents(source_id,service_id,hour DESC,seq DESC);
CREATE TABLE IF NOT EXISTS http_incident_revisions(
    incident_id TEXT NOT NULL,revision INTEGER NOT NULL,payload_json TEXT NOT NULL,
    PRIMARY KEY(incident_id,revision)
);
CREATE TABLE IF NOT EXISTS http_evidence(
    incident_id TEXT NOT NULL,event_id TEXT NOT NULL,event_ts REAL NOT NULL,record_json TEXT NOT NULL,
    PRIMARY KEY(incident_id,event_id)
);
CREATE INDEX IF NOT EXISTS http_evidence_page ON http_evidence(incident_id,event_ts,event_id);
CREATE TABLE IF NOT EXISTS http_evidence_membership(
    incident_id TEXT NOT NULL,event_id TEXT NOT NULL,from_revision INTEGER NOT NULL,to_revision INTEGER,
    PRIMARY KEY(incident_id,event_id,from_revision)
);
CREATE INDEX IF NOT EXISTS http_evidence_current ON http_evidence_membership(incident_id,event_id) WHERE to_revision IS NULL;
CREATE TABLE IF NOT EXISTS http_notice_outbox(
    topic TEXT PRIMARY KEY,revision INTEGER NOT NULL,cancelled INTEGER NOT NULL,
    payload_json TEXT NOT NULL,pending INTEGER NOT NULL
);
"""


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def sha(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def stamp(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


def meta(db, name, default=None):
    row = db.execute("SELECT value FROM http_analysis_meta WHERE name=?", (name,)).fetchone()
    return json.loads(row[0]) if row else default


def set_meta(db, name, value):
    db.execute("INSERT INTO http_analysis_meta VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value",
               (name, canonical(value)))


def initialize(db):
    db.executescript(SCHEMA)
    db.execute("INSERT OR IGNORE INTO http_analysis_meta VALUES('producer_id',?)", (canonical(uuid.uuid4().hex),))


def intake(db, now, limit):
    cursor = meta(db, "cursor", 0)
    high_row = db.execute("SELECT seq FROM sqlite_sequence WHERE name='http_events'").fetchone()
    high = high_row[0] if high_row else 0
    rows = db.execute("SELECT seq,record_json FROM http_events WHERE seq>? ORDER BY seq LIMIT ?", (cursor, limit)).fetchall()
    missing = meta(db, "missing_raw_records", 0)
    for row in rows:
        missing += max(0, row["seq"] - cursor - 1)
        event = json.loads(row["record_json"])
        db.execute("INSERT OR IGNORE INTO http_context VALUES(?,?,?,?,?,?)",
                   (row["seq"], event["source_id"], event["service_id"], event["client_ip"], event["event_ts"], row["record_json"]))
        hour = int(event["event_ts"] // 3600) * 3600
        hours = {hour}
        if event["event_ts"] - hour <= 300:
            hours.add(hour - 3600)
        if event["event_ts"] - hour >= 3300:
            hours.add(hour + 3600)
        for bucket in hours:
            db.execute("INSERT INTO http_windows VALUES(?,?,?,?,1,'pending',?) "
                       "ON CONFLICT(source_id,service_id,client_ip,hour) DO UPDATE SET dirty=1,updated_at=excluded.updated_at",
                       (event["source_id"], event["service_id"], event["client_ip"], bucket, now))
        cursor = row["seq"]
    caught_up = len(rows) < limit or cursor >= high
    if caught_up:
        missing += max(0, high - cursor)
        cursor = high
    set_meta(db, "cursor", cursor)
    set_meta(db, "missing_raw_records", missing)
    set_meta(db, "analyzed_input_records", meta(db, "analyzed_input_records", 0) + len(rows))
    return caught_up


def assessment(rules, evidence):
    reasons = [{"rule_id": rule, "points": RULES[rule][0], "reason": RULES[rule][1], "criteria": CRITERIA[rule]} for rule in sorted(rules)]
    score = min(90, sum(r["points"] for r in reasons))
    return {"version": VERSION, "score": score, "priority": "P2" if score >= 60 else "P3" if score >= 30 else None,
            "surfaced": score >= 30, "reasons": reasons, "evidence_count": len(evidence),
            "note": "仅表示 HTTP 请求模式；响应码不能证明认证成功、漏洞可利用或主机失陷。"}


def _save_case(db, key, coverage, events, findings, now):
    source, service, peer, hour = key
    identity = "HTTP-" + sha(list(key))[:32]
    old = db.execute("SELECT payload_json,revision FROM http_incidents WHERE incident_id=?", (identity,)).fetchone()
    previous = json.loads(old["payload_json"]) if old else None
    if coverage != "complete":
        if not old:
            return
        # Keep the last verifiable result and evidence, visibly stale. A limit
        # or missing context must never turn an unresolved case into score zero.
        payload = {k: v for k, v in previous.items() if k not in ("revision", "updated_at")}
        payload.update(coverage=coverage, stale=True)
        selected = None
    else:
        selected, rules = {}, {}
        lookup = {event.event_id: event for event in events}
        for finding in findings:
            # Context-only findings belong to the adjacent hour's case.
            if not any(hour <= lookup[eid].event_ts < hour + 3600 for eid in finding.evidence_ids):
                continue
            item = rules.setdefault(finding.rule_id, {"rule_id": finding.rule_id, "rule_version": finding.rule_version,
                                                      "window_seconds": 300, "label": RULES[finding.rule_id][1], "ids": set()})
            item["ids"].update(finding.evidence_ids)
            selected.update((eid, lookup[eid]) for eid in finding.evidence_ids)
        if not selected and not old:
            return
        rule_list = [{k: v for k, v in r.items() if k != "ids"} | {"evidence_count": len(r["ids"])} for _, r in sorted(rules.items())]
        selected_rows = sorted(selected.values(), key=lambda e: (e.event_ts, e.event_id))
        payload = {"incident_id": identity, "protocol": "http", "source_id": source, "service_id": service,
                   "client_ip": peer, "window_start": stamp(hour), "window_end": stamp(hour + 3600),
                   "correlation_version": CORRELATION_VERSION, "coverage": coverage, "stale": False,
                   "active": bool(selected), "title": "HTTP 请求异常" if selected else "HTTP 模式已撤回",
                   "first_seen": selected_rows[0].timestamp if selected else previous["first_seen"],
                   "last_seen": selected_rows[-1].timestamp if selected else previous["last_seen"],
                   "rules": rule_list, "evidence_count": len(selected), "evidence_sha256": sha([asdict(e) for e in selected_rows]),
                   "assessment": assessment(rules, selected)}
    old_content = {k: v for k, v in previous.items() if k not in ("revision", "updated_at")} if previous else None
    if old_content == payload:
        return
    revision = old["revision"] + 1 if old else 1
    payload.update(revision=revision, updated_at=stamp(now))
    encoded = canonical(payload)
    db.execute("INSERT INTO http_incidents(incident_id,source_id,service_id,client_ip,hour,revision,score,surfaced,active,coverage,updated_at,payload_json) "
               "VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(incident_id) DO UPDATE SET revision=excluded.revision,score=excluded.score,"
               "surfaced=excluded.surfaced,active=excluded.active,coverage=excluded.coverage,updated_at=excluded.updated_at,payload_json=excluded.payload_json",
               (identity, source, service, peer, hour, revision, payload["assessment"]["score"], int(payload["assessment"]["surfaced"]),
                int(payload["active"]), coverage, now, encoded))
    db.execute("INSERT INTO http_incident_revisions VALUES(?,?,?)", (identity, revision, encoded))
    if selected is not None:
        current = {r[0] for r in db.execute("SELECT event_id FROM http_evidence_membership WHERE incident_id=? AND to_revision IS NULL", (identity,))}
        for eid in current - selected.keys():
            db.execute("UPDATE http_evidence_membership SET to_revision=? WHERE incident_id=? AND event_id=? AND to_revision IS NULL",
                       (revision - 1, identity, eid))
        for eid in selected.keys() - current:
            event = selected[eid]
            db.execute("INSERT OR IGNORE INTO http_evidence VALUES(?,?,?,?)", (identity, eid, event.event_ts, canonical(asdict(event))))
            db.execute("INSERT INTO http_evidence_membership VALUES(?,?,?,NULL)", (identity, eid, revision))
    topic = "http:" + meta(db, "producer_id") + ":" + identity
    notify = payload["active"] and payload["assessment"]["surfaced"] and not payload["stale"] and hour + 3600 >= now - 86400
    db.execute("INSERT INTO http_notice_outbox VALUES(?,?,?,?,1) ON CONFLICT(topic) DO UPDATE SET "
               "revision=excluded.revision,cancelled=excluded.cancelled,payload_json=excluded.payload_json,pending=1",
               (topic, revision, int(not notify), encoded))


def analyze_window(db, row, now, retention_days):
    key = tuple(row[k] for k in ("source_id", "service_id", "client_ip", "hour"))
    hour = row["hour"]
    events, size, coverage = [], 0, "complete"
    if hour - 300 < now - retention_days * 86400:
        coverage = "expired_context"
    else:
        cursor = db.execute("SELECT record_json FROM http_context WHERE source_id=? AND service_id=? AND client_ip=? "
                            "AND event_ts>=? AND event_ts<=? ORDER BY event_ts,seq LIMIT ?",
                            (*key[:3], hour - 300, hour + 3900, MAX_CONTEXT_RECORDS + 1))
        for item in cursor:
            size += len(item[0].encode())
            if len(events) >= MAX_CONTEXT_RECORDS or size > MAX_CONTEXT_BYTES:
                coverage = "context_limit"
                break
            events.append(HttpEvent(**json.loads(item[0])))
    _save_case(db, key, coverage, events, detect_web(events) if coverage == "complete" else [], now)
    db.execute("UPDATE http_windows SET dirty=0,coverage=?,updated_at=? WHERE source_id=? AND service_id=? AND client_ip=? AND hour=?",
               (coverage, now, *key))


def process(store, now, *, intake_limit=200, window_limit=5):
    if not 1 <= intake_limit <= 1000 or not 1 <= window_limit <= 20:
        raise ValueError("Invalid HTTP analysis bounds")
    with store.connection(write=True) as db:
        caught_up = intake(db, now, intake_limit)
        set_meta(db, "last_run", stamp(now))
        set_meta(db, "last_error", None)
    processed = 0
    if caught_up:
        # Independent short transactions: HTTP receipt commit never waits for a
        # whole historical rebuild. One window has a record AND byte bound.
        for _ in range(window_limit):
            with store.connection(write=True) as db:
                row = db.execute("SELECT * FROM http_windows WHERE dirty=1 ORDER BY updated_at LIMIT 1").fetchone()
                if row is None:
                    break
                analyze_window(db, row, now, store.retention_days)
            processed += 1
    with store.connection(write=True) as db:
        db.execute("DELETE FROM http_context WHERE seq IN (SELECT seq FROM http_context WHERE event_ts<? ORDER BY event_ts LIMIT 1000)",
                   (now - store.retention_days * 86400,))
        pending = db.execute("SELECT 1 FROM http_windows WHERE dirty=1 LIMIT 1").fetchone() is not None
    return {"caught_up": caught_up and not pending, "windows_processed": processed}


def status(db):
    high = db.execute("SELECT seq FROM sqlite_sequence WHERE name='http_events'").fetchone()
    cursor = meta(db, "cursor", 0)
    pending = db.execute("SELECT 1 FROM http_windows WHERE dirty=1 LIMIT 1").fetchone() is not None
    issues = [dict(row) for row in db.execute("SELECT source_id,service_id,client_ip,hour,coverage FROM http_windows "
                                            "WHERE coverage IN ('context_limit','expired_context') ORDER BY updated_at DESC LIMIT 50")]
    return {"version": VERSION, "correlation_version": CORRELATION_VERSION, "last_run": meta(db, "last_run"),
            "last_error": meta(db, "last_error"), "pending": pending or cursor < (high[0] if high else 0),
            "analyzed_input_records": meta(db, "analyzed_input_records", 0),
            "missing_raw_records": meta(db, "missing_raw_records", 0), "coverage_issues": issues}


def list_cases(db, *, source_id=None, service_id=None, focus="all", page=1, limit=50):
    if focus not in ("all", "attention", "low", "retracted") or not 1 <= page <= 1000000 or not 1 <= limit <= 200:
        raise ValueError("Invalid HTTP incident page")
    where, params = ["1=1"], []
    for key, value in (("source_id", source_id), ("service_id", service_id)):
        if value is not None:
            where.append(key + "=?")
            params.append(value)
    if focus == "attention":
        where.append("surfaced=1 AND active=1")
    elif focus == "low":
        where.append("surfaced=0 AND active=1")
    elif focus == "retracted":
        where.append("active=0")
    clause = " AND ".join(where)
    total = db.execute("SELECT count(*) FROM http_incidents WHERE " + clause, params).fetchone()[0]
    pages = max(1, (total + limit - 1) // limit)
    page = min(page, pages)
    rows = db.execute("SELECT payload_json FROM http_incidents WHERE " + clause + " ORDER BY hour DESC,seq DESC LIMIT ? OFFSET ?",
                      (*params, limit, (page - 1) * limit)).fetchall()
    return {"items": [json.loads(r[0]) for r in rows], "page": page, "total_pages": pages, "total": total}


def get_case(db, identity, revision=None):
    if revision is None:
        row = db.execute("SELECT payload_json FROM http_incidents WHERE incident_id=?", (identity,)).fetchone()
    else:
        row = db.execute("SELECT payload_json FROM http_incident_revisions WHERE incident_id=? AND revision=?", (identity, revision)).fetchone()
    return json.loads(row[0]) if row else None


def evidence(db, identity, *, revision=None, page=1, limit=50):
    if not 1 <= limit <= 200 or not 1 <= page <= 1000000:
        raise ValueError("Invalid HTTP evidence page")
    incident = get_case(db, identity, revision)
    if incident is None:
        return None
    revision = incident["revision"]
    # Membership intervals preserve exact historical evidence without copying
    # an ever-growing list on every revision. Raw retention never deletes it.
    clause = "m.incident_id=? AND m.from_revision<=? AND (m.to_revision IS NULL OR m.to_revision>=?)"
    params = (identity, revision, revision)
    total = db.execute("SELECT count(*) FROM http_evidence_membership m WHERE " + clause, params).fetchone()[0]
    pages = max(1, (total + limit - 1) // limit)
    page = min(page, pages)
    rows = db.execute("SELECT e.record_json FROM http_evidence_membership m JOIN http_evidence e "
                      "ON e.incident_id=m.incident_id AND e.event_id=m.event_id WHERE " + clause +
                      " ORDER BY e.event_ts,e.event_id LIMIT ? OFFSET ?", (*params, limit, (page-1)*limit)).fetchall()
    return {"incident_id": identity, "revision": revision, "items": [json.loads(r[0]) for r in rows],
            "page": page, "total_pages": pages, "total": total}
