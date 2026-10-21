"""Bounded, restartable analysis of durable normalized firewall observations.

Review cases use monotonic-hour buckets within one source/boot/profile/peer.
Wall clocks only label evidence; they never join rule windows across boots.
All writes, including the cursor and immutable evidence, share the store's
bounded transaction guard. A failed calculation never clears an existing case.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import math
import uuid

from .network_detection import detect_network, RULE_ID, RULE_VERSION
from .network_protocol import encode, event_from_dict, fingerprint


VERSION = "network-evidence-v1"
CORRELATION_VERSION = "network-monotonic-peer-hour-v1"
HOUR_US = 3_600_000_000
WINDOW_US = 300_000_000
MAX_CONTEXT_RECORDS = 5000
MAX_CONTEXT_BYTES = 4 * 1024 * 1024
MAX_TIME_US = 2**63 - 1
KEY_COLUMNS = ("source_id", "boot_id", "source_profile_revision", "src_ip", "dst_ip",
               "monotonic_hour_us")
KEY_WHERE = " AND ".join(name + "=?" for name in KEY_COLUMNS)
TABLE_COLUMNS = {
    "network_analysis_meta": ("name", "value"),
    "network_analysis_sources": ("source_id", "coverage_json", "last_report_json"),
    "network_context": ("receipt_seq", "source_id", "boot_id", "source_profile_revision",
                        "src_ip", "dst_ip", "monotonic_us", "received_at_us", "event_json"),
    "network_analysis_losses": ("source_id", "event_id", "boot_id", "monotonic_us", "reason"),
    "network_windows": (*KEY_COLUMNS, "dirty", "coverage_json", "updated_at"),
    "network_incidents": ("seq", "incident_id", *KEY_COLUMNS, "revision", "score", "surfaced",
                          "active", "stale", "updated_at", "payload_json"),
    "network_incident_revisions": ("incident_id", "revision", "payload_json"),
    "network_evidence": ("incident_id", "event_id", "monotonic_us", "event_json"),
    "network_evidence_membership": ("incident_id", "event_id", "from_revision", "to_revision"),
    "network_notice_outbox": ("topic", "revision", "cancelled", "payload_json", "pending"),
}
INDEXES = {
    "network_context_peer", "network_context_expiry", "network_analysis_losses_window",
    "network_windows_dirty", "network_windows_source", "network_incidents_page",
    "network_incidents_source", "network_evidence_page", "network_evidence_current",
}
SCHEMA = """
CREATE TABLE network_analysis_meta(name TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE network_analysis_sources(
    source_id TEXT PRIMARY KEY,coverage_json TEXT NOT NULL,last_report_json TEXT NOT NULL
);
CREATE TABLE network_context(
    receipt_seq INTEGER PRIMARY KEY,source_id TEXT NOT NULL,boot_id TEXT NOT NULL,
    source_profile_revision TEXT NOT NULL,src_ip TEXT NOT NULL,dst_ip TEXT NOT NULL,
    monotonic_us INTEGER NOT NULL,received_at_us INTEGER NOT NULL,event_json TEXT NOT NULL
);
CREATE INDEX network_context_peer ON network_context(
    source_id,boot_id,source_profile_revision,src_ip,dst_ip,monotonic_us,receipt_seq
);
CREATE INDEX network_context_expiry ON network_context(received_at_us,receipt_seq);
CREATE TABLE network_analysis_losses(
    source_id TEXT NOT NULL,event_id TEXT NOT NULL,boot_id TEXT NOT NULL,
    monotonic_us INTEGER NOT NULL,reason TEXT NOT NULL,PRIMARY KEY(source_id,event_id)
);
CREATE INDEX network_analysis_losses_window ON network_analysis_losses(source_id,boot_id,monotonic_us);
CREATE TABLE network_windows(
    source_id TEXT NOT NULL,boot_id TEXT NOT NULL,source_profile_revision TEXT NOT NULL,
    src_ip TEXT NOT NULL,dst_ip TEXT NOT NULL,monotonic_hour_us INTEGER NOT NULL,
    dirty INTEGER NOT NULL,coverage_json TEXT NOT NULL,updated_at REAL NOT NULL,
    PRIMARY KEY(source_id,boot_id,source_profile_revision,src_ip,dst_ip,monotonic_hour_us)
);
CREATE INDEX network_windows_dirty ON network_windows(dirty,updated_at);
CREATE INDEX network_windows_source ON network_windows(source_id,boot_id,monotonic_hour_us);
CREATE TABLE network_incidents(
    seq INTEGER PRIMARY KEY AUTOINCREMENT,incident_id TEXT NOT NULL UNIQUE,
    source_id TEXT NOT NULL,boot_id TEXT NOT NULL,source_profile_revision TEXT NOT NULL,
    src_ip TEXT NOT NULL,dst_ip TEXT NOT NULL,monotonic_hour_us INTEGER NOT NULL,
    revision INTEGER NOT NULL,score INTEGER NOT NULL,surfaced INTEGER NOT NULL,
    active INTEGER NOT NULL,stale INTEGER NOT NULL,updated_at REAL NOT NULL,payload_json TEXT NOT NULL
);
CREATE INDEX network_incidents_page ON network_incidents(seq DESC);
CREATE INDEX network_incidents_source ON network_incidents(source_id,seq DESC);
CREATE TABLE network_incident_revisions(
    incident_id TEXT NOT NULL,revision INTEGER NOT NULL,payload_json TEXT NOT NULL,
    PRIMARY KEY(incident_id,revision)
);
CREATE TABLE network_evidence(
    incident_id TEXT NOT NULL,event_id TEXT NOT NULL,monotonic_us INTEGER NOT NULL,
    event_json TEXT NOT NULL,PRIMARY KEY(incident_id,event_id)
);
CREATE INDEX network_evidence_page ON network_evidence(incident_id,monotonic_us,event_id);
CREATE TABLE network_evidence_membership(
    incident_id TEXT NOT NULL,event_id TEXT NOT NULL,from_revision INTEGER NOT NULL,to_revision INTEGER,
    PRIMARY KEY(incident_id,event_id,from_revision)
);
CREATE INDEX network_evidence_current ON network_evidence_membership(incident_id,event_id)
    WHERE to_revision IS NULL;
CREATE TABLE network_notice_outbox(
    topic TEXT PRIMARY KEY,revision INTEGER NOT NULL,cancelled INTEGER NOT NULL,
    payload_json TEXT NOT NULL,pending INTEGER NOT NULL
);
"""


def canonical(value):
    return encode(value).decode("ascii")


def stamp(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat().replace("+00:00", "Z")


def event_stamp(microseconds):
    return (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=microseconds)).isoformat().replace("+00:00", "Z")


def meta(db, name, default=None):
    row = db.execute("SELECT value FROM network_analysis_meta WHERE name=?", (name,)).fetchone()
    return json.loads(row[0]) if row else default


def set_meta(db, name, value):
    db.execute("INSERT INTO network_analysis_meta VALUES(?,?) ON CONFLICT(name) "
               "DO UPDATE SET value=excluded.value", (name, canonical(value)))


def initialize(db):
    # executescript would implicitly commit a schema migration; keep every
    # statement inside the caller's explicit transaction instead.
    for statement in SCHEMA.split(";"):
        if statement.strip():
            db.execute(statement)
    set_meta(db, "producer_id", uuid.uuid4().hex)


def _buckets(monotonic_us):
    hour = monotonic_us // HOUR_US * HOUR_US
    result = {hour}
    if monotonic_us - hour <= WINDOW_US and hour:
        result.add(hour - HOUR_US)
    if monotonic_us - hour >= HOUR_US - WINDOW_US and hour + HOUR_US <= MAX_TIME_US:
        result.add(hour + HOUR_US)
    return sorted(result)


def _dirty(db, key, now):
    db.execute("INSERT INTO network_windows VALUES(?,?,?,?,?,?,1,'[]',?) "
               "ON CONFLICT(source_id,boot_id,source_profile_revision,src_ip,dst_ip,monotonic_hour_us) "
               "DO UPDATE SET dirty=1,updated_at=excluded.updated_at", (*key, now))


def _loss(db, row, reason, now):
    db.execute("INSERT OR IGNORE INTO network_analysis_losses VALUES(?,?,?,?,?)",
               (row["source_id"], row["event_id"], row["boot_id"],
                row["journal_monotonic_us"], reason))
    # No peer/profile is known once raw context expires before intake. The
    # conservative uncertainty is restricted to this source/boot/time window.
    for bucket in _buckets(row["journal_monotonic_us"]):
        db.execute("UPDATE network_windows SET dirty=1,updated_at=? WHERE source_id=? "
                   "AND boot_id=? AND monotonic_hour_us=?", (now, row["source_id"], row["boot_id"], bucket))


def _source_coverage(db, source_id, coverage, last=None):
    old = db.execute("SELECT coverage_json,last_report_json FROM network_analysis_sources "
                     "WHERE source_id=?", (source_id,)).fetchone()
    union = set(json.loads(old[0])) if old else set()
    union.update(coverage)
    previous = json.loads(old[1]) if old else {}
    db.execute("INSERT INTO network_analysis_sources VALUES(?,?,?) ON CONFLICT(source_id) "
               "DO UPDATE SET coverage_json=excluded.coverage_json,last_report_json=excluded.last_report_json",
               (source_id, canonical(sorted(union)), canonical(previous if last is None else last)))


def intake(db, now, limit):
    cursor, batch_cursor = meta(db, "cursor", 0), meta(db, "batch_cursor", 0)
    targets = meta(db, "intake_targets")
    if (targets is None or (cursor >= targets[0] and batch_cursor >= targets[1]
            and db.execute("SELECT 1 FROM network_windows WHERE dirty=1 LIMIT 1").fetchone() is None)):
        # A finite durable barrier prevents new deliveries from starving the
        # already accepted windows. Capture both streams in this transaction.
        targets = [db.execute("SELECT coalesce(max(rowid),0) FROM network_receipts").fetchone()[0],
                   db.execute("SELECT coalesce(max(seq),0) FROM network_batches").fetchone()[0]]
        set_meta(db, "intake_targets", targets)
    rows = db.execute("SELECT rowid AS receipt_seq,* FROM network_receipts WHERE rowid>? AND rowid<=? "
                      "ORDER BY rowid LIMIT ?", (cursor, targets[0], limit)).fetchall()
    accepted = missing = 0
    for row in rows:
        cursor = row["receipt_seq"]
        if row["kind"] != "event":
            _source_coverage(db, row["source_id"], {"rejected_records", row["code"]})
            continue
        accepted += 1
        raw = db.execute("SELECT event_json FROM network_events WHERE source_id=? AND event_id=?",
                         (row["source_id"], row["event_id"])).fetchone()
        if raw is None:
            missing += 1
            _loss(db, row, "raw_history_expired_before_analysis", now)
            _source_coverage(db, row["source_id"], {"raw_history_expired_before_analysis"})
            continue
        event = event_from_dict(json.loads(raw[0]))
        db.execute("INSERT INTO network_context VALUES(?,?,?,?,?,?,?,?,?)",
                   (cursor, event.source_id, event.boot_id, event.source_profile_revision,
                    event.src_ip, event.dst_ip, event.journal_monotonic_us, row["received_at_us"], raw[0]))
        _source_coverage(db, event.source_id, event.coverage)
        for hour in _buckets(event.journal_monotonic_us):
            _dirty(db, (event.source_id, event.boot_id, event.source_profile_revision,
                        event.src_ip, event.dst_ip, hour), now)
    set_meta(db, "cursor", cursor)
    set_meta(db, "analyzed_input_records", meta(db, "analyzed_input_records", 0) + accepted - missing)
    set_meta(db, "missing_raw_records", meta(db, "missing_raw_records", 0) + missing)
    # Reports on empty batches also matter, including drift before any event.
    batches = db.execute("SELECT seq,response_json FROM network_batches WHERE seq>? AND seq<=? ORDER BY seq LIMIT ?",
                         (batch_cursor, targets[1], min(limit, 20))).fetchall()
    for row in batches:
        report = json.loads(row["response_json"])
        coverage = set(report["reports"])
        if not report["caught_up"]:
            coverage.add("collection_backlog_observed")
        if any(result["code"] is not None for result in report["results"]):
            coverage.add("rejected_records")
        _source_coverage(db, report["source_id"], coverage,
                         {"batch_seq": row["seq"], "batch_id": report["batch_id"],
                          "reports": report["reports"], "caught_up": report["caught_up"],
                          "received_at_us": report["received_at_us"]})
        batch_cursor = row["seq"]
    set_meta(db, "batch_cursor", batch_cursor)
    return cursor >= targets[0] and batch_cursor >= targets[1]


def assessment(active, count):
    return {
        "version": VERSION, "score": 35 if active else 0, "priority": "P3" if active else None,
        "surfaced": bool(active),
        "reasons": [{"rule_id": RULE_ID, "points": 35, "reason": "入站 TCP 多端口探测模式",
                     "criteria": "同一来源、启动周期、配置和地址对，300 秒内观察到至少 10 个不同目标端口的拒绝相关 SYN 记录。"}]
                   if active else [],
        "evidence_count": count,
        "note": "仅表示已观察到的探测模式；记录数不是连接数，表面源地址不是身份，不证明漏洞利用或主机失陷。未执行阻断或 AI 调用。",
    }


def _save_case(db, key, coverage, events, findings, now, *, unavailable=False):
    identity = "NET-" + fingerprint([CORRELATION_VERSION, *key])[:32]
    old = db.execute("SELECT payload_json,revision FROM network_incidents WHERE incident_id=?",
                     (identity,)).fetchone()
    previous = json.loads(old["payload_json"]) if old else None
    if unavailable:
        if previous is None:
            return
        payload = {k: v for k, v in previous.items() if k not in ("revision", "updated_at")}
        payload.update(coverage=sorted(set(previous["coverage"]) | set(coverage)), stale=True)
        selected = None
    else:
        lookup = {event.event_id: event for event in events}
        selected, ports = {}, set()
        hour = key[-1]
        for finding in findings:
            if not any(hour <= lookup[eid].journal_monotonic_us < hour + HOUR_US
                       for eid in finding.evidence_ids):
                continue
            selected.update((eid, lookup[eid]) for eid in finding.evidence_ids)
            ports.update(finding.distinct_dst_ports)
            coverage.update(code for code in finding.coverage if code != "offline_context_only")
        if not selected and previous is None:
            return
        ordered = sorted(selected.values(), key=lambda event: (event.journal_monotonic_us, event.event_id))
        payload = {
            "incident_id": identity, "protocol": "network", **dict(zip(KEY_COLUMNS[:-1], key[:-1])),
            "window_start_monotonic_us": hour, "window_end_monotonic_us": min(MAX_TIME_US, hour + HOUR_US),
            "correlation_version": CORRELATION_VERSION, "coverage": sorted(coverage),
            "stale": False, "active": bool(selected),
            "title": "入站 TCP 多端口探测模式" if selected else "网络探测模式已撤回",
            "first_seen": event_stamp(ordered[0].journal_realtime_us) if ordered else previous["first_seen"],
            "last_seen": event_stamp(ordered[-1].journal_realtime_us) if ordered else previous["last_seen"],
            "rules": [{"rule_id": RULE_ID, "rule_version": RULE_VERSION, "window_seconds": 300,
                       "label": "入站 TCP 多端口探测模式", "evidence_count": len(selected),
                       "distinct_dst_ports": sorted(ports)}] if selected else [],
            "evidence_count": len(selected),
            "evidence_sha256": fingerprint([json.loads(_event_json(event)) for event in ordered]),
            "assessment": assessment(bool(selected), len(selected)),
        }
    old_content = {k: v for k, v in previous.items() if k not in ("revision", "updated_at")} if previous else None
    if old_content == payload:
        return
    revision = old["revision"] + 1 if old else 1
    payload.update(revision=revision, updated_at=stamp(now))
    encoded = canonical(payload)
    db.execute("INSERT INTO network_incidents(incident_id,source_id,boot_id,source_profile_revision,"
               "src_ip,dst_ip,monotonic_hour_us,revision,score,surfaced,active,stale,updated_at,payload_json) "
               "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(incident_id) DO UPDATE SET "
               "revision=excluded.revision,score=excluded.score,surfaced=excluded.surfaced,"
               "active=excluded.active,stale=excluded.stale,updated_at=excluded.updated_at,payload_json=excluded.payload_json",
               (identity, *key, revision, payload["assessment"]["score"], int(payload["assessment"]["surfaced"]),
                int(payload["active"]), int(payload["stale"]), now, encoded))
    db.execute("INSERT INTO network_incident_revisions VALUES(?,?,?)", (identity, revision, encoded))
    if selected is not None:
        current = {row[0] for row in db.execute("SELECT event_id FROM network_evidence_membership "
                                              "WHERE incident_id=? AND to_revision IS NULL", (identity,))}
        for event_id in current - selected.keys():
            db.execute("UPDATE network_evidence_membership SET to_revision=? WHERE incident_id=? "
                       "AND event_id=? AND to_revision IS NULL", (revision - 1, identity, event_id))
        for event_id in selected.keys() - current:
            event = selected[event_id]
            db.execute("INSERT OR IGNORE INTO network_evidence VALUES(?,?,?,?)",
                       (identity, event_id, event.journal_monotonic_us, _event_json(event)))
            db.execute("INSERT INTO network_evidence_membership VALUES(?,?,?,NULL)", (identity, event_id, revision))
    topic = "network:" + meta(db, "producer_id") + ":" + identity
    # Recent delivery is necessary, but old journal backlogs must not masquerade
    # as new alerts. Wall-time discontinuity remains visible as coverage.
    notify = (payload["active"] and payload["assessment"]["surfaced"] and not payload["stale"]
              and datetime.fromisoformat(payload["last_seen"].replace("Z", "+00:00")).timestamp() >= now - 86400
              and datetime.fromisoformat(payload["last_seen"].replace("Z", "+00:00")).timestamp() <= now + 300)
    db.execute("INSERT INTO network_notice_outbox VALUES(?,?,?,?,1) ON CONFLICT(topic) DO UPDATE SET "
               "revision=excluded.revision,cancelled=excluded.cancelled,payload_json=excluded.payload_json,pending=1",
               (topic, revision, int(not notify), encoded))


def _event_json(event):
    from .network_protocol import event_to_dict
    return canonical(event_to_dict(event))


def analyze_window(db, row, now):
    key = tuple(row[name] for name in KEY_COLUMNS)
    hour = key[-1]
    start, end = max(0, hour - WINDOW_US), min(MAX_TIME_US, hour + HOUR_US + WINDOW_US)
    coverage = {"observations_are_lower_bounds", "apparent_source_not_identity",
                "monotonic_hour_review_bucket"}
    losses = db.execute("SELECT DISTINCT reason FROM network_analysis_losses "
                        "WHERE source_id=? AND boot_id=? AND monotonic_us>=? AND monotonic_us<=?",
                        (key[0], key[1], start, end)).fetchall()
    coverage.update(loss[0] for loss in losses)
    events, size = [], 0
    if not losses:
        records = db.execute("SELECT event_json FROM network_context WHERE source_id=? AND boot_id=? "
                             "AND source_profile_revision=? AND src_ip=? AND dst_ip=? "
                             "AND monotonic_us>=? AND monotonic_us<=? ORDER BY monotonic_us,receipt_seq LIMIT ?",
                             (*key[:-1], start, end, MAX_CONTEXT_RECORDS + 1))
        for record in records:
            size += len(record[0].encode("ascii"))
            if len(events) >= MAX_CONTEXT_RECORDS or size > MAX_CONTEXT_BYTES:
                coverage.add("context_limit")
                break
            events.append(event_from_dict(json.loads(record[0])))
    unavailable = bool(losses) or "context_limit" in coverage
    report = None if unavailable else detect_network(events)
    if report:
        coverage.update(code for code in report.coverage if code != "offline_context_only")
    _save_case(db, key, coverage, events, report.findings if report else (), now, unavailable=unavailable)
    db.execute("UPDATE network_windows SET dirty=0,coverage_json=?,updated_at=? WHERE " + KEY_WHERE,
               (canonical(sorted(coverage)), now, *key))


def _prune_context(db, now, retention_days, limit=200):
    cutoff = int(now * 1_000_000) - retention_days * 86_400_000_000
    rows = db.execute("SELECT * FROM network_context WHERE received_at_us<? "
                      "ORDER BY received_at_us,receipt_seq LIMIT ?", (cutoff, limit)).fetchall()
    for row in rows:
        event = json.loads(row["event_json"])
        _loss(db, event, "expired_context", now)
        db.execute("DELETE FROM network_context WHERE receipt_seq=?", (row["receipt_seq"],))
    return len(rows) == limit


def process(store, now, *, intake_limit=200, window_limit=5):
    if (type(intake_limit) is not int or not 1 <= intake_limit <= 1000
            or type(window_limit) is not int or not 1 <= window_limit <= 20
            or type(now) not in (int, float) or not math.isfinite(now) or not 0 <= now < 253402300799):
        raise ValueError("invalid_network_analysis_bounds")
    with store.write_connection() as db:
        caught_up = intake(db, now, intake_limit)
        retention_pending = _prune_context(db, now, store.retention_days)
        set_meta(db, "last_run", stamp(now))
        set_meta(db, "last_error", None)
    processed = 0
    # Partial snapshot intake must not momentarily clear or lower a known case.
    # Later accepted deliveries remain pending while this finite cycle drains.
    if caught_up:
        for _ in range(window_limit):
            with store.write_connection() as db:
                # Another process may have finished this cycle and started a
                # new partial intake since our previous window transaction.
                targets = meta(db, "intake_targets", [0, 0])
                if meta(db, "cursor", 0) < targets[0] or meta(db, "batch_cursor", 0) < targets[1]:
                    break
                row = db.execute("SELECT * FROM network_windows WHERE dirty=1 ORDER BY updated_at LIMIT 1").fetchone()
                if row is None:
                    break
                analyze_window(db, row, now)
            processed += 1
    with store.connection() as db:
        db.execute("BEGIN")
        pending = (db.execute("SELECT 1 FROM network_windows WHERE dirty=1 LIMIT 1").fetchone() is not None
                   or db.execute("SELECT 1 FROM network_receipts WHERE rowid>? LIMIT 1",
                                 (meta(db, "cursor", 0),)).fetchone() is not None
                   or db.execute("SELECT 1 FROM network_batches WHERE seq>? LIMIT 1",
                                 (meta(db, "batch_cursor", 0),)).fetchone() is not None)
    return {"caught_up": caught_up and not pending and not retention_pending, "windows_processed": processed}


def status(db):
    cursor, batch_cursor = meta(db, "cursor", 0), meta(db, "batch_cursor", 0)
    pending = (db.execute("SELECT 1 FROM network_receipts WHERE rowid>? LIMIT 1", (cursor,)).fetchone() is not None
               or db.execute("SELECT 1 FROM network_batches WHERE seq>? LIMIT 1", (batch_cursor,)).fetchone() is not None
               or db.execute("SELECT 1 FROM network_windows WHERE dirty=1 LIMIT 1").fetchone() is not None)
    issues = []
    for row in db.execute("SELECT * FROM network_windows WHERE coverage_json LIKE '%context_limit%' "
                          "OR coverage_json LIKE '%expired_context%' "
                          "OR coverage_json LIKE '%raw_history_expired_before_analysis%' "
                          "ORDER BY updated_at DESC LIMIT 50"):
        issues.append({**{name: row[name] for name in KEY_COLUMNS}, "coverage": json.loads(row["coverage_json"])})
    sources = [{"source_id": row["source_id"], "coverage": json.loads(row["coverage_json"]),
                "last_report": json.loads(row["last_report_json"])}
               for row in db.execute("SELECT * FROM network_analysis_sources ORDER BY source_id")]
    return {"version": VERSION, "correlation_version": CORRELATION_VERSION,
            "last_run": meta(db, "last_run"), "last_error": meta(db, "last_error"),
            "pending": pending, "analyzed_input_records": meta(db, "analyzed_input_records", 0),
            "missing_raw_records": meta(db, "missing_raw_records", 0),
            "coverage_issues": issues, "source_coverage": sources}


def list_cases(db, *, source_id=None, focus="all", page=1, limit=50):
    if (focus not in {"all", "attention", "low", "stale", "retracted"}
            or type(page) is not int or not 1 <= page <= 1_000_000
            or type(limit) is not int or not 1 <= limit <= 200):
        raise ValueError("invalid_network_incident_page")
    where, params = ["1=1"], []
    if source_id is not None:
        where.append("source_id=?")
        params.append(source_id)
    if focus == "attention":
        where.append("surfaced=1 AND active=1")
    elif focus == "low":
        where.append("surfaced=0 AND active=1")
    elif focus == "stale":
        where.append("stale=1")
    elif focus == "retracted":
        where.append("active=0")
    clause = " AND ".join(where)
    total = db.execute("SELECT count(*) FROM network_incidents WHERE " + clause, params).fetchone()[0]
    pages = max(1, (total + limit - 1) // limit)
    page = min(page, pages)
    rows = db.execute("SELECT payload_json FROM network_incidents WHERE " + clause +
                      " ORDER BY seq DESC LIMIT ? OFFSET ?", (*params, limit, (page - 1) * limit)).fetchall()
    return {"items": [json.loads(row[0]) for row in rows], "page": page, "total_pages": pages, "total": total}


def get_case(db, identity, revision=None):
    if revision is not None and (type(revision) is not int or revision < 1 or revision > MAX_TIME_US):
        raise ValueError("invalid_network_revision")
    if revision is None:
        row = db.execute("SELECT payload_json FROM network_incidents WHERE incident_id=?", (identity,)).fetchone()
    else:
        row = db.execute("SELECT payload_json FROM network_incident_revisions WHERE incident_id=? AND revision=?",
                         (identity, revision)).fetchone()
    return json.loads(row[0]) if row else None


def evidence(db, identity, *, revision=None, page=1, limit=50):
    if (type(page) is not int or not 1 <= page <= 1_000_000
            or type(limit) is not int or not 1 <= limit <= 200):
        raise ValueError("invalid_network_evidence_page")
    incident = get_case(db, identity, revision)
    if incident is None:
        return None
    revision = incident["revision"]
    clause = "m.incident_id=? AND m.from_revision<=? AND (m.to_revision IS NULL OR m.to_revision>=?)"
    params = (identity, revision, revision)
    total = db.execute("SELECT count(*) FROM network_evidence_membership m WHERE " + clause, params).fetchone()[0]
    pages = max(1, (total + limit - 1) // limit)
    page = min(page, pages)
    rows = db.execute("SELECT e.event_json FROM network_evidence_membership m JOIN network_evidence e "
                      "ON e.incident_id=m.incident_id AND e.event_id=m.event_id WHERE " + clause +
                      " ORDER BY e.monotonic_us,e.event_id LIMIT ? OFFSET ?",
                      (*params, limit, (page - 1) * limit)).fetchall()
    return {"incident_id": identity, "revision": revision, "items": [json.loads(row[0]) for row in rows],
            "page": page, "total_pages": pages, "total": total}
