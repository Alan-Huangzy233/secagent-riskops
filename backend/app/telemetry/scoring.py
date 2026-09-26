"""Durable prioritisation over the pilot's existing deduplicated evidence.

No trust discount, suppression, model call or operator-state transition. Scores
are a derived projection; old releases can ignore the additive table safely.
"""
from __future__ import annotations

import json
import sqlite3

from ..reduction.score import SURFACE_THRESHOLD, assess_summary
from .sshd_parse import FAILURE_KINDS

VERSION = "ssh-evidence-v1"
SCHEMA = """
CREATE TABLE IF NOT EXISTS incident_scores (
    incident_id TEXT PRIMARY KEY REFERENCES incidents(incident_id),
    version TEXT NOT NULL, score INTEGER NOT NULL,
    priority TEXT, surfaced INTEGER NOT NULL,
    reasons_json TEXT NOT NULL, evidence_count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS incident_scores_order ON incident_scores(score DESC, incident_id);
-- Invalidate even when an older release edits evidence after a code rollback.
-- No evidence-count heuristic can detect an in-place parser correction.
CREATE TRIGGER IF NOT EXISTS score_evidence_insert AFTER INSERT ON incident_evidence BEGIN
    DELETE FROM incident_scores WHERE incident_id=NEW.incident_id;
END;
CREATE TRIGGER IF NOT EXISTS score_evidence_update AFTER UPDATE ON incident_evidence BEGIN
    DELETE FROM incident_scores WHERE incident_id IN (OLD.incident_id,NEW.incident_id);
END;
CREATE TRIGGER IF NOT EXISTS score_evidence_delete AFTER DELETE ON incident_evidence BEGIN
    DELETE FROM incident_scores WHERE incident_id=OLD.incident_id;
END;

"""


def refresh(db: sqlite3.Connection, incident_id: str) -> None:
    """Aggregate in SQLite; Python memory does not grow with evidence volume."""
    failures = tuple(sorted(FAILURE_KINDS | {"ssh_failure"}))
    marks = ",".join("?" for _ in failures)
    row = db.execute(f"""WITH evidence AS (
        SELECT source_id,event_ts,
            json_extract(snapshot_json,'$.event_type') AS kind,
            json_extract(snapshot_json,'$.ssh_user') AS username,
            coalesce(json_extract(snapshot_json,'$.message'),'') AS message
        FROM incident_evidence WHERE incident_id=?
    ), accounts AS (
        SELECT username,
            max(kind='auth_failure') AS attempted,
            max(kind='invalid_user' OR instr(lower(message),'invalid user ')>0
                OR instr(lower(message),'illegal user ')>0) AS invalid
        FROM evidence WHERE username IS NOT NULL AND username!='' AND username!='root'
        GROUP BY username
    ) SELECT count(*),coalesce(sum(kind IN ({marks})),0),
        coalesce(sum(kind IN ('auth_success','ssh_success')),0),
        count(DISTINCT source_id),coalesce(max(event_ts)-min(event_ts),0),
        (SELECT count(*) FROM accounts WHERE attempted AND NOT invalid)
        FROM evidence""", (incident_id, *failures)).fetchone()
    if not row[0]:
        db.execute("DELETE FROM incident_scores WHERE incident_id=?", (incident_id,))
        return
    result = assess_summary(failure_count=row[1], success_count=row[2], host_count=row[3],
                            span=row[4], existing_accounts=row[5])
    db.execute("""INSERT INTO incident_scores VALUES(?,?,?,?,?,?,?)
        ON CONFLICT(incident_id) DO UPDATE SET version=excluded.version,score=excluded.score,
        priority=excluded.priority,surfaced=excluded.surfaced,reasons_json=excluded.reasons_json,evidence_count=excluded.evidence_count""",
        (incident_id, VERSION, result.score, result.priority, int(result.surfaced),
         json.dumps(result.reasons, ensure_ascii=False), row[0]))


def read(db: sqlite3.Connection, incident_id: str) -> dict:
    row = db.execute("""SELECT incident_scores.* FROM incident_scores JOIN incident_details USING(incident_id)
        WHERE incident_id=? AND version=? AND incident_scores.evidence_count=incident_details.evidence_count""",
                     (incident_id, VERSION)).fetchone()
    return {"version": VERSION, "status": "scored" if row else "unscored",
            "score": row["score"] if row else None,
            "priority": row["priority"] if row else None,
            "surfaced": bool(row["surfaced"]) if row else None,
            "threshold": SURFACE_THRESHOLD,
            "reasons": json.loads(row["reasons_json"]) if row else [],
            "known_source_discount": False}
