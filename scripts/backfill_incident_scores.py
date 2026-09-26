#!/usr/bin/env python3
"""Inspect missing scores, or fill one bounded batch of derived scores.

No logs, receipts, evidence or operator decisions are rewritten. Run repeatedly
with --apply until scored=0; unscored rows remain visible in the console. This
is deliberately not an API endpoint or an automatic startup migration.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app.telemetry.scoring import VERSION  # noqa: E402
from app.telemetry.store import TelemetryStore  # noqa: E402


def run(database: Path, *, apply: bool = False, limit: int = 50) -> dict:
    if not database.is_absolute() or not database.is_file():
        raise ValueError("database must be an absolute path to an existing file")
    TelemetryStore._page(limit, 0)
    db = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        db.execute("BEGIN")
        if not db.execute("SELECT 1 FROM maintenance WHERE name='detection_metadata_v1'").fetchone():
            raise ValueError("upgrade detection metadata before scoring")
        exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='incident_scores'").fetchone()
        total = db.execute("SELECT count(*) FROM incidents WHERE status!='merged'").fetchone()[0]
        scored = db.execute("""SELECT count(*) FROM incidents i JOIN incident_details d USING(incident_id)
            JOIN incident_scores s USING(incident_id) WHERE i.status!='merged'
            AND s.version=? AND s.evidence_count=d.evidence_count""", (VERSION,)).fetchone()[0] if exists else 0
        no_evidence = db.execute("""SELECT count(*) FROM incidents i WHERE status!='merged'
            AND NOT EXISTS (SELECT 1 FROM incident_evidence e WHERE e.incident_id=i.incident_id)""").fetchone()[0]
    finally:
        db.close()
    result = {"mode": "apply" if apply else "dry_run", "total": total,
              "already_scored": scored, "unscored": total - scored, "without_evidence": no_evidence}
    if apply:
        result["batch"] = TelemetryStore(database).backfill_scores(limit)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--apply", action="store_true", help="write at most --limit derived scores")
    args = parser.parse_args()
    try:
        result = run(args.database, apply=args.apply, limit=args.limit)
    except Exception:
        raise SystemExit("score backfill failed; check database path, schema and limit (1-200)") from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
