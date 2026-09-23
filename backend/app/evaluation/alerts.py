"""Turn raw sshd log records into the alert stream the evaluation reduces.

This is the log-to-alert conversion layer, and it is part of the measured
system: changing the schedule or the rules changes every number downstream.
It reuses the production code on purpose, the same ``parse_sshd`` grammar and
the same ``detect_matches`` rules that run on the live pilot.

The rules are evaluated the way a SIEM runs a scheduled correlation search:
every ``TICK_SECONDS`` over the rules' longest lookback, raising one alert for
each rule match that contains at least one log record that arrived since the
previous run. An attack that keeps producing records therefore keeps raising
alerts, which is the duplication the reduction pipeline exists to remove.
Labels are never read here.
"""
from __future__ import annotations

import argparse
from bisect import bisect_left, bisect_right
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Iterable

from ..telemetry.detection import MAX_WINDOW_SECONDS, detect_matches
from ..telemetry.sshd_parse import FAILURE_KINDS, parse_sshd

TICK_SECONDS = 300
SCHEDULE_VERSION = 1
RELEVANT_KINDS = FAILURE_KINDS | {"auth_success"}


def _epoch(stamp: str) -> float:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()


def _iso(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def normalize(raw_events: Iterable[dict]) -> list[dict]:
    """Parse each message and keep the records the rules can use, oldest first."""
    records = []
    for raw in raw_events:
        parsed = parse_sshd(raw["message"])
        if parsed["event_kind"] not in RELEVANT_KINDS or parsed["peer_ip"] is None:
            continue
        records.append({"source_id": raw["host"], "event_id": raw["event_id"], "event_ts": _epoch(raw["ts"]),
                        "event_type": parsed["event_kind"], "src_ip": parsed["peer_ip"],
                        "ssh_user": parsed["username"]})
    records.sort(key=lambda row: (row["event_ts"], row["source_id"], row["event_id"]))
    return records


def scheduled_alerts(records: list[dict], tick: int = TICK_SECONDS) -> list[dict]:
    """Run the rules on a fixed schedule and return every alert they raise."""
    if not records:
        return []
    times = [row["event_ts"] for row in records]
    first = (int(times[0]) // tick + 1) * tick
    alerts: list[dict] = []
    for at in range(first, int(times[-1]) + 2 * tick, tick):
        new_from, new_to = bisect_right(times, at - tick), bisect_right(times, at)
        if new_from == new_to:
            continue
        window = records[bisect_left(times, at - MAX_WINDOW_SECONDS):new_to]
        triggers = {(row["source_id"], row["event_id"]) for row in records[new_from:new_to]}
        fired = []
        for match in detect_matches(window, triggers, include_burst=True):
            evidence = sorted(match.evidence, key=lambda row: (row["event_ts"], row["source_id"], row["event_id"]))
            fired.append({
                "rule_id": match.rule_id, "rule_version": match.rule_version,
                "window_seconds": match.window_seconds, "fired_at": _iso(at),
                "src_ip": evidence[0]["src_ip"],
                "hosts": sorted({row["source_id"] for row in evidence}),
                "users": sorted({row["ssh_user"] for row in evidence if row["ssh_user"]}),
                "first_ts": _iso(evidence[0]["event_ts"]), "last_ts": _iso(evidence[-1]["event_ts"]),
                "evidence": [row["event_id"] for row in evidence],
            })
        fired.sort(key=lambda alert: (alert["rule_id"], alert["src_ip"], alert["hosts"], alert["evidence"][0]))
        alerts.extend(fired)
    for number, alert in enumerate(alerts, start=1):
        alert["alert_id"] = f"A{number:07d}"
    return alerts


def convert(data: Path, out: Path) -> dict:
    """Read ``events.jsonl`` from a dataset directory and write ``alerts.jsonl``."""
    with (data / "events.jsonl").open(encoding="utf-8") as handle:
        records = normalize(json.loads(line) for line in handle)
    alerts = scheduled_alerts(records)
    payload = b"".join(json.dumps(alert, sort_keys=True, separators=(",", ":")).encode() + b"\n"
                       for alert in alerts)
    out.write_bytes(payload)
    by_rule: dict[str, int] = {}
    for alert in alerts:
        by_rule[alert["rule_id"]] = by_rule.get(alert["rule_id"], 0) + 1
    return {"tick_seconds": TICK_SECONDS, "schedule_version": SCHEDULE_VERSION, "rule_records": len(records),
            "alerts": len(alerts), "alerts_by_rule": dict(sorted(by_rule.items())),
            "sha256": hashlib.sha256(payload).hexdigest()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", required=True, type=Path, help="dataset directory holding events.jsonl")
    parser.add_argument("--out", required=True, type=Path, help="alerts.jsonl to write")
    args = parser.parse_args(argv)
    print(json.dumps(convert(args.data, args.out), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
