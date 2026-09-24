"""Export a run's audit chain as one timeline, and check it from the file alone.

    python -m app.audit_timeline verify <timeline.jsonl>
    python -m app.audit_timeline show <timeline.jsonl>

The export is the run's hash-chained audit events, one JSON object per line in
chain order: agent calls, tool calls, plans, policy decisions, approvals,
executions, verifications and rollbacks on one line of time. ``verify``
recomputes every entry hash and link from the file, without the program that
wrote it, and names the first event that does not hold.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .core.hashing import canonical_json
from .storage.audit_log import first_break

SEGMENTS = {
    "flow.started": "FLOW", "flow.status_changed": "FLOW", "task.started": "FLOW", "step.ran": "FLOW",
    "agent.run": "AGENT", "tool.called": "TOOL", "plan.created": "PLAN", "policy.decision": "POLICY",
    "approval.recorded": "APPROVAL", "execution.refused": "EXECUTE", "execution.applied": "EXECUTE",
    "execution.verified": "VERIFY", "rollback.applied": "ROLLBACK", "rollback.verified": "VERIFY",
}


def export(events, path: Path) -> None:
    """Write audit events (models or dicts) as canonical JSON lines, in chain order."""
    rows = [event if isinstance(event, dict) else event.model_dump() for event in events]
    path.write_text("".join(canonical_json(row) + "\n" for row in rows), encoding="utf-8")


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def verify(rows: list[dict]) -> tuple[bool, str]:
    broken = first_break(rows)
    if broken is not None:
        row = rows[broken]
        return False, (f"chain broken at event {broken + 1} of {len(rows)} ({row.get('event_id')}, "
                       f"{row.get('event_type')}): its hash or its link to the event before does not hold")
    head = rows[-1]["entry_hash"] if rows else "empty"
    return True, f"{len(rows)} events, every hash and link recomputed from the file; head {head[:19]}…"


def _short(value: str | None) -> str:
    return value[:19] + "…" if value and value.startswith("sha256:") else str(value)


def describe(row: dict) -> str:
    """One line for one event, from its payload alone."""
    kind, p, subject = row["event_type"], row["payload"], row.get("subject_ref") or ""
    if kind == "flow.started":
        return f"{row['flow_id']} started: {p['title']}"
    if kind == "flow.status_changed":
        return f"{row['flow_id']} is now {p['status']}"
    if kind == "task.started":
        return f"{subject} {p['name']}"
    if kind == "step.ran":
        return f"{subject} {p['name']} ({p['kind']})"
    if kind == "agent.run":
        if "model" in p:
            return (f"{subject}: {p['model']} says {p['verdict'].upper()} ({p['confidence']}), "
                    f"prompt {p['prompt_sha256'][:12]}…, replayed from the recording")
        return f"{', '.join(p['input_refs'])}: {p['disposition']} ({p['confidence']})"
    if kind == "tool.called":
        return f"{subject} {p['tool']} [{p['status']}]"
    if kind == "plan.created":
        return (f"{subject} {p['action_type']} on {p['target']} ({p['risk_level']} risk) "
                f"from {p['created_from']}, plan {_short(p['plan_hash'])}")
    if kind == "policy.decision":
        line = f"{subject} {p['effect'].upper()} {p['reason_code']}"
        if "scope_id" in p:
            line += f" under {p['scope_id']}"
        if p.get("plan_hash"):
            line += f", plan {_short(p['plan_hash'])}"
        return line + (f", approval {p['approval_id']}" if p.get("approval_id") else "")
    if kind == "approval.recorded":
        return f"{subject} {p['decision'].upper()} by {p['approver']}, bound to plan {_short(p['plan_hash'])}"
    if kind == "execution.refused":
        return f"{subject} refused on {p['target']}: {p['reason']}"
    if kind == "execution.applied":
        return (f"{subject} {p['file']} on {p['target']}: {len(p['edits'])} edits, "
                f"{_short(p['before_sha256'])} -> {_short(p['after_sha256'])}")
    if kind == "execution.verified":
        failed = [c for c in p["checks"] if not c["ok"]]
        if p["ok"]:
            return f"{subject} PASS on {p['target']}: {len(p['checks'])} settings read back as planned"
        reasons = "; ".join(f"{c['setting']} is {c['effective']} from {c['source']}" for c in failed)
        return f"{subject} FAIL on {p['target']}: {reasons or '; '.join(p['problems'])}"
    if kind == "rollback.applied":
        return f"{subject} restored {p['backup']} on {p['target']} ({p['reason']})"
    if kind == "rollback.verified":
        return (f"{subject} {'PASS' if p['ok'] else 'FAIL'} on {p['target']}: file identical to before "
                f"{'yes' if p['file_matches_before'] else 'NO'}, settings as before "
                f"{'yes' if p['state_matches_before'] else 'NO'}")
    return f"{subject} {json.dumps(p, sort_keys=True)[:100]}"


def render(rows: list[dict], *, highlight: bool = False) -> list[str]:
    lines = []
    for number, row in enumerate(rows, start=1):
        segment = SEGMENTS.get(row["event_type"], row["event_type"])
        line = f"{number:>3}  {row['recorded_at'][11:19]}  {segment:<8}  {row['actor']:<26}  {describe(row)}"
        if highlight and segment == "APPROVAL":
            line = f"\033[1;33m{line}\033[0m"
        lines.append(line)
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("verify", "show"))
    parser.add_argument("timeline", type=Path)
    args = parser.parse_args(argv)
    rows = load(args.timeline)
    ok, message = verify(rows)
    if args.command == "show":
        print("\n".join(render(rows, highlight=sys.stdout.isatty())))
    print(("chain intact: " if ok else "") + message)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
