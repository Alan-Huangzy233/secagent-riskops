"""The safety demo: what the system refuses, what it changes, and the record it keeps.

    python -m app.safety_demo                  # what `make safety` runs
    python -m app.safety_demo --export <timeline.jsonl>
    python -m app.safety_demo --check examples/safety-demo/audit-timeline.jsonl

It starts from two incidents Claude escalated in the seven-day evaluation: a
password guessed for ``jonas`` on bastion-01 and for ``pavel`` on web-02. The
recorded calls are replayed, so there is no key and no cost, and each dossier
must hash to its entry in the recording. A fixed playbook turns each into a
``harden_ssh_access`` plan, and then:

1. Blank and ambiguous scopes are refused with a reason code, and so is a
   plan with no approval or one edited after it was approved.
2. The approved plan for bastion-01 runs on a lab copy of the host, is checked
   by re-reading the host, and the before/after settings and diff are shown.
3. On web-02 the same change is overridden by cloud-init's drop-in, so the
   check fails and the change is rolled back without a person; the rollback
   is checked too.
4. The run's audit chain is exported as one timeline and verified from the
   file alone; a copy with one altered event is caught.

Lab copies live in a temporary directory; nothing outside it is touched. The
clock is a fixed stepping clock, so the exported timeline reproduces byte for
byte. One operator approves; a second-approver rule is planned, not built.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile

from . import audit_timeline
from .agents import model_triage
from .authorization import make_scope
from .core.clock import SteppingClock
from .pipeline import remediation
from .policy.engine import scope_problems
from .schemas.enums import AutonomyLevel, FlowStatus
from .services import Services
from .tools.harden_ssh import HardenSshExecutor

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "examples" / "safety-demo"
TAPE = ROOT / "docs" / "eval" / "triage-tape-synthetic-7d.jsonl"
INCIDENTS = ("INC-A0004561", "INC-A0003598")
OPERATOR = "security-operator"
START = datetime(2026, 11, 2, 9, 0, tzinfo=timezone.utc)
WINDOW = {"valid_from": "2026-11-01T00:00:00Z", "valid_until": "2026-11-30T23:59:59Z"}


def lab_scope(**overrides):
    fields = dict(autonomy_level=AutonomyLevel.EXECUTE_AFTER_APPROVAL, allowed_actors=(OPERATOR,),
                  target_allowlist=("bastion-01", "web-02"), **WINDOW)
    fields.update(overrides)
    return make_scope(fields.pop("scope_id", "SCOPE-LAB"), **fields)


def refused_scopes() -> list[tuple[str, object]]:
    """Scopes a person might write by mistake. Every one must deny."""
    return [
        ("blank, marked approved", make_scope("SCOPE-BLANK", autonomy_level=AutonomyLevel.EXECUTE_AFTER_APPROVAL)),
        ("target '*'", lab_scope(scope_id="SCOPE-STAR", target_allowlist=("*",))),
        ("target '*.internal'", lab_scope(scope_id="SCOPE-ZONE", target_allowlist=("*.internal",))),
        ("target '10.0.0.0/8'", lab_scope(scope_id="SCOPE-RANGE", target_allowlist=("10.0.0.0/8",))),
        ("until 'end of November'", lab_scope(scope_id="SCOPE-WORDS", valid_until="end of November")),
        ("not approved", lab_scope(scope_id="SCOPE-DRAFT", approved=False)),
    ]


def _say(out, text: str = "") -> None:
    print(text, file=out, flush=True)


def _states(out, states: dict[str, dict], columns: tuple[str, ...]) -> None:
    _say(out, f"      {'setting':30}" + "".join(f"{column:>19}" for column in columns))
    for setting in states[columns[0]]:
        values = [states[column][setting]["value"] for column in columns]
        _say(out, f"      {setting:30}" + "".join(f"{value:>19}" for value in values))


def _recorded_call(tape: model_triage.RecordedTriage, incident_id: str) -> tuple[dict, model_triage.TriageCall]:
    case = json.loads((FIXTURES / "incidents" / f"{incident_id}.json").read_text(encoding="utf-8"))
    call = tape.lookup(case)
    if call is None:
        raise SystemExit(f"{incident_id}: the dossier does not hash to any call in {TAPE.name}")
    return case, call


def run(out=sys.stdout, export: Path | None = None) -> tuple[int, list[dict]]:
    svc = Services.create(clock=SteppingClock(START))
    rt = svc.runtime
    tape = model_triage.RecordedTriage(TAPE)
    checks: list[tuple[str, bool]] = []
    _say(out, "SecAgent RiskOps — safety behaviours on two incidents Claude escalated (recorded, replayed)\n")

    flow = rt.start_flow("remediation", "Respond to two guessed passwords")
    plans = {}
    for incident_id in INCIDENTS:
        case, call = _recorded_call(tape, incident_id)
        task = rt.add_task(flow, f"Respond to {incident_id}")
        step = rt.add_step(flow, task, "model_triage", "agent")
        svc.audit.record("agent.run", "agent.model_triage", flow_id=flow.flow_id, subject_ref=incident_id,
                         payload={"model": call.model, "prompt_sha256": call.prompt_sha256, "verdict": call.verdict,
                                  "confidence": call.confidence, "evidence_ids": list(call.evidence_ids),
                                  "rationale": call.rationale, "replayed_from": f"docs/eval/{TAPE.name}"})
        actions = remediation.playbook(case, call.verdict)
        rt.tool_call(flow, step, "playbook.select", input={"incident_id": incident_id, "verdict": call.verdict},
                     output={"actions": [[action, host] for action, host, _ in actions]})
        for action, host, evidence in actions:
            plans[host] = remediation.draft_plan(svc, action, host, created_from=incident_id, evidence_ids=evidence)
        login = case["successful_logins"][0]
        _say(out, f"  {incident_id}  {call.model}: {call.verdict.upper()} ({call.confidence}) — "
                  f"{login['account']} on {login['host']} after {case['failed_records']} failures")
        _say(out, f"      playbook -> {', '.join(f'{a} on {h}' for a, h, _ in actions)}")

    bastion, web = plans["bastion-01"], plans["web-02"]
    _say(out, "\n1. Blank or ambiguous scope fails closed")
    for label, scope in refused_scopes():
        decision, _ = remediation.evaluate_execution(svc, bastion, scope, OPERATOR)
        problems = scope_problems(scope)
        why = problems[0] if problems else decision.message
        _say(out, f"   {label:26} {decision.effect.value.upper():5} {decision.reason_code:20} {why}")
        checks.append((f"scope {label} denied", decision.effect.value == "deny"))
    scope = lab_scope()
    decision, _ = remediation.evaluate_execution(svc, bastion, scope, OPERATOR)
    _say(out, f"   {'valid scope, no approval':26} {decision.effect.value.upper():5} {decision.reason_code:20} "
              "a medium-risk action needs a recorded approval")
    checks.append(("no approval denied", decision.reason_code == "APPROVAL_REQUIRED"))
    remediation.record_approval(svc, bastion, scope, OPERATOR)
    edited = bastion.model_copy(update={"parameters": {**bastion.parameters, "enforce_key_auth": False}})
    decision, _ = remediation.evaluate_execution(svc, edited, scope, OPERATOR)
    _say(out, f"   {'plan edited after approval':26} {decision.effect.value.upper():5} {decision.reason_code:20} "
              "the approval is bound to the plan's hash")
    checks.append(("edited plan denied", decision.reason_code == "APPROVAL_REQUIRED"))

    with tempfile.TemporaryDirectory(prefix="riskops-lab-") as scratch:
        lab = Path(scratch)
        for host in plans:
            shutil.copytree(FIXTURES / "lab" / host, lab / host)

        _say(out, f"\n2. Approved by {OPERATOR}, executed on a lab copy of bastion-01, verified from the host")
        done = remediation.execute_plan(svc, bastion, scope, OPERATOR, HardenSshExecutor(lab / "bastion-01", "bastion-01"))
        _say(out, f"   policy {done.decision.effect.value.upper()} {done.decision.reason_code} "
                  f"(approval {done.approval.approval_id} by {done.approval.approver})")
        _states(out, done.states, ("before", "after"))
        for line in done.change.diff:
            _say(out, f"      {line}")
        _say(out, f"   verification {'PASS' if done.verification.ok else 'FAIL'}: every setting read back from the "
                  f"host as planned -> plan {done.plan.status.value}")
        checks.append(("bastion-01 verified", done.plan.status.value == "verified"))

        _say(out, "\n3. The same change on web-02: verification fails, the change is rolled back automatically")
        remediation.record_approval(svc, web, scope, OPERATOR)
        failed = remediation.execute_plan(svc, web, scope, OPERATOR, HardenSshExecutor(lab / "web-02", "web-02"))
        for check in failed.verification.checks:
            if not check.ok:
                _say(out, f"   {check.setting} should be {check.expected} but sshd would use {check.effective} "
                          f"from {check.source} (read before the edited line)")
        _states(out, failed.states, ("before", "after", "restored"))
        _say(out, f"   rollback {'PASS' if failed.rollback['ok'] else 'FAIL'}: file byte-identical to before "
                  f"({failed.rollback['restored_sha256'][:19]}…), settings as before -> plan {failed.plan.status.value}")
        checks.append(("web-02 rolled back and verified", failed.plan.status.value == "rolled_back"
                       and failed.rollback["ok"]))

    rt.set_flow_status(flow, FlowStatus.COMPLETED)
    rows = [event.model_dump() for event in svc.audit.events()]
    _say(out, f"\n4. Audit trail: {len(rows)} hash-chained events, one timeline")
    for line in audit_timeline.render(rows, highlight=out.isatty() if hasattr(out, "isatty") else False):
        _say(out, f"   {line}")
    ok, message = audit_timeline.verify(rows)
    _say(out, f"   chain {'intact' if ok else 'BROKEN'}: {message}")
    checks.append(("audit chain intact", ok))
    forged = [dict(row) for row in rows]
    target = next(i for i, row in enumerate(forged) if row["event_type"] == "approval.recorded")
    forged[target] = {**forged[target], "actor": "someone-else"}
    caught, detail = audit_timeline.verify(forged)
    _say(out, f"   same trail with the approver's name changed: {detail}")
    checks.append(("altered approval caught", not caught))

    if export is not None:
        export.parent.mkdir(parents=True, exist_ok=True)
        audit_timeline.export(rows, export)
        _say(out, f"   exported to {export}; check it with: python -m app.audit_timeline verify {export}")
    failures = [label for label, passed in checks if not passed]
    _say(out, "\n" + ("all safety checks passed" if not failures else f"FAILED: {', '.join(failures)}"))
    return (1 if failures else 0), rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--export", type=Path, help="write the audit timeline (JSON lines) here")
    parser.add_argument("--check", type=Path, help="fail unless the run reproduces this exported timeline exactly")
    args = parser.parse_args(argv)
    if args.check is None:
        return run(export=args.export)[0]
    with tempfile.TemporaryDirectory() as scratch:
        produced = Path(scratch) / "timeline.jsonl"
        status, _ = run(out=io.StringIO(), export=produced)
        same = produced.read_bytes() == args.check.read_bytes()
    print(f"timeline {'reproduces' if same else 'DIFFERS FROM'} {args.check}")
    return status or (0 if same else 1)


if __name__ == "__main__":
    raise SystemExit(main())
