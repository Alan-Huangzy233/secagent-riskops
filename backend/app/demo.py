"""Runnable end-to-end demo of the walking skeleton.

    python -m app.demo        # from backend/, or PYTHONPATH=backend

Runs the flow on the bundled sample alerts, prints a readable summary, verifies
the audit chain, then replays from retained evidence and confirms the replay
reproduces the original objects. Exits non-zero if any invariant fails, so it
doubles as a CI smoke test.
"""
from __future__ import annotations

import sys

from .orchestrator import run_flow
from .replay import diff_collections, replay
from .samples import sample_sources


def main() -> int:
    svc, result = run_flow(sample_sources())

    print("=" * 68)
    print("SecAgent RiskOps — end-to-end walking skeleton")
    print("=" * 68)
    print(f"Flow {result.flow_id}: status={result.flow_status}")
    print(f"Ingested {len(result.ingest.alerts)} raw alerts "
          f"-> {len(result.ingest.groups)} alert groups "
          f"-> {len(result.incidents)} incident(s)\n")

    for o in result.outcomes:
        print(f"[{o.group_id}] {o.signature}  score={o.risk_score} ({o.risk_band})  "
              f"-> {o.recommendation.disposition.value} "
              f"(confidence {o.recommendation.confidence})")
        if o.recommendation.attack_techniques:
            print(f"    ATT&CK: {', '.join(o.recommendation.attack_techniques)}")
        if o.incident:
            print(f"    incident {o.incident.incident_id}")
        if o.control_mapping:
            print(f"    control {o.control_mapping.control_id}  risk {o.risk.risk_id}")
        if o.action_plan:
            d = o.policy_decision
            print(f"    action plan {o.action_plan.action_plan_id} "
                  f"[{o.action_plan.status.value}] risk={o.action_plan.risk_level.value}")
            print(f"    policy decision: {d.effect.value.upper()} ({d.reason_code}) "
                  f"-> executor NOT invoked")
        print()

    # --- Invariants -------------------------------------------------------
    checks: list[tuple[str, bool]] = []
    checks.append(("audit chain intact", svc.audit.verify_chain()))
    checks.append(("evidence integrity", all(
        svc.evidence.verify(e.content_hash) for e in result.ingest.evidences)))
    checks.append(("at least one incident created", len(result.incidents) >= 1))
    checks.append(("no action plan executed", all(
        p.status.value in ("draft", "proposed") for p in result.action_plans)))

    replay_svc, _ = replay(svc, svc.clock)
    mismatches = diff_collections(svc, replay_svc)
    checks.append(("replay reproduces run", not mismatches))

    print("-" * 68)
    ok = True
    for label, passed in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {label}")
        ok = ok and passed
    if mismatches:
        print(f"  replay mismatches: {mismatches}")
    print("-" * 68)
    print(f"Audit events recorded: {len(svc.audit.events())}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
