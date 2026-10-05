"""Evaluate built-in synthetic SSH/HTTP dossiers with evidence policy v3.

There is deliberately no custom-data argument. Live requests are constructed
only from the versioned, manifest-verified synthetic generator.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
from statistics import median

from ..agents import model_triage, triage_evidence
from ..agents.triage_api import APIConfig, APIError, APITriage, read_key
from ..agents.triage_budget import BudgetLedger, CallUncertain
from .metrics import _percentile
from .triage import _append
from .triage_scenarios import SUITE, verified_scenarios
from . import triage_pilot_scenarios

SUITES = (SUITE, triage_pilot_scenarios.SUITE)


def _scenarios(split: str, suite: str):
    if suite == SUITE:
        return verified_scenarios(split)
    if suite == triage_pilot_scenarios.SUITE:
        return triage_pilot_scenarios.verified_scenarios(split)
    raise ValueError("unknown built-in suite")


def _private_write(path: Path, text: str, *, exclusive: bool = False):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())


def protocol_path(tape: Path) -> Path:
    return tape.with_name(tape.name + ".protocol.json")


def _protocol(split: str, rows: list[dict], manifest: dict, config: APIConfig) -> dict:
    return {"suite": manifest["suite"], "split": split, "corpus": manifest["partitions"][split],
            "thresholds": manifest["thresholds"], "configuration": config.model_dump(mode="json"),
            "dossier_version": triage_evidence.VERSION,
            "validator_version": triage_evidence.VALIDATOR_VERSION,
            "system_sha256": hashlib.sha256(triage_evidence.SYSTEM.encode()).hexdigest(),
            "requests": {row["case"]["incident_id"]: config.fingerprint(row["case"]) for row in rows},
            "scope": "synthetic advisory scenarios only; no rule-layer or production qualification"}


def _metrics(rows: list[dict], calls: dict, *, proposed: bool) -> dict:
    matrix = {expected: dict.fromkeys(("escalate", "dismiss", "abstain", "invalid", "unjudged"), 0)
              for expected in ("escalate", "dismiss", "abstain")}
    for row in rows:
        call = calls.get(row["case"]["incident_id"])
        actual = "unjudged"
        if call is not None:
            proposal = call.metadata["evidence_validation"]["proposal"]
            actual = (proposal["verdict"] if proposal else "invalid") if proposed else call.verdict
        matrix[row["expected_verdict"]][actual] += 1
    n = len(rows)
    correct = sum(matrix[k][k] for k in matrix)

    def rate(expected, actual):
        count = sum(matrix[expected].values())
        return round(matrix[expected][actual] / count, 4) if count else None

    return {"n": n, "correct": correct, "decision_accuracy": round(correct / n, 4) if n else None,
            "attack_scenarios": sum(matrix["escalate"].values()),
            "attack_dismissals": matrix["escalate"]["dismiss"],
            "insufficient_dismissals": matrix["abstain"]["dismiss"],
            "unsafe_dismissals": matrix["escalate"]["dismiss"] + matrix["abstain"]["dismiss"],
            "attack_escalation_rate": rate("escalate", "escalate"),
            "benign_dismissal_rate": rate("dismiss", "dismiss"),
            "insufficient_abstention_rate": rate("abstain", "abstain"),
            "abstained": sum(v["abstain"] for v in matrix.values()),
            "matrix_expected_by_verdict": matrix}


def evaluate(split: str, tape: Path, *, config: APIConfig, live: APITriage | None = None,
             limit: int | None = None, suite: str = SUITE) -> dict:
    if limit is not None and (type(limit) is not int or limit <= 0):
        raise ValueError("limit must be positive")
    if live is not None and (live.config != config or live.run_id != str(tape.resolve())):
        raise ValueError("live configuration and recording path must match")
    all_rows, frozen = _scenarios(split, suite)
    protocol = _protocol(split, all_rows, frozen, config)
    saved = protocol_path(tape)
    if saved.exists():
        if json.loads(saved.read_text()) != protocol:
            raise ValueError("recorded protocol changed; retain it and use a new explicitly named run")
    elif live is not None:
        _private_write(saved, json.dumps(protocol, sort_keys=True, indent=2) + "\n", exclusive=True)
    else:
        raise ValueError("offline replay requires this recording's frozen protocol")
    rows = all_rows if limit is None else all_rows[:limit]
    recorded = model_triage.RecordedTriage(tape)
    if live is not None and not tape.exists():
        _private_write(tape, "", exclusive=True)
    calls = {}
    missing = []
    api_stop = budget_stop = None
    for row in rows:
        case = row["case"]
        call = recorded.lookup(case, request_sha256=config.fingerprint(case))
        if call is None and live is not None and not (api_stop or budget_stop):
            try:
                call = live.triage(case)
            except model_triage.BudgetExceeded as error:
                budget_stop = str(error)
            except (APIError, CallUncertain) as error:
                api_stop = str(error)
            else:
                _append(tape, call)
        if call is None:
            missing.append(case["incident_id"])
            continue
        details = (call.metadata or {}).get("evidence_validation")
        if (not details or details.get("dossier_sha256") != triage_evidence.digest(case)
                or details.get("validator_version") != triage_evidence.VALIDATOR_VERSION
                or details.get("revision") != case["revision"]):
            raise ValueError("recording evidence validation does not match the current dossier")
        calls[case["incident_id"]] = call
    proposed = _metrics(rows, calls, proposed=True)
    accepted = _metrics(rows, calls, proposed=False)
    times = sorted(c.latency_seconds for c in calls.values())
    total_cost = sum(c.usd for c in calls.values())
    validations = Counter(c.metadata["validation"] for c in calls.values())
    pass_rate = round(validations["valid"] / len(rows), 4) if rows else 0
    thresholds = frozen["thresholds"]
    checks = {
        "complete_corpus": len(calls) == len(all_rows) and not missing,
        "minimum_cases": len(rows) >= thresholds["minimum_cases"],
        "minimum_families": len({r["family"] for r in rows}) >= thresholds["minimum_families"],
        "proposal_unsafe_dismissals": proposed["unsafe_dismissals"] <= thresholds["max_proposed_unsafe_dismissals"],
        "accepted_unsafe_dismissals": accepted["unsafe_dismissals"] <= thresholds["max_accepted_unsafe_dismissals"],
        "proposal_accuracy": (proposed["decision_accuracy"] or 0) >= thresholds["minimum_proposal_accuracy"],
        "accepted_accuracy": (accepted["decision_accuracy"] or 0) >= thresholds["minimum_accepted_accuracy"],
        "benign_dismissal": (accepted["benign_dismissal_rate"] or 0) >= thresholds["minimum_benign_dismissal_rate"],
        "attack_escalation": (accepted["attack_escalation_rate"] or 0) >= thresholds["minimum_attack_escalation_rate"],
        "insufficient_abstention": (accepted["insufficient_abstention_rate"] or 0) >= thresholds["minimum_insufficient_abstention_rate"],
        "validation_pass_rate": pass_rate >= thresholds["minimum_validation_pass_rate"],
        "p95_latency": bool(times) and _percentile(times, .95) <= thresholds["maximum_p95_seconds"],
        "estimated_cost": bool(calls) and total_cost / len(calls) <= thresholds["maximum_estimated_usd_per_case"],
    }
    differences = []
    for row in rows:
        iid = row["case"]["incident_id"]
        call = calls.get(iid)
        if call is None:
            continue
        details = call.metadata["evidence_validation"]
        proposal = details["proposal"]
        if (proposal is None or proposal["verdict"] != row["expected_verdict"]
                or call.verdict != row["expected_verdict"] or details["reasons"]):
            differences.append({"incident_id": iid, "family": row["family"], "expected": row["expected_verdict"],
                                "proposed": proposal["verdict"] if proposal else None, "accepted": call.verdict,
                                "validation_reasons": details["reasons"]})
    return {"suite": suite, "split": split, "dossier_version": triage_evidence.VERSION,
            "validator_version": triage_evidence.VALIDATOR_VERSION, "protocol": protocol,
            "by_kind": {kind: {"proposed": _metrics([r for r in rows if r["case"]["kind"] == kind], calls, proposed=True),
                               "accepted": _metrics([r for r in rows if r["case"]["kind"] == kind], calls, proposed=False)}
                        for kind in ("ssh", "http")},
            "judged": len(calls), "not_judged": missing, "stopped_by_api": api_stop,
            "stopped_by_budget": budget_stop, "proposed": proposed, "accepted": accepted,
            "validation": {"counts": dict(sorted(validations.items())), "pass_rate": pass_rate},
            "cost": {"calls": len(calls), "estimated_usd": round(total_cost, 6),
                     "estimated_usd_per_case": round(total_cost / len(calls), 6) if calls else None,
                     "latency_p50_seconds": round(median(times), 3) if times else None,
                     "latency_p95_seconds": _percentile(times, .95) if times else None,
                     "input_tokens": sum(c.input_tokens for c in calls.values()),
                     "cache_read_input_tokens": sum(c.cache_read_input_tokens for c in calls.values()),
                     "cache_write_input_tokens": sum(c.cache_creation_input_tokens for c in calls.values()),
                     "output_tokens": sum(c.output_tokens for c in calls.values()),
                     "reasoning_tokens": sum(c.metadata["reasoning_tokens"] for c in calls.values()),
                     "served_by": dict(sorted(Counter(c.model for c in calls.values()).items()))},
            "checks": checks, "passes_scenario_gates": all(checks.values()),
            "production_qualified": False, "differences": differences,
            "limitations": ["Authored scenario families, not IID independent production samples.",
                            "Expected decisions are authored policy labels, not inferred from model agreement.",
                            "No rule-layer recall, live HTTP ingestion or automatic disposition is tested.",
                            "Typed claims are checked; arbitrary rationale text still requires human review.",
                            "Costs are configured-price estimates, not provider invoices."]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=SUITES, default=SUITE)
    parser.add_argument("--split", required=True, choices=("development", "holdout"))
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--tape", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--keys-file", type=Path)
    parser.add_argument("--ledger", type=Path)
    parser.add_argument("--budget-usd", default="0")
    args = parser.parse_args(argv)
    paths = [args.config, args.tape, args.out, protocol_path(args.tape), args.keys_file, args.ledger]
    resolved = [p.resolve() for p in paths if p is not None]
    if len(set(resolved)) != len(resolved):
        parser.error("configuration, recording, protocol, report, keys and ledger must be separate files")
    try:
        config = APIConfig.load(args.config)
        if args.limit is not None and args.limit <= 0:
            raise ValueError
        _scenarios(args.split, args.suite)
    except (OSError, ValueError):
        parser.error("invalid profile, limit or built-in synthetic corpus")
    live = ledger = None
    if args.live:
        if not (args.keys_file and args.ledger):
            parser.error("--live requires private keys, the existing shared ledger and a positive total budget")
        try:
            key = read_key(args.keys_file, config.key_name)
            ledger = BudgetLedger(args.ledger, args.budget_usd)
            live = APITriage(config, key, ledger=ledger, tape=args.tape)
        except (OSError, ValueError):
            parser.error("invalid private keys or shared budget configuration")
    elif args.keys_file or args.ledger or args.budget_usd != "0":
        parser.error("keys and budget arguments require --live")
    try:
        report = evaluate(args.split, args.tape, config=config, live=live, limit=args.limit, suite=args.suite)
    except (OSError, ValueError) as error:
        # Errors intentionally exclude key contents and remote responses.
        parser.error(str(error) if isinstance(error, ValueError) else "cannot read or save evaluation files")
    if ledger is not None:
        report["shared_budget"] = ledger.summary()
    _private_write(args.out, json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("judged", "not_judged", "proposed", "accepted",
                                          "validation", "cost", "passes_scenario_gates")}))
    return 1 if report["stopped_by_api"] or report["stopped_by_budget"] or (
        ledger is not None and report["shared_budget"]["halted"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
