"""AI triage agreement and cost (EVALUATION.md Table 4 and the model rows of Table 5).

    python -m app.evaluation.triage --data <dataset> --tape <recording.jsonl> --out <result.json>
    python -m app.evaluation.triage ... --live --api-key-file <file> --budget-usd 6

Triage runs on the incidents the pipeline surfaces. An incident's truth is
``attack`` when it holds any attack-labelled alert and ``benign`` otherwise.
Recorded calls are reused, so a rerun costs nothing and gives the same result;
only incidents missing from the recording are sent, and only with ``--live``.
Each paid call is appended to the recording the moment it returns.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
from statistics import median

from .. import reduction
from ..agents import model_triage
from ..reduction.score import known_sources
from . import alerts as alert_layer
from . import metrics


def _rates(pairs: list[tuple[str, str]]) -> dict:
    """``pairs`` of (truth, verdict). Agreement is measured where the agent committed."""
    total = len(pairs)
    abstained = sum(verdict == "abstain" for _, verdict in pairs)
    committed = [(truth, verdict) for truth, verdict in pairs if verdict != "abstain"]
    tp = sum(t == "attack" and v == "escalate" for t, v in committed)
    fn = sum(t == "attack" and v == "dismiss" for t, v in committed)
    tn = sum(t == "benign" and v == "dismiss" for t, v in committed)
    fp = sum(t == "benign" and v == "escalate" for t, v in committed)
    tpr = tp / (tp + fn) if tp + fn else None
    tnr = tn / (tn + fp) if tn + fp else None
    balanced = round((tpr + tnr) / 2, 4) if tpr is not None and tnr is not None else None
    n = len(committed)
    kappa = None
    if n:
        observed = (tp + tn) / n
        expected = ((tp + fn) * (tp + fp) + (tn + fp) * (tn + fn)) / (n * n)
        kappa = round((observed - expected) / (1 - expected), 4) if expected != 1 else None
    attacks = sum(truth == "attack" for truth, _ in pairs)
    benign = total - attacks
    return {"n": total, "attack_incidents": attacks, "benign_incidents": benign,
            "abstained": abstained, "abstention_rate": round(abstained / total, 4) if total else 0.0,
            "coverage": round(len(committed) / total, 4) if total else 0.0,
            "balanced_accuracy": balanced, "cohens_kappa": kappa,
            "attacks_escalated": tp, "attacks_dismissed": fn,
            "attacks_kept_for_an_analyst": round(1 - fn / attacks, 4) if attacks else None,
            "benign_dismissed": tn, "benign_dismissed_share": round(tn / benign, 4) if benign else None}


def surfaced_cases(data: Path) -> tuple[list[dict], dict[str, str], int]:
    """Dossiers of the surfaced incidents in id order, their truth, and the alert count."""
    records = alert_layer.load_records(data)
    raised = alert_layer.scheduled_alerts(records)
    with (data / "labels.jsonl").open(encoding="utf-8") as handle:
        labels = {row["event_id"]: row["label"] for row in map(json.loads, handle)}
    owner = metrics.alert_labels(raised, labels)
    by_id = {row["event_id"]: row for row in records}
    baseline = known_sources(records)
    cases, truth = [], {}
    for incident in sorted(reduction.reduce_alerts(raised, records), key=lambda item: item.incident_id):
        if not incident.surfaced:
            continue
        cases.append(model_triage.dossier(incident, [by_id[e] for e in incident.evidence], baseline))
        attack = any(owner[alert] != "benign" for alert in incident.alert_ids)
        truth[incident.incident_id] = "attack" if attack else "benign"
    return cases, truth, len(raised)


def evaluate(data: Path, tape: Path, *, live: model_triage.ClaudeTriage | None = None,
             limit: int | None = None) -> dict:
    cases, truth, alert_count = surfaced_cases(data)
    if limit is not None:
        cases = cases[:limit]
    recorded = model_triage.RecordedTriage(tape)
    calls, missing, stopped = [], [], None
    for case in cases:
        call = recorded.lookup(case)
        if call is None and live is not None and stopped is None:
            try:
                call = live.triage(case)
            except model_triage.BudgetExceeded as error:
                stopped = str(error)
            else:
                with tape.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(call.to_record(), sort_keys=True) + "\n")
        if call is None:
            missing.append(case["incident_id"])
        else:
            calls.append(call)
    judged = {call.incident_id: call for call in calls}
    score_only = [(truth[case["incident_id"]], "escalate") for case in cases if case["incident_id"] in judged]
    model_rows = [(truth[call.incident_id], call.verdict) for call in calls]
    latencies = sorted(call.latency_seconds for call in calls)
    usd = sum(call.usd for call in calls)
    result = {
        "model": model_triage.MODEL, "effort": model_triage.DEFAULT_EFFORT,
        "prompt_version": model_triage.PROMPT_VERSION,
        "surfaced_incidents": len(cases), "judged": len(calls), "not_judged": missing,
        "stopped_by_budget": stopped,
        "agreement": {"score only (every surfaced incident escalated)": _rates(score_only),
                      f"{model_triage.MODEL}, effort {model_triage.DEFAULT_EFFORT}": _rates(model_rows)},
        "attack_incidents_dismissed": sorted(c.incident_id for c in calls
                                             if truth[c.incident_id] == "attack" and c.verdict == "dismiss"),
        "cost": {"calls": len(calls), "input_tokens": sum(c.input_tokens for c in calls),
                 "output_tokens": sum(c.output_tokens for c in calls),
                 "cache_read_input_tokens": sum(c.cache_read_input_tokens for c in calls),
                 "usd": round(usd, 4), "usd_per_incident": round(usd / len(calls), 4) if calls else 0.0,
                 "usd_per_1000_input_alerts": round(usd * 1000 / alert_count, 4) if alert_count else 0.0,
                 "latency_p50_seconds": round(median(latencies), 2) if latencies else None,
                 "latency_p95_seconds": metrics._percentile(latencies, 0.95) if latencies else None,
                 "stop_reasons": dict(sorted(Counter(c.stop_reason for c in calls).items())),
                 "served_by": dict(sorted(Counter(c.model for c in calls).items()))},
        "input_alerts": alert_count,
    }
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", required=True, type=Path)
    parser.add_argument("--tape", required=True, type=Path, help="recording of model calls, appended to when live")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--live", action="store_true", help="call the API for incidents not in the recording")
    parser.add_argument("--api-key-file", type=Path, default=None)
    parser.add_argument("--budget-usd", type=float, default=0.0, help="hard ceiling for this run's new calls")
    parser.add_argument("--limit", type=int, default=None, help="only the first N surfaced incidents (pilot)")
    args = parser.parse_args(argv)
    live = None
    if args.live:
        if args.api_key_file is None or args.budget_usd <= 0:
            parser.error("--live needs --api-key-file and a positive --budget-usd")
        live = model_triage.ClaudeTriage(args.api_key_file.read_text().strip(), budget_usd=args.budget_usd)
    result = evaluate(args.data, args.tape, live=live, limit=args.limit)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    rows = result["agreement"]
    print(json.dumps({"judged": result["judged"], "not_judged": len(result["not_judged"]),
                      "usd": result["cost"]["usd"], "stopped_by_budget": result["stopped_by_budget"],
                      "model": rows[f"{model_triage.MODEL}, effort {model_triage.DEFAULT_EFFORT}"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
