"""Replay recorded triage, or evaluate a configured API on verified synthetic data.

    python -m app.evaluation.triage --data <dataset> --tape <recording.jsonl> --out <result.json>
    python -m app.evaluation.triage ... --config <profile.json> --live \\
        --keys-file <private.json> --ledger <shared.sqlite3> --budget-usd 10

Without --config, the historical Claude request fingerprint and report format
are preserved. New recordings require the same API configuration for replay.
Live evaluation accepts only the published synthetic datasets. All providers
and independent repeats must share one durable budget ledger.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
from statistics import median
from tempfile import TemporaryDirectory

from .. import reduction
from ..agents import model_triage
from ..agents.triage_api import FORMAT_VERSION, APIConfig, APIError, APITriage, read_key
from ..agents.triage_budget import BudgetLedger, CallUncertain
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


def stability(first: Path, second: Path) -> dict:
    """Agreement between two independent live runs on the same requests.

    The model accepts no temperature, so the same dossier can be judged twice
    differently; this measures how often that happens.
    """
    runs = [{row["prompt_sha256"]: row for row in map(json.loads, path.read_text().splitlines())}
            for path in (first, second)]
    shared = sorted(set(runs[0]) & set(runs[1]))
    pairs = [(runs[0][key]["verdict"], runs[1][key]["verdict"]) for key in shared]
    same = sum(a == b for a, b in pairs)
    kappa = None
    if pairs:
        observed = same / len(pairs)
        left, right = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
        expected = sum(left[v] * right[v] for v in model_triage.VERDICTS) / len(pairs) ** 2
        kappa = round((observed - expected) / (1 - expected), 4) if expected != 1 else 1.0
    return {"pairs": len(pairs), "same_verdict": same,
            "agreement": round(same / len(pairs), 4) if pairs else None, "cohens_kappa": kappa,
            "flips": [{"incident_id": runs[0][key]["incident_id"], "first": a, "second": b}
                      for key, (a, b) in zip(shared, pairs) if a != b]}


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


def _live_cases(data: Path) -> tuple[list[dict], dict[str, str], int]:
    """Verify against repository manifests and use the same immutable bytes.

    A caller-supplied manifest is not proof of synthetic provenance. In
    particular, load_records prefers records.jsonl over events.jsonl, so that
    alternate input is explicitly rejected.
    """
    if (data / "records.jsonl").exists():
        raise ValueError("live evaluation does not accept records.jsonl")
    names = ("events.jsonl", "labels.jsonl", "episodes.json")
    source = {}
    for name in names:
        path = data / name
        if path.stat().st_size > 128_000_000:
            raise ValueError("synthetic input is too large")
        source[name] = path.read_bytes()
    hashes = {name: hashlib.sha256(value).hexdigest() for name, value in source.items()}
    fixtures = Path(__file__).resolve().parents[3] / "examples" / "synthetic-sshd"
    trusted = [json.loads((fixtures / f"manifest-{days}d.json").read_text())["sha256"] for days in (1, 7)]
    if hashes not in trusted:
        raise ValueError("live evaluation requires the unchanged published 1-day or 7-day synthetic dataset")
    with TemporaryDirectory(prefix="triage-synthetic-") as directory:
        snapshot = Path(directory)
        for name, value in source.items():
            (snapshot / name).write_bytes(value)
        return surfaced_cases(snapshot)


def _append(tape: Path, call: model_triage.TriageCall):
    with tape.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(call.to_record(), sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def evaluate(data: Path, tape: Path, *, live: APITriage | None = None, config: APIConfig | None = None,
             limit: int | None = None) -> dict:
    if limit is not None and (type(limit) is not int or limit <= 0):
        raise ValueError("limit must be a positive integer")
    if live is not None:
        if config is not None and config != live.config:
            raise ValueError("live and replay configurations must match")
        if str(tape.resolve()) != live.run_id:
            raise ValueError("live client must use this recording's path")
        config = live.config
    cases, truth, alert_count = _live_cases(data) if live is not None else surfaced_cases(data)
    if limit is not None:
        cases = cases[:limit]
    recorded = model_triage.RecordedTriage(tape)
    if live is not None:
        tape.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(tape, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(descriptor)
    calls, missing, stopped, api_stop = [], [], None, None
    for case in cases:
        request_hash = config.fingerprint(case) if config is not None else None
        call = recorded.lookup(case, request_sha256=request_hash)
        if call is None and live is not None and stopped is None and api_stop is None:
            try:
                call = live.triage(case)
            except model_triage.BudgetExceeded as error:
                stopped = str(error)
            except (APIError, CallUncertain) as error:
                api_stop = str(error)
            else:
                _append(tape, call)
        if call is None:
            missing.append(case["incident_id"])
        else:
            calls.append(call)
    judged = {call.incident_id: call for call in calls}
    score_only = [(truth[case["incident_id"]], "escalate") for case in cases if case["incident_id"] in judged]
    model_rows = [(truth[call.incident_id], call.verdict) for call in calls]
    latencies = sorted(call.latency_seconds for call in calls)
    usd = sum(call.usd for call in calls)
    label = config.label if config else f"{model_triage.MODEL}, effort {model_triage.DEFAULT_EFFORT}"
    result = {
        "model": config.model if config else model_triage.MODEL,
        "effort": config.effort if config else model_triage.DEFAULT_EFFORT,
        "prompt_version": FORMAT_VERSION if config else model_triage.PROMPT_VERSION,
        "surfaced_incidents": len(cases), "judged": len(calls), "not_judged": missing,
        "stopped_by_budget": stopped,
        "agreement": {"score only (every surfaced incident escalated)": _rates(score_only),
                      label: _rates(model_rows)},
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
    if config is not None:
        result["cost"]["cache_creation_input_tokens"] = sum(c.cache_creation_input_tokens for c in calls)
        result["cost"]["reasoning_tokens"] = sum((c.metadata or {}).get("reasoning_tokens", 0) for c in calls)
        result.update(configuration=config.model_dump(mode="json"), stopped_by_api=api_stop,
                      invalid_outputs=dict(sorted(Counter(c.metadata["validation"] for c in calls
                          if c.metadata and c.metadata["validation"] != "valid").items())))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", required=True, type=Path)
    parser.add_argument("--tape", required=True, type=Path, help="recording, appended to when live")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--config", type=Path, help="API profile; omit only for historical Claude replay")
    parser.add_argument("--live", action="store_true", help="pay for missing synthetic cases using the configured API")
    keys = parser.add_mutually_exclusive_group()
    keys.add_argument("--keys-file", type=Path, help="private JSON mapping of key names to API keys")
    keys.add_argument("--api-key-file", type=Path, help="private file containing just the selected API key")
    parser.add_argument("--ledger", type=Path, help="one shared SQLite budget for every provider and repeat")
    parser.add_argument("--budget-usd", default="0", help="total ceiling persisted in the shared ledger")
    parser.add_argument("--limit", type=int, help="only the first N surfaced incidents")
    args = parser.parse_args(argv)
    paths = [args.tape, args.out, args.config, args.keys_file, args.api_key_file, args.ledger]
    selected = [path.resolve() for path in paths if path is not None]
    inputs = {args.data.resolve() / name for name in ("events.jsonl", "labels.jsonl", "episodes.json", "records.jsonl")}
    if len(selected) != len(set(selected)) or set(selected) & inputs:
        parser.error("recording, report, configuration, key file, ledger and dataset files must use distinct paths")
    live = ledger = config = None
    try:
        if args.config is not None:
            config = APIConfig.load(args.config)
        if args.limit is not None and args.limit <= 0:
            raise ValueError
    except (OSError, ValueError):
        parser.error("invalid API configuration or limit; see docs/model-triage.md")
    if args.live:
        if config is None or args.ledger is None or not (args.keys_file or args.api_key_file):
            parser.error("--live needs --config, --ledger, a key file, and a positive --budget-usd")
        try:
            key = read_key(args.keys_file or args.api_key_file, config.key_name, single=args.api_key_file is not None)
            ledger = BudgetLedger(args.ledger, args.budget_usd)
        except (OSError, ValueError, ArithmeticError):
            parser.error("invalid private key file or shared budget; check permissions, key name and original ceiling")
        live = APITriage(config, key, ledger=ledger, tape=args.tape)
    elif args.keys_file or args.api_key_file or args.ledger or args.budget_usd != "0":
        parser.error("key and budget arguments require --live")
    try:
        result = evaluate(args.data, args.tape, live=live, config=config, limit=args.limit)
    except (OSError, ValueError):
        parser.error("evaluation input or recording is invalid; live mode accepts only unchanged published synthetic data")
    if ledger is not None:
        result["shared_budget"] = ledger.summary()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    label = config.label if config else f"{model_triage.MODEL}, effort {model_triage.DEFAULT_EFFORT}"
    print(json.dumps({"judged": result["judged"], "not_judged": len(result["not_judged"]),
                      "usd": result["cost"]["usd"], "stopped_by_budget": result["stopped_by_budget"],
                      "model": result["agreement"][label]}, sort_keys=True))
    return 1 if result["stopped_by_budget"] or result.get("stopped_by_api") or (
        ledger is not None and ledger.summary()["halted"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
