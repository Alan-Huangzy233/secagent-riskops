"""Precompute what the web demo replays: one labelled synthetic week, end to end.

    python -m app.webdemo.snapshot --data <synthetic-7d dir> --out docs/eval/web-demo-synthetic-7d.json
    python -m app.webdemo.snapshot --data <synthetic-7d dir> --check docs/eval/web-demo-synthetic-7d.json

The page never computes a number itself. Everything it shows comes from this
file, which is built by running the same pipeline as the evaluation on the
same dataset: the production rules raise the alerts, the reduction pipeline
groups and scores them, and the model verdicts are the recorded calls, looked
up by request fingerprint exactly as ``make triage`` does. Ground truth is
attached afterwards and marked as such; nothing upstream reads it.

Every number is computed here from the dataset it is given, not copied from
``results-synthetic-7d.json``, so the tests can check the two against each
other. The build is deterministic, so CI rebuilds it and compares it byte for
byte.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
from statistics import median

from .. import reduction
from ..agents import model_triage
from ..evaluation import alerts as alert_layer
from ..evaluation import baselines, metrics
from ..pipeline import remediation
from ..reduction import score as scoring
from ..reduction.score import known_sources

SNAPSHOT_VERSION = 1
ROOT = Path(__file__).resolve().parents[3]
TAPE = ROOT / "docs" / "eval" / "triage-tape-synthetic-7d.jsonl"
LAB = ROOT / "examples" / "safety-demo" / "lab"
TICKER_EVERY = 250  # one raw log line in every N goes to the scrolling ticker
EVIDENCE_LINES = 30
SEED = 20261115


def _epoch(stamp: str) -> float:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()


def _iso(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def build(data: Path) -> dict:
    manifest = json.loads((data / "manifest.json").read_text())
    with (data / "events.jsonl").open(encoding="utf-8") as handle:
        raw = [json.loads(line) for line in handle]
    message = {row["event_id"]: row for row in raw}
    records = alert_layer.load_records(data)
    raised = alert_layer.scheduled_alerts(records)
    with (data / "labels.jsonl").open(encoding="utf-8") as handle:
        labels = {row["event_id"]: row["label"] for row in map(json.loads, handle)}
    episode_rows = json.loads((data / "episodes.json").read_text())
    episodes = [row["episode_id"] for row in episode_rows]
    scenario = {row["episode_id"]: row["scenario"] for row in episode_rows}
    owner = metrics.alert_labels(raised, labels)
    found = reduction.reduce_alerts(raised, records)
    as_dicts = [{"alert_ids": list(i.alert_ids), "surfaced": i.surfaced} for i in found]
    half = metrics.detection(as_dicts, owner, episodes, tau=0.5, seed=SEED)
    detected = set(half["detected_episodes"])
    b1 = baselines.b1_tuple_dedup(raised)
    b1_half = metrics.detection(b1, owner, episodes, tau=0.5, seed=SEED)
    baseline = known_sources(records)
    by_id = {row["event_id"]: row for row in records}
    tape = model_triage.RecordedTriage(TAPE)
    lab_hosts = sorted(path.name for path in LAB.iterdir() if (path / ".riskops-lab").is_file())

    start = _epoch(raw[0]["ts"]) // 3600 * 3600
    hours = int(manifest["days"]) * 24
    bins = [{"lines": 0, "alerts": 0, "incidents": 0, "surfaced": 0} for _ in range(hours)]

    def slot(stamp: str) -> int:
        return min(hours - 1, max(0, int((_epoch(stamp) - start) // 3600)))

    for row in raw:
        bins[slot(row["ts"])]["lines"] += 1
    for alert in raised:
        bins[slot(alert["fired_at"])]["alerts"] += 1
    for incident in found:
        bins[slot(incident.last_ts)]["incidents"] += 1
        bins[slot(incident.last_ts)]["surfaced"] += incident.surfaced

    surfaced = []
    for incident in sorted((i for i in found if i.surfaced), key=lambda i: (i.last_ts, i.incident_id)):
        case = model_triage.dossier(incident, [by_id[e] for e in incident.evidence], baseline)
        call = tape.lookup(case)
        own = Counter(owner[alert] for alert in incident.alert_ids if owner[alert] != "benign")
        verdict = call.verdict if call else None
        actions = remediation.playbook(case, verdict or "")
        shown = [row["event_id"] for row in case["record_sample"]][:EVIDENCE_LINES]
        surfaced.append({
            "id": incident.incident_id, "priority": incident.priority, "score": incident.score,
            "reasons": list(incident.reasons), "rules": list(incident.rules),
            "sources": list(incident.src_ips), "hosts": list(incident.hosts),
            "first": case["first_seen"], "last": case["last_seen"], "alerts": len(incident.alert_ids),
            "records": case["records_in_incident"], "failed_records": case["failed_records"],
            "accounts": case["accounts"][:8], "accounts_tried": case["distinct_accounts_tried"],
            "successful_logins": case["successful_logins"],
            "evidence": [{"event_id": e, "ts": message[e]["ts"][:19] + "Z", "host": message[e]["host"],
                          "message": message[e]["message"]} for e in shown],
            "model": None if call is None else {
                "model": call.model, "verdict": call.verdict, "confidence": call.confidence,
                "rationale": call.rationale, "evidence_ids": list(call.evidence_ids),
                "attack_techniques": list(call.attack_techniques), "usd": call.usd,
                "latency_seconds": call.latency_seconds, "prompt_sha256": call.prompt_sha256},
            "action": None if not actions else {"type": actions[0][0], "host": actions[0][1],
                                                "evidence_ids": actions[0][2], "lab_copy": actions[0][1] in lab_hosts},
            "truth": {"label": "attack" if own else "benign",
                      "episodes": [{"id": episode, "scenario": scenario[episode], "detected": episode in detected}
                                   for episode, _ in sorted(own.items(), key=lambda item: (-item[1], item[0]))]},
        })

    covering: dict[str, list[reduction.Incident]] = {}
    for incident in found:
        for episode in {owner[alert] for alert in incident.alert_ids} - {"benign"}:
            covering.setdefault(episode, []).append(incident)
    missed = []
    for episode in episodes:
        if episode in detected:
            continue
        best = max(covering.get(episode, []), key=lambda i: (sum(owner[a] == episode for a in i.alert_ids),
                                                              i.score), default=None)
        missed.append({"id": episode, "scenario": scenario[episode], "raised_an_alert": best is not None,
                       "closest_incident": None if best is None else {
                           "id": best.incident_id, "score": best.score, "surfaced": best.surfaced}})

    with_alerts = {label for label in owner.values() if label != "benign"}
    by_scenario = {}
    for name in sorted(set(scenario.values())):
        own = [episode for episode in episodes if scenario[episode] == name]
        by_scenario[name] = {"episodes": len(own), "raised_an_alert": sum(e in with_alerts for e in own),
                             "detected_tau_0.5": sum(e in detected for e in own)}
    judged = [(i["truth"]["label"], i["model"]) for i in surfaced if i["model"]]
    return {
        "snapshot_version": SNAPSHOT_VERSION,
        "dataset": {"synthetic": True, "seed": manifest["seed"], "days": manifest["days"],
                    "hosts": manifest["hosts"], "address_space": manifest["address_space"],
                    "start": _iso(start), "end": _iso(start + hours * 3600)},
        "headline": {"log_lines": len(raw), "rule_records": len(records), "alerts": len(raised),
                     "incidents": len(found), "surfaced": len(surfaced),
                     "reduction_pct": metrics.reduction(as_dicts, len(raised))["reduction_pct"],
                     "episodes": half["episodes"], "detected": half["detected"], "miss_rate": half["miss_rate"],
                     "miss_rate_ci95": half["miss_rate_ci95"], "precision": half["precision"],
                     "no_alert_episodes": half["no_alert_episodes"],
                     "b1_incidents": len(b1), "b1_miss_rate": b1_half["miss_rate"]},
        "scoring": {"threshold": scoring.SURFACE_THRESHOLD,
                    "priorities": [[floor, name] for floor, name in scoring.PRIORITIES],
                    "tick_seconds": alert_layer.TICK_SECONDS},
        "triage": {"model": model_triage.MODEL, "effort": model_triage.DEFAULT_EFFORT, "judged": len(judged),
                   "attacks_dismissed": sum(t == "attack" and m["verdict"] == "dismiss" for t, m in judged),
                   "attack_incidents": sum(t == "attack" for t, _ in judged),
                   "benign_dismissed": sum(t == "benign" and m["verdict"] == "dismiss" for t, m in judged),
                   "benign_incidents": sum(t == "benign" for t, _ in judged),
                   "usd_per_incident": round(sum(m["usd"] for _, m in judged) / len(judged), 4) if judged else None,
                   "latency_p50_seconds": round(median(m["latency_seconds"] for _, m in judged), 2) if judged else None},
        "hours": [[b["lines"], b["alerts"], b["incidents"], b["surfaced"]] for b in bins],
        "scores": sorted([score, count] for score, count in Counter(i.score for i in found).items()),
        "ticker": [{"ts": row["ts"][:19] + "Z", "host": row["host"], "message": row["message"]}
                   for row in raw[::TICKER_EVERY]],
        "incidents": surfaced,
        "missed": missed,
        "by_scenario": by_scenario,
        "lab_hosts": lab_hosts,
    }


def render(snapshot: dict) -> bytes:
    return (json.dumps(snapshot, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", required=True, type=Path, help="the rebuilt 7-day synthetic dataset")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--out", type=Path)
    target.add_argument("--check", type=Path, help="fail unless a rebuild matches this file byte for byte")
    args = parser.parse_args(argv)
    payload = render(build(args.data))
    if args.check is not None:
        same = args.check.exists() and args.check.read_bytes() == payload
        print(f"web demo snapshot {'reproduces' if same else 'DIFFERS FROM'} {args.check}")
        return 0 if same else 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(payload)
    print(json.dumps({"bytes": len(payload), "surfaced": len(json.loads(payload)["incidents"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
