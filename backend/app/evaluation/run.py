"""Run the whole evaluation on one dataset and write ``results.json``.

    python -m app.evaluation.run --data <dataset dir> --out <results.json> [--timings <file>]

Same inputs, commit and seed give a byte-identical ``results.json``: every
number in it is computed, never measured. Wall-clock timings change from run to
run, so they go to a separate file.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import time

from .. import reduction
from ..reduction import score as scoring
from ..reduction.correlate import DEFAULT_GAP_SECONDS
from . import alerts as alert_layer
from . import baselines, metrics

EVALUATION_VERSION = 1
SEED = 20261115
TAUS = (0.0, 0.5)
WINDOWS = (60, 300, 600, 1800, 3600)
THRESHOLDS = (0, 12, 25, 40, 60)


def _incidents(found: list[reduction.Incident]) -> list[dict]:
    return [{"alert_ids": list(incident.alert_ids), "surfaced": incident.surfaced} for incident in found]


def _all_surfaced(incidents: list[dict]) -> list[dict]:
    return [{"alert_ids": incident["alert_ids"], "surfaced": True} for incident in incidents]


def _system(incidents: list[dict], owner: dict[str, str], episodes: list[str], alert_count: int) -> dict:
    return {"reduction": metrics.reduction(incidents, alert_count),
            "detection": {f"tau_{tau:g}": metrics.detection(incidents, owner, episodes, tau=tau, seed=SEED)
                          for tau in TAUS},
            "clustering": metrics.clustering(incidents, owner)}


def evaluate(data: Path) -> tuple[dict, dict]:
    clock: dict[str, float] = {}
    started = time.perf_counter()
    records = alert_layer.load_records(data)
    clock["normalize"] = time.perf_counter() - started
    started = time.perf_counter()
    raised = alert_layer.scheduled_alerts(records)
    clock["alerts"] = time.perf_counter() - started
    with (data / "labels.jsonl").open(encoding="utf-8") as handle:
        labels = {row["event_id"]: row["label"] for row in map(json.loads, handle)}
    episode_rows = json.loads((data / "episodes.json").read_text())
    episodes = [row["episode_id"] for row in episode_rows]
    scenario_of = {row["episode_id"]: row["scenario"] for row in episode_rows}
    owner = metrics.alert_labels(raised, labels)
    count = len(raised)

    started = time.perf_counter()
    found = reduction.reduce_alerts(raised, records)
    clock["reduce"] = time.perf_counter() - started
    pipeline = _incidents(found)
    systems = {
        "B0 passthrough": _system(baselines.b0_passthrough(raised), owner, episodes, count),
        "B1 tuple dedup": _system(baselines.b1_tuple_dedup(raised), owner, episodes, count),
        "B2 rule window": _system(baselines.b2_window_aggregation(raised), owner, episodes, count),
        "pipeline, every incident": _system(_all_surfaced(pipeline), owner, episodes, count),
        "pipeline, surfaced": _system(pipeline, owner, episodes, count),
    }
    with_alerts = {label for label in owner.values() if label != "benign"}
    by_scenario = {}
    detected = set(systems["pipeline, surfaced"]["detection"]["tau_0"]["detected_episodes"])
    detected_half = set(systems["pipeline, surfaced"]["detection"]["tau_0.5"]["detected_episodes"])
    for scenario in sorted(set(scenario_of.values())):
        own = [episode for episode in episodes if scenario_of[episode] == scenario]
        by_scenario[scenario] = {"episodes": len(own), "raised_an_alert": sum(e in with_alerts for e in own),
                                 "detected_tau_0": sum(e in detected for e in own),
                                 "detected_tau_0.5": sum(e in detected_half for e in own)}
    shuffled = metrics.permuted(owner, SEED)
    control = {f"tau_{tau:g}": {key: value for key, value in
                                metrics.detection(pipeline, shuffled, episodes, tau=tau, seed=SEED).items()
                                if key != "detected_episodes"} for tau in TAUS}
    windows = []
    for window in WINDOWS:
        row = {"window_seconds": window}
        for name, incidents in (("B1 tuple dedup", baselines.b1_tuple_dedup(raised, window)),
                                ("B2 rule window", baselines.b2_window_aggregation(raised, window)),
                                ("pipeline, surfaced", _incidents(reduction.reduce_alerts(
                                    raised, records, gap_seconds=window)))):
            half = metrics.detection(incidents, owner, episodes, tau=0.5, seed=SEED)
            row[name] = {"output_incidents": metrics.reduction(incidents, count)["output_incidents"],
                         "reduction_pct": metrics.reduction(incidents, count)["reduction_pct"],
                         "miss_rate_tau_0.5": half["miss_rate"]}
        windows.append(row)
    thresholds = []
    for threshold in THRESHOLDS:
        incidents = _incidents(reduction.reduce_alerts(raised, records, threshold=threshold))
        detection = {f"tau_{tau:g}": metrics.detection(incidents, owner, episodes, tau=tau, seed=SEED)
                     for tau in TAUS}
        thresholds.append({"threshold": threshold, "surfaced": detection["tau_0"]["surfaced_incidents"],
                           **{f"{key}_{name}": value[key] for name, value in detection.items()
                              for key in ("precision", "recall", "miss_rate")}})
    for system in systems.values():
        for block in system["detection"].values():
            block.pop("detected_episodes")
    manifest = json.loads((data / "manifest.json").read_text())
    results = {
        "evaluation_version": EVALUATION_VERSION, "seed": SEED,
        "dataset": {key: manifest[key] for key in ("synthetic", "seed", "days", "events", "records", "episodes",
                                                   "window", "sha256", "generator_version", "slice_version")
                    if key in manifest},
        "configuration": {"tick_seconds": alert_layer.TICK_SECONDS, "schedule_version": alert_layer.SCHEDULE_VERSION,
                          "correlation_gap_seconds": DEFAULT_GAP_SECONDS,
                          "surface_threshold": scoring.SURFACE_THRESHOLD,
                          "baseline_window_seconds": baselines.WINDOW_SECONDS,
                          "score_weights": {name: getattr(scoring, name) for name in (
                              "SUCCESS", "EXISTING_ACCOUNT", "EXISTING_ACCOUNT_CAP", "SEVERAL_HOSTS", "PERSISTENT",
                              "PERSISTENT_SECONDS", "VOLUME", "VOLUME_RECORDS", "KNOWN_SOURCE")}},
        "alerts": {"count": count, "by_rule": dict(sorted(Counter(a["rule_id"] for a in raised).items())),
                   "attack_alerts": sum(label != "benign" for label in owner.values()),
                   "benign_share": round(sum(label == "benign" for label in owner.values()) / count, 4) if count else 0,
                   "sha256": hashlib.sha256("".join(json.dumps(a, sort_keys=True) for a in raised).encode()).hexdigest()},
        "rule_layer": {"episodes": len(episodes), "episodes_with_an_alert": len(with_alerts & set(episodes))},
        "systems": systems, "pipeline_by_scenario": by_scenario, "permutation_control": control,
        "window_sweep": windows, "threshold_sweep": thresholds,
    }
    per_thousand = 1000 / count if count else 0.0
    timings = {"records": len(records), "alerts": count,
               "seconds": {key: round(value, 3) for key, value in clock.items()},
               "seconds_per_1000_alerts": {"reduce": round(clock["reduce"] * per_thousand, 4)}}
    return results, timings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--timings", type=Path, default=None)
    args = parser.parse_args(argv)
    results, timings = evaluate(args.data)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
    if args.timings is not None:
        args.timings.write_text(json.dumps(timings, indent=2, sort_keys=True) + "\n")
    surfaced = results["systems"]["pipeline, surfaced"]
    print(json.dumps({"alerts": results["alerts"]["count"], "surfaced": surfaced["reduction"]["output_incidents"],
                      "reduction_pct": surfaced["reduction"]["reduction_pct"],
                      "miss_rate_tau_0": surfaced["detection"]["tau_0"]["miss_rate"],
                      "miss_rate_tau_0.5": surfaced["detection"]["tau_0.5"]["miss_rate"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
