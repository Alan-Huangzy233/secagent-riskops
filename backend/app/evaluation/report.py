"""Write the published numbers into EVALUATION.md and the README from results.json.

Every figure in those documents sits between ``<!-- generated:NAME -->`` and
``<!-- /generated:NAME -->`` and is rendered here, so a document can never
disagree with the results it cites. ``--check`` changes nothing and fails when a
document is out of date; CI runs it.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
RESULTS = {"synthetic": ROOT / "docs" / "eval" / "results-synthetic-7d.json",
           "lanl": ROOT / "docs" / "eval" / "results-lanl-v2.json"}
DOCUMENTS = (ROOT / "EVALUATION.md", ROOT / "README.md")
SYSTEMS = ("B0 passthrough", "B1 tuple dedup", "B2 rule window", "pipeline, every incident", "pipeline, surfaced")
LABELS = {"B0 passthrough": "B0 passthrough", "B1 tuple dedup": "B1 tuple dedup", "B2 rule window": "B2 rule window",
          "pipeline, every incident": "Pipeline, every incident", "pipeline, surfaced": "**Pipeline, surfaced**"}
MARKER = re.compile(r"(<!-- generated:(?P<name>[a-z0-9-]+) -->\n)(.*?)(<!-- /generated:(?P=name) -->)", re.S)


def _n(value: float) -> str:
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    return f"{value:,}" if isinstance(value, int) else f"{value:,.1f}"


def _pct(value: float, digits: int = 1) -> str:
    return f"{100 * value:.{digits}f} %"


def _table(header: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    return "\n".join(lines + ["| " + " | ".join(row) + " |" for row in rows]) + "\n"


def reduction(result: dict) -> str:
    rows = []
    for name in SYSTEMS:
        r = result["systems"][name]["reduction"]
        rows.append([LABELS[name], _n(r["input_alerts"]), _n(r["output_incidents"]), f"{r['reduction_pct']:.2f} %",
                     _n(r["median_alerts_per_incident"]), _n(r["p95_alerts_per_incident"])])
    return _table(["System", "Input alerts", "Output incidents", "Reduction", "Median alerts / incident",
                   "p95 alerts / incident"], rows)


def detection(result: dict) -> str:
    blocks = []
    for tau in ("tau_0", "tau_0.5"):
        rows = []
        for name in SYSTEMS:
            d = result["systems"][name]["detection"][tau]
            low, high = d["miss_rate_ci95"]
            rows.append([LABELS[name], _n(d["episodes"]), _n(d["detected"]), f"**{d['missed']}**",
                         f"**{_pct(d['miss_rate'])}** ({_pct(low)}–{_pct(high)})", _n(d["spurious_incidents"]),
                         f"{d['precision']:.2f}", f"{d['recall']:.2f}", f"{d['f1']:.2f}"])
        title = "τ = 0 (any overlap)" if tau == "tau_0" else "τ = 0.5 (most of the episode in one incident)"
        blocks.append(f"**{title}**\n\n" + _table(
            ["System", "Episodes", "Detected", "**Missed**", "**Miss rate** (95 % CI)", "Spurious incidents",
             "Precision", "Recall", "F1"], rows))
    layer = result["rule_layer"]
    blocks.append(f"The rules raised at least one alert for {layer['episodes_with_an_alert']} of "
                  f"{layer['episodes']} episodes; the other {layer['episodes'] - layer['episodes_with_an_alert']} "
                  "are missed by every system, which caps recall at "
                  f"{layer['episodes_with_an_alert'] / layer['episodes']:.2f}.\n")
    return "\n".join(blocks)


def clustering(result: dict) -> str:
    rows = []
    for name in SYSTEMS:
        c = result["systems"][name]["clustering"]
        rows.append([LABELS[name], f"{c['homogeneity']:.3f}", f"{c['completeness']:.3f}", f"{c['v_measure']:.3f}",
                     f"{c['ari']:.3f}", f"{c['mean_fragmentation']:.2f}", _n(c["over_merged_incidents"])])
    return _table(["System", "Homogeneity", "Completeness", "V-measure", "ARI", "Mean fragmentation",
                   "Over-merged incidents"], rows)


def scenarios(result: dict) -> str:
    rows = [[name.replace("_", " "), _n(row["episodes"]), _n(row["raised_an_alert"]), _n(row["detected_tau_0"]),
             _n(row["detected_tau_0.5"])] for name, row in result["pipeline_by_scenario"].items()]
    return _table(["Scenario", "Episodes", "Raised an alert", "Surfaced, τ = 0", "Surfaced, τ = 0.5"], rows)


def windows(result: dict) -> str:
    rows = []
    for row in result["window_sweep"]:
        cells = [_n(row["window_seconds"])]
        for name in ("B1 tuple dedup", "B2 rule window", "pipeline, surfaced"):
            cells += [_n(row[name]["output_incidents"]), _pct(row[name]["miss_rate_tau_0.5"])]
        rows.append(cells)
    return _table(["Window / gap (s)", "B1 incidents", "B1 miss rate", "B2 incidents", "B2 miss rate",
                   "Pipeline surfaced", "Pipeline miss rate"], rows)


def thresholds(result: dict) -> str:
    default = result["configuration"]["surface_threshold"]
    rows = [[f"**{row['threshold']}** (default)" if row["threshold"] == default else _n(row["threshold"]),
             _n(row["surfaced"]), f"{row['precision_tau_0.5']:.2f}", f"{row['recall_tau_0.5']:.2f}",
             _pct(row["miss_rate_tau_0.5"])] for row in result["threshold_sweep"]]
    return _table(["Surface threshold", "Surfaced incidents", "Precision τ = 0.5", "Recall τ = 0.5",
                   "Miss rate τ = 0.5"], rows)


def permutation(results: dict[str, dict]) -> str:
    rows = []
    for dataset, result in results.items():
        for tau, label in (("tau_0", "0"), ("tau_0.5", "0.5")):
            real = result["systems"]["pipeline, surfaced"]["detection"][tau]
            shuffled = result["permutation_control"][tau]
            rows.append([dataset, label, _n(real["detected"]), _n(shuffled["detected"]),
                         f"{real['precision']:.2f}", f"{shuffled['precision']:.2f}"])
    return _table(["Dataset", "τ", "Detected, real labels", "Detected, shuffled labels", "Precision, real",
                   "Precision, shuffled"], rows)


def datasets(results: dict[str, dict]) -> str:
    synthetic, lanl = results["synthetic"], results["lanl"]
    syn, real = synthetic["dataset"], lanl["dataset"]
    rows = [
        ["Kind", "Synthetic, labelled by construction", "Real (LANL, public domain), red-team labels"],
        ["Span", f"{syn['days']} days", f"days {real['window']['first_day']}–{real['window']['first_day'] + real['window']['days'] - 1}"
         f" of 58"],
        ["Raw records", f"{_n(syn['events'])} sshd log lines", f"{_n(real['records'])} logon records"],
        ["Attack episodes", _n(syn["episodes"]), _n(real["episodes"])],
        ["Alerts raised", _n(synthetic["alerts"]["count"]), _n(lanl["alerts"]["count"])],
        ["Alerts on attack records", _n(synthetic["alerts"]["attack_alerts"]), _n(lanl["alerts"]["attack_alerts"])],
        ["Benign share of alerts", _pct(synthetic["alerts"]["benign_share"]), _pct(lanl["alerts"]["benign_share"])],
        ["Fingerprint", f"`events.jsonl` SHA-256 `{syn['sha256']['events.jsonl'][:16]}…`",
         f"`records.jsonl` SHA-256 `{real['sha256']['records.jsonl'][:16]}…`"],
    ]
    return _table(["", "Synthetic week (seed 20261115)", "LANL slice v2"], rows)


def readme(results: dict[str, dict]) -> str:
    synthetic, lanl = results["synthetic"], results["lanl"]
    ours = synthetic["systems"]["pipeline, surfaced"]
    b1 = synthetic["systems"]["B1 tuple dedup"]
    d = ours["detection"]["tau_0.5"]
    low, high = d["miss_rate_ci95"]
    layer = lanl["rule_layer"]
    return (f"**Results:** on a labelled synthetic week (seed 20261115), {_n(synthetic['alerts']['count'])} raw "
            f"alerts become **{_n(ours['reduction']['output_incidents'])} incidents surfaced "
            f"({ours['reduction']['reduction_pct']:.2f} % fewer)**; **{d['detected']} of {d['episodes']} attacks "
            f"are caught, miss rate {_pct(d['miss_rate'])} (95 % CI {_pct(low)}–{_pct(high)})**, precision "
            f"{d['precision']:.2f}. Tuple dedup keeps {_n(b1['reduction']['output_incidents'])} incidents and misses "
            f"{_pct(b1['detection']['tau_0.5']['miss_rate'])} at the same bar. On real LANL authentication data the "
            f"rules see only {layer['episodes_with_an_alert']} of {layer['episodes']} red-team episodes; the method, "
            "baselines and limits are in [EVALUATION.md](./EVALUATION.md).\n")


def blocks(results: dict[str, dict]) -> dict[str, str]:
    rendered = {"datasets": datasets(results), "permutation": permutation(results), "readme-results": readme(results)}
    for dataset, result in results.items():
        for name, render in (("reduction", reduction), ("detection", detection), ("clustering", clustering)):
            rendered[f"{name}-{dataset}"] = render(result)
    rendered["scenarios-synthetic"] = scenarios(results["synthetic"])
    rendered["windows-synthetic"] = windows(results["synthetic"])
    rendered["thresholds-synthetic"] = thresholds(results["synthetic"])
    return rendered


def refresh(text: str, rendered: dict[str, str]) -> tuple[str, set[str]]:
    used: set[str] = set()

    def replace(match: re.Match) -> str:
        name = match.group("name")
        if name not in rendered:
            raise KeyError(f"no generated block named {name!r}")
        used.add(name)
        return match.group(1) + rendered[name] + match.group(4)

    return MARKER.sub(replace, text), used


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="fail instead of writing when a document is stale")
    args = parser.parse_args(argv)
    results = {name: json.loads(path.read_text()) for name, path in RESULTS.items()}
    rendered, stale, used = blocks(results), [], set()
    for document in DOCUMENTS:
        text = document.read_text()
        updated, names = refresh(text, rendered)
        used |= names
        if updated != text:
            stale.append(document.name)
            if not args.check:
                document.write_text(updated)
    unused = sorted(set(rendered) - used)
    if unused:
        print(f"generated blocks with no marker: {', '.join(unused)}")
        return 1
    if args.check and stale:
        print(f"out of date with results.json: {', '.join(stale)}; run python -m app.evaluation.report")
        return 1
    print(json.dumps({"updated" if not args.check else "stale": stale}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
