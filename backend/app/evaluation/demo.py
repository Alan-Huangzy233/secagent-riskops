"""The five-minute demo: one labelled synthetic day, reduced in front of you.

    python -m app.evaluation.demo        # what `docker compose up` and `make demo` run

It rebuilds the day from its seed and checks it against the published manifest,
raises alerts with the production rules, reduces them, and prints the
comparison last. Ground truth is read only to count caught and missed attacks.
The full seven-day evaluation, with confidence intervals and limits, is in
EVALUATION.md.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import time

from .. import reduction
from . import alerts as alert_layer
from . import baselines, metrics, synthetic

MANIFEST = Path(__file__).resolve().parents[3] / "examples" / "synthetic-sshd" / "manifest-1d.json"
SHOWN = 3


def _step(message: str) -> None:
    print(f"  {message}", flush=True)


def run(out=sys.stdout) -> int:
    started = time.perf_counter()
    print("SecAgent RiskOps — alert reduction on one labelled synthetic day (seed 20261115)\n", file=out)
    with tempfile.TemporaryDirectory() as scratch:
        data = Path(scratch)
        manifest = synthetic.write(synthetic.Config(days=1), data)
        verified = MANIFEST.exists() and not synthetic.mismatches(manifest, json.loads(MANIFEST.read_text()))
        _step(f"{manifest['events']:,} sshd log lines generated"
              + (", byte-identical to the published manifest" if verified else " (published manifest not found)"))
        records = alert_layer.load_records(data)
        raised = alert_layer.scheduled_alerts(records)
        _step(f"{len(raised):,} alerts raised by the detection rules, re-evaluated every "
              f"{alert_layer.TICK_SECONDS} s")
        incidents = reduction.reduce_alerts(raised, records)
        labels = {row["event_id"]: row["label"] for row in map(json.loads, (data / "labels.jsonl").open())}
        episodes = [row["episode_id"] for row in json.loads((data / "episodes.json").read_text())]
    owner = metrics.alert_labels(raised, labels)
    ours = [{"alert_ids": list(i.alert_ids), "surfaced": i.surfaced} for i in incidents]
    rows = [("B1 tuple dedup (what a SIEM does)", baselines.b1_tuple_dedup(raised)),
            ("SecAgent RiskOps, surfaced", ours)]
    _step(f"done in {time.perf_counter() - started:.0f} s\n")

    print(f"  {'':36}{'incidents':>11}{'reduction':>11}{'attacks caught':>16}{'miss rate':>11}{'precision':>11}",
          file=out)
    for name, found in rows:
        cut = metrics.reduction(found, len(raised))
        hit = metrics.detection(found, owner, episodes, tau=0.5, seed=0)
        print(f"  {name:36}{cut['output_incidents']:>11,}{cut['reduction_pct']:>10.2f}%"
              f"{hit['detected']:>9} of {hit['episodes']:<4}{100 * hit['miss_rate']:>10.1f}%"
              f"{hit['precision']:>11.2f}", file=out)
    print(f"\n  {len(raised):,} raw alerts in, the analyst reads the surfaced incidents. An attack counts as caught "
          "only when most\n  of its alerts land in one surfaced incident (τ = 0.5).\n", file=out)
    print("  Highest-scoring incidents, with the reasons behind each score:", file=out)
    top = sorted((i for i in incidents if i.surfaced), key=lambda i: (-i.score, i.incident_id))[:SHOWN]
    for incident in top:
        print(f"    {incident.priority}  score {incident.score:>3}  {', '.join(incident.src_ips)} -> "
              f"{', '.join(incident.hosts)}  ({len(incident.alert_ids)} alerts)", file=out)
        for reason in incident.reasons:
            print(f"          {reason}", file=out)
    print("\n  The seven-day evaluation, baselines, confidence intervals and limits: EVALUATION.md", file=out)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
