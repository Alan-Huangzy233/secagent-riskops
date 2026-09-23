# Evaluation

This document reports how well SecAgent RiskOps reduces alert volume without
losing real incidents, and how those numbers were produced. Every number here is
reproducible from a pinned dataset and a fixed seed; see
[Reproducing these numbers](#7-reproducing-these-numbers).

Status: **numbers not yet filled in.** Cells marked `—` are pending. The
evaluation harness (`scripts/eval/`, `make evaluate`) and the dataset are being
built; this document fixes the method before any number is produced, so the
metrics cannot be chosen after seeing the results.

---

## 1. What is being measured

One claim: *a stream of raw alerts is reduced to a much smaller set of incidents
that an analyst can work through, without dropping attacks.*

Two things have to be true at once, and they trade off against each other:

- **Volume goes down.** Measured as the reduction from input alerts to output
  incidents.
- **Nothing real disappears.** Measured as the miss rate over ground-truth
  attack episodes.

A system can trivially win either one alone. Reporting them together, against
baselines, is the point of this document.

Out of scope here: remediation execution, GRC control mapping, and knowledge-base
quality. Those are described in `ROADMAP.md` and are not evaluated yet.

---

## 2. Dataset

| Field | Value |
|---|---|
| Dataset | — |
| Version / release | — |
| SHA-256 of the archive | — |
| Time span covered | — |
| Raw records | — |
| Detection rule set used to generate alerts | `rules/` @ commit — |
| Alerts generated | — |
| Attack episodes labelled | — |
| Sample committed to the repo | `examples/` (— MB, — alerts) |

The public datasets are network traffic and host logs, **not alerts**. A fixed
rule set in `rules/` converts them into alerts first; that conversion is part of
the measured system and its code is in the repository. Changing the rule set
changes the input volume and therefore every reduction figure below, so the rule
set commit is pinned in the table above.

No data from any real SOC engagement is used here. All inputs are public or
synthetic, so any third party can re-run these numbers.

---

## 3. Ground truth and the unit of evaluation

### 3.1 Alert labels

Each generated alert inherits a label from the underlying dataset record:

- `benign`
- `attack:<episode_id>` — the alert is part of a known attack episode

### 3.2 Episodes

An **episode** is one ground-truth attack, identified by the dataset's own
campaign or scenario labels. An episode usually spans many alerts across
multiple rules and hosts. Episodes are the unit that matters: an analyst needs
to learn about the attack once, not once per alert.

### 3.3 Matching predicted incidents to episodes

Everything in §5 depends on this rule, so it is stated explicitly.

Let an incident `I` be a set of alerts, and an episode `E` be the set of alerts
labelled `attack:E`.

- `I` **covers** `E` at threshold τ when `|I ∩ E| / |E| ≥ τ`.
- `E` is **detected** when at least one incident covers it. Results are reported
  at **τ = 0** (any overlap — the analyst sees something about this attack) and
  at **τ = 0.5** (the majority of the episode lands in one incident — the analyst
  sees a coherent picture). Both are reported because τ = 0 flatters the system.
- `E` is **missed** when no incident covers it at the stated τ.
- `I` is **spurious** when `I` contains no attack-labelled alerts at all. This is
  wasted analyst time.
- `I` is **over-merged** when it contains alerts from two or more distinct
  episodes. Two attacks presented as one is a safety problem, not just a quality
  problem.
- **Fragmentation** of `E` is the number of distinct incidents containing alerts
  of `E`. Fragmentation above 1 means the analyst has to reassemble the story.

---

## 4. Baselines

A reduction percentage with no baseline is not a result. Four comparisons are run
on identical input.

| ID | Baseline | What it represents |
|---|---|---|
| B0 | Passthrough — one incident per alert | The analyst's status quo; supplies the denominator |
| B1 | Tuple dedup on `(rule_id, src_ip, dst_ip)` within a fixed window | What a SIEM does out of the box; the bar to beat |
| B2 | Tumbling-window aggregation on `rule_id` alone | Cruder still; catches whether correlation adds anything over time-bucketing |
| B3 | Label permutation control | Sanity check on the metric itself, not a competitor |

B3 shuffles the ground-truth labels across alerts and re-runs scoring unchanged.
If the system's detection scores do not collapse to chance under B3, the metric
or the matching rule is broken and the other rows mean nothing. Run it every time.

### Reference implementation

Canonical code lives in `scripts/eval/baselines.py`; the definitions are short
enough to state here so that the comparison is unambiguous.

```python
from collections import defaultdict

WINDOW_S = 600  # pinned; sensitivity reported in §6

def b0_passthrough(alerts):
    return [[a] for a in alerts]

def b1_tuple_dedup(alerts, window_s=WINDOW_S):
    """Group by (rule_id, src_ip, dst_ip); start a new group when the gap
    since the previous alert in that group exceeds the window."""
    buckets, out = {}, defaultdict(list)
    for a in sorted(alerts, key=lambda x: x.ts):
        key = (a.rule_id, a.src_ip, a.dst_ip)
        prev = buckets.get(key)
        if prev is None or a.ts - prev[1] > window_s:
            gid = (key, a.ts)
            buckets[key] = (gid, a.ts)
        else:
            gid = prev[0]
            buckets[key] = (gid, a.ts)
        out[gid].append(a)
    return list(out.values())

def b2_window_agg(alerts, window_s=WINDOW_S):
    """Tumbling windows keyed on rule_id only."""
    out = defaultdict(list)
    for a in alerts:
        out[(a.rule_id, int(a.ts // window_s))].append(a)
    return list(out.values())

def b3_permuted_labels(alerts, seed):
    """Returns a copy of the alert set with labels shuffled. The pipeline under
    test is NOT modified; only scoring input changes."""
    import random
    rng = random.Random(seed)
    labels = [a.label for a in alerts]
    rng.shuffle(labels)
    return [a.with_label(l) for a, l in zip(alerts, labels)]
```

`WINDOW_S` is a free parameter that makes B1 and B2 look better or worse. It is
pinned at 600 s for the headline table, and §6.6 reports the sweep so the choice
cannot be accused of being tuned against the baselines.

---

## 5. Metrics

### Table 1 — Reduction

| System | Input alerts | Output incidents | Reduction % | Median alerts/incident | p95 alerts/incident |
|---|---|---|---|---|---|

### Table 2 — Detection quality, episode level

Reported at τ = 0 and τ = 0.5 as separate blocks.

| System | Episodes | Detected | **Missed** | **Miss rate** | Spurious incidents | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|

Miss rate is `1 − recall` and is given its own column deliberately. It is the
only number in this document that corresponds to a real attack going unseen, and
it should not require arithmetic to find. A bootstrap 95 % CI accompanies it,
because with few episodes a single miss moves the rate a lot.

### Table 3 — Clustering quality

| System | Homogeneity | Completeness | V-measure | ARI | Mean fragmentation | Over-merged incidents |
|---|---|---|---|---|---|---|

Table 2 can look good while the grouping is incoherent — an attack detected but
smeared across eleven incidents is technically detected and practically useless.
Table 3 is what catches that.

### Table 4 — AI triage agreement

Measured only on the incidents surfaced by the pipeline, against the same ground
truth.

| Model / config | n | Abstention rate | Coverage | Balanced accuracy | Cohen's κ | Escalation recall |
|---|---|---|---|---|---|---|

Raw accuracy is **not** reported. Most alerts in this setting are benign, so a
classifier that answers "benign" every time scores a high raw accuracy and has
learned nothing. Balanced accuracy and κ are used instead; the benign share of
the evaluated set is reported in §2.

Abstention is a feature, not a failure: a triage agent that declines low-confidence
calls and routes them to a human is behaving correctly. Coverage and accuracy are
therefore reported as a pair, and the coverage/accuracy curve is plotted in
`docs/eval/coverage.svg`.

### Table 5 — Cost and latency, per 1 000 input alerts

| Stage | p50 latency | p95 latency | LLM calls | Input tokens | Output tokens | USD |
|---|---|---|---|---|---|---|
| Normalize | | | | | | |
| Deduplicate | | | | | | |
| Correlate | | | | | | |
| Enrich | | | | | | |
| Score | | | | | | |
| AI triage | | | | | | |
| **Total** | | | | | | |

---

## 6. Results

### 6.1 Reduction
*(Table 1)*

### 6.2 Detection quality
*(Table 2, τ = 0 and τ = 0.5)*

### 6.3 Clustering quality
*(Table 3)*

### 6.4 AI triage agreement
*(Table 4)*

### 6.5 Cost and latency
*(Table 5)*

### 6.6 Window sensitivity
Reduction and miss rate for B1, B2 and the full pipeline at
`WINDOW_S ∈ {60, 300, 600, 1800, 3600}`.

### 6.7 Permutation control
B3 scores. Expected: detection collapses to chance. If it does not, §6.1–6.4 are
void.

---

## 7. Reproducing these numbers

```bash
git clone https://github.com/Alan-Huangzy233/secagent-riskops
cd secagent-riskops
docker compose up -d
make evaluate          # writes docs/eval/results.json and refreshes §6
```

| Field | Value |
|---|---|
| Git commit | — |
| Seed | `20261115` |
| Dataset SHA-256 | — |
| LLM snapshot | — |
| Hardware | — |
| Wall-clock for a full run | — |

Two runs of `make evaluate` on the same commit, seed and model snapshot must
produce byte-identical `results.json`. If they do not, the run is not
reproducible and the cause is recorded in §9 rather than being silently retried.

---

## 8. Threats to validity

1. **Ground truth is dataset labels, not analyst decisions.** A labelled attack
   record and "an alert a human would have wanted to see" are not the same set.
   Real triage is narrower and partly subjective; these numbers likely flatter
   recall relative to a live SOC.
2. **The alert-generation rule set is mine.** A different rule set produces a
   different input volume, so reduction percentages are not comparable across
   papers or products that started from different alerts.
3. **Single dataset, single topology.** No claim of generalisation is made. Cross-
   dataset evaluation is listed in `ROADMAP.md`.
4. **No adaptive adversary.** Correlation and suppression keys are themselves an
   attack surface: an attacker who knows that alerts merge on
   `(rule_id, src_ip)` can shelter inside an existing noisy cluster and be
   summarised away. Nothing here tests that, and it is the most security-relevant
   gap in this evaluation.
5. **LLM nondeterminism.** Temperature 0 does not guarantee stability across
   provider-side model updates. Runs are pinned to a model snapshot; drift is
   recorded in §9.
6. **Scale.** Evaluated at the volume in §2. Behaviour at 10⁶ alerts/day is
   untested and the correlation stage is the likely bottleneck.
7. **Few episodes.** With a small number of ground-truth episodes, one missed
   episode moves the miss rate by a large margin; CIs are reported and point
   estimates alone should not be quoted.

---

## 9. Evaluation run log

| Date | Commit | Dataset | Model snapshot | Change | Miss rate (τ=0.5) |
|---|---|---|---|---|---|

Every published number traces to a row here. Rows are appended, never edited.
