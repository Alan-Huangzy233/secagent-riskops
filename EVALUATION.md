# Evaluation

This document reports how well SecAgent RiskOps reduces alert volume without
losing real incidents, and how those numbers were produced. Every number here is
reproducible from a pinned dataset and a fixed seed; see
[Reproducing these numbers](#7-reproducing-these-numbers). The tables are
generated from `docs/eval/results-*.json` by `python -m app.evaluation.report`,
and CI fails if this document and those files disagree.

Status: reduction, detection and clustering are measured on two datasets, and
model-backed triage of the surfaced incidents — agreement, stability, cost and
latency — on both.

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

## 2. Datasets

<!-- generated:datasets -->
|  | Synthetic week (seed 20261115) | LANL slice v2 |
|---|---|---|
| Kind | Synthetic, labelled by construction | Real (LANL, public domain), red-team labels |
| Span | 7 days | days 12–14 of 58 |
| Raw records | 169,649 sshd log lines | 629,907 logon records |
| Attack episodes | 60 | 74 |
| Alerts raised | 32,458 | 2,262 |
| Alerts on attack records | 1,999 | 5 |
| Benign share of alerts | 93.8 % | 99.8 % |
| Fingerprint | `events.jsonl` SHA-256 `227a458837940c3f…` | `records.jsonl` SHA-256 `0292d8f5d36473cf…` |
<!-- /generated:datasets -->

**Synthetic week** (`backend/app/evaluation/synthetic.py`, seed `20261115`).
Raw sshd journal messages for twelve hosts over seven days: people logging in
and sometimes mistyping, automation, a monitor retrying an expired password,
internet scanners and commodity bots, and five attack scenarios, twelve of
each. Addresses come from `198.18.0.0/15`, one pool for every role. The events,
their labels and the episode list are separate files; the committed manifests
in `examples/synthetic-sshd/` hold the SHA-256 of each, and `make dataset`
rebuilds and verifies them.

**LANL slice** (`backend/app/evaluation/lanl.py`). Real Windows authentication
data from A. D. Kent, *Comprehensive, Multi-Source Cyber-Security Events*, Los
Alamos National Laboratory, 2015, doi:10.17021/1179829 (public domain). The
slice rule, fixed before any evaluation ran: the three consecutive days with the
most red-team events (days 12–14), `LogOn` records only, every record from the
window's red-team source computers plus a 2 % hash sample of the other source
computers. Slice rule 1 (every record touching a red-team computer) selected
15.3 million records through hub destinations and was replaced before any run.
`examples/lanl-slice/` holds the manifest and the SHA-256 of the source files.

**From logs to alerts.** The datasets are logs, not alerts. The production
rules of the live pilot (`backend/app/telemetry/detection.py`: burst,
slow scan, multiple accounts, cross-source, success after failures) run every
300 s over their lookback, the way a scheduled SIEM search does, and raise an
alert for each match that contains a record newer than the previous run
(`backend/app/evaluation/alerts.py`). This layer is part of the measured system:
it decides which attacks reach the pipeline at all.

No data from any real SOC engagement, and none from the live pilot, is used here.

---

## 3. Ground truth and the unit of evaluation

### 3.1 Alert labels

Each record carries `benign` or `attack:<episode_id>`. An alert takes the
episode that owns most of its evidence records, or `benign` when none do. No
alert on either dataset mixes attack and benign evidence.

### 3.2 Episodes

An **episode** is one ground-truth attack. In the synthetic week it is one
injected campaign. In the LANL slice it is one red-team account on one day —
deliberately not "one source close in time", which would mirror the pipeline's
own correlation rule and flatter it.

### 3.3 Matching predicted incidents to episodes

Let an incident `I` be a set of alerts, and an episode `E` be the set of alerts
labelled `attack:E`.

- `I` **covers** `E` at threshold τ when `|I ∩ E| / |E| ≥ τ`. **τ = 0 means any
  overlap** (the analyst sees something about this attack); **τ = 0.5** means
  most of the episode lands in one incident (the analyst sees a coherent
  picture). Both are reported because τ = 0 flatters the system; §6.7 shows by
  how much.
- `E` is **detected** when at least one *surfaced* incident covers it.
- `E` is **missed** when no surfaced incident covers it. **An episode that raised
  no alert at all is missed**, and is counted separately so the rule layer's
  share of the misses stays visible.
- `I` is **spurious** when it contains no attack-labelled alert.
- **Precision** is the share of surfaced incidents that cover some episode at τ.
- `I` is **over-merged** when it contains alerts from two or more episodes.
- **Fragmentation** of `E` is the number of incidents holding alerts of `E`.

---

## 4. Systems compared

A reduction percentage with no baseline is not a result. All systems read the
same alert stream (`backend/app/evaluation/baselines.py`,
`backend/app/reduction/`).

| ID | System | What it represents |
|---|---|---|
| B0 | Passthrough — one incident per alert | The analyst's status quo; supplies the denominator |
| B1 | Tuple dedup on `(rule_id, src_ip, hosts)`; a gap longer than the window starts a new group | What a SIEM does out of the box; the bar to beat |
| B2 | Tumbling-window aggregation on `rule_id` alone | Cruder still; tests whether correlation adds anything over time-bucketing |
| — | Pipeline, every incident: dedup + correlate, no score | Correlation alone |
| — | **Pipeline, surfaced**: dedup + correlate + score, incidents at or above the threshold | The claim |
| B3 | Label permutation control | Sanity check on the metric itself, not a competitor |

Baselines have no score, so every group they form reaches the analyst. The
window of B1 and B2 and the correlation gap of the pipeline are pinned at 600 s
and 3,600 s for the headline tables; §6.6 sweeps both.

**The pipeline** (`backend/app/reduction/`). *Dedup*: alerts of one rule, source
and set of hosts that share a log record are the same detection raised again.
*Correlate*: groups that share a record, or come from one source with active
periods at most an hour apart, form one incident; different sources are never
joined without a shared record. *Score*: fixed weights from what the logs show —
success after failures +50, each existing non-root account attempted +12 (at
most three; sshd's own `Invalid user` marks the rest), several hosts +10,
persistence over two hours +15, fifty or more failures +5, and −40 when every
success comes from a source that had already logged in as that user. Incidents
scoring 25 or more are surfaced; the rest are kept with their reasons. The
weights were fixed before any evaluation run and developed on a different seed
(7); §6.8 sweeps the threshold.

---

## 5. Metrics

All tables are in §6.

Miss rate is `1 − recall` and has its own column because it is the only number
here that corresponds to a real attack going unseen. Its 95 % interval comes
from 2,000 bootstrap resamples of the episodes (fixed seed), because with few
episodes one miss moves the rate a lot.

Raw accuracy is not reported for AI triage: a classifier that always answers
the majority class scores well and has learned nothing. Balanced accuracy,
Cohen's κ, abstention and the number of attacks dismissed are reported instead.

---

## 6. Results

### 6.1 Reduction

**Synthetic week**

<!-- generated:reduction-synthetic -->
| System | Input alerts | Output incidents | Reduction | Median alerts / incident | p95 alerts / incident |
|---|---|---|---|---|---|
| B0 passthrough | 32,458 | 32,458 | 0.00 % | 1 | 1 |
| B1 tuple dedup | 32,458 | 28,716 | 11.53 % | 1 | 2 |
| B2 rule window | 32,458 | 3,809 | 88.27 % | 6 | 26 |
| Pipeline, every incident | 32,458 | 9,473 | 70.81 % | 3 | 7 |
| **Pipeline, surfaced** | 32,458 | 50 | 99.85 % | 24 | 153 |
<!-- /generated:reduction-synthetic -->

**LANL slice**

<!-- generated:reduction-lanl -->
| System | Input alerts | Output incidents | Reduction | Median alerts / incident | p95 alerts / incident |
|---|---|---|---|---|---|
| B0 passthrough | 2,262 | 2,262 | 0.00 % | 1 | 1 |
| B1 tuple dedup | 2,262 | 1,248 | 44.83 % | 1 | 4 |
| B2 rule window | 2,262 | 981 | 56.63 % | 2 | 5 |
| Pipeline, every incident | 2,262 | 70 | 96.91 % | 5 | 285 |
| **Pipeline, surfaced** | 2,262 | 32 | 98.58 % | 14 | 323 |
<!-- /generated:reduction-lanl -->

### 6.2 Detection quality

**Synthetic week**

<!-- generated:detection-synthetic -->
**τ = 0 (any overlap)**

| System | Episodes | Detected | **Missed** | **Miss rate** (95 % CI) | Spurious incidents | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| B0 passthrough | 60 | 42 | **18** | **30.0 %** (20.0 %–41.7 %) | 30,459 | 0.06 | 0.70 | 0.11 |
| B1 tuple dedup | 60 | 42 | **18** | **30.0 %** (20.0 %–41.7 %) | 28,008 | 0.02 | 0.70 | 0.05 |
| B2 rule window | 60 | 42 | **18** | **30.0 %** (20.0 %–41.7 %) | 3,024 | 0.21 | 0.70 | 0.32 |
| Pipeline, every incident | 60 | 42 | **18** | **30.0 %** (20.0 %–41.7 %) | 9,429 | 0.00 | 0.70 | 0.01 |
| **Pipeline, surfaced** | 60 | 41 | **19** | **31.7 %** (21.7 %–43.3 %) | 7 | 0.86 | 0.68 | 0.76 |

**τ = 0.5 (most of the episode in one incident)**

| System | Episodes | Detected | **Missed** | **Miss rate** (95 % CI) | Spurious incidents | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| B0 passthrough | 60 | 1 | **59** | **98.3 %** (95.0 %–100.0 %) | 30,459 | 0.00 | 0.02 | 0.00 |
| B1 tuple dedup | 60 | 2 | **58** | **96.7 %** (91.7 %–100.0 %) | 28,008 | 0.00 | 0.03 | 0.00 |
| B2 rule window | 60 | 1 | **59** | **98.3 %** (95.0 %–100.0 %) | 3,024 | 0.00 | 0.02 | 0.00 |
| Pipeline, every incident | 60 | 42 | **18** | **30.0 %** (20.0 %–41.7 %) | 9,429 | 0.00 | 0.70 | 0.01 |
| **Pipeline, surfaced** | 60 | 41 | **19** | **31.7 %** (21.7 %–43.3 %) | 7 | 0.82 | 0.68 | 0.75 |

The rules raised at least one alert for 42 of 60 episodes; the other 18 are missed by every system, which caps recall at 0.70.
<!-- /generated:detection-synthetic -->

By scenario, for the surfaced pipeline:

<!-- generated:scenarios-synthetic -->
| Scenario | Episodes | Raised an alert | Surfaced, τ = 0 | Surfaced, τ = 0.5 |
|---|---|---|---|---|
| brute force success | 12 | 12 | 12 | 12 |
| distributed spray | 12 | 1 | 0 | 0 |
| low and slow | 12 | 5 | 5 | 5 |
| password spray | 12 | 12 | 12 | 12 |
| stuffing then success | 12 | 12 | 12 | 12 |
<!-- /generated:scenarios-synthetic -->

Almost every miss happens before the pipeline: distributed spray and slow
guessing were built to stay under the per-source thresholds, and they do. Of the
episodes the rules saw, the pipeline surfaced all but one. The baselines see the
same episodes at τ = 0 but scatter each one over many incidents, so at τ = 0.5
they miss almost everything.

**LANL slice**

<!-- generated:detection-lanl -->
**τ = 0 (any overlap)**

| System | Episodes | Detected | **Missed** | **Miss rate** (95 % CI) | Spurious incidents | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| B0 passthrough | 74 | 4 | **70** | **94.6 %** (89.2 %–98.7 %) | 2,257 | 0.00 | 0.05 | 0.00 |
| B1 tuple dedup | 74 | 4 | **70** | **94.6 %** (89.2 %–98.7 %) | 1,244 | 0.00 | 0.05 | 0.01 |
| B2 rule window | 74 | 4 | **70** | **94.6 %** (89.2 %–98.7 %) | 977 | 0.00 | 0.05 | 0.01 |
| Pipeline, every incident | 74 | 4 | **70** | **94.6 %** (89.2 %–98.7 %) | 67 | 0.04 | 0.05 | 0.05 |
| **Pipeline, surfaced** | 74 | 4 | **70** | **94.6 %** (89.2 %–98.7 %) | 29 | 0.09 | 0.05 | 0.07 |

**τ = 0.5 (most of the episode in one incident)**

| System | Episodes | Detected | **Missed** | **Miss rate** (95 % CI) | Spurious incidents | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| B0 passthrough | 74 | 4 | **70** | **94.6 %** (89.2 %–98.7 %) | 2,257 | 0.00 | 0.05 | 0.00 |
| B1 tuple dedup | 74 | 4 | **70** | **94.6 %** (89.2 %–98.7 %) | 1,244 | 0.00 | 0.05 | 0.01 |
| B2 rule window | 74 | 4 | **70** | **94.6 %** (89.2 %–98.7 %) | 977 | 0.00 | 0.05 | 0.01 |
| Pipeline, every incident | 74 | 4 | **70** | **94.6 %** (89.2 %–98.7 %) | 67 | 0.04 | 0.05 | 0.05 |
| **Pipeline, surfaced** | 74 | 4 | **70** | **94.6 %** (89.2 %–98.7 %) | 29 | 0.09 | 0.05 | 0.07 |

The rules raised at least one alert for 4 of 74 episodes; the other 70 are missed by every system, which caps recall at 0.05.
<!-- /generated:detection-lanl -->

On real data the method mostly fails, and the reason is specific: the red team
logs in with valid credentials, and every rule here is driven by failed logins.
The pipeline surfaces the few episodes the rules see, but its precision is low
because the score's strongest signal, sshd's `Invalid user`, has no counterpart
in Windows authentication. Credential misuse without failures is outside what
this rule set can detect; it is listed in `ROADMAP.md` as future work, not
claimed here.

### 6.3 Clustering quality

**Synthetic week**

<!-- generated:clustering-synthetic -->
| System | Homogeneity | Completeness | V-measure | ARI | Mean fragmentation | Over-merged incidents |
|---|---|---|---|---|---|---|
| B0 passthrough | 1.000 | 0.425 | 0.597 | 0.000 | 47.60 | 0 |
| B1 tuple dedup | 1.000 | 0.545 | 0.705 | 0.172 | 16.86 | 0 |
| B2 rule window | 0.956 | 0.478 | 0.638 | 0.043 | 21.38 | 92 |
| Pipeline, every incident | 1.000 | 0.998 | 0.999 | 1.000 | 1.05 | 0 |
| **Pipeline, surfaced** | 1.000 | 0.998 | 0.999 | 1.000 | 1.05 | 0 |
<!-- /generated:clustering-synthetic -->

**LANL slice**

<!-- generated:clustering-lanl -->
| System | Homogeneity | Completeness | V-measure | ARI | Mean fragmentation | Over-merged incidents |
|---|---|---|---|---|---|---|
| B0 passthrough | 1.000 | 0.828 | 0.906 | 0.000 | 1.25 | 0 |
| B1 tuple dedup | 1.000 | 1.000 | 1.000 | 1.000 | 1.00 | 0 |
| B2 rule window | 1.000 | 1.000 | 1.000 | 1.000 | 1.00 | 0 |
| Pipeline, every incident | 0.792 | 1.000 | 0.884 | 0.615 | 1.00 | 1 |
| **Pipeline, surfaced** | 0.792 | 1.000 | 0.884 | 0.615 | 1.00 | 1 |
<!-- /generated:clustering-lanl -->

The near-perfect synthetic clustering is partly a property of the generator:
every synthetic episode except distributed spray comes from one address. It is
evidence that correlation does not smear a single-source attack, not that it
would group a multi-source one.

### 6.4 AI triage agreement

`backend/app/agents/model_triage.py` gives `claude-opus-5` (effort `medium`) a
dossier of each surfaced incident — sources, hosts, timing, the rules that
fired, per-account attempts and successes, whether sshd marked an account
invalid, whether a source had logged in cleanly as that account before, and a
sample of the records — and constrains the answer with a JSON schema to
`escalate`, `dismiss` or `abstain` with the event ids it relied on. The
pipeline's score and the labels are never sent. The system prompt states the
team's triage policy, which is the same line the ground truth draws (targeted
campaigns and successful guessing are attacks; opportunistic scanning of
generic names that never succeeds, and a known user mistyping, are noise), and
tells the model that account names are attacker-chosen data. A refusal or a
truncated answer counts as an abstention. The model accepts no temperature, so
every call is recorded in `docs/eval/triage-tape-*.jsonl`; `make triage`
replays the recording with no key and no cost, and CI checks the replay byte
for byte.

An incident's truth is `attack` when it holds any attack-labelled alert.
"Score only" is the status quo: every surfaced incident goes to the analyst.

<!-- generated:triage-agreement -->
| Dataset | Triage | Incidents | Attack / benign | Abstained | Balanced accuracy | Cohen's κ | **Attacks dismissed** | Benign dismissed |
|---|---|---|---|---|---|---|---|---|
| synthetic | claude-opus-5, effort medium | 50 | 43 / 7 | 0 (0 %) | 0.86 | 0.81 | **0** | 5 of 7 |
| synthetic | score only (every surfaced incident escalated) | 50 | 43 / 7 | 0 (0 %) | 0.50 | 0.00 | **0** | 0 of 7 |
| lanl | claude-opus-5, effort medium | 32 | 3 / 29 | 3 (9 %) | 0.94 | 0.61 | **0** | 23 of 29 |
| lanl | score only (every surfaced incident escalated) | 32 | 3 / 29 | 0 (0 %) | 0.50 | 0.00 | **0** | 0 of 29 |
<!-- /generated:triage-agreement -->

Each dataset was judged twice, in two independent live runs:

<!-- generated:triage-stability -->
| Dataset | Incidents judged twice | Same verdict | Agreement | Cohen's κ | Verdicts that changed |
|---|---|---|---|---|---|
| synthetic | 50 | 48 | 96.0 % | 0.80 | escalate → abstain, dismiss → abstain |
| lanl | 32 | 32 | 100.0 % | 1.00 | none |
<!-- /generated:triage-stability -->

On both datasets the model **dismissed no incident that held an attack**, in
either run. What it adds is on the benign side. On the synthetic week it
dismissed five of the seven benign incidents the score surfaced — scanners
sweeping generic names that sshd itself marks invalid — and escalated two: the
monitor retrying an expired password for six hours, and a user who mistyped
three times and then logged in on the first day, before any clean login could
vouch for that source. Both are cases an analyst would also check. On the LANL
slice it dismissed 23 of 29 benign incidents, almost all Windows machine
accounts (`C123$`) failing against their own host — stale cached credentials,
a pattern the rule-based score has no feature for — abstained on 3, and
escalated all 3 attack incidents. The analyst's queue there drops from 32
incidents to 6 escalations and 3 for review.

The two verdicts that changed between runs both moved to `abstain`, never
between `escalate` and `dismiss`; both were the expired-password monitor, which
the first run had judged once each way. That is the most ambiguous pattern in
the data, and the model's inconsistency on it is itself informative.

Limits: seven and twenty-nine benign incidents are small samples, and three
LANL attack incidents are fewer still; the prompt states the same triage policy
the ground truth encodes; and the model is a second opinion on incidents the
pipeline already chose. It never sees the incidents the score kept back, so it
cannot recover the pipeline's misses.

### 6.5 Cost and latency

Wall-clock on a 4-vCPU AMD EPYC virtual machine, Python 3.12, one run each.
The deterministic stages are single batch runs, so no p50/p95 is claimed for
them.

| Stage | Synthetic week (32,458 alerts) | LANL slice (2,262 alerts from 629,907 records) |
|---|---|---|
| Parse and normalize records | 3.5 s | 4.1 s |
| Rules on the 300 s schedule (log → alert) | 55.7 s | 184.7 s |
| Dedup + correlate + score | 2.7 s (0.08 s per 1,000 alerts) | 1.7 s |
| Model triage | see below | see below |

Model triage, one call per surfaced incident (first live run; prices at $5 / $25
per million input / output tokens):

<!-- generated:triage-cost -->
| Dataset | Calls | Input tokens | Output tokens | USD | USD per incident | USD per 1,000 alerts | Latency p50 / p95 | Served by | Stop reasons |
|---|---|---|---|---|---|---|---|---|---|
| synthetic | 50 | 141,182 | 20,349 | $1.24 | $0.025 | $0.038 | 8.8 s / 13.8 s | claude-opus-5 × 50 | end_turn × 50 |
| lanl | 32 | 88,105 | 14,867 | $0.82 | $0.026 | $0.364 | 8.7 s / 16.9 s | claude-opus-5 × 32 | end_turn × 32 |
<!-- /generated:triage-cost -->

The rule schedule dominates the deterministic stages, and the reduction itself
is cheap. Model triage costs cents per incident because it only ever sees what
the pipeline surfaces, never the raw alert stream.

### 6.6 Window sensitivity (synthetic week)

<!-- generated:windows-synthetic -->
| Window / gap (s) | B1 incidents | B1 miss rate | B2 incidents | B2 miss rate | Pipeline surfaced | Pipeline miss rate |
|---|---|---|---|---|---|---|
| 60 | 32,458 | 98.3 % | 6,800 | 98.3 % | 48 | 31.7 % |
| 300 | 28,986 | 96.7 % | 6,800 | 98.3 % | 48 | 31.7 % |
| 600 | 28,716 | 96.7 % | 3,809 | 98.3 % | 48 | 31.7 % |
| 1,800 | 28,237 | 88.3 % | 1,371 | 98.3 % | 48 | 31.7 % |
| 3,600 | 28,190 | 88.3 % | 701 | 98.3 % | 50 | 31.7 % |
<!-- /generated:windows-synthetic -->

The pipeline barely moves across a sixty-fold range of gaps; the baselines only
trade one kind of failure for another.

### 6.7 Permutation control

<!-- generated:permutation -->
| Dataset | τ | Detected, real labels | Detected, shuffled labels | Precision, real | Precision, shuffled |
|---|---|---|---|---|---|
| synthetic | 0 | 41 | 31 | 0.86 | 0.68 |
| synthetic | 0.5 | 41 | 0 | 0.82 | 0.00 |
| lanl | 0 | 4 | 4 | 0.09 | 0.09 |
| lanl | 0.5 | 4 | 4 | 0.09 | 0.09 |
<!-- /generated:permutation -->

At τ = 0.5 the synthetic result collapses to nothing under shuffled labels, as
it should. At τ = 0 it does not: with shuffled labels a large surfaced incident
still overlaps many random "episodes", which is exactly why τ = 0 alone would
flatter the system. On the LANL slice the control does not collapse at either
threshold, because the detected episodes raised only one or two alerts each;
**the LANL detection figure cannot be distinguished from chance**, and only the
rule-layer finding in §6.2 should be taken from it.

### 6.8 Surface threshold (synthetic week)

<!-- generated:thresholds-synthetic -->
| Surface threshold | Surfaced incidents | Precision τ = 0.5 | Recall τ = 0.5 | Miss rate τ = 0.5 |
|---|---|---|---|---|
| 0 | 9,473 | 0.00 | 0.70 | 30.0 % |
| 12 | 1,464 | 0.03 | 0.70 | 30.0 % |
| **25** (default) | 50 | 0.82 | 0.68 | 31.7 % |
| 40 | 38 | 0.95 | 0.60 | 40.0 % |
| 60 | 32 | 0.97 | 0.52 | 48.3 % |
<!-- /generated:thresholds-synthetic -->

The default was chosen before any evaluation run; the sweep shows it sits at the
knee, and what moving it costs in either direction.

---

## 7. Reproducing these numbers

```bash
git clone https://github.com/Alan-Huangzy233/secagent-riskops && cd secagent-riskops
make install
make evaluate      # rebuilds the synthetic week, verifies it, writes docs/eval/results-synthetic-7d.json
```

CI runs the same steps on a clean runner and fails unless the result is
byte-identical to the committed file. The LANL slice needs the source data
(registration at <https://csr.lanl.gov/data/cyber1/>); the commands and the
source fingerprints are in `examples/lanl-slice/README.md`.

| Field | Synthetic week | LANL slice |
|---|---|---|
| Method committed | `c2740b5` | `6ecdcd6` (slice rule 2) |
| Results committed | `4d7b9c5` | `38385b7` |
| Seed | `20261115` | `20261115` (hash sample) |
| Dataset fingerprint | `examples/synthetic-sshd/manifest-7d.json` | `examples/lanl-slice/manifest-v2.json` |
| LLM | `claude-opus-5`, effort `medium`, recorded per call | same |
| Hardware | 4-vCPU AMD EPYC VM | same |
| Wall-clock for a full run | about 2 minutes | about 9 minutes (slice 5.6 + evaluation 3.5) |

Two runs on the same commit and seed produce byte-identical `results.json`. If
they ever do not, the cause is recorded in §9 rather than silently retried.

---

## 8. Threats to validity

1. **Ground truth is dataset labels, not analyst decisions.** Synthetic labels
   are true by construction; LANL labels are the red team's own record. Neither
   is "an alert a human would have wanted to see", and the benign/attack line
   for the synthetic week (commodity scanning is benign, targeted campaigns are
   attacks) is a choice stated in §2.
2. **The rules and the generator have one author.** The scenario catalogue and
   the score were written by the same person, so the synthetic week is not an
   independent test of the score. The weights were fixed before any evaluation
   run and developed on another seed, and the LANL slice is the external check;
   on it the method does poorly, which is reported, not tuned away.
3. **The rule layer caps recall.** Most misses on both datasets are attacks the
   rules never alert on. The reduction pipeline cannot recover what never
   reaches it.
4. **Synthetic structure.** Synthetic episodes are single-source except
   distributed spray, which favours source-based correlation (§6.3).
5. **No adaptive adversary.** Correlation keys are an attack surface: an attacker
   who spreads over many addresses, or stays under the per-source thresholds, is
   summarised away or never alerted on. Distributed spray and slow guessing
   exercise this, and the pipeline misses them.
6. **LLM nondeterminism.** The model takes no temperature, so a verdict can
   change between runs; §6.4 measures how often. Published triage numbers come
   from the recorded first run, replayed byte for byte; the served model is
   recorded per call. A provider-side model update would change future runs,
   not the recording.
7. **Scale.** 32,458 alerts in a week and 2,262 from 630 k LANL records. The rule
   schedule is the bottleneck; behaviour at 10⁶ alerts per day is untested.
8. **Few episodes.** Sixty and seventy-four. One missed episode moves the
   synthetic miss rate by 1.7 points; quote the interval, not the point.

---

## 9. Evaluation run log

| Date | Commit | Dataset | Model snapshot | Change | Miss rate (τ = 0.5) |
|---|---|---|---|---|---|
| 2026-09-23 | `4d7b9c5` | synthetic week, seed 20261115 | none | First headline run; method committed in `c2740b5` | 31.7 % |
| 2026-09-23 | `38385b7` | LANL slice rule 2 | none | First LANL run; slice rule changed in `6ecdcd6` before it | 94.6 % |
| 2026-09-23 | `cd90e76` (method) | synthetic week and LANL slice | `claude-opus-5`, effort `medium` | Model triage of surfaced incidents, first run and an independent rerun; triage cannot change the miss rate and dismissed no attack | unchanged |

Every published number traces to a row here. Rows are appended, never edited.
