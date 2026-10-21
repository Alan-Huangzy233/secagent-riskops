# Continuous network analysis and console

This increment of [#120](https://github.com/Alan-Huangzy233/secagent-riskops/issues/120)
connects [durable network ingestion](network-ingestion.md) to bounded continuous
analysis, versioned evidence, advisory scores and console notifications. It is
implemented for review; production source enrollment and passive acceptance are
still pending. `network_ingest: null` remains the default: no network database
or worker is created without explicit configuration. No model call, firewall
change or response action is part of analysis.

## Correlation and score

The [existing rule](network-detection.md) requires at least ten distinct TCP
destination ports within 300 seconds, verified local-input provenance and SYN
without ACK/RST/FIN. Continuous analysis retains that rule. Review cases group
one source, boot, profile revision, apparent source IP and destination IP per
**monotonic-clock hour**, including five minutes of context on each side. A
cross-hour pattern can therefore appear in two cases with shared evidence;
case counts are not unique attack counts. Wall-clock timestamps are displayed
as journal observations and never determine the detection interval.

One qualifying case scores **35 / P3**, once per rule, with an explicit scoring
version and reason. Repeated observations do not accumulate unbounded points.
This score describes an observed probing pattern, not successful connections,
a final firewall verdict, exploitation, attribution or compromise. UDP traffic,
normal same-port retransmissions, non-SYN traffic and uncertain directions do
not satisfy this rule. No alert is not proof of safety: source logging limits
and journal coverage still apply. The SSH management allowlist does not exempt
all network observations; no maintenance authorization or suppression UI is
introduced here.

Late accepted observations dirty the affected windows. A changed result gets
an immutable revision, a digest and the exact selected normalized evidence.
Previous revisions and their evidence remain readable after ordinary event
retention. An unchanged replay does not create another version. When bounded
context cannot be reconstructed, an existing case retains its last verifiable
assessment/evidence and is marked stale; a previously unseen incomplete window
does not fabricate a complete scored result. Rate-limit and source-report
warnings remain visible separately and do not, by themselves, erase a valid
observed pattern or raise its score.

## Durability and resource boundaries

Receipt and batch checkpoints, pending windows, context, immutable revisions,
evidence membership and the notification outbox live in the same network
SQLite database. Intake advances through retained identity receipts, so an
accepted event that expired before analysis is detected as missing. Missing
observations retain source/boot/monotonic scope. Context retention uses server
receipt time rather than the journal wall clock. Batch report history remains
visible even after a clean heartbeat. Current delivery health and cumulative
historical coverage are different signals.

By default each tick consumes at most 200 identity receipts and 20 batch reports,
recalculates at most five windows (at most 5,000 records / 4 MiB per window),
and removes at most 200 expired context rows, using short transactions. Window
recalculation waits for a persisted finite receipt/batch boundary, then drains
that cycle's pending windows before opening the next cycle. New arrivals remain
pending without indefinitely postponing that cycle's detection; restart keeps
the same boundary. Status still reports the entire current backlog. Measure
intake capacity before enrollment; these bounds are not a throughput guarantee. Analysis writes
use the same database/WAL capacity guard as ingestion; they do not create an
unlimited side database. Case/evidence/revision/receipt history is not silently
pruned: the configured storage limit eventually stops new writes. The status
API exposes storage limits, pending analysis and coverage failures. Safe
long-term compaction and capacity calibration remain activation gates. The
analysis checkpoint uses receipt row IDs: do not manually delete/rebuild
receipts or run `VACUUM`/`VACUUM INTO`; any future compaction must preserve or
explicitly migrate that checkpoint identity.

The network database schema moves from version 1 to version 2. Only the known
version-1 schema is eligible for an atomic migration; existing receipts, ACKs
and collector checkpoints are preserved. Foreign/partially modified schemas
are rejected. An old binary cannot open schema version 2. Before upgrading an
**enabled** installation, obtain a consistent network recovery set and account
for this schema boundary in rollback; never restore an older database while
retaining a newer collector cursor. No network migration runs when the feature
is unconfigured. Paired network store/spool/cursor recovery acceptance is still
pending, so this code change alone does not authorize real enrollment.

## Console and notifications

The independent **网络检测** tab has source/filter controls, a paginated case
table and a nearby drawer for the selected revision and paginated evidence.
Monotonic windows are labelled as elapsed boot time, not calendar dates.
Collection health, historical gaps, analysis backlog, context failures and
storage limits are separate from case scores. Loading, disabled, empty and
read-failure states are explicit; source-controlled text is rendered as text.

Authenticated operator read endpoints:

- `GET /api/network/status`: ingestion, source health and `analysis` status.
- `GET /api/network/incidents`: `source_id`, `focus`, `page`, `limit` (at most 100).
  Focus is `all`, `attention`, `low`, `retracted` or `stale`.
- `GET /api/network/incidents/{id}?revision=N`: current or immutable revision.
- `GET /api/network/incidents/{id}/evidence?revision=N&page=1&limit=50`: evidence
  bound to that revision; at most 100 records per page.

A source Bearer token cannot read these operator endpoints. Existing event and
batch APIs retain their independent cursor/snapshot pagination. Missing or
unknown revisions return 404; read failures return an explicit error rather
than an empty success response.

When console notifications are enabled, network cases use `network_incident`
and current source-health changes use `network_collection`. They are separate
from SSH/HTTP notices. The bridge commits the imported producer revision in the
console before acknowledging its source outbox, making a crash in between safe
to retry. It never holds both database write locks together. Existing console
coalescing/cooldown applies; newer revisions can replace a pending notice, and
delivered history remains. Stale candidates cancel pending case notices. The
notification links to the version that generated it.

Source-health notices describe the latest sampled condition; they do not
promise one notification for every intermediate report. Historical reports and
missing evidence remain in network status/batch history. Setting
`notifications_enabled: false` stops this bridge but leaves configured network
analysis running. External push, network daily briefings, automatic AI and
remediation are outside this increment.

## Reproduce the synthetic path

With development dependencies installed, from the repository root:

```sh
PYTHONPATH=backend python scripts/simulate_network_analysis.py \
  --out runtime-data/network-analysis-simulation/report.json
python -m pytest backend/tests/test_network_incidents.py \
  backend/tests/test_network_worker.py backend/tests/test_network_dashboard.py \
  backend/tests/test_network_analysis_exercise.py
```

The exercise uses authored IPv4/IPv6 and UDP records, injected journal/SSH I/O,
in-process authenticated HTTP and disposable SQLite files. It checks threshold
crossing across batches, delayed evidence revisions, original ACK replay after
restart, revision-bound evidence pagination and notification import retries.
It neither reads host logs nor sends probes, contacts a provider or changes
production. These are functional acceptance checks, not a measured detection
accuracy, real-source, HTTPS, throughput or backup/restore result.

## Next gates and coverage expansion

Before real enrollment: verify complete source/profile provenance, perform a
passive source comparison, measure sustained resource usage, and accept paired
network recovery and long-term receipt handling. Keep #120 open until those
source-specific gates pass. The exporter still does not guard all native or
mixed nftables producers; this implementation does not resolve that boundary.

After the first source is accepted, consider small batches of additional
network rules supported by actual observations, such as slow multi-port probes
or repeated single-port probes. These are candidates requiring benign baselines
and separate acceptance, not implemented rules. DNS or egress detection needs
an appropriate additional data source. Linux host behavior
[#121](https://github.com/Alan-Huangzy233/secagent-riskops/issues/121) follows:
inventory sudo/account/privilege, service and scheduled-task evidence, then
select a reliable subset. Source inventory can proceed early. HTTP #119 still
awaits a real business service.
