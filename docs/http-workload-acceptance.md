# HTTP workload and catch-up acceptance

This isolated exercise checks the collection and analysis bounds for
[issue #119](https://github.com/Alan-Huangzy233/secagent-riskops/issues/119).
It sends synthetic access records through the actual collector CLI, a real
loopback TCP API and the normal background HTTP analysis worker. The API
runs in a separate process. Production record, byte and worker limits are
not reduced to make the cases pass.

## Run locally

Use Linux with `/proc` available and install the project's development
dependencies. From the repository root:

```sh
PYTHONPATH=backend python scripts/simulate_http_workload.py \
  --out runtime-data/http-workload-acceptance/report.json
```

`--out` is optional. Run without `python -O`; the acceptance assertions must
remain enabled. Nginx and external services are not required. The exercise
uses loopback HTTP, disposable source/operator credentials, temporary logs,
collector state and databases. It does not read production data, enroll a
source, change services or call a model. Temporary runtime files are removed
after completion; an explicitly requested report contains synthetic results
and resource observations.

Console caching, notifications and AI are disabled in this exercise to keep
the measurements focused on HTTP ingestion and analysis. Their contribution
to a full production workload is not measured. This exercise is independent
of the separate HTTPS acceptance work and does not validate TLS.

The record/page and context bounds remain at 200 records per page,
5 pages per run, 5,000 context records and 4 MiB of normalized context.
The ordinary test collector uses a 300-second per-stream budget and a
5-second HTTP timeout; those are deliberate drill settings, rather than the
collector defaults of 20 and 10 seconds. The time-budget case explicitly
sets its budget to 1 second. The API uses the normal background worker and
its normal processing bounds and polling schedule.

## Acceptance cases

| Case | Required behavior |
| --- | --- |
| Normal benign requests | Accepted records remain individually inspectable; ordinary requests do not create a detection case. |
| More than one collection run | The 200-record page and configured per-run page limit leave unread input for subsequent runs; eventual catch-up stores each occurrence once. |
| Per-stream time budget | A deliberately delayed response causes the collector to stop after a completed page reaches its time budget, retaining unread input for the next run. |
| Spool capacity | A batch exceeding the configured spool capacity is not transmitted or committed locally; raising capacity allows collection to resume. |
| Pending batch after server commit and restart | The harness submits the real pending batch directly to the API and withholds its ACK from the collector, then restarts the API. The unchanged collector spool replays to the original receipt without duplicate records or counters. |
| Record context limit | Exactly 5,000 records remain complete; adding record 5,001 produces visible `context_limit`. The previous verified score and evidence remain available, marked stale. |
| Byte context limit | More than 4 MiB of normalized context, with fewer than 5,000 records, produces the same explicit incomplete state. |
| New incomplete context | A new context over the limit cannot produce a case scored from a truncated sample. |
| Expired raw backlog | Durable receipts and collection counts can remain after raw-event expiry; analysis exposes the lost raw records instead of claiming full historical coverage. |
| Expired analysis context | A retained record whose window needs context older than retention is marked `expired_context`; incomplete evidence cannot establish a complete result. |

The 4 MiB bound counts UTF-8 bytes of the stored normalized record JSON,
including both original and decoded paths. It is not a limit on source-log
file size. Each analysis context belongs to a source, service, peer and UTC
hour, including five minutes on either side.

The collector checks its time budget after completing a page. The budget is
not a hard process deadline: an in-flight request can complete after the
budget, subject to its HTTP timeout. Budgets apply separately to each stream.

Collection acknowledgement and analysis catch-up are separate milestones.
A durable ACK commits intake data; the worker scores it asynchronously. The
report keeps these timings separate. Retry receipts describe the original
commit, so summing their `accepted` fields would overcount new records.
Acceptance instead checks durable event identities, receipts and counters.

An empty case list or `pending: false` alone is not proof of complete
coverage. Retention can remove raw data before analysis sees it, and completed
analysis can leave explicit context-limit or expiry issues. Inspect those
issues and `missing_raw_records` alongside collection and analysis progress.

## Resource observations

Each collector wrapper records its own CPU usage and maximum resident set
size with `RUSAGE_SELF`. The supervisor obtains the API child's resource usage
from `wait4` for that specific PID when it exits. Both describe the individual
process lifetime; the script does not subtract cumulative maxima across child
processes. API usage includes its background HTTP analysis work.

Collector CPU/RSS observations include interpreter and wrapper startup. Its
`elapsed_including_startup_seconds` additionally measures wall time from the
supervisor's process launch; the child wrapper's own `wall_seconds` starts
when its execution handler begins. These are process measurements, not total
host memory, filesystem cache or complete production-service consumption.

A separate sampler observes API RSS and the temporary HTTP/console database,
WAL, SHM, pending-spool and collector-cursor file sizes at approximately
50 ms intervals. The scenarios share the databases, so later file-size peaks
include retained data from previous phases; they are not incremental storage
costs of a single phase. The report distinguishes per-component peaks from
the highest combined size observed at
one instant. Adding independent component peaks would not establish an
actual simultaneous peak.

Sampled peaks can miss changes between samples. SQLite can checkpoint or
remove WAL files when connections close, so an end-of-run WAL size is not
the maximum used during ingestion. File sizes are logical byte lengths, not
allocated disk blocks or a filesystem quota. Source-log sizes are reported
separately from the managed database/spool/cursor total. Other temporary
files and filesystem overhead also matter when sizing a deployment.

The numeric observations depend on the machine, Python/SQLite versions,
filesystem and concurrent work. They are not a public-network requests-per-
second guarantee or a fixed RAM/disk recommendation. Logical assertions
verify catch-up and failure behavior; resource numbers provide evidence for
choosing the next representative workload.

## Remaining production boundaries

The worker currently analyzes windows after its intake catches up. With a
sustained arrival rate greater than its intake rate, acknowledged data can
continue accumulating while scoring remains pending. Fast ingestion ACKs
therefore do not establish real-time detection capacity. Validate sustained
arrival, end-to-end detection delay and recovery after a real outage for the
chosen source.

Raw-event and analysis-context cleanup is bounded, but receipts, case
revisions and retained evidence can continue growing. This short exercise
does not establish steady-state disk usage or a retention policy for all
tables. A single analysis window also holds a SQLite write transaction while
it calculates and saves its result; ingestion latency under representative
concurrency needs separate validation.

Issue #119 remains open. Production enrollment still needs the real source's
log format and peer semantics, TLS and credentials, rotation/retention,
rejected-line rate, alert usefulness and volume, and an accepted recovery
mapping. This exercise does not replace the
[paired recovery rehearsal](http-recovery.md), remote-collector/full-host
recovery acceptance or tests with notifications and console caching enabled.
