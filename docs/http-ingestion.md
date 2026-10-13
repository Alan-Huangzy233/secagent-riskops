# HTTP collection and durable ingestion

This is the opt-in HTTP ingestion and review path for
[issue #119](https://github.com/Alan-Huangzy233/secagent-riskops/issues/119).
It stores collector receipts, continuously correlates committed HTTP records,
and exposes scored, versioned cases in a separate console table. Qualifying
HTTP cases use the existing console notification queue. HTTP collection is
still disabled unless `http_ingest` is configured; this does not enroll a real
source or complete #119. SSH evidence, scoring, response actions and AI remain
separate. Daily briefings summarize SSH and HTTP separately; see
[HTTP daily briefings](console-notifications.md#http-daily-briefings).

## Run the isolated simulation

With development dependencies installed, from the repository root:

```sh
PYTHONPATH=backend python scripts/simulate_http_ingest.py \
  --out runtime-data/http-ingest-simulation/report.json
```

The script advances the 42 authored access records to a recent timestamp,
appends them in four groups, and runs the actual collector spool and
credential-bound API using an in-process ASGI transport and temporary
databases. It deliberately loses the first response **after database commit**,
then verifies the retry retains the same batch and receipt. It reads the
stored evidence through bounded API pages and drives the actual background
analysis worker after each batch. A separate rule replay checks the expected
patterns against those same committed inputs.
Expected findings: one sensitive-resource group (2 records), one traversal
attempt (1 record), and one multi-path scan (20 records spanning batches).
There are 42 unique stored requests, 3 persisted HTTP cases scored 25/35/30,
and 2 console notifications (scores 35 and 30). Repeat ticks do not duplicate
receipts, cases or notifications. There are no production writes or model calls.
Temporary logs/databases are removed after the run; the optional report is
synthetic. This is a reproducible functional exercise, not an accuracy estimate
or a test of a deployed TLS proxy/Nginx rotation.

The older `python -m app.evaluation.web` remains an offline file replay. Its
snapshot IDs and the durable collector's generation/offset IDs are different
identity schemes and must not be used interchangeably.

## Input and identity

Use the five-field [structured Nginx format](../deploy/nginx-http-access.example.conf)
and [parser contract](web-detection.md). Each service gets an explicit source
and service identity. `client_ip` is the connection peer; forwarded headers
are rejected. Proxy attribution and realip rewriting require a separate
reviewed adapter. Query suffixes are removed **before spooling**; neither raw
invalid lines nor cookies, headers, credentials or request bodies are sent.
A syntactically valid path can still contain sensitive material in path
segments: review application URLs before enrolling a real source.

The collector reads a local file on a Linux/POSIX log host. It pushes only to HTTPS,
or loopback HTTP, using an independent HTTP source token. It does not fetch a
remote file through SSH and does not discover services automatically. A source
token grants ingestion for that configured source's explicit service list;
SSH tokens cannot ingest HTTP and HTTP tokens cannot read operator APIs.

## Isolated configuration

Add this optional object to a **staging copy** of the live API configuration,
using a separate absolute database path and the SHA-256 of a privately
provisioned token:

```json
"http_ingest": {
  "database_path": "/var/lib/secagent-riskops-http/http.sqlite",
  "retention_days": 14,
  "sources": [{
    "id": "web-a", "hostname": "web-a.example.invalid",
    "services": ["public"], "token_sha256": "REPLACE_WITH_64_HEX_SHA256"
  }]
}
```

On the log host, create an owner-readable collector configuration (mode 0600):

```json
{
  "endpoint": "https://console.example.invalid/api/http/batches",
  "state_dir": "/var/lib/secagent-riskops-http-collector",
  "streams": [{
    "source_id": "web-a", "service_id": "public",
    "path": "/var/log/nginx/riskops-access.jsonl",
    "rotated_path": "/var/log/nginx/riskops-access.jsonl.1",
    "token": "REPLACE_WITH_INDEPENDENT_PRIVATE_TOKEN"
  }],
  "http_timeout_seconds": 10,
  "max_pages_per_run": 5,
  "max_seconds_per_stream": 20,
  "max_spool_bytes": 16777216,
  "rotation_quiet_seconds": 5
}
```

The examples are templates, not usable credentials or a production enrollment.
Install the Python package and keep both collector scripts together. With
appropriate file permissions and a private state directory, run:

```sh
PYTHONPATH=backend python scripts/http_collector.py \
  --once --config /etc/secagent-riskops/http-collector.json
```

Schedule only after staging acceptance. A process lock prevents overlapping
runs. Credentials are absent from cursor/spool files, reports and stdout.
Changing the destination, identity or file mapping with an outstanding cursor
or spool fails closed; settle the old stream first and enroll a new stream
with a new state directory. Token rotation alone preserves the spool.

## Delivery, rotation and limits

- Start from byte zero of the configured current file. There is no claim of
  coverage before that file. Every event ID binds a random file generation to
  its byte offset; equal lines at different offsets remain distinct requests.
- Atomically fsync a bounded pending batch before transmission. Require the
  matching source, service and batch ID plus `durable: true`, then fsync the
  new cursor **before** removing the spool. A failed request, invalid ACK or
  failed state write leaves the identical batch available for retry.
- One server transaction commits normalized events, rejection receipts, batch
  receipt and stream counters. Conflicting event/batch identities roll back
  the entire batch. Replaying a batch returns its original receipt without
  double-counting. Receipts are scoped by source **and service**.
- Read at most 200 lines and 1 MiB of input per page; each line is at most
  32 KiB and the outgoing body at most 900,000 bytes. Recheck consumed bytes
  before spooling to detect rewriting during the read. Catch-up is bounded by
  pages/time; one in-flight HTTP request can run to its configured timeout.
- Follow a single explicitly configured, uncompressed renamed file by device
  and inode. Drain it before starting the new current file. Wait for its
  modification time to be quiet before switching. Configure rename/reopen
  rotation so writers actually stop using the old file within that interval;
  a quiet interval cannot prove that a writer will never append again.
- Missing the retained old inode reports `rotation_gap`. Shrinkage or changed
  prefix/cursor anchors reports `file_truncated` and starts a new generation.
  `copytruncate` is not lossless: regrowth identical at both anchors, inode
  reuse with identical sampled bytes, late writes to a retired inode, or
  rotation through more retained files than configured can evade recovery.
  Use rename/reopen with retention longer than the maximum outage; compressed
  archives, glob discovery and arbitrary rotation histories are unsupported.
- A complete invalid line advances only after an explicit rejection receipt
  (generation/offset ID and reason, without raw text). A partial tail waits
  for its newline. An overlong line **stalls at its start**, reports the
  condition and requires fixing the source format; it is never silently cut
  or skipped. File errors do not advance the previous cursor.

Current status and historical integrity are separate: a subsequent healthy
heartbeat can become `current`, but prior batch reports/rejections remain
inspectable. The original collection timestamp survives retries, so a late
spooled batch is `delayed`, not freshly collected. `caught_up` describes the
file observation during collection, not the absence of historical gaps.

## API and storage

All bodies share the live API's 1 MiB request cap. Body/record validation errors
are generic and do not echo private values.

| Route | Authentication | Purpose |
| --- | --- | --- |
| `POST /api/http/batches` | HTTP source Bearer | Up to 200 combined records/rejections, collector timestamp, fixed report codes, catch-up state |
| `GET /api/http/streams` | Operator Basic | Configured streams, accepted/rejected totals, current/delayed/degraded/stale/never-seen status |
| `GET /api/http/events` | Operator Basic | Explicit source/service, `after`, `limit` (1–200), optional frozen `snapshot` |
| `GET /api/http/batches` | Operator Basic | Same keyset pagination for durable receipts, reports and rejected record IDs |
| `GET /api/http/status` | Operator Basic | Analysis progress, incomplete windows and collection status; `enabled: false` when unconfigured |
| `GET /api/http/incidents` | Operator Basic | HTTP-only source/service/focus filters and page/limit (up to 200) |
| `GET /api/http/incidents/{id}` | Operator Basic | Current case or immutable `revision` |
| `GET /api/http/incidents/{id}/evidence` | Operator Basic | Exact evidence for `revision`, page/limit (up to 200) |

`next_after`, `snapshot` and `has_more` allow complete bounded enumeration.
New ingests cannot enter a frozen page sequence. Raw-event retention can remove
rows while reading; this is not an archival snapshot. No full-table count is
needed. HTTP health contributes to `/health` only when HTTP is configured.

Raw events expire by event timestamp after the configured retention (14 days
by default), at most 1,000 rows per new batch including heartbeat batches.
Receipts, counters and rejection/gap history survive raw expiry; disk capacity
for these growing tables needs monitoring. A late event outside retention is
acknowledged and may immediately expire; durable receipt is not unlimited raw
retention. Case versions and their evidence survive raw-event expiry. They are
not automatically pruned; include their growth in disk monitoring and backup
capacity planning. Read endpoints do not advance analysis or call models.

## Continuous correlation and scores

The worker starts only for a configured HTTP database. A durable ACK commits
raw records first; analysis follows asynchronously. Each tick reads up to 200
new records and, once intake catches up, processes up to 5 affected windows in
separate transactions. Idle polls are five seconds; catch-up polls are one
second. Cursor, dirty windows, revisions and notification intent survive a
restart. A failed window transaction leaves it dirty for retry.

`http-peer-hour-v1` groups a review case by source, service, connection peer
and **UTC hour**. The existing 300-second sliding rules run over that hour with
five minutes of context on either side. Only findings touching the core hour
are retained. Cross-hour findings can appear in both adjacent review cases
with shared evidence: case counts are not counts of distinct attacks. Late
records dirty affected windows again, including adjacent hour boundaries.
For example, late normal responses can invalidate the scan's 80% denied
threshold and create a new, withdrawn revision with score zero.

| Pattern | Points per case | Interpretation |
| --- | --- | --- |
| Sensitive resource | 25 | A named resource was probed |
| Parent-directory traversal | 35 | The path expresses a traversal attempt |
| Multi-path scan | 30 | The documented request/path/denial thresholds match |

Each rule contributes once, regardless of request count. Total score is capped
at 90; P2 starts at 60, P3/console attention at 30, below 30 is low. This policy
is `http-evidence-v1`, a review aid rather than a calibrated compromise
probability. Status 200 does not add success points. No automatic response,
SSH whitelist inference or AI verdict is attached to an HTTP case.

Each analysis window is bounded to 5,000 records **and** 4 MiB of normalized
context. A truncated sample is never used to decide whether a scan occurred.
`context_limit` or `expired_context` preserves any previous verified score and
evidence, visibly marked stale; a new incomplete window appears in status
without inventing a case or a clean result. The status endpoint shows up to
50 recent incomplete windows and records lost to raw retention before intake.
Backlog and collection gaps must be checked before interpreting an empty table.
These limits need workload acceptance before real-source enrollment.

The incident, immutable revision, evidence membership and source notification
outbox commit atomically. Evidence APIs pin the revision across page reads;
old versions remain inspectable when newer evidence changes or withdraws a
pattern. The HTTP console has its own filters, pagination and nearby drawer;
overview/evidence tabs avoid scrolling through metadata to reach the evidence
table. The header counters remain explicitly SSH-scoped.

## Console notifications

Active, complete cases with score at least 30 and an hour ending within the
last 24 hours enqueue `http_incident` notifications. Historical backfills do
not flood the inbox. An idempotent bridge remembers imported source revisions
in the console database, then acknowledges the HTTP outbox; interruption
between the two commits safely replays. No transaction holds both DB locks.
The existing queue coalesces updates, retries failures and applies its one-hour
cooldown; priority escalation can bypass the cooldown. Disabling
`notifications_enabled` stops the bridge while retaining its outbox.

Withdrawn, stale or low-score revisions cancel pending delivery. Already
delivered notifications remain historical records and link to the exact HTTP
revision/evidence that generated them. A later withdrawal does not rewrite that
history. Delivery can briefly lag the current HTTP revision because the two
databases and workers synchronize asynchronously. HTTP does not enter the
SSH-specific delivery revalidation path, controls or AI summary.


## Before production activation

Validate a real source's format, peer semantics, rejected-line rate, rotation,
catch-up resource use and TLS/source authorization. Validate analysis latency,
context bounds, scoring usefulness and alert volume against that workload.
Extend the environment's backup/recovery mapping to include this independent
HTTP database, console notification checkpoints and collector state/spool, then
perform the [paired HTTP recovery rehearsal](http-recovery.md). The same-host
recovery mapping and an isolated real-Nginx drill are now available; remote
collectors and full-host restore still need separate acceptance.
The existing SSH recovery-package automation does **not** discover these new
paths automatically. No source is enrolled by merging this increment.

For code rollback, stop the HTTP collector and drain or retain its pending
spool, back up the HTTP store/state, remove `http_ingest` from the configuration,
then switch to the previous release (older config validation rejects unknown
fields; the receipt-only release also rejects newer analysis tables). Retain
the independent HTTP database for a future compatible release;
never reset offsets or delete receipts to make a retry succeed.
