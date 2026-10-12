# HTTP collection and durable ingestion

This is the first live-ingestion increment of [issue #119](https://github.com/Alan-Huangzy233/secagent-riskops/issues/119).
It adds an **opt-in HTTP receipt store and local-file collector** to the live
API. It is disabled unless `http_ingest` is configured. The SSH database,
incidents, scores, notifications, controls and AI summaries remain separate.
Continuous HTTP correlation, incident scoring, console views, notification
routing and real-source acceptance are still subsequent work; this increment
does not complete #119 or establish production HTTP coverage.

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
stored evidence through bounded API pages before replaying the three rules.
Expected findings: one sensitive-resource group (2 records), one traversal
attempt (1 record), and one multi-path scan (20 records spanning batches).
There are 42 unique stored requests, no production writes and no model calls.
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

`next_after`, `snapshot` and `has_more` allow complete bounded enumeration.
New ingests cannot enter a frozen page sequence. Raw-event retention can remove
rows while reading; this is not an archival snapshot. No full-table count is
needed. HTTP health contributes to `/health` only when HTTP is configured.

Raw events expire by event timestamp after the configured retention (14 days
by default), at most 1,000 rows per new batch including heartbeat batches.
Receipts, counters and rejection/gap history survive raw expiry; disk capacity
for these growing tables needs monitoring. A late event outside retention is
acknowledged and may immediately expire; durable receipt is not unlimited raw
retention. No separate long-lived HTTP incident evidence exists yet.

## Before production activation

Validate a real source's format, peer semantics, rejected-line rate, rotation,
catch-up resource use and TLS/source authorization. Complete live correlation,
versioned findings/evidence, suitable scoring and console/notification display.
Extend the environment's backup/recovery mapping to include this independent
HTTP database and the collector state/spool, then perform a restore rehearsal.
The existing SSH recovery-package automation does **not** discover these new
paths automatically. No source is enrolled by merging this increment.

For code rollback, stop the HTTP collector and drain or retain its pending
spool, back up the HTTP store/state, remove `http_ingest` from the configuration,
then switch to the previous release (older config validation rejects unknown
fields). Retain the independent HTTP database for a future compatible release;
never reset offsets or delete receipts to make a retry succeed.
