# Live collection and query stability

A batch can time out while waiting for the central SQLite writer even when SSH
export succeeded. Two write paths previously grew with unrelated retained
history: the first batch of the UTC day deleted every expired raw event in one
transaction, and merging incidents searched the entire `events` table for the
old incident ID. Separately, `/api/summary` recomputed source totals on every
request, including while the console's background cache was already rebuilding.

These are reproducible amplification paths, not proof that every historical
HTTP failure had the same cause. Backup I/O, cold reads, detection work and
connection failures still need to be distinguished using runtime evidence.

## Bounded maintenance and merge work

Automatic retention deletes at most 1,000 expired raw events per **new** batch,
oldest first. This is larger than the API's maximum 500 arriving records per
batch so maintenance can catch up. Until no expired row remains, the daily
completion marker stays unchanged and subsequent batches, including empty
heartbeats, resume the work after a restart. Cleanup and the batch receipt
commit atomically. Replaying an acknowledged batch reuses its receipt without
repeating cleanup.

Expiry still uses the configured retention period and preserves a record at the
exact cutoff. It removes only raw events; event and batch receipts, incident
evidence, scoring and operator history remain. Cleanup is gradual and depends
on new batches arriving, so this is not a hard deletion-time guarantee. The
explicit `TelemetryStore.cleanup()` maintenance operation still performs a full
pass and should not be run in a request handler.

Incident merging finds the other incident's source/event keys through the
existing evidence index, then updates the matching raw rows by their composite
primary key before reparenting evidence. Expired raw rows need no update, and
identical event IDs on different sources remain distinct. No schema migration,
index build or historical score backfill is needed for these changes.

## Prepared summaries

With `console_cache_enabled=true`, `/api/summary` and the summary portion of
`/api/dashboard` reuse the same prepared generation as `/api/console/bootstrap`.
The summary keeps its original `generated_at` and includes `cache` metadata with
age, generation, stale/refresh status and the existing maximum age. Failed
refreshes may serve the last good generation only within that age bound.

A cold or expired summary returns HTTP **503** with `Retry-After`; it does not
start another history scan. Bootstrap retains its existing **202 warming**
response and **503 unavailable** response. The console already polls bootstrap
while warming. Authentication and `Cache-Control: no-store` apply as before.
When the cache is disabled, summary reads remain on demand. Detailed pages and
mutations keep their own checks and database reads.

The background source aggregation still scales with retained event counts.
Reusing it removes duplicate foreground scans; it does not make arbitrary cold
history reads constant-time or guarantee a particular public-network latency.

## Diagnose the next delay

Collector output now includes each source's `duration_ms`, including failed
runs. HTTP transport failures distinguish `http_timeout`,
`http_connection_refused`, and the fallback `http_unavailable`. An HTTP rejection
remains `http_rejected`; malformed or mismatched receipts remain `invalid_ack`.
Every failure retains the pending batch and cursor until a matching durable ACK.
Do not clear the spool or move a cursor to make a delay disappear.

Transactions taking at least two seconds emit `telemetry_db_slow` with a fixed
operation label, read/write flag, outcome, and three durations:

- `wait_ms`: connection setup and transaction acquisition, including writer wait.
- `work_ms`: statements executed inside the transaction.
- `finish_ms`: commit or rollback and connection close, including possible WAL work.

Logs contain no SQL, request parameters, raw evidence, exception text or
credentials. Correlate these timings with collector failures, service restarts,
cache age and backup activity. A row limit bounds work count, not storage latency;
an observed timeout still requires investigation.

## Release and acceptance

1. Complete CI, package checks and consistent, verified telemetry/control/AI
   backups before stopping the API. Include the matching collector state using
   the existing recovery-package procedure. Run expensive integrity checks,
   whole-history counts and hash comparisons outside the API stop window.
2. Pause collection for the brief version switch, start the API, and check
   `/health`. Treat bootstrap 202 as a normal warming state and poll with a
   bounded deadline. Accept the release only once a ready generation and its
   age are verified; one warming response alone is not a rollback signal.
3. Resume collection and verify every configured source receives a durable ACK
   and catches up. Compare immutable evidence and operator history where needed.
   For control state compare actual block membership, channel, expiry and
   verification result; routine `checked_at`/`verified_at` refreshes are expected.
   Read-only acceptance must not trigger external AI or reputation requests.
4. Verify warm summary responses use the prepared generation and that desktop
   and mobile refresh still work. Observe the following UTC retention window and
   any slow-transaction logs before claiming the intermittent issue is resolved.

A code rollback needs no database restore for this change; receipts and evidence
remain compatible. The previous code can resume a pending retention pass in one
large transaction, so its original writer-delay risk returns after rollback.

Regression coverage uses synthetic data only. It checks restart/resume and
rollback of partial cleanup, durable retry after transport failures, retention
boundaries, 20,000 unrelated raw rows during merges and expiry, and concurrent
summary reads without new source-total queries. SQLite instruction budgets test
work growth rather than machine-specific wall-clock thresholds.
