# Network collection and durable ingestion

The second increment of [#120](https://github.com/Alan-Huangzy233/secagent-riskops/issues/120)
is merged. It adds a dedicated UFW journal exporter, retrying collector,
authenticated protocol, separate SQLite store and operator read APIs. `network_ingest` defaults to `null`: no network
store or collector is activated by the existing configuration. This is a
collection foundation. [Continuous analysis, versioned evidence, console views
and notifications](network-analysis.md) are implemented in the next increment
for review; live source enrollment remains pending. The
[offline rule](network-detection.md) remains separately callable.

Implementation, merge, deployment and passive source acceptance are separate
gates. This change does not enable a production detector, change firewall policy
or logging limits, send probes, or call a model.

## Exercise the synthetic path

With development dependencies installed, from the repository root:

```sh
PYTHONPATH=backend python scripts/simulate_network_ingest.py \
  --out runtime-data/network-ingest-simulation/report.json
```

`--out` is optional. The exercise uses 23 authored journal records and disposable
state to drive exporter page logic, the actual collector, in-process API and
store. It retains 22 unique normalized events and one redacted rejection in two
durable batches. It loses the first ACK after commit, verifies identical retry
and restart receipts, and reads the retained events through four bounded pages.
The standalone offline rule then finds two 10-event TCP groups and excludes the
two UDP observations. This delivery exercise does not assert continuous case
or notification results; use the [analysis exercise](network-analysis.md) for
that path.

The exercise reads no host journal, contacts no source host and changes no
production data. Its report is synthetic; it is not a live SSH/TLS,
detection-accuracy, throughput or recovery acceptance result. The separate
`scripts/simulate_network_detection.py` exercises the bounded offline rule.

The focused regression suites can also be run directly:

```sh
python -m pytest backend/tests/test_network_protocol.py \
  backend/tests/test_network_store.py backend/tests/test_network_api.py \
  backend/tests/test_network_export.py backend/tests/test_network_collector.py
```

## Trust and enrollment boundary

A source token authenticates one explicitly configured network source and its
enrolled profile revisions. Tokens must be independent of SSH/auth and HTTP
ingestion tokens. The API checks the supplied source, profile, typed event
fields, hashes and coverage interpretation; arbitrary client JSON cannot
establish that a packet came from the kernel. The dedicated exporter must run
on the trusted log host and obtain journal metadata itself.

The exporter accepts only `source_id` and an opaque cursor on standard input.
Its fixed, root-owned `/etc/secagent-riskops/network-export.json` contains
`version`, `profile` and `profile_valid_from_us`. It rejects caller commands,
extra filters, paths and relay destinations. It reads only enrolled labels from
`_TRANSPORT=kernel` through `journalctl --all`; otherwise JSON fields larger
than 4,096 bytes can become `null`, while non-UTF8 fields are byte arrays.
See the [journalctl output contract](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html).
Raw `MESSAGE`,
MAC values and packet payload are never sent or spooled. A malformed packet
with usable journal identity becomes a redacted rejection; unusable identity
aborts the page without advancing a cursor.

New real sources must explicitly select a [reviewed Netfilter guard](network-source-guard.md):
static `netfilter-full-v1`, or `netfilter-terminal-v2` with its narrow explicit
dynamic terminal-set policy. Both bind a reviewed validity time and checks nftables plus default/nft/legacy
iptables views before and after reading a page. The legacy `iptables-v1` mode
retains its old revision contract but covers only `iptables-save` and
`ip6tables-save`; it does not justify mixed/native source enrollment. Full-guard
native prefixes are retained as unknown-direction, non-rejection observations.

Before real enrollment, the operator must still verify that no unrelated
producer reuses an enrolled label, trace every intended hook/interface, and
establish the profile's valid-from time. A matching complete fingerprint is an
equality check, not automatic attestation of provenance or historical rules.
See the [source guard](network-source-guard.md) and
[enrollment procedure](network-enrollment.md) for drift and compatibility limits.

Do not infer local input from `BLOCK` or an empty `OUT` field alone. If the
operator cannot establish unambiguous provenance, leave local-input profile
assertions empty. A pre/post page snapshot detects changes within the supported
iptables view; drift produces an empty `profile_drift` report and leaves the
cursor unchanged. Records older than `profile_valid_from_us` are rejected with
`profile_context_unavailable`, rather than interpreted under a later profile.
Historical correctness still depends on the operator's profile and time claims.

## Configuration and script prerequisites

The optional live API `network_ingest` object contains:

| Setting | Contract |
| --- | --- |
| `database_path` | Absolute persistent path, separate from SSH and HTTP databases. Foreign tables or an unsupported schema version are refused. |
| `sources` | One to 16 sources, each with `id`, `hostname`, a private token's `token_sha256`, and one to 16 `profiles`. |
| `retention_days` | Default 14; normalized event retention uses server receipt time. |
| `max_receipts`, `max_batches` | Default 100,000 event identities and 10,000 batch receipts, across all sources. |
| `max_storage_bytes` | Default 256 MiB for database/WAL/SHM accounting, with a conservative internal page limit and reserve. |

Keep older enrolled profile revisions while their pending batches may replay.
The collector binds its state to source, profile revision, API endpoint, SSH
alias and the dedicated SSH configuration's path and contents. Changing that
mapping does not silently migrate a checkpoint or retarget pending evidence.
Profile/mapping migration requires a separately reviewed handoff; deleting
state or receipts is not a recovery procedure. Rotating only the ingestion
token preserves the mapping and permits retry.

The private collector configuration uses `version`, `endpoint`, `state_dir`,
`profile`, `ssh_config`, `ssh_host` and `token`, with optional limits listed
below. Use a mode-0600 configuration, a mode-0700 state directory, and trusted
ancestor directories. SSH configuration must be self-contained: executable
conditions/commands and includes are rejected. The fixed SSH command requires
host-key verification and disables interactive authentication, forwarding,
agent forwarding and connection sharing. HTTPS is required for remote API
endpoints; plain HTTP is restricted to loopback. Redirects are not followed.

After a separately reviewed installation/configuration, a single collector run
from the repository checkout is:

```sh
PYTHONPATH=backend python scripts/network_collector.py --once \
  --config /etc/secagent-riskops/network-collector.json
```

For an installed invocation, its Python environment must import `app`, and the
scripts must retain their sibling helpers: the exporter imports
`journal_export.py`; the collector imports `network_export.py` and
`telemetry_collector.py`. The exporter needs Linux/systemd journal access,
`libsystemd`, `/usr/bin/journalctl`, `/usr/sbin/iptables-save` and
`/usr/sbin/ip6tables-save`; the collector needs `/usr/bin/ssh` and Linux locking.
Run the exporter only through its dedicated, reviewed SSH forced command with
no caller-supplied command or forwarding. No exporter account, credential,
systemd schedule or source installation is provisioned by this change.

## Delivery and cursor contract

A version-1 batch binds source/profile, batch ID, `collected_at_us`, before/after
cursors, ordered entries, report codes and `caught_up`. Each entry is a typed
normalized event or a rejection containing only identity, content hash, journal
metadata and a fixed code. Source journal timestamps are preserved separately
from collection and server `received_at_us` timestamps. New collection times
more than five minutes ahead of the server are refused.

The collector fsyncs the complete pending batch before POST. The server uses a
FULL-synchronous SQLite transaction to commit event identities, retained events,
an immutable batch ACK and the source checkpoint together. An ACK binds the
payload hash and every ordered result, including accepted/rejected/duplicate
status. A repeated batch ID with identical content returns the original ACK,
including its original receipt time, before new-write capacity or cursor checks.
A reused batch/event identity with conflicting content or interpretation aborts
the entire transaction. A new batch must start at the committed source cursor;
an empty batch cannot invent a new cursor.

Only after validating the complete ACK does the collector atomically fsync its
new state, then remove and fsync the pending file. If it crashes between those
steps, the original pending batch can still replay after restart. Lost ACKs,
rejected credentials and API failures retain pending evidence. A separate
nonblocking lock prevents concurrent runs, and lock/state/spool files reject
unsafe types, permissions and symlinks.

Exact cursor availability is checked before reading and again before releasing
a resumed page. A vacuum race discards that page and reports
`journal_cursor_unavailable`; it cannot silently seek to a nearby record. When
a cursor is already missing, recovery reads a bounded recent window and records
the missing-cursor condition. With no cursor, collection starts from at most the
last ten minutes and no earlier than profile validity. Neither path claims to
recover all older history. A reboot alone is not classified as a history gap.

## Bounds, retention and capacity

| Resource | Implemented bound |
| --- | --- |
| Batch | At most 200 entries and 1 MiB of JSON; the exporter leaves encoding headroom. |
| Export | 10-second CLI wall deadline; each `iptables-save` / `ip6tables-save` subprocess has at most two seconds and 4 MiB. A fingerprint reads both families. |
| Journal input | 64 KiB per JSON line and 4 MiB per exported page's raw input. |
| Collector | At most five pages or 20 seconds per run; SSH and HTTP calls each have at most ten seconds within the remaining run budget. These limits may be lowered. |
| Spool | At most 16 MiB of file content; checks at most 256 existing artifacts per scan. Includes old state and orphan atomic-write temporaries, with room reserved for the next state commit before POST. |
| Operator pages | At most 200 rows, ordered by sequence with a source-scoped snapshot bound. |
| Normalized events | Default 14 days by server receipt time; at most 1,000 expired events removed per new committed batch. Event count is also capped by `max_receipts`. |
| Durable receipts | Default 100,000 event identities and 10,000 batches; receipts are not automatically pruned. |
| SQLite files | Default 256 MiB total accounting; strict `max_page_count` reserves substantial headroom for WAL/SHM. The database cannot consume the entire configured total by itself. |

Subprocess output is bounded while reading, and cleanup terminates the process
group even if the direct child has exited. The collector also applies a wall
deadline around its run. Resource limits are engineering bounds, not measured
production capacity.

Event expiry never removes compact identity receipts or reinserts an expired
record when it is replayed. All batch receipts, including rejection and gap
reports, remain retained until the configured hard capacity stops further
writes. Rejected raw lines are never stored. This intentionally avoids unsafe
receipt pruning; replay horizons, safe compaction and long-term activation need
follow-up work. A 14-day event setting does not promise that receipt capacity
will last 14 days.

Counts, limits, file/page usage and exhausted capacities are exposed in status.
Quota failures roll back the batch and checkpoint; already committed identical
batch ACKs remain replayable. WAL truncation occurs before a new write. An
external reader holding an old snapshot can prevent truncation and stop new
writes with `network_storage_busy`, while durable replay remains available.
Do not delete pending files or receipts to bypass a capacity or integrity error.

## Inspection and visible uncertainty

Operator authentication protects `GET /api/network/events`,
`GET /api/network/batches`, `GET /api/network/sources` and
`GET /api/network/status`. Event/batch pages accept `source_id`, `after`,
`limit` and `snapshot`; they return `next_after` and `has_more`. An event page
contains retained normalized records; a batch page contains immutable ACKs.
The source Bearer token permits ingestion only. With ingestion omitted, status
reports `enabled: false`; configured status now reports `analysis_enabled: true`
and includes separate `analysis` progress/coverage. This flag indicates the
worker is configured, not that it is caught up or accepted for production.

| Signal | Meaning |
| --- | --- |
| `coverage_start` | First collection begins within the bounded initial window; older history is outside coverage. |
| `journal_cursor_unavailable` | Exact resumption is unavailable or raced journal cleanup; earlier observations may be missing. |
| `profile_drift` | Supported rules snapshot differs; no page evidence or cursor advancement is released. |
| `profile_boundary` | The profile's validity limits interpretation/history. |
| `catching_up` | The bounded page reached a limit; more history may remain. |
| `invalid_record`, `profile_context_unavailable` | Record rejection reasons retained without raw content. |
| `event_history_expired` / `expired_events` | Previously accepted normalized evidence has expired; the marker persists after cleanup and replay. |
| `event_retention_incomplete` | Expired normalized rows remain because cleanup is bounded or no new batch has run. |

Source status distinguishes `never_seen`, `stale`, `delayed`, `degraded` and
`current`. These describe recent delivery and the latest report; immutable
batch history is still needed to inspect earlier gaps. `caught_up` is bounded
collection progress, not a claim that the firewall logged every packet or that
continuous analysis has completed. Source rate limits, unknown retention and
apparent-address attribution remain limitations of the evidence.

## Next gates

The [continuous analysis and console](network-analysis.md) increment is merged.
[Enrollment preparation](network-enrollment.md) and [paired recovery](network-recovery.md)
are implemented for review; live source acceptance remains separate. Data-quality failures remain separate from attack
candidates. Before any real enrollment, complete the supported-source/profile review,
passive source comparison, resource measurements and paired store/spool/cursor
backup and restore acceptance. Do not extend the existing SSH/HTTP recovery
claim to this new namespace. Keep #120 open; Linux host behavior #121 follows
acceptance of the bounded network increment. HTTP #119 still awaits a real
business service. Existing SSH, HTTP and the bounded manual AI pilot remain
independent.
