# Joint-case console and explicit observation updates

[Issue #147](https://github.com/Alan-Huangzy233/secagent-riskops/issues/147) adds a
read-only investigation view over the [joint evidence contract](joint-evidence.md).
The console lists saved observations, with exact-IP, asset, association-state and
UTC window filters. Details keep the selected revision's reasons, timeline and
source references together. A shared IP and a matching time window establish an
association to inspect, not an attacker identity or a compromise verdict.

The repository default is off. This implementation does not activate production
mapping, create a production derived store or run a background refresh job.
The existing manual SSH AI pilot is separate: these routes make no model calls
and add no response actions.

## Configure and prepare an isolated pilot

`LiveConfig.joint_cases` is optional. When present it contains:

| Field | Meaning |
| --- | --- |
| `database_path` | Absolute path of a separate derived SQLite database |
| `scope` | Canonical `CaseScope.to_dict()` JSON, including policy versions and expected network producer |
| `catalog_min_seq` | Fixed inclusive network-catalog sequence floor; default 1 |
| `store_limits` | Optional lower `StoreLimits` values; omitted fields retain defaults |

Explicit mappings name each asset's enrolled SSH sources and network source,
exact destination addresses and accepted profile revisions. The compiler checks
those identities against the existing live configuration. Network profiles must
provide the local-input evidence required by the association contract. Neither
source-name prefixes nor IP similarity infer ownership. Paths must be separate
from SSH, HTTP and network storage; the CLI also rejects filesystem aliases.
Configuration validation does not read evidence or create directories.

Use an isolated copy and synthetic records first. Prepare the scope using
`CaseScope` and the actual accepted profile revision and producer identity; do not
copy another deployment's values. Configuration, scope, limits and the fixed
catalog floor must agree with the existing derived store. Changing them requires
an explicitly prepared new store rather than a silent scope rewrite.

From the repository root, using the deployment's Python environment:

```sh
PYTHONPATH=backend python -m app.telemetry.joint_cli --config /absolute/live.json check
PYTHONPATH=backend python -m app.telemetry.joint_cli --config /absolute/live.json init
PYTHONPATH=backend python -m app.telemetry.joint_cli --config /absolute/live.json discover
PYTHONPATH=backend python -m app.telemetry.joint_cli --config /absolute/live.json refresh
```

`check` is read-only. `init` explicitly creates a new private v2 file and refuses
to overwrite an existing path. Discovery and refresh each perform one bounded
step; inspect the returned progress and repeat the relevant command as needed.
There is no unbounded “run until caught up” command and no automatic scheduler.

Discovery pins a maximum network sequence for a finite catalog round. Each call
reads at most 50 catalog candidates with a five-second cooperative budget,
then atomically records eligible anchors and its cursor in the derived store.
The source transaction closes before this write. A new round revisits old heads
from the fixed floor, so retractions and revision changes are not hidden by an
“only new sequence” cursor. Newly appended cases wait for the next round.

Refresh freezes the registered worklist and attempts at most five items within a
ten-second cooperative budget, including unchanged network heads so SSH-only
late evidence can change a case. Failed reads preserve the previous valid
observation. A completed attempt cycle is distinct from all items refreshing
successfully; neither discovery nor refresh establishes complete collection.
These budgets do not provide hard OS I/O deadlines.

## What the page shows

The **联合案件** workspace reads the derived database only. Reloading its table
retrieves saved observations; it does not scan source logs or initiate a refresh.
The page distinguishes absent configuration, unavailable storage, empty results,
ongoing work and source revalidation required after a restore or failed discovery. Asset filtering belongs to this
page; the global SSH-source selector does not silently narrow joint observations.

The first page pins a generation and normalized filters in an opaque snapshot.
Subsequent pages select each case's last revision at or before that generation,
so a newly published revision cannot move rows between those pages. Rows and
counts use the same predicate. Reload to adopt a newer generation. A token from a
different store, restored identity or set of filters requires an explicit reload.
Typed summaries support the list without decoding every stored evidence payload.

Details always request the selected case revision. Its projection and first-read
metadata remain historical; a separate **current** section shows the latest
refresh status. Timeline pagination covers only the records actually saved in
that revision. A cap does not create hidden evidence pages: saved and observed
counts and incomplete coverage remain visible. Network references select a fixed
upstream revision; SSH pivots run an exact-IP search across all current SSH
sources over the last 24 hours. Adjust that search window for older observations.
This search does not select a historical canonical incident or claim a durable
historical SSH revision.

Authenticated GET routes are `/api/joint/status`, `/api/joint/cases`,
`/api/joint/cases/{id}?revision=N` and
`/api/joint/cases/{id}/timeline?revision=N`. Lists default to 20 and cap at 50 rows;
timelines cap at 50. Exact-IP filters reject CIDRs and malformed IPs. Time filters
must use UTC (`Z` or `+00:00`) and apply to overlapping association windows. An empty
search result is not a safety verdict. No joint POST or source-refresh route is
provided, and a joint read failure does not disable the existing collection health
endpoint.

## Schema upgrades, snapshots and recovery

Schema v1 stores from the persistence-only increment require an explicit offline
upgrade. Stop all writers to the selected derived file first. The upgrade writes
a new destination; it never changes the v1 source in place:

```sh
PYTHONPATH=backend python -m app.telemetry.joint_cli --config /absolute/live.json migrate-v1 --output /absolute/joint-v2.sqlite
PYTHONPATH=backend python -m app.telemetry.joint_cli --config /absolute/live.json snapshot --output /absolute/joint-snapshot.sqlite
PYTHONPATH=backend python -m app.telemetry.joint_cli --config /absolute/live.json restore --input /absolute/joint-snapshot.sqlite --output /absolute/joint-restored.sqlite
```

The upgrade preserves case/revision identities, pure hashes, first metadata and
work history, and creates typed summaries. The target has a new query identity;
old pagination tokens cannot carry across. Explicit snapshots use SQLite's backup
API to include committed WAL content and produce a verification manifest. Do not
copy only a live main `.sqlite` file. Destinations must not already exist; a
failed operation must leave its input and existing destinations intact. Offline
operations use a 60-second cooperative budget and a 1 GiB database-size ceiling,
and require free space for the temporary copy and verification. These bounds may
reject a large or slow operation; they never permit a partially upgraded file.

Restoration creates a new file and marks it as requiring source revalidation.
Old observations remain readable with that warning. Verify the configured source
producer and mapping, run a complete fresh discovery round, and successfully
refresh all registered items before treating current observations as revalidated.
A missing/regressed network revision or a failed refresh must retain the warning.
The SSH store has no stable producer UUID, so an unchanged network producer alone
cannot prove SSH was not restored; use this explicit recovery flow after any
source restore.

A derived snapshot is not an atomic backup of the network, SSH and collector
state. Existing paired-source disaster recovery rules still apply. The joint
store is not a collector ACK participant. For code rollback, stop explicit joint
updates, remove the new configuration and retain the derived file; do not rewind
source databases, cursors or pending deliveries. Production activation and any
refresh schedule need a concrete reviewed mapping, capacity and recovery plan.
