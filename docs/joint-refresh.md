# Bounded joint-evidence refresh

Joint refresh updates the separate derived store described in
[joint-console.md](joint-console.md). It reads enrolled network and SSH evidence;
it makes no model calls, changes no source records and performs no response
actions. Console GET requests continue to read saved observations only.

The feature defaults to off. Omitting `joint_cases.refresh`, setting it to `null`,
or setting `enabled` to `false` disables scheduled work. The service and timer
are optional templates; adding these files does not install or enable them.
The derived store, explicit asset mapping and accepted profiles must already
exist. `tick` does not initialize a database or infer additional assets.

## Configuration and progress

Add this member to an otherwise valid `joint_cases` configuration:

```json
"refresh": {
  "enabled": true,
  "interval_seconds": 300,
  "stale_after_seconds": 900,
  "retry_seconds": 60
}
```

| Field | Meaning |
| --- | --- |
| `enabled` | Opt in to bounded refresh work; defaults to false |
| `interval_seconds` | Delay before starting another ordinary refresh round |
| `stale_after_seconds` | Age after which the last fully successful round is no longer fresh |
| `retry_seconds` | Minimum delay before retrying unsuccessful work |

The explicit entry point is:

```sh
PYTHONPATH=backend python -m app.telemetry.joint_cli --config /absolute/live.json tick
```

Each call performs at most one discovery page of 50 candidates with a five-second
cooperative budget, or one refresh segment of five items with a ten-second
cooperative budget. It does not loop until caught up. Discovery traverses a
finite round from the configured catalog floor, then refresh visits the frozen
registered worklist. More than one invocation can be needed for a round.

A completed attempt is not necessarily a successful refresh. Only a complete
new discovery round followed by successful refresh of all registered items
advances full-round success. Failed reads retain earlier observations and do
not turn missing evidence into a negative finding. The configured interval and
retry delay are scheduling limits, not guarantees of when a round finishes.
Durations use whole seconds, and the freshness threshold must be at least the
ordinary interval. Allow for every step in the registered scope when choosing
that threshold; the interval does not make a large round finish faster.

The sidecar `<database_path>.refresh.json` records bounded progress and freshness,
including attempt, completion, success and next-attempt times. Its identity is
bound to the store, restoration epoch and configuration digest. Missing state
or an identity mismatch cannot establish a recent successful refresh. Recovery
uses the committed round completion time, not the time the worker restarts.
The fixed
`<database_path>.refresh.lock` serializes scheduled and manual derived-store
writers. Do not delete or replace this lock inode while any writer may use it.
Pending and failed counts belong to the corresponding frozen refresh worklist;
a changed or unfinished discovery round, or a round without a bound refresh
worklist, reports those counts as unknown instead of reusing old totals.

## Optional systemd scheduling

The [service](../deploy/systemd/secagent-riskops-joint-refresh.service) runs one
`tick` as `riskops:riskops`. The
[timer](../deploy/systemd/secagent-riskops-joint-refresh.timer) offers a run every
15 seconds after the previous invocation ends, with up to one second of
jitter. Application state decides whether work is due. A configured retry shorter
than the timer cadence cannot make that timer fire sooner. Missed opportunities
are not replayed as an accumulated queue. The unit does not require or start the
API service and makes no network requests.

The service uses a 30-second startup timeout, then allows five seconds for
termination before SIGKILL. `KillMode=control-group` covers every service process.
These are OS termination controls in addition to cooperative reader budgets;
uninterruptible kernel I/O can still delay process exit. An interrupted step
does not itself establish full-round success; the next invocation uses committed
progress and the saved round state.
The template also sets a 256 MiB memory ceiling, a 50% CPU quota and a 24-task
limit. These bounds can cause a large or slow step to fail; they do not authorize
larger input or storage limits.

Use the existing database owner and a private derived directory. The database,
refresh state and writer lock should remain private to that account. The
configuration must be readable by it. The default namespace allows writes under
`/var/lib/secagent-riskops`, covering derived state and SQLite WAL sidecars.
Source connections use `mode=ro` and `PRAGMA query_only=ON`, but a WAL reader may
need to create or update shared-memory files beside the source database. This
permission is not an OS-level source-data write prohibition. Do not run the
worker as root, use `immutable=1` on live WAL sources, or make the source files
world-readable to bypass access problems. Adapt the namespace explicitly if
configured database paths differ from the template.

## Backup, maintenance and recovery

The outer wrapper takes a **shared, nonblocking** lock on the protected
`/run/secagent-riskops-backup/maintenance.lock` already used exclusively by the
[backup services](backup-serialization.md). Before enabling the optional timer,
verify that existing directory is `0750 root:riskops` and its regular, nonsymlink
lock file is `0660 root:riskops`. The service conditions require an existing
readable/writable regular file and reject symlinks; the protected parent does
not permit the service account to create a replacement. The service does not
initialize or repair that lock. An exclusive holder makes the wrapper exit with status 75 without invoking `tick`;
this deliberate skip is accepted by this service, and the next timer opportunity
can retry. Other worker failures remain failures. The existing backup units keep
their own failure handling unchanged.

The wrapper reduces competition with heavy backups and keeps cooperating
refreshes out of exclusive maintenance. It is not what makes a network/console
backup pair consistent: joint evidence is not a collector ACK participant, and
its sequential source reads are not an atomic cross-database snapshot. A long
exclusive backup can outlast the freshness threshold. Display the resulting
staleness; do not advance success times merely because a tick was skipped.

For manual derived-store writes during scheduled operation, use the identical
shared maintenance wrapper around the CLI, or pause and drain the refresh
service before coordinated maintenance. The per-store writer lock alone does
not coordinate with backup or release operations. Stop the timer and wait for
an active refresh service to exit before changing its unit, mapping, configuration
or source/derived files. Use the same existing maintenance inode for operations
that need exclusive access; do not acquire it twice in one command chain.

Scheduling does not add the derived database or its refresh sidecar to any backup
configuration. Follow the explicit snapshot and restore flow in
[joint-console.md](joint-console.md); a naked main-file copy can omit committed
WAL content. Restoration creates a new identity/epoch and requires source
revalidation. Old scheduler state must not clear that requirement or make
restored observations fresh. Stop scheduled writers before migration, restore
or code rollback, retain the derived history, and never rewind source databases,
collector cursors or pending deliveries to undo a refresh.
