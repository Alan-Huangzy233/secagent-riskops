# HTTP recovery and a real Nginx drill

HTTP recovery must preserve the file-generation identity, durable receipts,
analysis cursor, incident revisions/evidence, producer ID and notification
checkpoints together. Independently copying the HTTP and console databases can
lose a notification: its HTTP outbox may already be acknowledged while the
restored console has never imported it. Restoring an older collector cursor
can also generate new IDs for a rotation already stored in the HTTP database.

## Explicit same-host mapping

Merge [the HTTP example](../deploy/recovery-package-http.example.json) into the
**existing deployment inventory**, keeping its other databases, cursors,
configuration and references. Replace example paths, filenames and recipient
fingerprints; inspect the captured component/file counts. Nothing discovers
or changes the deployed backup configuration automatically. The example is
not a complete inventory for every installation.

The optional `http_recovery` object names the HTTP database, the console's
telemetry database, and **every local HTTP collector state directory** feeding
that database. It currently supports one HTTP/console pair on the same host,
with both databases using WAL. Each collector component must select exactly
`*.state.json` and `*.pending.json`. An ungrouped database with `http_receipts`
is rejected instead of silently receiving the generic SSH capture guarantee.
Keep source/service, endpoint and log mappings stable during capture. Include
the matching private API/collector configuration in the encrypted package or
manage it in a separately versioned recovery inventory.

Capture proceeds as follows:

1. Acquire all configured collectors' actual `collector.lock` locks, then copy
   their cursor/spool files. Retain those locks through the database pin below.
2. Reserve both database writers in deterministic order. Establish a read
   transaction on each database while both reservations are held.
3. Release writer and collector locks **before** copying databases, hashing,
   compressing or encrypting. WAL read snapshots preserve the common state
   while normal writes resume.
4. Check source notification revisions against console import checkpoints,
   then build the normal compressed, encrypted, optionally signed package.
   Deep verification repeats those compatibility checks after integrity/hash
   checks. Manifest version 1 gains optional `consistency.http_recovery` data;
   existing SSH-only configurations continue to work.

A busy collector fails immediately; the cumulative database lock deadline is
1–10 seconds (default 5). Failed builds publish nothing and preserve earlier
packages. Schedule a retry and monitor package freshness. No service shutdown
is required to build; collectors and database writers can briefly contend with
capture. Long copies keep WAL read transactions open and may delay checkpoint
reclamation, so measure disk headroom and runtime on the actual dataset.

**Remote collectors are outside this guarantee.** Listing a local empty
folder cannot substitute for their state. Before activating such a source,
add a coordinated protocol or stop *all* collectors, wait for in-flight work
to finish, capture every cursor/spool and the paired databases, and rehearse
that topology. A partial inventory must not be advertised as lossless recovery.

## Restore rehearsal and cutover

- Verify/decrypt into a fresh private directory using
  `recovery_package.py verify PACKAGE --into EMPTY_DIRECTORY`. Require a valid
  component report and compatible `http_recovery` checkpoints; if the package
  is signed, verify it with the expected trusted key. Keep the original files
  until acceptance and use the manifest's restore mapping.
- Stop HTTP collectors, API and notification/analysis workers before cutover.
  Restore **both databases from the same package**, plus every matching HTTP
  cursor/spool and configuration. Preserve ownership/modes. Isolate old
  `-wal`/`-shm` files with the old databases; never combine them with restored
  main database files. Follow the existing SSH/control restore procedure too.
- Preserve producer IDs, receipts, analysis cursors, historical revisions and
  notification import metadata. Do not clear them to make a retry succeed.
  Preserve endpoint/source/service/log mappings so a pending spool still has
  its original identity. Renaming these requires a separately reviewed migration.
- Retain the original current/renamed log files **and their inode identity**
  long enough to replay. Recreating log bytes on a new host creates different
  inodes; arbitrary full-host/file-loss recovery is not guaranteed by this
  local drill. Missing/truncated sources must produce explicit gap/degraded
  reports and require review; never claim continuous coverage from a green
  current heartbeat alone.
- Start the API, verify health and historical case/evidence versions, then
  resume collectors. Check ACK replay, stream totals, catch-up state, analysis
  coverage and console notifications. Repeating a receipt/import must not add
  another record or duplicate delivery; a new case revision may legitimately
  produce a later notification after the cooldown.

`mark-restored` currently records **SSH collection history only**. Do not run it
against the HTTP database or treat it as an HTTP restore marker. HTTP restore
visibility and whole-host recovery remain separate follow-up work.

## Run the isolated real-Nginx exercise

Install the development dependencies, GnuPG and zstd. Supply a Nginx binary
available on the test machine; this script does not install/start a system
service or use deployment configuration:

```sh
PYTHONPATH=backend python scripts/simulate_http_recovery.py \
  --nginx /absolute/path/to/nginx \
  --out runtime-data/http-recovery/report.json
```

The script runs Nginx and the real API on ephemeral **loopback** ports, in a
private temporary directory. Nginx returns fixed 404s; there is no vulnerable
application or external target. It generates 24 real requests using the
published five-field log format, including sensitive paths, encoded traversal
and a scan. It checks query removal at Nginx, deliberately loses an API ACK
**after commit**, interrupts the notification bridge after console commit,
renames/reopens the log and leaves two more requests unread.

A disposable GPG key encrypts/signs the package; deep verification decrypts it
into a new directory. After stopping the original isolated API, the script
restores its databases, pending spool and configuration, then restarts at the
same endpoint. It checks the original ACK, historical revision/evidence,
notification import replay, rotation catch-up, 24 unique events and unchanged
counts after further retries. Logs, keys, listeners and temporary databases
are removed on exit; only the optional synthetic report is retained.

Usually these requests form one 90-point case and two legitimate notifications
for different revisions. A UTC-hour boundary can produce adjacent cases with
shared evidence, so the report records actual case/notification counts. This
is a functional restore exercise, **not an accuracy benchmark**, TLS/load test,
remote-source acceptance or whole-host disaster recovery. It makes no model
calls or production writes. CI runs it with an extracted Ubuntu Nginx binary.

Real-source deployment still needs workload/rotation/retention/TLS/capacity
acceptance. HTTP daily briefings and a visible HTTP restore marker are not
implemented by this increment; issue #119 remains open.
