# Paired network recovery

Network collection has a stricter checkpoint contract than SSH journal replay.
A new batch must start at the stored source checkpoint; an old cursor and a
newer network database are not interchangeable. Network notifications also
cross from the network database into the console database. Back up both
SQLite snapshots, all local collector cursors and original pending batches as
one explicitly configured cohort.

This supports same-host collectors posting to the local API. It does not
coordinate remotely running collectors, restore remote journals, install source
credentials, or attest firewall profiles. HTTP and network recovery cohorts in
one package are currently rejected; support for a larger shared-console cohort
needs a separate implementation. Ordinary SSH and HTTP-only packages retain
their existing behavior.

## Configuration

Add a separate SQLite component and one state component per collector to the
existing private recovery configuration, then declare the cohort. Example
fragment (merge it with the existing components; do not replace the other
backup components):

```json
{
  "components": [
    {"name": "telemetry", "kind": "sqlite", "path": "/var/lib/secagent-riskops/live.sqlite"},
    {"name": "network", "kind": "sqlite", "path": "/var/lib/secagent-riskops/network.sqlite"},
    {"name": "network-source-a", "kind": "state_dir", "path": "/var/lib/secagent-riskops-network-collector/source-a", "patterns": ["*.state.json", "*.pending.json"]}
  ],
  "network_recovery": {
    "network_database": "network",
    "console_database": "telemetry",
    "collectors": [
      {"state": "network-source-a", "config": "/etc/secagent-riskops/network/source-a.json"}
    ],
    "lock_timeout_seconds": 5
  }
}
```

List every local collector, including sources not seen yet. The configuration
accepts one to sixteen entries; duplicate sources, configuration paths and state
directories fail. State patterns must include exactly `*.state.json` and
`*.pending.json`. Each private collector config must resolve to that state
directory. Each observed network source must have a matching collector.

The collector endpoint, source/profile, SSH alias, and SSH configuration path
and contents form the mapping identity. A mapping change is not an implicit
migration. The package records the identity, profile and configuration digest;
it never puts the API token in the public manifest. Include the required
private collector/API/SSH configuration in separately protected encrypted
components, or retain it through an independently verified recovery method.
A `config` path in the cohort declaration does **not** itself back up that file.
The scheduled recovery service must be able to read these configs and create
or open each `collector.lock`; grant only the relevant state directories in
its existing systemd filesystem restrictions. A first backup may create a lock
for an unused source; only that freshly created inode is assigned to the
protected state directory owner. Existing locks are never silently reassigned.
The root backup process accepts private configs/SSH files owned by root or that
collector directory owner, with protected ancestors and the original strict
file permissions; unrelated UIDs remain rejected.

## Capture and validation

The builder obtains every collector lock in sorted path order, loads and hashes
the mappings, then copies the state and pending files. Busy collectors fail the
package without publishing a partial replacement. It briefly reserves both
SQLite writers, pins both WAL read snapshots, and releases the writers before
copying either database. Before releasing the collector locks it verifies:

- Each state refers to a retained durable ACK with the same cursor, batch,
  payload digest and receipt timestamp.
- A pending batch is the original valid envelope under that exact mapping.
  If already committed, its full ACK and every identity receipt must match;
  otherwise its starting cursor must equal the database checkpoint.
- An acknowledged cursor is the current source checkpoint, except for the
  original pending batch spanning a lost ACK. Earlier checkpoints are refused.
- The network notification producer and console import revisions agree.
  A completed import cannot be missing from the console, and the console
  cannot have imported a revision absent from the network snapshot.

The small network database is copied first and its pinned read transaction is
closed immediately. The larger console copy follows. This avoids blocking
network WAL truncation for the entire console backup. A transient busy response
during the small network snapshot is safe: collectors keep their pending batch
and retry. Writer locks are short; encryption and compression hold no collector
or database writer locks. Existing backup-maintenance serialization still
applies to the complete package operation.

Adding a network database only as a generic SQLite component is rejected.
Storage or verification errors fail closed; no cursor or receipt is deleted to
make a backup succeed.

## Restore acceptance

Run the existing `recovery_package.py verify PACKAGE --into EMPTY_DIRECTORY`
with the appropriate private decryption key in the restore environment. This
performs component hash/integrity checks and checks the network cohort again
against the extracted files. It does not start services or write live stores.
Shallow ciphertext verification alone does not establish decryptability or
paired restore acceptance.

Before starting any restored collector, API or worker:

1. Restore the network and console SQLite snapshots from the **same** verified
   package, together with **all** its network state/pending directories.
2. Restore the private configuration and preserve the original mapping.
   A token alone may rotate without changing the identity; changing the
   endpoint, source/profile, SSH path/contents or alias requires a reviewed
   migration. Remove stale destination WAL/SHM only as part of an offline,
   verified replacement, never from a running database.
3. Preserve the original pending file. Replaying it returns its original
   durable ACK if already committed, or commits it once if not yet accepted.
4. Resume the worker. A notification imported just before a crash is not
   imported twice; the network outbox catches up with the console checkpoint.
5. Inspect source catch-up, rejected records, historical gaps and capacity.
   A paired snapshot cannot recreate a journal cursor already removed on the
   source. Initial or gap collection has the existing bounded replay window.

Do not mix a newer collector state with an older database, silently drop a
collector, delete receipts, or run `VACUUM`/`VACUUM INTO` on the network store.
Retain the approved schema-compatible binary. Network schema v2 must not be
opened with a v1-only release.

`backend/tests/test_network_recovery.py` exercises three synthetic collectors,
all pending/ACK crash windows, cross-database notification retry, mapping and
checkpoint mismatch rejection, lock timing, and early network reader release.
The encrypted exercise uses a temporary test key and isolated files; it neither
uses production keys nor contacts a host or production API. Production-recipient
decryption still requires a separate drill where its private key is available.
