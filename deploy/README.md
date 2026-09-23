# SSH telemetry configuration

The independent telemetry entry point is `app.live_api:app`. It uses SQLite,
an authenticated read-only console, and bounded SSH journal polling. The sample
systemd units assume a Linux host with Python 3.12 and systemd. Install the
project dependencies before adapting the units to your installation paths.

All values below are examples. Create real configuration files outside the
checkout and make them readable only by their respective service accounts.
Do not commit credentials, SSH configuration, collected logs, state, or backups.

## API

Set `RISKOPS_CONFIG` to an absolute JSON configuration path:

```json
{
  "database_path": "/var/lib/secagent-riskops/live.sqlite",
  "operator_username": "operator",
  "operator_password_pbkdf2": "<GENERATED_PASSWORD_HASH>",
  "retention_days": 14,
  "heartbeat_timeout_seconds": 300,
  "sources": [
    {
      "id": "source-a",
      "hostname": "host-a",
      "token_sha256": "<SHA256_OF_SOURCE_TOKEN>"
    }
  ]
}
```

Use `app.telemetry.config.hash_operator_password()` to hash a password entered
through a hidden prompt. Each source needs a separate randomly generated token;
the API stores its SHA-256 digest and the collector stores the token itself.
The placeholders above are intentionally invalid until replaced.

The API unit binds to loopback. HTTP Basic credentials require an encrypted
transport when accessed remotely, such as an SSH tunnel or HTTPS reverse proxy.
The optional socket proxy also defaults to loopback; explicitly adapt its address,
interface and access controls before using it on a management network.

## Collector and exporter

Pass a private configuration file to `scripts/telemetry_collector.py --once --config`:

```json
{
  "endpoint": "http://127.0.0.1:8088/api/telemetry/batches",
  "state_dir": "/var/lib/secagent-riskops-collector",
  "sources": [
    {
      "id": "source-a",
      "hostname": "host-a",
      "token": "<GENERATE_A_PRIVATE_SOURCE_TOKEN>",
      "ssh_command": ["/usr/bin/ssh", "-T", "-F", "/etc/ssh/riskops.conf", "export-source-a"]
    }
  ]
}
```

Source IDs and hostnames must match the API configuration. Only loopback HTTP
or verified HTTPS endpoints are accepted. Configure SSH with pinned host keys,
`StrictHostKeyChecking=yes`, `BatchMode=yes`, and a dedicated identity.

On each source, install `scripts/journal_export.py` as a root-owned forced command
for a restricted SSH key. Its root-owned `/etc/secagent-riskops/export.json` selects
the local source and any fixed relay aliases:

```json
{"local_source_id": "source-a", "relays": {}}
```

Optional `relays` entries map an allowed source ID to `ssh_config` and `host`.
These values come exclusively from the root-owned file. A request cannot select
an arbitrary command, host, file, or journal unit. Configure the key with
`restrict` and a fixed `command`; do not grant shell or forwarding access.

The collector writes pending batches before transmission and advances its
cursor only after durable acknowledgement. Keep its state directory across
restarts. Initial collection covers the recent ten-minute window; unavailable
journal cursors produce a gap report, not a promise of complete history.

## Optional enrichment and maintenance

- `RISKOPS_GEOIP_DIRECTORY` selects offline DB-IP City/ASN databases. Use
  `scripts/update_geoip.py --directory <directory>` and the optional update timer.
  Lookup IPs are not sent to a geolocation API.
- `RISKOPS_ABUSEIPDB_KEY_FILE` points to a private key file readable by the API
  account. Only an explicit operator check sends the selected public IP to
  AbuseIPDB. Dashboard refresh and offline lookup do not make that request.
- Refresh is manual by default, with optional 1/5/15-minute intervals. Pagination
  includes total pages and direct page navigation.
- `scripts/backup_telemetry.py` creates verified SQLite copies and keeps the
  newest seven; `--keep <n>` or `RISKOPS_BACKUP_KEEP=<n>` (one drop-in covers
  every ExecStart line of the unit) changes that. Store backups securely and
  separately from published source code.
- `scripts/recovery_package.py build --config <file> --output-dir <directory>`
  bundles what a restore actually needs: consistent snapshots of every
  configured database, the collector cursors that match them, and a manifest
  with SHA-256 digests, schema fingerprints and restore order. See
  `deploy/recovery-package.example.json`. Cursors are captured before the
  snapshots, so a restored cursor can only replay acknowledged events, never
  skip them; collection keeps running while a package is built. Pass
  `--recipient <40-hex-fingerprint>` to encrypt with `gpg` to a key whose
  private half is kept off the host, or `--allow-unencrypted` for a local
  staging copy. `verify <package>` re-checks the stored bytes; `verify
  <package> --deep` decrypts, unpacks and runs `integrity_check` on every
  database; `verify <package> --into <empty-directory>` leaves the verified
  contents behind for a restore drill.
  Recipients can also be listed under `recipients` in the configuration, which
  keeps fingerprints out of unit files; `--recipient` replaces that list.
- `scripts/backup_export.py` is the only thing a backup node's SSH key may run.
  Give the node a dedicated system account whose `~/.ssh/authorized_keys` is
  root-owned, and install the key there with `restrict,command="/usr/bin/python3
  -I .../backup_export.py --store <directory> --peer <name>"`. The store and its
  parents must be root-owned and not group- or world-writable; make the store
  `root:<account group> 0750` and build with `--share-group <account group>` so
  each published package is group-readable and only its `confirmations/`
  directory is group-writable. The peer name comes from the key, never from the
  client; the client may only `list`, `fetch <backup-id> <file>` for a file that
  package's own manifest lists, and `ack <backup-id> <sha256>` once it holds the
  published object. It cannot supply a path, open a shell or forward a port, and
  its only write is its own confirmation record.
- `deploy/systemd/secagent-riskops-recovery-package.service` and `.timer` build
  one package a day after the plain backup and then prune. The unit reads
  `/etc/secagent-riskops/recovery-package.json`, encrypts with a public-only
  keyring in `/var/lib/secagent-riskops-recovery/gnupg`, and publishes to
  `/var/backups/secagent-riskops-packages` for the `riskops-backup` group.
- `scripts/pull_recovery_packages.py --target <ssh-destination> --destination
  <directory>` runs on the backup node. It pulls, checks every file against the
  package's `SHA256SUMS`, publishes the copy only once it verifies, and then
  confirms it. The control node holds no credential for the backup node, so a
  compromised control node cannot delete what the node already pulled.
- `scripts/recovery_package.py prune <store> --keep <n> --require-confirmations
  <n>` reports which local packages an independent confirmed copy protects, and
  deletes them with `--apply`. It never goes below the retained generations,
  never touches a package whose manifest it cannot read, and refuses any package
  directory holding files it did not publish. Without confirmations it deletes
  nothing, which is why a package timer is only safe once a node is pulling.
- `scripts/reparse_ssh_telemetry.py --database <absolute-path>` defaults to dry-run.
  Applying requires `--apply --backup <new-absolute-path>` and a maintenance pause
  for writers. Raw record identity and existing incident links are protected.

The five-minute incident rule counts abnormal SSH log lines, not distinct
connections. It does not provide a long-window slow-scan detector. Raw event
retention does not automatically remove receipts or incident evidence; plan
storage capacity and a matching database/collector-state recovery strategy.
