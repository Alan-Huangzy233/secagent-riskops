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
- `scripts/backup_telemetry.py` creates verified SQLite copies. Store backups
  securely and separately from published source code.
- `scripts/reparse_ssh_telemetry.py --database <absolute-path>` defaults to dry-run.
  Applying requires `--apply --backup <new-absolute-path>` and a maintenance pause
  for writers. Raw record identity and existing incident links are protected.

The five-minute incident rule counts abnormal SSH log lines, not distinct
connections. It does not provide a long-window slow-scan detector. Raw event
retention does not automatically remove receipts or incident evidence; plan
storage capacity and a matching database/collector-state recovery strategy.
