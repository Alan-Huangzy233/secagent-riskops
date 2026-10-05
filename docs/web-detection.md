# HTTP detection foundation

The first non-SSH increment is an **offline structured HTTP access-log parser
and three request-pattern rules**. It is not connected to live ingestion, the
console, incident scoring or notifications. It does not make model calls. A
real web service and a reviewed collection configuration are needed before
claiming production HTTP coverage.

## Try the synthetic fixture

After `make install`, run `make web-detect`, or:

```sh
python -m app.evaluation.web \
  --input examples/http-access/access.jsonl \
  --source-id synthetic-web --service-id example-site
```

The fixture's expected report is `examples/http-access/report.json`. CI replays
it byte for byte. The 42 authored request records exercise normal browsing,
health checks, login requests with ambiguous HTTP outcomes, sensitive resource
probes, encoded traversal and a multi-path scan. These are regression examples,
not a representative labelled dataset or a measured production detection rate.

To inspect a locally exported file, substitute its path and configured source
and service identities. The output includes client addresses and query-free
paths; keep reports made from private data private. Errors identify a line,
never print its contents, and stop without a partial report.

## Input contract

Each UTF-8 JSON line must contain exactly these five fields:

```json
{"timestamp":"2026-01-05T00:00:00Z","client_ip":"198.51.100.23","method":"GET","path":"/.env","status":404}
```

- `timestamp`: an ISO timestamp with timezone, normalized to UTC.
- `client_ip`: the original connection peer, a valid IPv4/IPv6 address. Mapped
  IPv6 addresses normalize to IPv4. No forwarded header is consumed.
- `method`: an uppercase method token; `status`: an integer from 100 to 599.
- `path`: an origin-form encoded path (or `*`), at most 8192 UTF-8 bytes. A query
  suffix is removed before detection and evidence output. A separate view is
  percent-decoded at most three times; dot segments remain visible to rules.

Source/service identities are operator-supplied, not inferred from Host or
Forwarded headers. The replay assigns evidence IDs from the input file hash
and line number. Identical lines at different offsets are separate requests;
re-delivery of the same normalized evidence ID is deduplicated. A conflicting
ID fails in either arrival order. These are snapshot replay IDs, not a live
rotation/cursor protocol: appending to a file changes its hash and replay IDs.

[Nginx configuration example](../deploy/nginx-http-access.example.conf) uses
`escape=json` and strips query arguments from the original request URI. It does
not enable collection. It assumes address rewriting is disabled; if realip is
enabled, review its configuration and log the original peer instead. A future
proxy adapter must explicitly configure trusted proxies before attributing
requests to forwarded client addresses. See the official
[log module](https://nginx.org/en/docs/http/ngx_http_log_module.html) and
[realip module](https://nginx.org/en/docs/http/ngx_http_realip_module.html).

Records outside this contract (including malformed request lines with missing
method/path) fail offline validation. Production ingestion will need explicit
rejected-record accounting and coverage reporting; silently skipping them is
not an acceptable integration strategy.

## Rules, version 1

| Rule | Condition | Evidence and interpretation |
| --- | --- | --- |
| `http_sensitive_resource` | A decoded path segment names `.env`/`.env.*`, `.git`, `.svn`, `.hg`, `.htpasswd`, or `wp-config.php`/its `.bak` or `.old` variant | A resource probe, at any response status; a 2xx response does not prove exposure |
| `http_path_traversal` | A decoded path has a `..` segment, including backslash separators | A traversal attempt, not proof the server resolved it or returned a file |
| `http_multi_path_scan` | A trailing 300-second window has at least 20 request records, at least 10 distinct query-free decoded paths, and at least 80% 403/404 responses | A scanning pattern; a crawler or an authorized scanner can also match |

Rules group only within the same source, service and connection peer. Nearby
resource/traversal attempts are grouped when adjacent matching requests are
within 300 seconds. Scan windows merge only when they share evidence. These
groups can span longer than 300 seconds; every scan window independently meets
its threshold. Each finding includes rule version, reason and all supporting
evidence IDs. Cross-rule findings remain separate at this offline stage.

There is no User-Agent allowlist: an attacker can copy a crawler's header.
There is no authentication-success inference: applications can return HTTP 200
for a failed login and 302 for several different outcomes. Login-attack rules
need application authentication events or a configured, tested result mapping.

## Limits and next integration

- Paths only: no query/body inspection, WAF rules, SQLi/XSS-success claim,
  distributed-client correlation or general exploit coverage. Encodings beyond
  three rounds and other application-specific path semantics are outside scope.
- Replay memory/input is bounded to 50,000 records, 32 KiB per line and 32 MiB
  total; inputs over a limit fail rather than return incomplete findings.
- Peer grouping behind a proxy can combine many users. Trust-aware attribution,
  service inventories, tuning and operator feedback belong to live integration.
- Live integration must add an independent collection cursor/receipt protocol,
  rotation/restart/duplicate handling, coverage reporting, durable evidence and
  HTTP-specific scoring/notifications without changing existing SSH results.
- Detection expansion order is HTTP/Web first, connection/DNS/firewall telemetry
  second, Linux host behaviour third. Each requires its own actual data source.
