# HTTP HTTPS collection acceptance

This isolated exercise checks the HTTPS transport used by the HTTP collector
for [issue #119](https://github.com/Alan-Huangzy233/secagent-riskops/issues/119).
It runs the actual collector CLI against a real Nginx TLS listener and the
application API with temporary databases. It complements the
[functional ingestion simulation](http-ingestion.md#run-the-isolated-simulation)
and [paired recovery rehearsal](http-recovery.md).

## Run locally

Install the project's development dependencies, OpenSSL and an Nginx binary
with HTTP SSL support. From the repository root:

```sh
PYTHONPATH=backend python scripts/simulate_http_https.py \
  --nginx /path/to/nginx \
  --out runtime-data/http-https-acceptance/report.json
```

`--out` is optional. Run without `python -O`: assertions are the acceptance
checks, and the CLI refuses Python optimization. CI runs the same script after the real-Nginx recovery
exercise, reusing its extracted Nginx binary without installing or starting a
system Nginx service.

The exercise uses synthetic requests, disposable credentials, loopback
listeners and temporary files. OpenSSL creates a disposable CA and server
certificates. Collector subprocesses receive the temporary CA through
`SSL_CERT_FILE`; the system trust store and the caller's environment are not
changed. There is no production configuration, production data or model call
in this exercise. Temporary keys, logs, collector state and databases are
removed when it finishes; an explicitly requested JSON report contains only
synthetic acceptance results.

## What the exercise checks

| Boundary | Acceptance condition |
| --- | --- |
| Verified HTTPS | A trusted certificate with the expected hostname allows the actual collector to receive a durable API acknowledgement and commit its cursor. |
| Invalid certificates | An unknown CA, wrong hostname or expired server certificate fails before ingestion; the pending batch remains available for retry. |
| Corrected trust | After an unknown-CA failure, supplying the correct trust allows the same pending batch to receive its durable acknowledgement. |
| Redirects | All 15 combinations of HTTP 301/302/303/307/308 and same-origin, another HTTPS origin or plaintext destination are rejected; destinations receive no forwarded request or source credential. |
| Ambient proxy settings | Environment proxy settings do not route collector traffic through a proxy. |
| TLS key logging | Setting `SSLKEYLOGFILE` does not make the collector write session secrets. |
| Credential isolation | HTTP ingestion requires its own source credential and matching source/service; SSH and operator credentials do not grant ingestion, and an HTTP token does not grant operator access. |
| Token rotation | An invalid token leaves the original pending batch intact; replacing only the token allows that batch to be acknowledged. |
| Upstream unavailable or invalid ACK | A 503 response or an ACK with `durable: false` preserves an existing cursor and the pending batch byte for byte until a successful retry. |
| Lost usable acknowledgement | The API commits a batch but the response is damaged before reaching the collector. The collector retains its pending batch and retries it unchanged; the API returns the existing receipt without duplicate events or counters. |
| Source log privacy and peer | Nginx's structured log removes query arguments and records the connection peer even when the request supplies forwarded-address headers. |

The script generates three monitored-site requests. Independent collector
states and appended copies exercise separate file generations, producing
15 unique stored event identities across the accepted cases. This is not
a count of 15 website requests or a detection accuracy measurement. Retry
assertions compare the original receipt and stream counters; new test
generations are distinct from retry duplicates.

The collector advances only on a matching source, service and batch identity
with `durable: true`. A TLS failure, HTTP rejection or unusable response must
leave its cursor unchanged. Transport error reports use fixed error codes;
private endpoint details, credentials and exception messages are not an
operator diagnostic channel.

## Reverse proxy and source attribution boundaries

The TLS reverse proxy in front of the ingestion API and a proxy in front of
the monitored website have different roles. The ingestion API binds a batch
to the authenticated source and configured service. Its TCP peer is not the
client address contained in a monitored access record.

The example monitored-site log format assumes Nginx realip rewriting is
disabled and records `$remote_addr`. Forwarded request headers do not become
client identity. An installation using `real_ip_header`, a CDN or another
proxy needs a separately reviewed trust and attribution configuration; this
exercise does not recover the original client through such a proxy. See the
comments in the [Nginx log template](../deploy/nginx-http-access.example.conf).

A production reverse proxy must preserve the collector's `Authorization`
header. A server-wide Basic authentication rule can reject Bearer ingestion
before it reaches the application. Configure the exact ingestion route so
that application Bearer authentication can run, while preserving operator
authentication on console/read endpoints. Do not replace the collector's
Bearer header with a shared proxy credential or exempt operator endpoints
from their authentication. Review the effective configuration, including
inherited location and authentication rules, before enrolling a source.

The collector rejects redirects rather than forwarding credentials to a new
destination. Configure its final HTTPS URL directly. It uses the platform's
trusted certificates; it has no insecure certificate-verification bypass.
The disposable trust used by this local exercise is not a production CA
installation procedure.

## What remains before production enrollment

Passing this exercise does not validate a deployed certificate, public DNS,
firewall, production proxy configuration or actual source credentials. It is
not a load test, accuracy estimate or remote-collector/full-host recovery
test. It does not enable HTTP collection in production or enroll a website.

Issue #119 remains open for the chosen real source's format and peer
semantics, rejected-line rate, rotation/retention, catch-up resources,
analysis latency and alert volume. Production TLS and authentication must be
checked on that source's actual route. Its HTTP database, console checkpoints
and collector state/spool also need an accepted recovery mapping. The
existing same-host recovery drill does not prove remote-collector recovery.
