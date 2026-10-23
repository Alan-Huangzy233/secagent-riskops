# Telemetry console workspace

The console groups incidents, logs, source overview, notifications/briefings,
collection history, IP lookup and response controls into separate views. Tables
retain server pagination, filters and keyboard navigation. Opening a record shows
a side dialog with overview, evidence and AI tabs; Escape closes it and restores
focus. Long explanations and log filters are expandable. Skeleton rows indicate
loading, including when a server starts with no prepared snapshot.

This uses the existing self-contained HTML/JavaScript and CSP, with no CDN,
framework dependency, browser service worker or external asset requests. The
interaction follows [Element tabs](https://github.com/ElemeFE/element/blob/dev/examples/docs/zh-CN/tabs.md)
and [drawers](https://github.com/ElemeFE/element/blob/dev/examples/docs/zh-CN/drawer.md);
a skeleton is a loading placeholder rather than the navigation itself.

## Prepared first page

Opt in with `"console_cache_enabled": true` in the existing private `RISKOPS_CONFIG`
JSON and restart through the reviewed deployment process. The default is false;
disabled deployments fetch the selected view on demand. Existing endpoints keep
their filters and authentication. With the cache enabled, summary endpoints also
reuse the prepared generation and expose its freshness metadata; see
[live stability](production-stability.md#prepared-summaries).

One background worker per API process prepares the overview, the default global
pending-incident page (score order) and the newest 50 logs. It starts before any
browser connects and refreshes about every 15 seconds. Successful ingestion,
disposition changes and completed block dispositions wake it, coalescing bursts
with at least two seconds between starts. A slow build never overlaps another.
Unfiltered global and source counts use the existing compact covering index;
long cursor IDs remain in the separate pagination indexes. No index is added.
The process publishes all three sections together; their database reads can
observe adjacent collection transactions rather than one shared transaction.

`GET /api/console/bootstrap` requires operator authentication, including for old
snapshots. Source bearer tokens cannot read it. It returns an immutable copy of
the prepared payload and never runs a database query. There is a 4 MiB serialized
payload bound. It contains display data only, without keys, CSRF tokens, action
plans or AI submissions. Original write APIs still recheck their own inputs.

| State | HTTP | Browser behavior |
| --- | --- | --- |
| Disabled | 200 | Read the active view on demand |
| Warming | 202 | Display loading state; poll again in two seconds |
| Ready | 200 | Display prepared overview/default pages and preparation time |
| Refresh failed, last good data no older than 120 seconds | 200, stale | Show freshness warning; retain visible data, avoid replacing lists with stale snapshots |
| Refresh failed with no usable snapshot | 503 | Keep displayed rows with a warning; explicit Refresh reads non-overview views directly while the overview waits for a new generation |

The cache is server memory, not a public HTTP cache; authenticated responses stay
`Cache-Control: no-store`. It is rebuilt on restart and needs no new backup or
schema migration. Keep the current single API process for the pilot. Multiple
workers would each build independent snapshots and receive only their local
invalidation signals; shared caching is later work.

## Refresh and navigation semantics

- The visible page polls the prepared endpoint every 15 seconds. Hidden pages
  pause polling. Default incident rows update when no request/action, selected
  response target or open detail dialog needs to be preserved.
- Nondefault sources, incident filters and deeper pages use the original APIs.
  Only the selected view loads; opening the console does not eagerly query
  notification, collection and response-history views.
- Logs keep one receipt boundary while browsing. New cached logs show **有新日志，
  获取最新** without shifting an existing page. A new page visit starts at the
  latest first log page; saved search fields and source remain selected.
- Explicit Refresh reads the active view again. The optional minute-based refresh
  does the same. Server synchronization of the overview/default page is separate
  from this setting. Last-success timestamps remain visible on failures.
- A local incident disposition blocks old cache generations until a newer clean
  snapshot arrives, so a successful manual action is not visually undone.
- Control status/CSRF, incident detail/evidence, notifications and manual AI status
  remain direct reads. No refresh submits AI work, marks notifications read or
  executes a response operation.

## Verification and rollout

Regression coverage includes authenticated warm reads without database work,
concurrent rebuild coalescing, invalidation during a build, failure/expiry/size
limits, inactive-view request avoidance, filter/snapshot preservation, manual
mutation freshness and keyboard/dialog behavior. Run the existing dashboard,
manual-AI, notification and live-API suites as well.

For release acceptance, measure first visible rows and a second device's first
visit, then source/filter changes, log pagination and mobile details. Verify
cache timestamps, a failed-refresh warning, absence of external requests and
unchanged collection/notification health. Synthetic browser timing is not a
production latency guarantee. Old receipt boundaries far behind current
collection and expensive custom searches remain outside this cache.

Roll back the opt-in by setting `console_cache_enabled` false and restarting.
When rolling back to code that predates this field, remove the field too: the
configuration rejects unknown keys. No telemetry or AI database should be
restored backwards for a UI/cache rollback.

For summary-cache compatibility, warming responses and release acceptance, see
[live stability](production-stability.md#prepared-summaries).

## Search an observed source IP

SSH alerts and logs each have a visible exact-IP search form above their table.
The server validates complete IPv4/IPv6 addresses, canonicalizes equivalent
representations and rejects CIDR or scoped addresses. Manual submissions default
to a fixed last-24-hours window. Custom local times and **全部保留时间** are
available; the applied IP, source, time window and disposition scope are displayed
beside the form. The default unsearched overview keeps its existing all-retained
pending-alert behavior. Search does not exclude protected management addresses.

Network incident rows and versioned details provide **查 SSH 告警** and **查 SSH
日志**. These query the observed source IP across all SSH sources, from 30 minutes
before the first network evidence to 30 minutes after its last evidence. They
clear unrelated account/message filters and select all alert dispositions and
scores, including resolved incidents. They do not infer that a network source ID
is an SSH source ID, geolocate the address, submit AI work or execute a response.
Matching an IP alone does not establish a cross-protocol incident or identity.

Alert matching uses evidence-interval overlap with the chosen window; logs use
individual event times. Result totals and rows use identical filters with
server-side pagination. Disposition facets share IP/time/source conditions but
span dispositions; score facets also honor the disposition choice while spanning
score categories. The browser does not download every page or filter only visible rows.
IP/time filters participate in the request identity and saved view. They exclude
the prepared default cache; stale requests and failed new queries cannot relabel
older IP results. Query changes reset the page and log receipt boundary. Refresh,
page navigation and **获取最新日志** preserve the applied fixed time window; submit
**最近 24 小时** again to move that window to the current time. A new browser visit
retains search fields but starts a new log snapshot on page one.

Coverage notes distinguish unconfigured sources, known collection gaps and
unknown coverage. Actual retained-history boundaries are currently unknown to
this view and are labelled accordingly; configured retention days are not a
promise that every event is present. No matches do not establish safety or absence
of activity. Log account/type/message filters remain in expandable advanced
options. Network/HTTP native-IP search and joint-case correlation are separate
future increments.

### Search resource and rollout boundary

Explicitly filtered SSH reads share a five-second cooperative SQL deadline across
one page's count, rows and facets, with a 250 ms SQLite lock wait. Progress checks
run every 1,000 VM instructions and between statements. Expiry or lock contention
returns a sanitized HTTP 503 with a retry/narrow-range message and no partial
success; subsequent reads and ingestion use fresh connections. This is not a
hard operating-system or storage-I/O deadline. Source/status-only default reads,
prepared-cache construction, ingestion and maintenance retain their existing
policies. The combined dashboard endpoint may perform separate filtered page
reads; the budget is per store read, not an entire HTTP request SLA.

A partial `incidents_ip_paging` index seeks across sources by IP and recent time.
It is additive and leaves raw logs, retained evidence and receipts unchanged;
older code can ignore it. First startup must build it if absent, which consumes
space and may hold a database writer lock. Before deployment, measure the index
build on an appropriate isolated copy, check headroom and backup/recovery scope,
and verify readiness before returning collection to its normal schedule. No
production migration or timing guarantee is established by the synthetic tests.
