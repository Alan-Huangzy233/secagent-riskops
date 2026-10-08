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
their filters, authentication and response shapes.

One background worker per API process prepares the overview, the default global
pending-incident page (score order) and the newest 50 logs. It starts before any
browser connects and refreshes about every 15 seconds. Successful ingestion,
disposition changes and completed block dispositions wake it, coalescing bursts
with at least two seconds between starts. A slow build never overlaps another.
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
| Refresh failed with no usable snapshot | 503 | Keep any previously displayed rows with a warning; explicit Refresh can read the active view directly |

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
