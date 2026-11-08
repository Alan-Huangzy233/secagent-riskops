# Scoped network log lookup

This first slice of [#146](https://github.com/Alan-Huangzy233/secagent-riskops/issues/146)
adds exact source-IP lookup in retained normalized network records. In the network
workspace, switch between **检测事件** (findings) and **原始日志** (raw observations).
The raw-log form requires one configured network source, an IPv4 or IPv6 address,
and a finite time range. A finding can also open that search with its source,
peer and surrounding time range already selected.

Matching an address is an investigation aid. It does not identify a person,
establish an SSH/network association or prove an attack. A raw record need not
have produced a finding. The search uses the observed `src_ip`; it does not also
match destination addresses, CIDR ranges, account names or arbitrary text.

## Query contract

The operator-authenticated `GET /api/network/events/search` route accepts:

| Parameter | Meaning |
| --- | --- |
| `source_id` | One configured network source; no all-source scan |
| `ip` | Exact IPv4/IPv6 source address, canonicalized before comparison; no zone ID or CIDR |
| `start`, `end` | Required timezone-aware ISO timestamps, inclusive, at most seven days apart |
| `limit` | Page size, 1–100; defaults to 50 |
| `cursor` | Optional opaque continuation token for the same canonical query and page size |

The console interprets custom date/time controls in the browser's local timezone
and sends UTC timestamps. Selection is based on `journal_realtime_us`, the source
journal's wall clock. Clock discontinuities and source clock error still apply;
this is not the detector's monotonic-time correlation window.

A successful response contains `items`, the canonical `query`, `snapshot`,
`page_cursor`, `next_cursor` and fixed `limitations`. Items retain the existing
normalized network-event shape and include their sequence and collection/receipt
times. There is no unbounded total count or inferred total page count. The UI
shows the current page and provides previous/next navigation.

The first page freezes an ingestion sequence high-water mark. Later arrivals,
including late records whose journal time falls inside the window, are excluded
until an explicit new search or refresh. `page_cursor` preserves that mark when
returning to an earlier page, including page one. Tokens are navigation state,
not authorization credentials; operator authentication and source enrollment are
checked on every request.

Each page has its own read transaction. Retention may remove older records
between pages, so pagination is not an immutable historical export. An empty
result means no retained matching observations were found in that bounded query;
it does not prove that no traffic or earlier records existed. Search tokens do
not provide continuity guarantees across database restoration.

## Bounded, read-only access

Lookup uses the existing source/time index and keyset pagination. It does not
initialize, migrate or checkpoint a source database, run a detector or call a
model. Read-only SQLite access can still use the normal WAL shared-memory
sidecars; source rows and schema are not changed by lookup.

Candidate, JSON-size, SQLite-work and cooperative time limits apply to the whole
request. The time limit is not an operating-system I/O deadline. Busy, unavailable,
invalid-schema or over-budget reads fail without returning a partial successful
page. The console asks the operator to narrow the time range or retry instead of
presenting those failures as an empty result. Invalid query/cursor inputs return
422; disabled or unknown sources return 404; unavailable reads return 503.

Raw logs are fetched only after an explicit search or pivot. Editing filters
invalidates the old result and pagination; delayed responses cannot overwrite a
newer query. The ordinary findings view, source collection and existing source
pagination routes keep their separate behavior.

## Remaining scope

All-source lookup, HTTP raw-log search and grouped cross-type results remain in
#146. They need separate query/index and migration decisions. This narrower
source/time-bounded search does not complete that issue or imply new detection
coverage. Development checks use disposable synthetic sources and local browser
fixtures; validation and operating records stay outside public tracking.
