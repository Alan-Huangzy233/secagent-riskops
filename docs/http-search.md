# Exact connection-IP search for HTTP incidents

The HTTP incidents view accepts an exact **connection IP** alongside its existing
source, service and risk filters. Submit the search or press Enter; clear it to
return to the ordinary incident list. Paging retains the submitted scope, and
editing search inputs invalidates results and pending requests from the previous
scope.

This is another slice of [#146](https://github.com/Alan-Huangzy233/secagent-riskops/issues/146).
It searches retained, analyzed HTTP cases, including low-score and retracted cases
when their selected filter permits them. It does not search raw access records,
add a time-range filter, or establish a link to an SSH or network event. An empty
result is not evidence that the peer made no requests: analysis backlog, rejected
input, retention and coverage gaps still apply. Existing collection and analysis
health indicators remain visible.

## Address meaning

The HTTP parser currently accepts the connection peer and deliberately does not
use forwarded headers. A reverse proxy may therefore appear as the connection
address; matching it does not identify the original visitor or an attacker.
Search follows the same normalization as ingestion: IPv4 and IPv6 use canonical
forms, and IPv4-mapped IPv6 addresses match the corresponding IPv4 address.
Substrings, CIDR ranges, zone identifiers and hostnames are not accepted.

## API and pagination

The operator-authenticated `GET /api/http/incidents` route adds an optional `ip`
parameter. Omit it to retain the existing listing behavior. An explicitly empty
or invalid value is rejected rather than treated as an unfiltered search.
`source_id`, `service_id`, `focus`, `page` and `limit` keep their existing meaning;
source and service selectors refer to configured HTTP sources.

Filtered responses retain `items`, `page`, `total_pages` and `total`, and add:

- `query`: the canonical `ip`, optional `source_id` and `service_id`, and `focus`.
- `limitations`: `retained_cases_only`, `connection_peer_only`,
  `analysis_coverage_limited` and `pages_may_change`.

Count and page rows use the same read transaction. Separate page requests read
current saved cases; they are not a frozen historical export. Analysis may add
or revise cases between requests. An out-of-range page is clamped to the current
last page, as in the ordinary list.

The console displays the applied scope and checks that the returned scope
matches its request. It does not download pages and filter them in the browser.
Invalid query inputs return 422. Unavailable, corrupt or over-budget filtered
reads return a fixed 503 error, not a partial successful or empty result.

## Storage and compatibility

An additive `http_incidents_peer` index lets SQLite seek the normalized IP column
before loading incident JSON. Existing databases acquire the index through the
normal idempotent HTTP store initialization; rows, receipts, evidence and case
revisions retain their existing formats. Search itself uses bounded read-only
access and does not initialize or migrate storage, run detection or call a model.
Busy waits, SQLite work, elapsed work and selected payload sizes are bounded.
The elapsed limit is cooperative, not an operating-system I/O deadline.

Recovery retains the existing ordering: verify and register the restored paired
snapshots before opening stores for normal initialization. A legacy snapshot
therefore keeps its captured schema during verification and receives the index
when the HTTP store subsequently starts. The recovery package format is unchanged.

## Remaining work

Raw HTTP log lookup needs its own indexed address/time design, existing-record
migration and bounded pagination. Grouped results across evidence types and
broader address roles remain separate work in #146. Real HTTP source acceptance
still depends on #119; this feature does not create business traffic or imply
that a live HTTP source has been enrolled.
