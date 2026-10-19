# First network source: host firewall observations

Updated 2026-10-19. This is the proposed implementation and acceptance plan for
[#120](https://github.com/Alan-Huangzy233/secagent-riskops/issues/120), not an
implemented or deployed network detector. Follow #120 with Linux host behavior
[#121](https://github.com/Alan-Huangzy233/secagent-riskops/issues/121).
HTTP #119 still requires a real business service; that gate does not block this
increment. Existing SSH collection and demo Suricata parsing do not supply it.

## Source decision and limits

Start with the **first firewall host**, which already emits UFW packet metadata
to its kernel journal. Read that journal as the single canonical source; do not
also ingest its mirrored text log. Keep enrollment details and source inventory
private. No real log excerpts, infrastructure identifiers or topology belong in
public fixtures; write synthetic scenarios independently from first principles.

The inspected source has kernel-origin records with cursor, boot identity,
wall-clock and monotonic timestamps, TCP flags and ports. Its bounded sample is
not a full-day count. Before enrollment, retain a private, versioned source
profile covering effective rules, hooks, labels, address families, journal
retention and logging limits. Fingerprint stable configuration, excluding
dynamic packet/byte counters. Revalidate it after firewall changes.

UFW labels can recur in input, forwarding and explicit-deny paths; `BLOCK` text
alone does not identify the hook or prove the final packet outcome. Validate
local-input attribution against that source profile. Missing or ambiguous
provenance remains unknown and is excluded from the first detection rule.
Existing per-rule logging limits can suppress observations, including during a
burst. Counts are lower bounds on matching logged activity, not total traffic,
connections or attack attempts. No logs or no rule hit does not mean safety.
Do not change firewall policy or logging limits as a side effect of collection.

A separate UDP NAT observation point is unsuitable for the first scan rule:
legitimate port hopping can span destination ports. Preserve pre-translation
addresses as observations; do not invent a translated destination or successful
session. A connection-tracking `new` match does not establish a response,
authentication or successful application use. NAT chains see initial flow
packets rather than every packet; logging itself does not terminate rule
processing. See the [nftables manual](https://netfilter.org/projects/nftables/manpage.html).

## Typed event and source contract

Version the schema and parser. Enrolled credentials bind each batch to one
`source_id`; the server must reject a conflicting caller-supplied identity.
Use these typed fields rather than exporting arbitrary journal dictionaries:

| Fields | Meaning and validation |
| --- | --- |
| `source_id`, `schema_version`, `parser_version` | Stable enrolled source and explicit format versions. |
| `boot_id`, `journal_cursor` | Required boot identity and opaque journal position; never parse a cursor's internal format. |
| `event_id`, `content_hash` | Hash a canonical encoding of source, boot and cursor for identity; separately bind immutable normalized content. Same identity with different content is a conflict. |
| `journal_realtime_us` | UTC journal receipt time in integer microseconds; not a promise of exact packet occurrence time. |
| `journal_monotonic_us` | Receipt time usable for ordering within the same boot only. |
| `collected_at`, `received_at` | Separate collector and server timestamps; do not replace source time with arrival time. |
| `transport` | Require trusted journal metadata `_TRANSPORT=kernel`, not a message prefix alone. |
| `ip_family`, `src_ip`, `dst_ip` | Canonical numeric IPv4/IPv6 addresses with consistent family; reject malformed values. |
| `protocol`, `src_port`, `dst_port` | Typed protocol; ports are integers in 0–65535 when present, otherwise null. Missing is not port zero. |
| `tcp_flags` | Validated flag set for TCP; null means unavailable, distinct from a known empty set. |
| `ingress_interface`, `egress_interface` | Bounded observed interface names or null; blank output alone does not establish local delivery. |
| `direction`, `observation_point` | Local input, local output, forwarding or unknown, supported by the enrolled hook/profile. |
| `log_label`, `final_outcome` | Keep observed label separate from final outcome; default outcome is unknown. Never infer successful connection from either. |
| `source_profile_revision`, `coverage` | Bind interpretation to the effective profile and record known gaps, limits or uncertain provenance. |

The [systemd journal fields reference](https://www.freedesktop.org/software/systemd/man/latest/systemd.journal-fields.html)
defines the cursor and receipt timestamps. Preserve boot boundaries, clock
changes and collection delay explicitly. Do not reinterpret old observations
using a later ruleset. `src_ip` is the apparent source at this observation point,
not attribution to a real user or device; shared NAT and spoofing remain possible.

Allow only the enrolled labels and expected kernel formats. Reject ambiguous
repeated core fields; handle legitimate repeated optional fields explicitly
rather than overwriting them in a generic key/value dictionary. Omit packet
payload, MAC addresses and unrelated kernel messages from the initial contract.
Account for IPv6 extensions, absent TCP flags, truncated lines and unknown
protocols through explicit parse/coverage states rather than invented values.

## Durable collection, storage and budgets

Use a dedicated, narrowly scoped source exporter and ingestion credential.
The exporter permits only the fixed kernel/profile filter; a caller cannot
supply shell commands, arbitrary journal filters or other source identities.
Do not widen the existing SSH exporter or reuse its cursor, credentials or
storage namespace. Reading network evidence still requires operator access.

Persist a pending batch before transmission. A durable ACK is valid only after
server commit and must bind the source, batch identity, content and per-record
results. Retain the identical pending batch on timeout, authentication failure,
invalid ACK or restart; advance the cursor only after verifying its ACK. Lock
collector state against concurrent runs. Replaying committed records returns
the original receipt without changing counts or incident evidence.

Resume from an exact known cursor. Record boot boundaries and source-profile
drift; a reboot alone is not proof of lost history. Detect vacuumed or otherwise
unavailable records and report a gap or uncertain interval instead of silently
resetting to the newest record. Keep ingest ACK progress separate from analysis
progress. Expired backlog and incomplete correlation must remain visible.

Proposed initial budgets are 200 records and 1 MiB per batch, at most five pages
or 20 seconds per run, and a 16 MiB durable spool. Validate and revise these
explicit limits with the actual source; they are not measured capacity.
Bound line size, API pagination, analysis windows, database growth and worker
work per iteration. Full spool or storage quotas must pause safely with visible
health state, preserving retry evidence rather than silently dropping records.
Measure source/collector/API CPU and RSS, plus database, WAL, SHM and spool
peaks. Separate synthetic measurements from public-network capacity claims.

Specify retention for raw normalized observations, receipt/idempotency records,
case revisions, evidence, rejected records and gap history before activation.
A replay horizon must cover supported source retention, outages and restores.
Do not prune deduplication evidence while those records can still be replayed:
use bounded retained receipts/checkpoints and reject out-of-horizon replay
explicitly. Evidence expiry must mark affected views unavailable or incomplete.
Neither raw data nor receipts may grow without a bound. Include the new store,
spool and cursor in backup/restore acceptance before treating it as durable.

## First rule proposal and benign context

Start with an **observed inbound TCP multi-port probing pattern**, not a claim
of compromise. Require verified local-input provenance, complete addresses and
ports, SYN set and ACK/RST/FIN absent, and an enrolled rejection-related label.
Group by source host, observed remote address and destination address. A first
synthetic threshold proposal is at least 10 distinct destination ports within
five minutes; it is uncalibrated and must pass passive shadow review. Repeated
attempts to one port alone do not meet it. Do not join activity across hosts or
boots implicitly. Deduplicate before counting, and retain the exact evidence.

Shared logging limits may prevent this threshold from ever being observed in
some windows; do not publish a recall claim or infer no probing from no alert.
Preserve coverage warnings and bounded-context failures instead of silently
issuing a complete assessment. Keep UDP port hopping, normal TCP retries,
health checks, shared source addresses and authorized tests as negative or
contextual fixtures. Rule output is advisory; no automatic blocking or AI call
is part of this increment.

Management allowlisting protects access and remediation decisions; it is not a
universal exemption from detection. Attach separately approved, time-bounded
maintenance/test context with source, protocol, destination and port scope.
A matching authorization can explain a reviewed/suppressed notification while
preserving observations and the audit reason. Expired or out-of-scope activity
remains eligible. Do not silently inherit a global SSH whitelist exemption.

## Small PRs and acceptance gates

1. **Offline parser and one rule:** versioned typed schema, source-profile
   validation, the single bounded candidate rule and wholly authored IPv4/IPv6
   positive/negative fixtures. No collector, console, source enrollment or
   production firewall changes.
2. **Durable transport and store:** dedicated exporter/collector, credentials,
   bounded batches/spool, commit receipts, read APIs, retention and restart/gap
   handling. Exercise a disposable service and collector before real access.
3. **Continuous analysis and console:** integrate the offline rule with durable
   correlation, versioned evidence, appropriate scores, a separate network view
   and console notifications. Show
   data-quality failures independently from attack candidates.
4. **First-source acceptance:** enroll in passive shadow mode after review;
   privately compare selected journal records with durable receipts and evidence.
   Verify direction/profile assumptions, resource budgets, retention and restore;
   record analyst review before considering detection active or closing #120.

Offline gates include threshold boundaries, repeated ports, UDP NAT/port-hopping
negatives, ACK/RST traffic, absent flags, unknown direction and spoofed labels
outside trusted kernel metadata. Cover duplicate replay, conflicting content,
malformed/truncated records, IPv6, out-of-order arrivals and clock changes.
Failure tests cover lost ACKs, rejected credentials, storage/spool exhaustion,
API outage and restart, cursor vacuum, boot changes, late/expired backlog,
retention/pruning, bounded-context overflow and restore without double counting.
Real-source acceptance is passive and source-specific: preserve sampling and
rate-limit caveats, do not scan production or claim whole-network coverage.
No external model calls are required. Advance to #121 after this bounded network
increment is accepted; revisit HTTP real-source activation when a service exists.
