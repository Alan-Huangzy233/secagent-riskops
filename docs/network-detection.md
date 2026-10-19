# Offline UFW network detection

This first increment of [#120](https://github.com/Alan-Huangzy233/secagent-riskops/issues/120)
parses bounded journal records and evaluates one advisory rule. It has no network
I/O, firewall changes, collector, database, console or AI dependency. Deployment
and real-source acceptance remain separate gates in the
[network source plan](network-source-plan.md).

## Run the synthetic exercise

From the repository root, with the project dependencies installed:

```bash
PYTHONPATH=backend python scripts/simulate_network_detection.py
python -m pytest backend/tests/test_network_parse.py backend/tests/test_network_detection.py
```

The script constructs four scenarios from scratch, using documentation-only IP
addresses: IPv4 and IPv6 multi-port SYN probes, UDP port hopping and repeated TCP
attempts to one port. It checks for two findings, 40 unique observations and one
ignored replay duplicate, then prints deterministic JSON with evidence IDs and
coverage limitations. It does not read production logs or send packets. These
examples test rule behavior; they do not measure accuracy, recall or capacity.

## Parser and trust boundary

`app.telemetry.network_parse.parse_ufw(record, profile=profile)` accepts one
structured journal record. `SourceProfile` binds a source identity to stable
ruleset digest, enrolled labels, address families, verified local-input label
and interface combinations, logging-limit state and retention context. Its
revision is a hash of that configuration. Exclude changing counters when
preparing the ruleset digest. Revalidate the profile after configuration changes.

The profile is a trusted operator assertion, not a firewall inspector or an
authentication mechanism. Resolving reused UFW labels across input, forwarding
and explicit-deny hooks is a prerequisite for setting `local_input_labels` and
`local_input_interfaces`. Leave these empty when attribution is uncertain; blank
`OUT` or `BLOCK` alone never establishes local input. The parser also requires
journal `_TRANSPORT=kernel`; a future dedicated exporter must obtain that field
from the journal and authenticate the source. Arbitrary JSON supplied by an
untrusted client cannot establish kernel origin.

The normalized immutable event retains opaque journal cursor, boot identity,
integer receipt timestamps, canonical same-family IPs, protocol, ports, TCP
flags and coverage codes. Source/boot/cursor determine identity; normalized
content and profile interpretation have a separate hash. Reusing an identity
with changed normalized content fails, even if delivery order is reversed.
Arrival times are not substituted for source timestamps. Raw messages, packet
payload and MAC addresses are not retained. Malformed or unsupported records
raise safe machine-readable errors rather than returning a successful empty
assessment; callers must keep rejection counts/coverage when adding ingestion.

TCP flags are available only for a complete supported TCP header. Missing
completion fields produce unavailable flags, distinct from a complete header
with no flags. Unknown direction, unsupported protocol or unavailable ports/
flags remain visible in coverage and cannot satisfy the first rule. IPv4-mapped
IPv6 and scoped addresses are rejected rather than ambiguously joining families.

## Rule, time and bounds

`app.telemetry.network_detection.detect_network(events, maintenance=())` returns
a `NetworkReport`. A candidate requires **10 distinct destination ports within
300 seconds**, with verified local-input provenance, an enrolled rejection-
related label, both ports, and TCP SYN without ACK/RST/FIN. This is an
uncalibrated threshold describing an observed probing pattern, not compromise.
Neither a log label nor a finding establishes the final firewall/session outcome.

Groups are isolated by source, boot, profile revision, apparent source address
and destination address. Windows use journal monotonic receipt time within the
same boot; shuffled delivery is deterministic. Overlapping qualifying windows
are merged and preserve the union of their exact evidence; a merged episode may
span longer than five minutes. `qualifying_windows` counts the constituent
windows, and `distinct_dst_ports` describes the retained episode. Finding IDs
bind rule version, group and evidence, not a durable cross-batch case identity.

A discrepancy greater than one second between adjacent wall-clock and monotonic
deltas marks that source/boot with `journal_clock_discontinuity`. Detection
continues on monotonic time. First/last wall timestamps follow monotonic order
and may decrease after a clock adjustment. This check only observes changes
between supplied records; it cannot establish that their absolute UTC time is
correct. Future collection must track delay, missing history and profile drift.

Input is capped at 10,000 records including duplicates and 16 MiB of normalized
JSON. Invalid events, conflicting identities or either cap abort the whole call
with `ValueError`; a caller must show failure, not replace it with zero findings.
The sliding rule uses sorted observations and incremental port counts, then
materializes merged evidence once. It does not repeatedly copy dense windows.
Record-level parser bounds apply before normalization. This finite offline
context is not a streaming correlator: splitting it into separate calls can miss
a pattern across boundaries. Durable context and late-data handling come next.

Every report retains `offline_context_only`, `observations_are_lower_bounds`
and `apparent_source_not_identity`, even with zero findings. Source rate limits,
retention uncertainty and parser limitations add coverage codes. Logged counts
are lower bounds; missing logs or an unmet threshold do not mean safety. Shared
NAT, spoofed source addresses and authorized scanning require analyst context.

## Maintenance context

Management/SSH allowlists are not imported or treated as detection exemptions.
An optional immutable `MaintenanceWindow` carries a previously approved reason,
authorization ID, exact source/IP endpoints, TCP destination ports and UTC range.
Its interval is inclusive and at most 24 hours; each window allows at most 1,024
ports and a call accepts at most 64 windows. Duplicate authorization IDs with
different contents fail. The caller must authenticate the approval separately.

Matches annotate **only the specific evidence IDs** inside that scope. Expired,
out-of-scope or partially matching activity is still retained, with the same
finding ID and evidence. Clock-discontinuous source/boot contexts receive no
maintenance annotation because the UTC match is uncertain. This module does not
suppress notifications or authorize any action; notification policy belongs to
the later integration increment.

## Remaining gates

Next build the dedicated exporter/collector and durable storage: bounded pending
batches, source-bound credentials, commit receipts, cursor recovery, rejection/
gap history and explicit retention. Then integrate continuous versioned cases,
scores, network tables and console notifications. Passive source enrollment,
resource measurements and backup/restore acceptance precede live coverage claims
or closing #120. Existing SSH, HTTP and the manual AI pilot remain independent.
