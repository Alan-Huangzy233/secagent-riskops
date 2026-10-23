# Reviewed firewall sources and native observation prefixes

Real source enrollment uses `guard_version: "netfilter-full-v1"` explicitly.
This guard is an equality check against an operator-reviewed snapshot; it does
not establish provenance, rule meaning or historical correctness on its own.
Keep hostnames, credentials, rulesets and enrollment timestamps in private
configuration and acceptance evidence.

## Guarded profile and compatibility

The `SourceProfile` adds two fields:

| Field | Contract |
| --- | --- |
| `guard_version` | Legacy default `iptables-v1`, or explicit `netfilter-full-v1`. |
| `profile_valid_from_us` | Required integer UTC microseconds for the full guard. Must equal the exporter configuration's outer field of the same name. Legacy profiles must leave this field null/omitted. |

Both new fields enter a full profile's revision. Changing the reviewed snapshot
or validity time creates a new profile revision. The existing API enrollment,
collector mapping and durable receipts continue to bind that revision. Do not
silently update a profile, erase pending batches or reset a checkpoint to make
drift disappear. Review the changed source and perform an explicit profile
handoff while preserving pending evidence and older enrolled revisions.

Legacy profiles retain their **exact original revision calculation** and
`ufw-kernel-v1` event version. Omitting the new fields still decodes old profiles;
legacy collector identity and persisted receipts are unchanged. That mode only
guards `iptables-save` and `ip6tables-save`: it cannot justify enrolling a mixed
or native nftables source. Full profiles produce `netfilter-kernel-v2` events,
which use the same typed event schema. Older deployed binaries do not understand
these new profiles/events; reverting code after enrollment must account for
that compatibility boundary while retaining the current evidence and state.

The exporter rejects events before the reviewed validity time, as before, and
the API separately refuses accepted full-profile events older than that time.
Initial collection covers at most ten minutes and never precedes validity.
The guard cannot detect a change that occurs and is reverted between snapshots,
or prove which rules applied to historical records. Stop collection before
planned rule changes, review the new context and use a new validity boundary.

## Fixed complete Netfilter views

The full guard runs these fixed commands before reading the journal and again
before releasing the page:

```text
/usr/sbin/nft --json --handle --numeric list ruleset
/usr/sbin/iptables-save
/usr/sbin/ip6tables-save
/usr/sbin/iptables-nft-save
/usr/sbin/ip6tables-nft-save
/usr/sbin/iptables-legacy-save
/usr/sbin/ip6tables-legacy-save
```

Callers cannot choose paths, families, tables, filters or fallback modes. All
seven commands must be present and succeed. There is no implicit downgrade when
a tool is missing, permission is insufficient or a snapshot is malformed.
Each command has at most two seconds and 4 MiB output; the existing ten-second
export wall deadline covers both snapshots, cursor checks, input and journal
reading together. A full source may therefore time out even if each individual
command could succeed within its own limit. Measure the complete exporter on
the enrolled host before scheduling it.

The nft reader accepts JSON schema version 1, rejects duplicate JSON keys and
unknown top-level object kinds, and caps structure depth at 32 and nodes at
100,000. It preserves the order of rules and expressions, set/map elements,
timeouts, limit/quota configuration, comments and unrecognized nested expression
content. It removes only the top-level version/release metadata, known object
handles, anonymous rule counters consisting exactly of `packets`/`bytes`, and
the packet/byte values of named counter objects. A field called `counter` or
`handle` in arbitrary nested data is not globally erased. Default/nft/legacy
iptables views preserve rule tokens and remove generated comments and chain
packet/byte counters; the full mode also checks the save-format structure.

Set membership changes, fail2ban changes, quota usage or dynamic expiry fields
can cause conservative drift. They are retained because omitting semantic state
would weaken the guard. This implementation does not promise continuous
availability on a host whose firewall state changes frequently.

A changed digest reports `profile_drift`, discards the whole page and preserves
the input cursor. Missing tools report `firewall_guard_tool_unavailable`;
failed command execution reports `firewall_guard_snapshot_failed`; invalid nft
or iptables structure reports `invalid_nft_rules_snapshot` or
`invalid_rules_snapshot`. Deadline/output failures retain their existing fixed
codes. An exception in either snapshot releases no batch and cannot advance a
collector cursor. Error messages never include command output or actual rules.

This is a Netfilter ruleset guard, not comprehensive host attestation. The
operator must still establish that enrolled kernel prefixes have no unrelated
producer, identify all hooks/interfaces that use them, and review other packet
processing or logging mechanisms. A bracketed `BLOCK` label and an empty `OUT`
field are insufficient evidence of local input or a final firewall verdict.

## Native prefixes remain observations

A full profile may enroll a literal native prefix matching
`[A-Za-z][A-Za-z0-9_.-]{0,58}:` (for example `sample-observation:`).
The separating trailing space is supplied by the journal format and is not part
of the configured label. Prefixes containing whitespace, shell/regex syntax,
non-ASCII text or other punctuation are rejected. They are passed through
unchanged; no native message is rewritten to resemble UFW.

Native prefixes cannot appear in `rejection_labels` or `local_input_labels`.
The parser, wire validation and event validation keep those events at
`direction: "unknown"`, `final_outcome: "unknown"` and
`rejection_related: false`. Thus even native TCP SYN records are excluded from
the existing inbound TCP multi-port rule. UDP port hopping remains UDP evidence,
not a scan or a successful connection. Supporting a native prefix adds delivery
and visibility; it does not add a detection rule or NAT attribution.

Full profiles can still enroll reviewed bracketed UFW prefixes with existing
local-input assertions. Review every producer of that prefix, including
forwarding and explicit-deny rules, before making those assertions. Keep log
rate and retention limits explicit. Complete passive comparison, resource and
paired recovery acceptance separately before treating a source as operational.
