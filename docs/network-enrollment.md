# Preparing passive network source enrollment

This increment prepares real-source enrollment for [#120](https://github.com/Alan-Huangzy233/secagent-riskops/issues/120).
It adds the [full firewall guard and native observation format](network-source-guard.md),
[paired network recovery](network-recovery.md), capacity notices and an isolated
workload exercise. Installing code is separate from enrolling sources. The default
remains `network_ingest: null`; this repository contains no live identities,
credentials, traffic samples or host-specific deployment settings.

## Choose the supported observation

For an existing UFW source, inspect the complete current IPv4/IPv6 rules and
native nftables hooks. Trace every producer of an enrolled prefix and all callers
of shared logging chains. Only assert `local_input_labels` and interfaces when
that complete review establishes the observed interface shape's local-input
meaning. An empty `OUT` field alone is insufficient. Uncertain provenance stays
unknown and cannot feed the inbound TCP rule.

An existing native kernel LOG prefix can be enrolled under the full guard as an
**observation only**. Preserve its literal prefix, keep `rejection_labels`,
`local_input_labels` and `local_input_interfaces` empty, and do not interpret
UDP NAT port hopping as TCP probing. No new firewall accept/drop or logging
rule is installed by this feature. An observation-only source can be healthy
without producing any security incident; inspect its retained events and source
quality rather than fabricating a score to populate the table.

Start the profile's validity at the completed current review. Do not backdate it
based on a sample of old logs. Read the complete guard twice around enrollment;
any semantic drift requires review. The collector must not automatically replace
a digest, delete a pending batch or rebind its identity to make an error disappear.

## Dedicated delivery

Install a versioned, root-owned exporter package with its Python modules and
sibling `journal_export.py`. Verify the source Python version and all fixed
firewall tools required by the full guard before granting the key. Use one
dedicated SSH key per exporter, strict host-key verification and a forced command
which invokes only the exporter. Reject caller commands, interactive shells,
agent/X11 forwarding, arbitrary paths and journal filters. Keep existing SSH
telemetry keys and cursors separate. A required jump host must have a separate
forwarding credential restricted to the explicitly enrolled endpoints; do not
broaden the exporter credential into a general jump or shell key.

Keep source exporter configuration root-owned and not group/world writable.
Store each API token and collector configuration with mode 0600, owned by its
dedicated collector account. Each source needs a distinct mode-0700 state
folder and self-contained SSH configuration. The latter is part of the durable
identity: changing another source must not rewrite an active source's shared SSH
mapping. Enroll the matching token digest and full profile in the live API before
starting delivery. Set a fresh validity time and guard digest immediately before
source activation, after verifying the exact reviewed code.

The example [service](../deploy/systemd/secagent-riskops-network-collector@.service)
and [timer](../deploy/systemd/secagent-riskops-network-collector@.timer) are
opt-in templates. They require the `riskops-network-collector` system account,
installed Python environment and private per-source configuration. Start with
one source and bounded single runs; inspect durable ACK, cursor, analysis and
source quality before enabling its timer or proceeding to the next source.
The template uses about one poll per minute, a 35-second service deadline,
128 MiB memory and 25% CPU quota. These are operator-adjustable engineering
bounds, not guaranteed source capacity. No active scan or model request is part
of enrollment.

## Capacity is finite

Empty heartbeats consume batch receipts. With three sources polling each minute,
10,000 default batch receipts last at most about 2.3 days, even with no events;
additional pages shorten that estimate. Event expiry does not prune replay
receipts, batch history or case evidence. A 14-day event retention setting is
not a promise of 14 days' capacity.

Measure the actual source rate and synthetic resource report, then choose explicit
receipt, batch and total-storage budgets. The database page limit reserves room
for WAL/SHM; its page budget may exhaust before the total byte cap. At 70% of
any event/receipt/batch, total-storage or database-page budget, an independent
console collection notice warns of capacity pressure. It is emitted before
analysis so full network storage can still report through the console. This
warning never changes an incident score. Hard limits retain pending batches and
stop new writes; they do not silently delete old evidence.

Review capacity during the pilot and stop scheduled collection before exhausting
the agreed budget. Resolve capacity through a reviewed retention/migration plan;
do not delete receipts, reset cursors or run manual VACUUM. Safe long-term
compaction remains outstanding and #120 stays open for sustained operation.

Run the authored workload on a development environment:

```sh
PYTHONPATH=backend python scripts/simulate_network_workload.py
```

It measures only its stated temporary-store workload. It does not benchmark the
real source, remote SSH, sustained Internet traffic or detection accuracy.

## Recovery and activation evidence

Configure the explicit network recovery cohort **before scheduled collection**.
A generic list of state folders plus SQLite snapshots can mix an old cursor with
a newer checkpoint or lose a cross-database notification. Follow the
[paired recovery guide](network-recovery.md); keep the collector mapping and
original pending payload, and restore network, console and all state folders
from the same package. Use an isolated restore/replay exercise. Verifying
ciphertext with a public key alone is not a decrypted restore test.

Retain a private per-source acceptance record: reviewed rule/profile digest and
validity, installed artifact hashes, fixed-command/host-key restrictions,
resource measurements, durable cursor and replay checks, source quality and
notification checks, recovery results and rollback instructions. A source that
has only sent an empty heartbeat is connected but has not yet demonstrated
real observation delivery. Historical gaps and logging limits remain visible.

For rollback, stop all new collectors first and preserve their pending files,
network/console databases and profile mappings. Strong profiles/new normalized
parser versions require compatible code. A pre-enrollment code rollback must
also disable network ingestion while retaining its data; do not start an older
binary against the new active network namespace or overwrite acknowledged data
with an older snapshot merely to revert code.
