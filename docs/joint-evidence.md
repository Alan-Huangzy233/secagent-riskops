# Joint SSH and network evidence: foundation and read-only adapters

[Issue #147](https://github.com/Alan-Huangzy233/secagent-riskops/issues/147) tracks
joint investigation cases. The pure association contract has reproducible
synthetic acceptance; explicit read-only adapters can now project retained
source evidence into that contract. Production continues to use the
existing SSH/network views and IP search; no joint database, worker, configuration,
API or console tab is activated by importing this module.

## Why inspect actual evidence

An SSH incident may span several hosts. Its whole-incident score, counts and
start/end times cannot establish that the mapped host had activity near a network
finding. `correlate()` selects individual SSH records by explicit source ownership,
canonical observed peer IP and the bounded evidence window. An incident label
shared with another host is insufficient. The original SSH score is not an input
and no joint risk score is produced.

A mapping lists an asset's SSH sources and exact network source, destination
addresses and accepted profile revisions. Names and prefixes do not imply an
asset identity. Ambiguous ownership, invalid addresses and inconsistent evidence
provenance fail validation. Unmapped observations return an explicit rejected
projection. The contract currently supports local-input TCP evidence only.

The network case identifies its producer, incident, revision, boot and profile.
SSH evidence references retain original and resolved incident IDs. Repeated event
identities count once; conflicting facts fail validation. Adapters must supply
resolved references and the exact retained version, not a preview of a page or a
whole-incident summary. The read adapters below supply only evidence retained
by the existing source schemas.

## Results and limits

The result is an immutable canonical JSON projection with a deterministic hash,
case identity, typed timeline, selected per-source evidence counts, association
reasons and uncertainties. Reordering equivalent inputs does not change the hash;
late matching SSH evidence changes the projection while retaining case identity.
`to_dict()` returns a separate copy. These hashes identify a supplied projection;
they are not signatures or proof that a collector supplied authentic records.

States distinguish linked, unmatched, partial, stale, retracted and rejected
inputs. These are investigation states, not probabilities of compromise. An
observed SSH authentication success does not prove exploitation. Shared IPs,
unknown clock alignment and source coverage remain visible even when evidence is
linked. Missing data cannot establish safety.

The default margin is 30 minutes on each side of the network evidence, bounded by
the contract's maximum. Temporal association must be withheld for detected clock
discontinuity or an excessive anchor span. Declared omitted evidence and timeline
caps produce explicit partial results; returned counts describe observed records.
Input completeness describes supplied/declared records only, not collection
coverage or the full retained history. Callers must truthfully declare omissions
and coverage; this pure module cannot discover what an adapter failed to read.

Tuples, identities, profiles, timestamps, account strings, record counts and byte
sizes are bounded. Raw journal messages are excluded. Account or event-identity
strings remain data; they are never prompts, shell commands or rendered HTML.
The pure `joint_evidence` module performs no file, database, model, notification,
disposition or response I/O. The separate readers perform only the explicit
source reads described below.

## Explicit retained-source reads

`joint_reader.read_joint_evidence(network_path, ssh_path, mappings, incident_id,
revision, ...)` reads one required network revision and the mapped SSH evidence.
It returns an immutable `JointRead` with the pure projection and separate read
metadata. It is an internal explicit-call interface: no configuration, scheduled
worker, API endpoint, database migration or console feature activates it.

The network reader checks the store identity/version and reads the producer,
revision payload and historical evidence membership in one read transaction.
The selected membership must agree with both the payload count and retained
records. Current-version updates cannot silently replace the requested revision.
All typed records must agree with the incident's source, boot, profile and peer.

The SSH reader selects canonical incident candidates by exact IP and overlapping
time, then inspects actual `incident_evidence` rows from the mapped sources and
window. Existing incident/source/time indexes narrow both steps. It does not
filter out handled, low-score or protected-address incidents. UTC timestamps
are converted with integer microseconds; outward rounding of SQLite REAL query
bounds avoids losing an exact boundary before the precise timestamp check.

This scope is **retained incident evidence, not all SSH logs**. Unassociated raw
log records have no incident ID and are excluded. Raw log expiration does not
remove evidence still retained by the incident. A no-match result means only
that this read found no matching retained incident evidence in the specified
scope; it does not establish no activity, complete collection or safety.

SSH merges rewrite current event ownership. The adapter retains the owner it
actually reads and its bounded canonical resolution; it cannot reconstruct an
unrecorded pre-merge event owner. It never invents old references from an alias
family. Loops, inconsistent owners or peer facts are errors.

Network and SSH transactions run sequentially and close before final projection
publication. The returned read intervals are observations, **not a cross-store
atomic snapshot**. SSH evidence is mutable: late records and merges can change a
later read even for the same network revision. Read metadata provides a selected
SSH projection hash and explicitly no durable SSH revision. A raw-event receipt
cursor does not freeze incident evidence. Wall-clock read metadata can differ
between otherwise equivalent reads; the pure evidence hash remains deterministic.

Only required typed JSON fields cross the SQLite/Python boundary. Raw messages,
journal cursors and private database paths are excluded from returned data and
fixed public error messages. Field type/byte bounds apply before materialization;
a matching IP or an evidence hash does not authenticate source records.

### Resource and failure contract

Callers can lower, but not raise, `ReadLimits` defaults:

- One network incident/revision and at most 200 candidate SSH incidents.
- At most 5,000 network and 5,000 SSH evidence rows, fetched in batches of at most
  200, with an 8 MiB shared projected-input byte budget and the pure contract
  limits of 8 MiB serialized input and 4 MiB serialized projection.
- A shared five-second cooperative SQLite/Python deadline and at most 250 ms
  lock wait per connection. A lock wait already in progress can exceed the
  remaining deadline by up to its configured wait. SQLite native work and OS
  I/O are not hard-interruptible deadlines.

Limits, missing revisions/sources, incompatible schemas, locks, malformed evidence
and timeouts raise distinct fixed `EvidenceReadError.code` values. Readers never
silently truncate into a complete negative result. A later pure timeline cap can
still return `partial`, retaining its explicit evidence count/hash and truncation
reason. Invalid mappings or untrustworthy temporal windows skip the SSH source
read and explicitly report that the association was not evaluated.

Connections use `mode=ro`, `query_only` and explicit read transactions without
store constructors. Cleanup releases handlers, transactions and connections on
success and failure. Normal SQLite WAL reads may require existing or writable
shared-memory sidecars; read-only here means no retained-row or schema mutation,
not a guarantee of zero filesystem writes. `immutable=1` is not used on changing
WAL databases. These readers do not establish a backup or recovery snapshot.

## Reproduce the fixture

From the repository root:

```sh
PYTHONPATH=backend python -m app.evaluation.joint --check examples/joint-evidence/report.json
python -m pytest backend/tests/test_joint_evidence.py backend/tests/test_joint_reader_io.py \
  backend/tests/test_joint_network_reader.py backend/tests/test_joint_ssh_reader.py \
  backend/tests/test_joint_reader.py
```

The report uses authored documentation addresses and fixed timestamps. It exercises
positive associations, wrong-host/time/peer counterexamples, duplicate delivery,
partial inputs, stale/retracted revisions and unreviewed destinations/profiles.
It is a deterministic contract check, not measured production detection accuracy.
The unit suite additionally covers boundary, clock and malformed-input cases.
Adapter tests create temporary databases through the actual source store schemas
and check historical membership, late arrivals, raw-only exclusions, source
isolation, concurrent reads/writes, indexed bounded queries and error cleanup.
They do not read production databases or measure production detection accuracy.

## Remaining delivery

Issue #147 remains open. The adapters have isolated acceptance; they are not yet
connected to a production joint workflow. Next increments need explicit mapping
validation against enrolled sources, a separate durable derived
store, finite reconciliation that notices SSH-only late arrivals, revision-pinned
pagination and the joint-case console. Reads must release source transactions
before publishing derived records; sequential source snapshots must not be
presented as a cross-store atomic snapshot.

Recovery must preserve original network/console/collector pairing. Derived-store
backup and source-restore revalidation need their own tested contract. A reviewed
production mapping and resource/rollout plan precede activation. Manual joint AI
is separate [#148](https://github.com/Alan-Huangzy233/secagent-riskops/issues/148);
automatic response remains separate
[#150](https://github.com/Alan-Huangzy233/secagent-riskops/issues/150).
