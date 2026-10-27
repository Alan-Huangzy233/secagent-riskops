# Joint SSH and network evidence: retained observations and derived cases

[Issue #147](https://github.com/Alan-Huangzy233/secagent-riskops/issues/147) tracks
joint investigation cases. The pure association contract has reproducible
synthetic acceptance; explicit read-only adapters project retained source
evidence into that contract. An independent derived store and explicit finite
refresh are also implemented and tested with isolated sources. The optional
[joint console and explicit CLI](joint-console.md) expose those observations with
validated mapping, bounded discovery and recovery. Production activation remains
separate; importing these modules creates no joint database or worker.

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
metadata. It is an explicit-call interface. The optional joint CLI invokes it during
refresh; console GET requests never invoke it. No scheduled worker is started.

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

## Explicit derived persistence and finite refresh

`joint_case_contract`, `joint_case_store` and `joint_reconcile` implement an
internal workflow over a separate SQLite database. `CaseScope` fixes the explicit
asset mappings, expected producer, association window, timeline cap and declared
SSH coverage. It also pins the projection, reader and transformation policies.
Changing this scope requires a separately reviewed store; it is not an in-place
configuration edit.

A caller uses these internal interfaces explicitly:

| Interface | Behavior |
| --- | --- |
| `JointCaseStore.create(path, scope, limits=...)` | Create a new private derived file; refuse an existing file |
| `JointCaseStore.open(path)` | Validate an existing derived store's identity, schema, scope and limits without migrations |
| `store.register((AnchorRequest(incident_id, revision), ...))` | Register 1–50 distinct anchors per atomic batch; equal requested revisions are unchanged, higher revisions advance the request generation, lower revisions fail |
| `store.begin_cycle()` | Freeze registered requests into one finite worklist; reuse an already active cycle |
| `joint_reconcile.reconcile_step(store, network_path, ssh_path, ...)` | Attempt a bounded step of the explicitly begun cycle |
| `store.get_cycle()` / `store.get_registration(incident_id)` | Inspect worklist progress or an anchor's current refresh status |
| `store.get_case(case_id, revision=None)` | Read the current projection or an explicitly selected immutable revision |

This internal refresh workflow does not discover network cases or start a worker.
The optional CLI performs separately bounded discovery through the enrolled mapping. Its coverage is only the explicitly registered anchors and the
retained incident evidence read for them.

The store retains the pure canonical projection as an immutable numbered case
revision. A repeated current projection hash updates read/freshness metadata
without adding a semantic revision. A changed SSH projection can add a revision
under the same case ID even when the requested network revision is unchanged.
Returning from content A to B and later to A is a third observation revision;
historical hash reuse must not erase that transition. Read times, query costs
and operational retries do not become new evidence revisions.
`get_case(case_id, revision=N)` retains that revision's projection and first-read
metadata; its `current_revision`, `is_current` and refresh fields separately
report current state. Those current-state fields can change during later reads.

Each cycle freezes the registered-anchor boundary and each item's requested
revision/generation. It revisits every registered item, including previous
unmatched and failed reads. It does not use network changes or SSH receipt or
`updated_at` cursors as a substitute for this revisit. New registrations wait
for the next cycle; a request changed during an outstanding read cannot publish
its obsolete result. Explicit bounded steps resume the saved worklist, and a
single failed anchor does not prevent later items being attempted. The step
reports the cycle it selected separately from `current_cycle`, which another
caller may already have advanced.

One explicit step admits at most five items within a ten-second cooperative
budget. Each joint read keeps the adapters' shared maximum five-second deadline,
shortened to the step's remaining budget. An in-flight read can finish with an
error; its bounded outcome transaction is still attempted before returning.
These are admission and cooperative execution bounds, not hard filesystem or
end-to-end timing guarantees.

The source read transactions close before the derived write transaction. A
semantic revision, current pointer and completed item are published atomically.
Reader failures, adapter caps and deadlines preserve the previous case and
record a separate refresh failure; they never become an empty successful finding. A
successful pure `partial`, `stale` or `retracted` observation retains its own
meaning and history. Finishing the finite worklist means every item was
attempted, not that every source refreshed successfully or that all production
cases are covered. `attempted_complete` means no worklist items remain pending;
`all_items_refreshed` additionally requires no failed, ineligible or superseded
items. Neither status establishes complete source coverage.

Callers may lower these `StoreLimits` defaults when creating a store. The selected
limits are then immutable:

| Limit | Default maximum |
| --- | --- |
| Registered anchors | 1,000 |
| Semantic revisions across the store | 10,000 |
| Total stored canonical projection bytes | 256 MiB |
| One canonical projection | 4 MiB |
| One read metadata object | 32 KiB |

A logical capacity limit during refresh preserves existing evidence and records
a refresh failure when the outcome transaction can commit. Registration capacity
rejects the whole new batch. If a busy/full database or I/O failure prevents even
the outcome commit, the caller receives a fixed store error and the item stays
pending for retry. There is no automatic pruning or silent limit increase.

The derived file has its own identity, schema and fixed capacity limits; its
mapping/policy scope and limits cannot be silently replaced. Logical projection
byte limits exclude SQLite pages, indexes, bounded metadata and WAL overhead, so
they are not a hard disk-usage limit. The file must not alias a source database,
participate in collector ACKs or mutate source rows.
The retained timeline remains bounded: saving a partial projection does not
store hidden evidence or create full historical evidence pagination. Two
sequential source reads remain separate observations; the store does not turn
them into a cross-database atomic snapshot or a durable upstream SSH revision.

The [console guide](joint-console.md) describes the optional validated
configuration, explicit discovery/refresh CLI, v2 typed summaries, read-only
routes, paginated view and derived recovery. There is no scheduler, joint
notification, AI or response-control integration. Production activation remains
separate; the default configuration creates no joint store or refresh job.

## Reproduce the fixture

From the repository root:

```sh
PYTHONPATH=backend python -m app.evaluation.joint --check examples/joint-evidence/report.json
python -m pytest backend/tests/test_joint_evidence.py backend/tests/test_joint_reader_io.py \
  backend/tests/test_joint_network_reader.py backend/tests/test_joint_ssh_reader.py \
  backend/tests/test_joint_reader.py backend/tests/test_joint_case_contract.py \
  backend/tests/test_joint_case_store.py backend/tests/test_joint_reconcile.py
```

The report uses authored documentation addresses and fixed timestamps. It exercises
positive associations, wrong-host/time/peer counterexamples, duplicate delivery,
partial inputs, stale/retracted revisions and unreviewed destinations/profiles.
It is a deterministic contract check, not measured production detection accuracy.
The unit suite additionally covers boundary, clock and malformed-input cases.
Adapter tests create temporary databases through the actual source store schemas
and check historical membership, late arrivals, raw-only exclusions, source
isolation, concurrent reads/writes, indexed bounded queries and error cleanup.
Derived-store and refresh tests cover SSH-only late arrivals, unmatched-to-linked
transitions, A→B→A history, metadata-only refresh, finite cycle boundaries,
request-generation races, source failures, capacity limits and atomic rollback.
They verify that both source transactions close before publication and that
source content remains unchanged. These tests do not read production databases
or measure production detection accuracy.

## Remaining delivery

Issue #147 remains open. The pure foundation, source adapters and explicit
derived store/finite refresh have isolated acceptance. Production integration
still needs mapping validation against enrolled sources, bounded anchor
discovery, scheduling, revision-pinned
pagination and the joint-case console. Explicit registration cannot stand in for
an inventory of all production findings. Source transactions must close before
publication, and sequential source observations remain non-atomic across stores.

Recovery must preserve original network/console/collector pairing. Derived-store
backup and source-restore revalidation need their own tested contract. A reviewed
production mapping and resource/rollout plan precede activation. Manual joint AI
is separate [#148](https://github.com/Alan-Huangzy233/secagent-riskops/issues/148);
automatic response remains separate
[#150](https://github.com/Alan-Huangzy233/secagent-riskops/issues/150).
