# Joint SSH and network evidence: offline foundation

[Issue #147](https://github.com/Alan-Huangzy233/secagent-riskops/issues/147) tracks
joint investigation cases. This first increment supplies a pure, bounded evidence
contract and reproducible synthetic acceptance. Production continues to use the
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
whole-incident summary. No source adapter is implemented in this increment.

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
There is no file, database, model, notification, disposition or response I/O.

## Reproduce the fixture

From the repository root:

```sh
PYTHONPATH=backend python -m app.evaluation.joint --check examples/joint-evidence/report.json
python -m pytest backend/tests/test_joint_evidence.py
```

The report uses authored documentation addresses and fixed timestamps. It exercises
positive associations, wrong-host/time/peer counterexamples, duplicate delivery,
partial inputs, stale/retracted revisions and unreviewed destinations/profiles.
It is a deterministic contract check, not measured production detection accuracy.
The unit suite additionally covers boundary, clock and malformed-input cases.

## Remaining delivery

Issue #147 remains open. Next increments need bounded retained-source adapters,
explicit mapping validation against enrolled sources, a separate durable derived
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
