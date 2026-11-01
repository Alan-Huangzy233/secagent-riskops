# Shared budget foundation for joint AI jobs

The queue layer can bind an independent joint queue to an existing SSH budget
owner. This is a foundation for [#148](https://github.com/Alan-Huangzy233/secagent-riskops/issues/148),
not a live-provider configuration. The joint service still accepts only `offline`
and `recorded` modes. Neither mode uses this binding or makes paid calls.

## One budget owner

`Jobs(..., queue_kind="joint", budget_owner=ssh_jobs)` requires an initialized
private SSH queue with existing positive total and daily limits. It never creates
another allowance or copies existing calls. The owner's existing reservations,
charges, uncertainty and halted state remain authoritative for both queues.
An unresolved reservation continues to consume its full reserved amount.

The joint queue persists an immutable binding to the owner’s resolved path,
filesystem identity, alias-key digest and original limits. Reopening it requires
that same owner; a missing, replaced or incompatible owner fails closed. A queue with
local financial records cannot be adopted into shared accounting. Queue and
owner paths, SQLite side files and existing file aliases must be disjoint;
conflicts are rejected before initialization can alter either store. A bound joint
queue cannot set budget limits. Its budget view reports the shared owner's
accounting, and its local `ai_calls` table remains empty.

Bound queues use a distinct persistent queue-kind marker. Readers that only
understand the earlier ordinary-joint marker reject them. Binding an existing
unbound joint queue changes that marker and writes its owner binding in one
transaction, preserving its alias key and job history. Stop existing workers
before binding a queue: a marker cannot revoke an operation that an older worker
has already admitted. Keep ordinary SSH and offline joint queues on their
existing formats.

This API does not change the existing SSH service configuration or authorize
network summaries. No browser endpoint or joint-service setting enables it.

## Reservation and recovery

The joint queue lock is acquired before the owner ledger lock. A new reservation
checks the current job, attempt and lease while retaining the joint lock, then
commits the reservation in the owner's ledger. The owner transaction enforces
both total and UTC daily limits, including concurrent SSH calls. The owner's
clock determines the reservation day; job leases use the queue's own clock.

Only the owner stores financial state. There is no claim of an atomic commit
across two databases. Recovery, cached-result lookup and retry decisions consult
the same bound owner:

- Before a reservation commits, an expired attempt can use the existing bounded
  retry policy. A later attempt receives a new call ID.
- After a reservation commits, a lost response or interrupted local update leaves
  the original call uncertain. It keeps its reservation and cannot be resent.
- After a completed receipt commits, an interrupted job can recover the saved
  receipt using the same call ID, without another provider request.
- A late billed response can settle the original reservation even after its job
  lease expires. Identical settlement is idempotent; conflicting settlement is
  rejected. A charge above its reservation halts further shared spending.

Budget exhaustion, owner unavailability and uncertain calls never create a new
pool or release reserved funds automatically. Repeated reservation of a completed
call returns its saved receipt; an unresolved call cannot authorize another send.

## Recovery boundary and remaining integration

Keep both queues and the owner ledger in a coordinated recovery procedure.
Do not replace just one database with an older copy or bypass the owner binding.
The binding is an identity guard, not proof that an administrator has never
rewound database contents. Reconciliation and any reauthorization after such a
restore require separate design; this foundation does not automatically rebind,
reset limits, discard calls or repair financial history.

Live transport and service wiring remain separate work, together with outgoing
network-field policy, provider selection, independent explanation review and
explicit pilot approval. That integration must reuse this ledger contract and
qualify request/receipt handling end to end before sending a joint dossier.
Automatic analysis (#149) and enforcement (#150) remain later stages.

Only general code, documentation and authored synthetic tests belong in version
control. Credentials, queue contents, operating records and check outputs stay
local.
