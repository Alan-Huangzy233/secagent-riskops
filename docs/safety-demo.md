# Safety behaviours

`make safety` (or `docker compose run --rm safety`) shows what the system
refuses, what it changes, and the record it keeps. It runs in under a second
with no API key and no network, and writes nothing outside a temporary
directory. The exported audit timeline is committed at
[`examples/safety-demo/audit-timeline.jsonl`](../examples/safety-demo/audit-timeline.jsonl)
and CI checks that a fresh run reproduces it byte for byte.

## Where it starts

The demo begins from two incidents Claude escalated in the seven-day
evaluation. In both, a password was guessed and then used:

| Incident | What the logs show | Recorded verdict |
|---|---|---|
| `INC-A0004561` | 185 failures for `jonas` on bastion-01, then a login from a source never seen as `jonas` | escalate, high |
| `INC-A0003598` | 74 failures for `pavel` on web-02, then a login from a new source | escalate, high |

The dossiers are in `examples/safety-demo/incidents/`. The recorded calls are
read from `docs/eval/triage-tape-synthetic-7d.jsonl`, which CI replays against
the rebuilt dataset. A dossier is used only if its request fingerprint (model,
effort, prompt version, schema and the exact text sent) matches a recorded
call, so the verdicts shown are the ones the model actually returned for these
dossiers.

The model only escalates, dismisses or abstains. A fixed playbook decides the
response: a login that succeeded from a source never seen logging in as that
account means the password was guessed, so the host should stop accepting
passwords. Each incident becomes a `harden_ssh_access` plan for its host, with
root login disabled and key-only authentication.

## 1. Blank and ambiguous scope fails closed

Before any request is compared with a scope, the policy engine checks that
the scope can only be read one way:

- It names at least one actor and one target. Otherwise it is refused with
  `SCOPE_EMPTY`, even when the scope is marked approved.
- Every target is a plain host name, or a `*.` wildcard over two or more
  labels. `*`, `*.internal`, `web-*`, `10.0.0.0/8`, padded or upper-case
  entries are all refused with `SCOPE_AMBIGUOUS`.
- Every actor is a plain name.
- The validity window is made of real timestamps with a time zone, and it
  starts before it ends.

Request times are compared as instants, not as text. Before this check existed,
a blank target matched a blank allowlist entry, `*.` and `*.internal` matched
whole zones, and a decision time of `yesterday` passed the window check. Those
cases are in `backend/tests/test_policy_adversarial.py`.

The demo also refuses a medium-risk plan that has no approval
(`APPROVAL_REQUIRED`). It refuses the same plan again after it was approved and
then edited: an approval is bound to the plan's hash and the scope's policy
hash, so any change to the plan withdraws it.

## 2. An approved change, verified on the host

One operator approves the bastion-01 plan. **A second-approver rule is not
built**: the deployment has one operator, and the rule is planned for the
approval service. The policy engine then allows execution.

The executor works only on a directory with a `.riskops-lab` marker that names
the target asset. A plan for bastion-01 cannot run against web-02's copy, and it
cannot run against `/`. It makes the smallest edit to the one file it owns:

- the first global line for each setting is rewritten in place;
- a missing setting is added before the first `Match` block;
- the original is kept byte for byte and the new file is swapped in
  atomically.

Verification is separate code (`backend/app/tools/sshd_config.py`). It re-reads
the host with sshd's own precedence:

- the first value read wins;
- an `Include` is read where it appears, its files in lexical order;
- lines under `Match` override the global value for matching connections, so
  any of them that weakens a planned setting fails the check.

The demo prints the settings before and after, and the diff.

## 3. A failed check rolls back by itself

The web-02 copy has the layout of an Ubuntu cloud image. Its `sshd_config`
includes `sshd_config.d/*.conf` near the top, and cloud-init's
`50-cloud-init.conf` sets `PasswordAuthentication yes`. The executor's edit
lands further down, so sshd would still accept passwords. Verification reports
that setting and the file and line it comes from.

The change is then rolled back without waiting for a person, and the rollback
is checked twice: the file must hash to its pre-change value, and the settings
sshd would use must match the ones read before the change. The plan ends as
`rolled_back`, and the conflict is left for a person to decide. Overriding
cloud-init's file or reordering the operator's `Include` would change more than
the plan approved.

## 4. One audit timeline

Every step writes a hash-chained audit event carrying the facts it rests on:

- the model, prompt fingerprint and verdict;
- the playbook call;
- the plan hash;
- each policy decision with its reason code;
- the approval and its approver;
- the edits, diff, before and after hashes and settings;
- the verification checks;
- the rollback and its checks.

The sequence can be rebuilt from the chain alone.

```bash
python -m app.audit_timeline show examples/safety-demo/audit-timeline.jsonl
python -m app.audit_timeline verify examples/safety-demo/audit-timeline.jsonl
```

`verify` recomputes every hash and link from the file, without the program that
wrote it, and names the first event that does not hold. The demo changes the
approver's name in a copy of the trail and shows that the chain breaks at that
event.

The timestamps come from a deterministic clock that steps one second per
reading, so the export reproduces exactly. They order the events; they are not
wall-clock measurements.

## What this does not show

- Real hosts. The executor runs only on lab copies, and nothing reloads a
  daemon.
- A second approver, approval requests, or authentication of approvers.
- Full `sshd_config` semantics. `Match` criteria are not evaluated, a `Match`
  inside an included file is assumed to end with that file, and keywords other
  than the four managed ones are not checked.
