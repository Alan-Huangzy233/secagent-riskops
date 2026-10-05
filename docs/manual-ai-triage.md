# Manual AI review in the telemetry console

The telemetry application now has an optional **preview → queued analysis →
human review** workflow. It starts disabled. Opening an incident does not submit
a model request. Enabling offline mode exercises the workflow without credentials
or network calls; its result always asks for human review.

This is an implementation foundation for issue #118. It is not a production
rollout or approval to send real telemetry to a provider. The latest
[three-model synthetic comparison](eval/triage-pilot-model-comparison.md)
supports trying Luna low under human review; production model selection remains
open.

## Operator workflow

1. Open an incident and select **预览分析摘要**. The visible JSON is the dossier
   used for analysis. Check its completeness and contents.
2. Select **提交本地演练**, **读取录制结果**, or **开始模型分析**, depending on the
   configured mode. The server rebuilds the dossier and rejects an expired
   preview. It accepts a preview key, never a client-supplied dossier.
3. Results show the suggestion, original model explanation, checked citations,
   local reference mapping, validation reasons and summary revision. Invalid
   evidence or schema produces review rather than a usable noise recommendation.
   Free-text explanations and ATT&CK tags still require human judgement.
4. Save **同意建议 / 不同意建议 / 需要更多证据**, optionally with a note. This adds an
   audit entry; it does not change the incident's disposition. Use the existing
   incident controls separately.
5. New evidence or trusted context makes older results visibly stale. Up to 20
   recent jobs are shown, including jobs belonging to merged incident identities.
   A disposition-only change does not invalidate an unchanged dossier.

Rule scores, advice and human disposition have separate meanings. No suggestion
dismisses, acknowledges, resolves or blocks an incident automatically. The current
application has one authenticated operator, not an analyst-role or approval system.

## Configuration and modes

Set `RISKOPS_AI_CONFIG` to an absolute path of a private JSON file readable only
by the service account (0600). Unset means disabled: no AI worker, queue creation,
key read or model request. Invalid optional configuration disables AI while
collection remains available.

An offline configuration is available in
[`examples/manual-ai-triage/offline.json`](../examples/manual-ai-triage/offline.json).
Adapt its absolute database path and create its parent directory privately for
the service account. The queue must be separate from the telemetry database.

```json
{
  "mode": "offline",
  "database_path": "/var/lib/riskops-ai/analysis.sqlite",
  "allow_external": false
}
```

Configure the service environment and restart the application through your normal
release process. No deployment unit or live configuration is changed by this
feature. The console states the mode before submission.

| Mode | Additional requirements | Behavior |
| --- | --- | --- |
| `offline` | None | Zero-cost workflow exercise; always human review |
| `recorded` | Absolute `profile_path` and `recording_path` | Exact dossier/request fingerprint lookup; missing recording asks for review |
| `api` | Profile, private `keys_file`, `allow_external: true`, `approved_summary_version: 1`, positive total/daily budgets | Explicitly submitted jobs can send the approved dossier |

A recording must match the exact aliased dossier and profile fingerprint. A tape
from the evaluation corpus is not interchangeable with a telemetry incident.
Offline and recorded modes never instantiate a model HTTP client.

Before an API pilot, agree the provider, field policy and production budget.
`profile_path` uses the existing [configurable provider profiles](model-triage.md);
API mode needs the optional HTTP dependency installed with `pip install '.[ai]'`.
`keys_file` uses that guide's 0600 JSON format; key values never enter the browser.
`total_budget_usd` and `daily_budget_usd` are required, with
`0 < daily <= total <= 1000`. Defaults are zero. The code supports API mode,
but the current acceptance used fake transports and offline browser fixtures only.

The paid **synthetic evaluation** continues using its original shared ledger.
This separate manual-job database is not a replacement for that ledger and does
not authorize further spending or real-log egress.

## Outgoing summary version 1

The server reads the newest at most 40 incident evidence records in one SQLite
read transaction. The dossier is limited to 100 evidence/context records.
Collection gaps, unknown coverage, catch-up, skipped records and truncation are
explicit; none is silently treated as complete.

| Input | Dossier value |
| --- | --- |
| Source identity, peer IP, account, event ID, incident ID | Stable keyed aliases; raw values remain local |
| Event time and context validity windows | Relative times shifted to a fixed synthetic epoch |
| SSH outcome | Normalized failure, invalid-user or success type |
| Trusted account/history/authorization context | Typed fields with aliases and checked windows |
| Raw log message, hostname, user agent | Omitted |
| HTTP method/status | Available only through the normalized offline/future adapter |
| HTTP path | Opaque alias unless the administrator approves that exact path |

Alias keys persist privately in the queue database. Aliases preserve equality
within that installation; this is pseudonymization, not anonymity. The
authenticated browser can view local reference mappings, but they are not part
of the model request.

The live adapter currently consumes **SSH evidence only**. Pre-authentication
records without the required identity are marked incomplete. HTTP adapter tests
do not establish live HTTP collection; that remains #119. Queries, headers and
bodies are never copied from a raw request. A path containing a query cannot
match the approved exact-path list.

Optional `context_file` is a private, administrator-maintained inventory:
version 1, at most 500 records / 256 KiB, no unknown fields or duplicate IDs.
Supported records are `account_context`, `source_history`, `authorization`
and `service_context` from the [evidence schema](triage-evidence.md). For example:

```json
{
  "version": 1,
  "records": [{
    "event_id": "inventory-account-example",
    "kind": "account_context",
    "host": "source-a",
    "account": "example-account",
    "classification": "organisation"
  }]
}
```

Here `host` is the configured **source ID**, not its display hostname.
Inventory source/account values use the original local identities before
aliasing; times use Unix seconds. Source-history windows must precede the
incident. The implementation records the inventory digest and record ID as
local provenance. It does not independently verify an administrator's assertions.
Absent account classification remains `unknown`; names such as root/admin
never prove ownership, generic status, authorization or source familiarity.
Telemetry-derived history and external inventory synchronizers remain future work.

## Persistence, costs and recovery

The private SQLite queue uses WAL, full synchronization and transactional claims.
It stores jobs, bounded dossiers, local references, versions, attempts, leases,
results, audit events and API reservations. A unique dossier/configuration key
coalesces repeat clicks across processes and restarts. Changes to approved
summary settings, context, model profile or evidence produce a new key.

The default queue limit is 100 pending jobs, lease 300 seconds, and maximum two
attempts for work that has not reserved a paid call. Calls use the provider
adapter's bounded request timeout. When a worker loses its lease:

- A completed durable response is replayed locally, without another HTTP call.
- An unsettled reservation stays `uncertain`, keeps its budget and is not
  automatically resubmitted. A late response can still settle the original call.
- An attempt that never submitted a call can retry within its configured bound.

Reservations account for configured maximum input/output cost before HTTP.
Total and UTC daily caps include outstanding reservations, are enforced in one
write transaction, and survive worker restarts. Limits are pinned in the
database; changing JSON cannot silently reset or raise them. A charge above its
reservation records the cost and halts further reservations. Costs are estimates
from usage and profile prices; provider billing is authoritative.

Budget exhaustion, invalid output, missing recordings, expired evidence and
unavailable providers remain visible review states. Repeated submission of the
same terminal job returns that job. There is no self-service retry/refund for an
uncertain paid call; an operator must investigate the provider outcome first.

Back up the queue with SQLite's online backup API, together with the private
configuration, inventory and access-controlled credential recovery procedure.
Copying a live database file alone can omit WAL data. The queue is not yet wired
into the existing telemetry recovery-package configuration. Restore it without
discarding reservations or regenerating the alias key. Audit entries are
append-only through the application, not a cryptographic tamper-proof archive.
Removing the environment configuration and restarting disables future work;
it does not retract a request already sent to a provider.

## API and verification

Reads require existing operator authentication:

- `GET /api/ai/status`
- `GET /api/incidents/{id}/ai/preview`
- `GET /api/ai/jobs/{id}`

Writes also require JSON, the existing CSRF token and same-origin checks:

- `POST /api/incidents/{id}/ai` with `{"preview_key": "..."}`
- `POST /api/ai/jobs/{id}/review` with verdict and optional note

Regression tests exercise alias/privacy boundaries, trusted context changes,
concurrent clicks/workers, leases and late results, cached settlement, concurrent
total/daily reservations, date changes, invalid responses, merging, stale
evidence, CSRF and optional-component failures. Dashboard tests execute the
shipped script in an inert DOM. Separate localhost browser acceptance covers
desktop/mobile previews, duplicate submission, persisted review after refresh,
and unchanged disposition, using synthetic evidence and no external requests.
