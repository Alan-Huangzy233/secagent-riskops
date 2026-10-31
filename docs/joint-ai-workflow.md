# Local manual review of joint cases

The optional joint-case workflow connects the saved [local preview](joint-ai-contract.md)
to durable manual jobs and bounded result history. It implements the offline
submission increment of [#148](https://github.com/Alan-Huangzy233/secagent-riskops/issues/148).
It does not call a model. The built-in rehearsal always asks for human review;
an optional recording adapter revalidates previously supplied raw responses.
Live-provider integration remains follow-up work.

## Operator flow

1. Open a joint case at an explicit saved revision and select **AI摘要**.
2. Generate the local preview. With the optional workflow enabled, select
   **提交本地演练**, or the explicitly labelled recording action when configured,
   to create a job for that exact preview. Opening a case, changing tabs or viewing
   history never submits work.
3. Read or refresh **研判历史** to inspect up to 20 recent jobs. The history table
   stays separate from the full saved result and evidence references.
4. Inspect the selected job's saved revision, checked advisory result and original
   proposal. Historical results remain visible; changed or unavailable evidence
   is explicitly marked. A result never changes incident disposition or blocks an IP.

Repeated submissions of the same dossier and settings return the same job,
including after a restart or terminal result. A preview key is not an authorization
credential: authentication, same-origin checks and the existing CSRF header are
required for every submission.

## Optional configuration

The feature is off unless `RISKOPS_JOINT_AI_CONFIG` names an absolute, private
JSON configuration file (0600). The existing AI service must already have loaded
its private alias key. The workflow reuses that key so preview and submission
refer to the same aliases. It does not read API credentials or create another
paid budget pool.

A minimal configuration is:

```json
{
  "mode": "offline",
  "database_path": "/var/lib/riskops-joint-ai/jobs.sqlite",
  "allow_external": false
}
```

The default `offline` mode keeps its fixed human-review rehearsal. The optional
`recorded` mode below only reads a local recording. API and automatic modes are
not supported. Invalid optional configuration disables the joint workflow;
existing collection and local preview remain available where their prerequisites
are valid. No repository example activates a deployed service.

The queue is a separate private database. It must not reuse any source database,
the joint derived store, another AI/control queue, configuration/credential file,
refresh checkpoint or their reserved side files. Resolved paths and existing file
identities are checked before queue creation. Protect the directory from unrelated
writers; these checks are not a defense against a privileged process changing
filesystem links during initialization.

The shared queue implementation pins a queue kind. Joint queues cannot consume
legacy SSH jobs, and the updated SSH worker refuses a joint queue. Recognized
legacy SSH queues acquire only the missing queue-kind metadata marker and retain
their aliases, reservations, history and budget limits. SQLite read preflight may
create normal WAL/shared-memory bookkeeping; it does not change queue records.
Do not point an older worker that predates this guard at the joint queue.

## Optional local recording adapter

A separate explicit configuration can select raw recorded responses:

```json
{
  "mode": "recorded",
  "database_path": "/var/lib/riskops-joint-ai/jobs.sqlite",
  "recording_path": "/var/lib/riskops-joint-ai/responses.json",
  "allow_external": false
}
```

The recording must be an absolute, owner-private regular file owned by the
service account, with one hard link and no symlink components. Its path must not overlap a source store, queue,
configuration, checkpoint or reserved side file. Loading and validation happen
before queue initialization. An invalid optional recording disables the joint
component without changing the SSH workflow. The recording path is forbidden in
`offline` mode; no API client, credential file or live fallback can be configured.

`joint_ai_recorded.make_tape(entries)` builds the recording format from entries
containing `case`, `outcome` and `response_text`. Each `case` is exactly the aliased
`case` object from the local preview; never pass the full preview or its private
references. Use authored synthetic data for qualification. The helper generates
no response and performs no file or network I/O. Store its JSON output in a new
private file outside version control. The adapter cannot use a response whose
request was made with different evidence, aliases or protocol.

The format is `joint-recorded-response-v1`, with a self-reported
`source: local_recording`, exact protocol, and records containing only
`request_sha256`, `outcome` and `response_text`. A response outcome carries raw
text; an unavailable outcome carries null. The protocol binds dossier, summary,
envelope and validator versions plus prompt/schema hashes. Each request hash
binds that protocol and the complete dossier. Duplicate requests or JSON keys,
unknown fields, incompatible protocols, invalid files and oversized input are
rejected. The tape is limited to 8 MiB and 256 records; each response is bounded.
Its format is separate from the fixed-corpus evaluation tape in
[synthetic replay](joint-ai-replay.md).

The service loads an immutable in-memory snapshot at startup and binds its
content hash into job identity. Editing a file does not hot-reload it. Reloading
with changed responses or availability requires a fresh preview and submission;
old queued bindings become stale and old results remain readable as history.
Raw responses always pass through the current validator. The tape cannot supply
a pre-approved verdict or validation result. A missing record fails explicitly;
an unavailable record uses bounded retries and ends without a result. Neither
is counted as a valid abstention or silently replaced by the built-in rehearsal.

The console preserves each job's saved execution mode, including when settings
later change. It labels recording playback separately, identifies the source as
unverified and keeps explanations subject to human review. Zero cost means only
this local replay; the original response's generation cost is unknown. Recording
provenance, model identity and model accuracy are not established by a hash.

## Revision and recovery rules

The server rebuilds the complete saved-case preview before enqueueing. It never
accepts a browser-supplied dossier. Job identity binds the dossier, configuration,
validator and summary versions, plus the recording snapshot when applicable.
The dossier revision already binds evidence, mapping, store identity, restore
epoch and freshness context. Capture timestamps
alone do not create new jobs.

Workers revalidate before processing and after producing a result. Result reads
also compare the saved binding with current observations. Missing data, restore
revalidation, changed evidence or changed configuration cannot silently establish
current applicability. The saved result remains available as history. These are
bounded optimistic comparisons, not a cross-file transaction or a guarantee that
an observation remains current after the response.

Jobs reuse durable claims, bounded retries, leases and append-only application
audit entries. Duplicate clicks are coalesced transactionally. An expired worker
cannot overwrite a later worker's result. No model call, paid reservation,
incident disposition or enforcement action is performed by this offline worker.
The joint validator checks exact revisions and typed citations; it does not
independently verify a narrative or establish model accuracy.

Include the separate queue in an appropriate local recovery procedure, using
SQLite's online backup API instead of copying a live main file alone. Keep the
existing alias key and the joint evidence/recovery context. Turning the optional
workflow off stops future worker startup; it does not remove saved history.

## API

All reads require operator authentication and are served without browser caching:

- `GET /api/joint/ai/status`
- `GET /api/joint/cases/{id}/ai/preview?revision=N`
- `GET /api/joint/cases/{id}/ai/history`
- `GET /api/joint/ai/jobs/{job_id}`

When enabled, the preview adds `preview_key` and `execution` metadata. The history
response contains lightweight rows; a full result and its local references are
loaded only through the job endpoint. Existing local preview behavior remains
available when the workflow is disabled.

`POST /api/joint/cases/{id}/ai` takes only `revision` and `preview_key`, requires
JSON and the existing CSRF/same-origin checks, and returns the durable job. There
is no browser endpoint for running the worker, changing its mode or authorizing
external transmission.

## Remaining work

The [synthetic response replay](joint-ai-replay.md) qualifies fake and local
recorded responses against a fixed corpus. This workflow can consume separately
bound local recordings. Live transport, production network field policy, provider
choice, shared budget accounting, independent explanation review and explicit
rollout approval still precede any live joint-model call.
Existing SSH approval does not authorize network summaries. Automatic analysis (#149) and automatic response (#150) remain separate.

Only code, general documentation and authored synthetic fixtures belong in the
repository. Local check outputs and operating records stay outside it.
