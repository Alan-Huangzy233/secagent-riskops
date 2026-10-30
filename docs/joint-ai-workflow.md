# Local manual review of joint cases

The optional joint-case workflow connects the saved [local preview](joint-ai-contract.md)
to durable manual jobs and bounded result history. It implements the offline
submission increment of [#148](https://github.com/Alan-Huangzy233/secagent-riskops/issues/148).
It does not call a model: the built-in rehearsal always asks for human review.
Recorded-provider and live-provider integration remain follow-up work.

## Operator flow

1. Open a joint case at an explicit saved revision and select **AI摘要**.
2. Generate the local preview. With the optional workflow enabled, select
   **提交本地演练** to create a job for that exact preview. Opening a case, changing
   tabs or viewing history never submits work.
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

Only `offline` is supported. API, recorded and automatic modes are not enabled
by this setting. Invalid optional configuration disables the joint workflow;
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

## Revision and recovery rules

The server rebuilds the complete saved-case preview before enqueueing. It never
accepts a browser-supplied dossier. Job identity binds the dossier, configuration,
validator and summary versions; the dossier revision already binds evidence,
mapping, store identity, restore epoch and freshness context. Capture timestamps
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

Recorded/fake-provider contract qualification, production network field policy,
provider choice, shared budget accounting and explicit rollout approval precede
any live joint-model call. Existing SSH approval does not authorize network
summaries. Automatic analysis (#149) and automatic response (#150) remain separate.

Only code, general documentation and authored synthetic fixtures belong in the
repository. Local check outputs and operating records stay outside it.
