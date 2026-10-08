# Proposed first online AI pilot

Prepared 2026-10-08; **proposal only, not permission to activate, spend or send
production data**. The console's offline mode is a workflow rehearsal whose
result always asks for human review. It does not run a local language model.

The [36-case synthetic comparison](eval/triage-pilot-model-comparison.md) supports
Luna low as the first human-reviewed candidate: 36/36 effective agreement versus
29/36 for DeepSeek and 24/36 for GLM. This small authored set establishes neither
production accuracy nor permission for automatic dismissal or blocking.

## Concrete scope to approve

| Item | Proposed setting |
| --- | --- |
| Provider and model | OpenAI Responses API, `gpt-6-luna`, reasoning `low`, standard processing |
| Trigger | An operator previews the outgoing summary and explicitly starts analysis |
| Coverage | Existing SSH incidents only, at most 40 evidence records per summary |
| Outbound identity | Stable keyed aliases for IP/account/source/event/incident; relative shifted times |
| Other outbound fields | Normalized SSH outcome, counts, completeness flags, typed evidence and approved trusted context |
| Excluded | Raw messages, hostnames, raw IPs/accounts, local reference map, headers, cookies, query strings, bodies; no approved HTTP paths |
| Budget | Proposed new production ceiling **USD 5 total / USD 0.50 per UTC day**, including outstanding reservations |
| Initial review | First 20 manually selected incidents, spanning high/low rule scores and incomplete evidence where available |
| Result | Advice and validation state only; keep existing rule scores and manual disposition |

Twenty incidents is a manual review checkpoint, not an implemented hard job-count
cap. The total/daily dollar caps are enforced in the persistent AI ledger. The
previous USD 10 synthetic-evaluation authorization and ledger remain separate.
Unknown asset/account context stays unknown until the owner supplies trusted
inventory; names such as root or admin do not establish authorization.

The existing [Luna profile](../examples/model-triage/openai-luna-low.json) sets
65,536 maximum input and 8,192 output tokens. Its prices match the
[official model page](https://developers.openai.com/api/docs/models/gpt-6-luna)
checked on 2026-10-08: USD 0.10 input / 0.50 output per million tokens, cached
input 0.01 and cache writes 0.125, for this bounded standard configuration.
Actual billed usage is authoritative; record the profile and pricing date for
activation rather than treating synthetic per-case cost as a production quote.

The adapter sends `store: false`. This is not zero retention: standard abuse
monitoring can retain content for up to 30 days, with documented exceptions;
prompt caching has separate retention behavior. API data is not used for model
training by default unless opted in. Review the account's data controls before
activation; pseudonymized summaries still go to an external provider.
[OpenAI data controls](https://developers.openai.com/api/docs/guides/your-data).

## Activation preparation after approval

1. Preserve the existing analysis SQLite database, alias key, offline history and
   reviews. Check the queue has no running work and inspect its current budget
   limits. Offline mode does not pin zero limits; the first API initialization
   pins the approved positive limits. If limits already exist, retain them or
   prepare a separately reviewed migration, never recreate the ledger.
2. Stage a 0600 private candidate settings file with the existing database/context
   paths, the reviewed model profile, `mode: api`, `allow_external: true`,
   `approved_summary_version: 1`, the two approved budget values, `max_events: 40`
   and `http_paths: []`. Keep it inactive until approval. Validate settings and
   profile locally without constructing a paid Service or sending a request.
3. Give the service account a private provider-specific key file with only the
   OpenAI key. Keep keys out of Git, terminal output, the browser and telemetry
   caches. Retain the original evaluation configuration unchanged.
4. Include queue, settings, trusted inventory, model profile and key recovery in
   the encrypted recovery package; verify an isolated restore and permissions.
   The profile and key are additional activation dependencies even if the offline
   queue/config are already covered. Do not copy an active SQLite file without
   its online-backup procedure.
5. Switch configuration through a reviewed release, verify `/api/ai/status`,
   health and the original three collection sources, then explicitly submit one
   approved incident. Confirm persisted usage, repeat-click idempotency and human
   feedback across restart before continuing to the review checkpoint.

## Review and stopping conditions

Record validity, evidence-reference failures, unsupported claims, incorrect
noise suggestions, abstentions, human agreement, latency and actual usage. An
unlabelled disagreement is not a miss rate. Keep each rule alert available even
when the provider fails or asks for more evidence. Investigate any unsafe
suggestion or unexplained charge before expanding the pilot.

To stop, disable future external calls via the prior offline configuration and
restart during a controlled window. Preserve the queue, reservations, alias key
and results. A request already sent cannot be recalled, and an uncertain
reservation must not be refunded or automatically retried without checking the
provider outcome. The next decision is whether to extend manual review; automatic
analysis, automatic disposition and additional providers require separate scope.
