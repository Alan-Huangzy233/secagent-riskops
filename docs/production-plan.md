# Production plan and issue tracking

Updated 2026-10-03. Further demo work is paused while development focuses on the
independent telemetry pilot. This is a plan, not a statement that the features
below are implemented or deployed. See [implementation status](./implementation-status.md).
Historical issue-seeding files in `docs/process/` are provenance, not a live
copy of GitHub.

## Baseline and active work

Collection integrity, durable incident scoring, console notifications and UTC
daily briefings landed in PRs [#112](https://github.com/Alan-Huangzy233/secagent-riskops/pull/112),
[#113](https://github.com/Alan-Huangzy233/secagent-riskops/pull/113) and
[#115](https://github.com/Alan-Huangzy233/secagent-riskops/pull/115).
External notification transports remain deferred.

The [evaluation runner](model-triage.md) now accepts configurable OpenAI,
DeepSeek, Z.AI and compatible APIs with shared durable budget reservations.
The original live command accepts only the published synthetic authentication
datasets. A separate [evidence-aware benchmark](triage-evidence.md) adds 72
built-in SSH/HTTP scenarios, development/holdout families and deterministic
typed-claim/dismissal checks. Production context adapters, background jobs,
console review integration and broader model selection remain unfinished;
historical demo results retain their original attribution.

The offline HTTP parser, three rules and evidence replay are in
[PR #116](https://github.com/Alan-Huangzy233/secagent-riskops/pull/116), awaiting
review at this update. Live HTTP collection/integration and an actual source are
still needed before claiming production HTTP coverage.

| Work | Issue | Acceptance boundary |
| --- | --- | --- |
| First-pass model comparison | [#117](https://github.com/Alan-Huangzy233/secagent-riskops/issues/117) | Reproducible labelled comparison and justified selection, or an explicit no-winner result |
| Durable production AI | [#118](https://github.com/Alan-Huangzy233/secagent-riskops/issues/118) | Redacted summaries, persistent jobs/budgets, versioned results and offline acceptance; real-provider pilot is a later gate |
| AI result validation | [#10](https://github.com/Alan-Huangzy233/secagent-riskops/issues/10) | Recorded schema/evidence validation, overclaiming and unsafe-dismissal checks, explicit review/failure states |
| HTTP collection and integration | [#119](https://github.com/Alan-Huangzy233/secagent-riskops/issues/119) | Durable collection, evidence, event-appropriate scoring and console notifications; real-source acceptance before activation |
| First network source | [#120](https://github.com/Alan-Huangzy233/secagent-riskops/issues/120) | A real observation point and a small validated connection/DNS/firewall rule set |
| Linux host behavior | [#121](https://github.com/Alan-Huangzy233/secagent-riskops/issues/121) | Source-backed rules for a selected subset of sudo, account/privilege, service or scheduled-task activity |

Start with the evaluation corpus and offline AI foundation alongside HTTP
engineering. Detection expands in order: **Web → network → Linux host behavior**.
Source discovery can continue while real HTTP activation waits for an available
service; offline fixtures never establish live coverage.

## Model comparison

| Candidate | Initial comparison configuration |
| --- | --- |
| GPT-6 Luna | Supported low-reasoning configuration, bounded summary and structured verdict |
| DeepSeek-V4.1-Flash (`deepseek-flash`) | Compare non-thinking and low-reasoning settings |
| GLM-5.3-Flash (`glm-5.3-flash`) | Low reasoning; current API does not allow disabling thinking |

These are candidates, not a production default. Exercise DeepSeek first without
assuming it wins on accuracy or latency. Verify availability, API behavior and
prices again when running the comparison; distinguish Z.AI and mainland
platforms when selecting the GLM endpoint.

References reviewed for the plan: [Luna](https://developers.openai.com/api/docs/models/gpt-6-luna),
[DeepSeek models](https://api-docs.deepseek.com/quick_start/pricing/),
[DeepSeek thinking controls](https://api-docs.deepseek.com/guides/thinking_mode/),
[GLM model](https://docs.z.ai/guides/vlm/glm-5.3-flash),
[GLM parameters](https://docs.z.ai/api-reference/llm/chat-completion) and
[Z.AI pricing](https://docs.z.ai/guides/overview/pricing).

Use the same bounded, redacted summaries and evidence IDs across candidates.
Cover SSH/HTTP attacks and benign activity, incomplete evidence, encoding
variants and instructions embedded in untrusted logs. Version the corpus, keep
labels out of prompts, and separate tuning from held-out evaluation. Existing
HTTP regression fixtures are a starting point, not an accuracy benchmark.

Measure attacks wrongly dismissed among surfaced attack incidents, benign
noise reduction, abstention, evidence-reference validity, schema failures, P95
latency and actual cost including reasoning tokens and retries. Report sample
counts/uncertainty and rule-layer misses separately: triage cannot recover an
attack that detection never surfaced. Unlabelled analyst disagreement is not a
miss rate. Set acceptance thresholds before the held-out run.

Record provider/model version, reasoning/output settings, prompt/schema/dossier
versions, usage and pricing date. Offline CI uses fake or recorded calls. Real
calls depend on an agreed budget, server-side credentials and permitted outbound
fields; planning this comparison does not enable or fund API calls.

## Production AI stages

1. **Offline foundation:** field allowlists and local aliases; bounded summaries;
   persistent jobs, leases, attempts and idempotency; transactional budget
   reservations; versioned results and cache invalidation. Test restart,
   concurrency, stale evidence, invalid references, prompt injection, failures
   and uncertain request outcomes with fake/recorded providers.
2. **Manual-trigger pilot:** use the evaluated configuration within agreed data
   and spending limits. Show advice and validation/failure states in the console.
   Preserve rule alerts and manual disposition; collection and human handling
   continue when the provider is unavailable.
3. **Possible later automatic analysis:** after quality, cost and throughput meet
   the agreed gate, define cooldown, concurrency and daily limits before enabling
   it. Automatic analysis does not grant automatic dismissal, blocking or
   remediation execution.

Issue #10 owns validation; #118 owns workflow/storage/UI integration. A second
paid model is optional after evidence of need. Full correction-to-knowledge
promotion remains later work in
[#87](https://github.com/Alan-Huangzy233/secagent-riskops/issues/87).

## Detection stages

For HTTP, retain explicit source/service identity, fields and evidence; handle
rotation, retries, truncation and bounded catch-up with independent cursors.
Trust proxy-derived client addresses only under a configured trust chain.
Exclude raw query strings, cookies, authorization headers and request bodies
from default summaries. HTTP status alone proves neither successful
authentication nor exploitation; login rules require explicit application
authentication outcomes.

For network and Linux, choose rules after confirming actual fields and coverage.
The skeleton's Suricata sample parser and a host's SSH journal do not provide
whole-network or complete host-change visibility. Each increment needs labelled
positive/negative fixtures, bounded correlation, retained evidence, appropriate
scores/notifications and existing-source regressions.

## Issue audit, 2026-09-29

The audit inventoried all 91 existing issues and checked all 11 open items'
acceptance criteria and discussions against main and merged PRs. Nine are closed
as completed for the **narrowed demo scope recorded on 2026-09-23**. Each issue
retains its original broader description and explicit completion evidence;
closure does not claim that all original product requirements were delivered.

| Completed issues | Evidence |
| --- | --- |
| [#7](https://github.com/Alan-Huangzy233/secagent-riskops/issues/7), [#8](https://github.com/Alan-Huangzy233/secagent-riskops/issues/8): grouping/scoring | [PR #106](https://github.com/Alan-Huangzy233/secagent-riskops/pull/106) |
| [#9](https://github.com/Alan-Huangzy233/secagent-riskops/issues/9): demo model triage | [PR #109](https://github.com/Alan-Huangzy233/secagent-riskops/pull/109) |
| [#89](https://github.com/Alan-Huangzy233/secagent-riskops/issues/89): labelled datasets | [PR #101](https://github.com/Alan-Huangzy233/secagent-riskops/pull/101), [PR #107](https://github.com/Alan-Huangzy233/secagent-riskops/pull/107) |
| [#90](https://github.com/Alan-Huangzy233/secagent-riskops/issues/90), [#91](https://github.com/Alan-Huangzy233/secagent-riskops/issues/91): lab execution/verification/rollback | [PR #110](https://github.com/Alan-Huangzy233/secagent-riskops/pull/110) |
| [#93](https://github.com/Alan-Huangzy233/secagent-riskops/issues/93), [#102](https://github.com/Alan-Huangzy233/secagent-riskops/issues/102): evaluation/CI | [PR #107](https://github.com/Alan-Huangzy233/secagent-riskops/pull/107), expanded by subsequent model/safety/browser checks |
| [#103](https://github.com/Alan-Huangzy233/secagent-riskops/issues/103): published results | [PR #108](https://github.com/Alan-Huangzy233/secagent-riskops/pull/108), [PR #109](https://github.com/Alan-Huangzy233/secagent-riskops/pull/109) |

Issue #10 is reopened and #117–#121 are new. Two unfinished items stay open:

- [#73](https://github.com/Alan-Huangzy233/secagent-riskops/issues/73) returns to
  the production approval-service milestone after the immediate AI/detection
  work. One demo operator is not an authenticated approval-request service or a
  second-approver path. Restore deferred identity/approval prerequisites when
  that stage starts.
- [#105](https://github.com/Alan-Huangzy233/secagent-riskops/issues/105) remains
  deferred: recording, release tag/notes and an independent timed walkthrough
  have not been completed.

Older items closed as `not_planned` during demo scoping remain deferred, not
implemented. In particular, UTC console briefings do not complete all original
#12 requirements (priority buckets, recommendations and Markdown export), and
console notifications are not #77's approval-transition notifier. GRC, full
knowledge promotion, general executors and the formal multi-user frontend remain
in the later [roadmap](../ROADMAP.md). Finding-derived training labs remain a
[long-term exploration](./finding-derived-training-labs.md).

Changes proceed through a feature branch, PR and CI, then maintainer review
before merge and deployment. No deployment, model switch or paid API call is
part of this plan/issue audit.
