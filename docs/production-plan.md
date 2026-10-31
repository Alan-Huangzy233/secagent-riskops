# Production plan and issue tracking

GitHub tracking index: [#170](https://github.com/Alan-Huangzy233/secagent-riskops/issues/170).

Updated 2026-10-24. Further demo work is paused while development focuses on the
independent telemetry pilot. This is a plan, not a statement that the features
below are implemented or deployed. See [implementation status](./implementation-status.md).
Historical issue-seeding files in `docs/process/` are provenance, not a live
copy of GitHub. The [complete known-work inventory](backlog.md) links active,
deferred and exploratory requirements to current issue owners.

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
typed-claim/dismissal checks. A separate new 36-case
[three-model comparison](eval/triage-pilot-model-comparison.md) supports Luna low
as the bounded manual-pilot candidate. The [optional console workflow](manual-ai-triage.md)
now implements bounded SSH summaries, private trusted context, durable jobs,
total/daily budgets, versioned results and human feedback. It remains disabled
by default in the repository; the maintained deployment has a bounded manual
pilot. Broader independent validation and automatic analysis remain pending.
Historical demo results retain their original attribution.

The offline HTTP parser, three rules and evidence replay are in
[merged PR #116](https://github.com/Alan-Huangzy233/secagent-riskops/pull/116).
[Opt-in durable HTTP collection and ingestion](http-ingestion.md), independent
storage, retry receipts, continuous correlation, retained evidence, scoring,
console notifications and UTC daily briefings are now implemented. Same-host
recovery/history and isolated [HTTPS](http-https-acceptance.md) and
[workload](http-workload-acceptance.md) acceptance are also implemented.
No business website is currently available for real-source acceptance. Issue
#119 stays open for that deployment gate; isolated acceptance does not establish
live HTTP coverage or remote/whole-host recovery.

| Work | Issue | Acceptance boundary |
| --- | --- | --- |
| Broader model qualification (initial comparison delivered) | [#117](https://github.com/Alan-Huangzy233/secagent-riskops/issues/117) | Broader independent and pilot qualification beyond the delivered frozen comparison |
| Durable AI (manual SSH workflow delivered) | [#118](https://github.com/Alan-Huangzy233/secagent-riskops/issues/118) | Additional live evidence adapters and operational acceptance; SSH manual pilot is active |
| AI result validation | [#10](https://github.com/Alan-Huangzy233/secagent-riskops/issues/10) | Recorded schema/evidence validation, overclaiming and unsafe-dismissal checks, explicit review/failure states |
| HTTP collection and integration | [#119](https://github.com/Alan-Huangzy233/secagent-riskops/issues/119) | Durable collection, evidence, event-appropriate scoring and console notifications; real-source acceptance before activation |
| Sustained network source acceptance | [#120](https://github.com/Alan-Huangzy233/secagent-riskops/issues/120) | Initial passive sources enrolled; sustained coverage/resource acceptance and safe receipt governance remain |
| Linux host behavior | [#121](https://github.com/Alan-Huangzy233/secagent-riskops/issues/121) | Source-backed rules for a selected subset of sudo, account/privilege, service or scheduled-task activity |

[Tabbed views and a server-prepared first page](console-workspace.md) have
shipped, alongside the bounded [manual AI workflow](manual-ai-triage.md).
The [online-AI proposal](online-ai-pilot.md) records the rollout constraints;
automatic calls and broader outgoing fields are not implied by the manual pilot.
Detection expands in order: **Web → network → Linux host behavior**.
The network foundation (#120) is now enrolled in the maintained deployment:
reviewed passive sources, durable delivery, one inbound TCP rule, retained
incidents and console notices. Narrow UDP observations and empty heartbeats
have explicit coverage limits. Repository defaults remain off. Sustained
operation and long-term receipt/capacity work continue in #120 and
[#152](https://github.com/Alan-Huangzy233/secagent-riskops/issues/152); new rule families belong to [#151](https://github.com/Alan-Huangzy233/secagent-riskops/issues/151).

Visible IP search and network→SSH pivots ([#145](https://github.com/Alan-Huangzy233/secagent-riskops/issues/145)) are implemented.
Joint evidence cases in [#147](https://github.com/Alan-Huangzy233/secagent-riskops/issues/147) use the
[foundation and read adapters](joint-evidence.md) for bounded typed association
and explicit retained-source reads. An independent derived store and finite,
explicitly invoked refresh of registered anchors are implemented. Semantic changes create immutable case revisions; read metadata and
failures do not overwrite previous evidence. The [joint console](joint-console.md)
adds optional mapping validation, explicit bounded catalog discovery/refresh,
derived-store migration/recovery and a read-only paginated view. Optional bounded
continuous refresh is implemented. The current [#148](https://github.com/Alan-Huangzy233/secagent-riskops/issues/148)
increment adds [local manual joint jobs/history](joint-ai-workflow.md);
a separate [synthetic response replay](joint-ai-replay.md) now qualifies raw fake/local-recording
responses. Workflow provider integration and live field/budget approval remain
separate. Grouped cross-type search [#146](https://github.com/Alan-Huangzy233/secagent-riskops/issues/146) ships in
bounded increments; its raw-log index/migration work does not block retained-case
correlation. Linux #121 source inventory can run alongside these steps and does
not wait for paid AI approval. HTTP real-source acceptance still waits for an
available business service. Automatic analysis [#149](https://github.com/Alan-Huangzy233/secagent-riskops/issues/149) and
automatic response [#150](https://github.com/Alan-Huangzy233/secagent-riskops/issues/150) remain separate later stages.

## Full backlog reconciliation, 2026-10-23

The [known-work inventory](backlog.md) restores unfinished production scope that
older issues closed during demo scoping. It includes formal runtime/evidence and
identity, product SOC/UI, GRC, knowledge/intelligence/upload, authorized validation,
real executors, whole-workflow acceptance and training-lab exploration. Operational
capacity, recovery/key lifecycle, external transports, richer briefings and ongoing
repository/dependency maintenance also have owners. Existing #10, #73 and #117–#121
are updated with delivered foundations and remaining acceptance; #105 stays paused.
No old demo completion is silently reopened or counted as a finished product.

## Model comparison

| Candidate | Initial comparison configuration |
| --- | --- |
| GPT-6 Luna | Supported low-reasoning configuration, bounded summary and structured verdict |
| DeepSeek-V4.1-Flash (`deepseek-flash`) | Compare non-thinking and low-reasoning settings |
| GLM-5.3-Flash (`glm-5.3-flash`) | Low reasoning; current API does not allow disabling thinking |

The October 3 low-reasoning comparison gave Luna 36/36, DeepSeek 29/36 and
GLM 24/36 effective agreement with authored decisions. Only Luna passed every
frozen scenario gate; use it as the next human-reviewed candidate. This does
not set a production default or establish production accuracy. Verify
availability, behavior and prices again for new runs; distinguish Z.AI and
mainland platforms when selecting the GLM endpoint.

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

1. **Offline foundation (implemented; opt-in):** field allowlists and local aliases; bounded summaries;
   persistent jobs, leases, attempts and idempotency; transactional budget
   reservations; versioned results and cache invalidation. Test restart,
   concurrency, stale evidence, invalid references, prompt injection, failures
   and uncertain request outcomes with fake/recorded providers.
2. **Manual-trigger pilot (implemented; limited deployment active):** each new
   deployment still requires agreed backup/recovery, outbound fields and budget
   before using the evaluated configuration. Advice and validation/failure
   states are shown in the console.
   Preserve rule alerts and manual disposition; collection and human handling
   continue when the provider is unavailable.
3. **Possible later automatic analysis:** after quality, cost and throughput meet
   the agreed gate, define cooldown, concurrency and daily limits before enabling
   it. Automatic analysis does not grant automatic dismissal, blocking or
   remediation execution.

Issue #10 owns validation; #118 owns workflow/storage/UI integration. Network/joint
dossiers are tracked separately in [#148](https://github.com/Alan-Huangzy233/secagent-riskops/issues/148). A second
paid model is optional after evidence of need. Full correction-to-knowledge
promotion remains later work in
[#161](https://github.com/Alan-Huangzy233/secagent-riskops/issues/161) (follow-up to historical #87).

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

The October 19 read-only inventory found existing UFW kernel records suitable
for the first network increment. A different host's narrow UDP NAT-entry logs
are not a substitute for general inbound visibility or evidence of a successful
connection. The [source plan](network-source-plan.md) defines the chosen scope,
delivery order, resource gates and false-positive cases. Private host identities,
addresses, routing and raw production samples remain outside the public repo.

## Historical issue audit, 2026-09-29

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
