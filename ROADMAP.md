# SecAgent RiskOps Roadmap

## Current focus: `v0.3.0-demo` — measured alert reduction

One claim, backed by numbers a third party can re-run: raw alerts are reduced to
a much smaller set of incidents, reported with episode-level precision, recall,
**miss rate**, baselines and cost. Method: [EVALUATION.md](./EVALUATION.md).

- Labelled synthetic alert generator (fixed seed) plus a public-dataset slice, and the log-to-alert rule set that feeds both
- Pure dedup / correlate / score stages with unit tests
- Baselines, metrics and `make evaluate` with byte-identical reruns
- Model-backed triage with an offline fallback; agreement, abstention, cost and latency
- Visible safety behaviours: second-person approval, execute-and-rollback in a sandbox, fail-closed scope, exported audit timeline
- `docker compose up` with no API key

Nothing else below is in scope for this milestone. Not planned for it: real SIEM
integration, multi-tenancy, notifications, external intelligence collection,
GRC or knowledge UI, PostgreSQL.

## Status of every section below

| Section | Status |
|---|---|
| v0.1 Foundation | Implemented in the walking skeleton; persistence is SQLite, PostgreSQL is planned, not implemented |
| v0.1.5 Agent Workflow Runtime | Implemented in the walking skeleton |
| v0.1.6 External Intelligence Ingestion | Planned, not implemented (design only) |
| v0.1.7 Authorized Security Validation | Planned, not implemented (design only) |
| v0.1.8 Curated Knowledge Intake | Planned, not implemented (design only) |
| v0.1.9 Assessment Authorization and Rules of Engagement | Partly implemented: hash-bound scope and fail-closed policy gates; the rest is planned |
| v0.2 AI SOC Inbox | Reduction pipeline implemented in the skeleton and measured under `v0.3.0-demo`; inbox UI and daily briefing planned, not implemented |
| v0.2.4 Approval Service and Local Authentication | Planned, not implemented (a minimal second-approver path is part of `v0.3.0-demo`) |
| v0.2.5 Web Console | Planned, not implemented |
| v0.3 GRC Bridge | Planned, not implemented beyond a fixed control mapping; to be renumbered after `v0.3.0-demo` |
| v0.4 Controlled Remediation | Policy engine and ActionPlan implemented; executors, verification and rollback planned, not implemented |
| v0.5 Knowledge Loop | Planned, not implemented |
| v1.0 End-to-End Demo | Planned, not implemented |

> **Reading note.** Entries below are grouped by theme, not strict chronological
> order — the `v0.1.6`–`v0.1.9` sections are early increments that were appended
> after the `v0.2`–`v1.0` outline, not work that follows `v1.0`. For what is
> actually built versus still design-only, see
> [docs/implementation-status.md](./docs/implementation-status.md).
>
> **Delivered so far:** a runnable, tested end-to-end *walking skeleton* (`v0.2`
> foundations) that ingests sample alerts and carries them through triage →
> incident → GRC mapping → a policy-gated remediation plan, with replay.

## v0.1 Foundation

Goal: Establish the project structure, architecture, core schemas, evidence model, and audit trail.

Deliverables:
- Project charter
- System architecture
- Threat model
- Core data schemas
- PostgreSQL persistence *(moved to `v0.2.4`, where the approval and auth tables land)*
- Evidence and audit trace model

## v0.1.5 Agent Workflow Runtime

Goal: Build the Flow / Task / Step / ToolCall / Artifact runtime that powers SOC investigations, GRC mapping, remediation workflows, and knowledge review.

Deliverables:
- Flow / Task / Step / ToolCall / Artifact model
- Workflow state machine
- Agent activity timeline
- Memory model for SOC, GRC, and remediation
- Supervisor agent and stuck-state detection
- Evaluation and replay framework design

## v0.2 AI SOC Inbox

Goal: Reduce alert fatigue by normalizing, grouping, scoring, and triaging alerts.

Deliverables:
- Alert ingestion
- Deduplication and grouping
- Risk scoring
- AI triage agent
- Skeptic agent
- SOC Inbox UI *(moved to `v0.2.5 Web Console`)*
- Daily SOC briefing

## v0.2.4 Approval Service and Local Authentication

Goal: Give the fail-closed policy engine a counterpart that can actually grant
approval, with an authenticated identity behind every decision, and move
persistence to PostgreSQL before the new tables land.

Approval is not execution. An approval only lifts the policy `DENY` for a
specific plan; no executor is introduced in this milestone.

Deliverables:
- ApprovalRequest / ApprovalDecision schemas, bound to the ActionPlan canonical hash
- Approval state machine (`PENDING → APPROVED / REJECTED / EXPIRED / VOIDED`), single-direction terminal states
- Automatic request creation when the policy engine returns `APPROVAL_REQUIRED`
- Plan-hash rebinding: a changed plan voids outstanding approvals
- Local session authentication (argon2 password hashing, opaque server-side revocable sessions, httpOnly + SameSite cookies, CSRF protection)
- Role model (`viewer / analyst / approver / admin`) and role-based approval routing
- Risk-tiered self-approval rules (see below)
- Approval TTL and expiry sweep
- Approval API (`/auth/*`, `/approvals`, approve/reject)
- Existing endpoints moved behind authentication (`/health` excepted)
- Notification dispatch interface (reserved seam; no transport implemented)
- PostgreSQL persistence behind the existing Repository interface, with migrations
- Audit-chain and replay coverage for every approval state transition

### Approval routing and self-approval

Routing uses the `RiskLevel` already carried on every `ActionPlan`, so approval
requirements follow the action's blast radius rather than the requester's rank
alone.

| Requester role | `low` | `medium` | `high` |
| --- | --- | --- | --- |
| `analyst` | routes to approver/admin queue | routes to approver/admin queue | routes to approver/admin queue |
| `approver` / `admin` | self-approval allowed, flagged | self-approval allowed, flagged | separate approver required |

Self-approved decisions are recorded with `self_approved = true`, emitted as a
distinct audit event type rather than an ordinary approval, and highlighted in
the console so they can be filtered and reviewed after the fact.

High-risk actions always require a second person, whatever the requester's role.
This keeps routine work unblocked for small teams while preserving four-eyes
control on the paths where a compromised privileged account would do the most
damage.

### Notification seam

Routing a request into a role's queue is the only delivery mechanism in this
milestone. A `Notifier` interface is defined so email, Slack, or webhook
transports can be added later without touching approval logic; no transport is
implemented here.

### Scope boundary

This is single-tenant local authentication, not production identity. SSO/OIDC,
password reset, self-registration, and multi-tenancy are explicitly out of scope
and deferred to a later milestone.

## v0.2.5 Web Console

Goal: Replace the API-docs-only interface with a browser console for the
capabilities that already exist in the backend.

Deliverables:
- Vite + React + TypeScript scaffold with routing and server-state caching
- OpenAPI-generated TypeScript client types, with a CI drift check
- Local development proxy and a single-command `make dev` (backend + frontend)
- Login and session handling
- SOC Inbox (incident list) and incident detail with agent timeline
- Approval queue and decision screens, including self-approval highlighting
- Audit-chain viewer with integrity verification status
- Frontend CI job (typecheck, lint, build)

Pages for GRC controls, the risk register, and the knowledge base are owned by
the milestones that build their backends (`v0.3`, `v0.5`) rather than bundled
here, so no screen ships ahead of the capability behind it.

Out of scope: realtime push (polling first), mobile layouts, internationalization.

## v0.3 GRC Bridge

Goal: Convert confirmed findings and incidents into compliance evidence and risk register entries.

Deliverables:
- Control library
- Finding-to-control mapping
- Evidence package
- Risk register
- GRC report export

## v0.4 Controlled Remediation

Goal: Execute already-approved remediation actions with verification and rollback.

Approval and policy decision-making are no longer part of this milestone. The
fail-closed policy engine and the `ActionPlan` schema shipped with the walking
skeleton; approval moved to `v0.2.4`. What remains here is the execution layer —
the part that was always meant to come last.

Deliverables:
- ~~ActionPlan schema~~ *(delivered in the walking skeleton)*
- ~~Policy engine~~ *(delivered in the walking skeleton)*
- ~~Approval queue~~ *(moved to `v0.2.4` / `v0.2.5`)*
- Precondition, backup, verification, and rollback schemas
- GitHub adapter
- Linux SSH lab adapter
- Verifier and rollback manager

## v0.5 Knowledge Loop

Goal: Store validated detection, suppression, control mapping, and remediation knowledge for future reuse.

Deliverables:
- Knowledge item schema
- Candidate to reviewed to active workflow
- TTL and versioning
- Human feedback loop
- Detection tuning suggestions

## v1.0 End-to-End Demo

Goal: Demonstrate the full workflow from raw alerts to incident, GRC evidence, remediation, verification, and knowledge update.

Deliverables:
- Demo scenario and sanitized multi-source alert dataset
- Approval and execution carried through the demo flow
- Verification and rollback demonstrated, including a deliberate failure
- Knowledge loop closed: outcome promoted back into active knowledge
- End-to-end acceptance checks in CI

## v0.1.6 External Intelligence Ingestion

Goal: Build the source registry, connector, crawler-safety, raw document, extracted entity, and knowledge candidate foundation for external security intelligence enrichment.

Deliverables:
- External intelligence ingestion architecture
- Source Registry
- Raw Intelligence Document schema
- Extracted Entity schema
- Knowledge Candidate schema
- NVD and CISA KEV connector skeletons
- EPSS enrichment design
- ATT&CK enrichment design
- Crawler safety and governance policy
- External intelligence integration into risk scoring design

## v0.1.7 Authorized Security Validation

Goal: Build a safe, scoped, read-only validation layer that checks authorized targets and converts results into findings, evidence, risks, controls, and remediation plans.

Deliverables:
- Authorized Security Validation architecture
- AssessmentTarget schema
- AssessmentScope schema
- ValidationJob schema
- ValidationCheck schema
- Scanner orchestrator skeleton
- Safe service discovery checks
- Web security baseline checks
- External intelligence enrichment for validation findings
- No-exploit default policy

## v0.1.8 Curated Knowledge Intake

Goal: Build a secure manual upload, parsing, review, and promotion workflow for user-provided security documents, authorized lab writeups, advisories, rules, and remediation guidance.

Deliverables:
- UploadBatch, UploadedDocument, and DocumentChunk schemas
- Secure manual upload API
- Safe parser pipeline
- Defensive entity extraction
- Candidate preview and editing
- Manual review queue
- Malware, secret, PII, and prompt-injection screening
- Lab-writeup-to-defensive-knowledge transformation
- Deduplication and cross-source validation
- Public repository privacy and secret audit

## v0.1.9 Assessment Authorization and Rules of Engagement

Goal: Turn user-provided assessment scope and pentest constraints into an explicit, reviewable, versioned, and deterministically enforced authorization policy.

Deliverables:
- Authorization attestation and evidence-reference model
- Structured scope and Rules of Engagement form
- Optional natural-language scope input
- AI-assisted parsing with per-field confidence, conflicts, and unresolved questions
- Effective-policy preview and human confirmation flow
- Immutable AssessmentScopeVersion and approval binding
- Typed allow and deny target matchers
- Time window, rate, concurrency, crawl, credential, data-handling, and stop-condition controls
- Default-deny behavior for blank, ambiguous, expired, and unapproved scope
- Runtime checks for DNS, redirects, discovered services, credentials, and every target-facing tool call
- Scope extension, revocation, expiration, and emergency-stop workflows
- Stable policy decision reason codes and audit events
