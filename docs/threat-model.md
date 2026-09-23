# SecAgent RiskOps Threat Model

## Purpose and Scope

This threat model covers the SecAgent RiskOps control plane, including the API and UI, ingestion pipelines, AI agents, workflow runtime, evidence and knowledge stores, policy and approval services, typed executors, and their external integrations.

It focuses on platform abuse and loss of confidentiality, integrity, availability, authorization, or auditability. Threat models for individual connectors and executor adapters should extend this baseline.

## Security Objectives

1. Only authorized actors can access data or initiate workflows.
2. Active checks and changes remain inside an explicit target and action scope.
3. Security conclusions remain traceable to unmodified evidence.
4. AI output cannot become an authorization decision or direct tool instruction.
5. Sensitive evidence and credentials are minimized, isolated, and redacted.
6. Approvals, state transitions, tool calls, and remediation outcomes are auditable.
7. The system fails closed when authorization, evidence, policy, or verification is insufficient.

## Assets to Protect

- Security alerts, findings, incident data, and evidence artifacts.
- Agent instructions, model inputs and outputs, evaluation data, and traces.
- Assessment scopes, target allowlists, and authorization records.
- Tool permissions, executor credentials, API tokens, and signing material.
- Control libraries, risk registers, and compliance evidence.
- Detection, suppression, remediation, and external-intelligence knowledge.
- Approval decisions, policy versions, and audit records.
- Application availability and workflow integrity.

## Threat Actors

- Unauthenticated external attackers.
- Authenticated users exceeding their role or tenant scope.
- Malicious or compromised insiders and approvers.
- Attackers controlling a monitored or assessed target.
- Attackers injecting content into logs, documents, repositories, advisories, or web responses.
- Compromised connectors, AI providers, dependencies, or executor credentials.
- Accidental operators making unsafe configuration or approval decisions.

## Trust Boundaries and Entry Points

| Boundary | Entry points | Principal risk |
|---|---|---|
| User/API | API, UI, authentication, uploads | unauthorized access, IDOR, injection, tenant leakage |
| Ingestion | alerts, logs, documents, external feeds | malformed input, poisoning, secrets, prompt injection |
| AI provider | prompts, retrieved context, structured outputs | data disclosure, hallucination, instruction injection |
| Policy/approval | policy configuration and approval actions | bypass, stale approval, confused deputy |
| Executor/target | GitHub, SSH lab, scanners, cloud APIs | scope escape, destructive action, credential theft |
| Persistence | database, evidence/artifact store, backups | tampering, over-retention, cross-tenant exposure |
| Supply chain | dependencies, CI, containers, models | compromised build or runtime component |

## Threat Register

### TM-01: Authorization or Tenant-Scope Bypass

An actor reads another tenant's evidence or starts a workflow against a target outside their scope.

Controls:

- Central authentication and role/tenant authorization.
- Server-side object-level checks on every access.
- Explicit, time-bound AssessmentScope records for active operations.
- Target canonicalization before allowlist comparison.
- Deny-by-default policy and authorization audit events.

### TM-02: Prompt Injection and Tool Manipulation

Untrusted logs, documents, repository content, or target responses attempt to override instructions or induce tool use.

Controls:

- Treat retrieved and target content as quoted data.
- Separate trusted policy from model context.
- Require structured model output with schema validation.
- Independently evaluate every proposed tool call.
- Prevent model access to raw credentials and unrestricted tools.

### TM-03: Evidence or Audit Tampering

An attacker modifies evidence, deletes an unfavorable decision, or changes history after remediation.

Controls:

- Content hashes and immutable object identifiers.
- Append-oriented audit records and explicit correction events.
- Restricted write/delete permissions and retention controls.
- Link decisions to exact evidence, policy, prompt, and model versions.
- Export or integrity-verification mechanism for high-value audit packages.

### TM-04: Unsafe or Out-of-Scope Remediation

An incorrect proposal, compromised agent, or malicious user triggers an unsafe change.

Controls:

- Typed ActionPlans and executor operations.
- Tool, target, parameter, autonomy, and risk policy checks.
- Human approval for medium/high-risk or non-preapproved actions.
- Preflight, dry-run where supported, backup, verification, and rollback.
- No arbitrary shell or direct execution of model-generated commands.

### TM-05: Approval Abuse or Replay

An approval is forged, reused for a different action, or remains valid after the plan changes.

Controls:

- Bind approval to actor, ActionPlan version/hash, target, parameters, risk, and expiry.
- Invalidate approval when material plan fields change.
- Enforce separation of duties for high-impact actions where configured.
- Record rejection, expiry, revocation, and execution events.

### TM-06: Alert Suppression Abuse

Incorrect or malicious suppression hides a real attack.

Controls:

- Require reason, evidence, scope, owner, expiry, and reversible status.
- Require approval for high-impact or broad suppression.
- Preserve original alerts and suppression matches.
- Periodically review, replay, and expire suppression rules.

### TM-07: Knowledge or Intelligence Poisoning

False, stale, or attacker-controlled content degrades triage, scoring, or remediation.

Controls:

- Candidate-only ingestion from external or AI-generated content.
- Source provenance, reputation, confidence, TTL, and conflict tracking.
- Human or deterministic validation before promotion.
- Versioning, rollback, expiry, and usage traceability.

### TM-08: Secret or Sensitive-Data Leakage

Credentials, customer data, personal data, or internal topology reach logs, prompts, exports, or the public repository.

Controls:

- Data minimization and classification.
- Secret and PII scanning at ingestion and before model/export boundaries.
- Redaction with references to protected originals.
- Dedicated secret storage and least-privilege short-lived credentials.
- Repository and history auditing using sanitized examples.

### TM-09: Parser and Upload Exploitation

A malicious document exploits a parser, expands excessively, or carries active content.

Controls:

- MIME allowlists, size/count limits, hashing, and malware scanning.
- Isolated parsers with CPU, memory, time, and network limits.
- Disable macros, scripts, archives, and active content by default.
- Store uploads outside executable and public paths.

### TM-10: Availability and Workflow Exhaustion

Large inputs, recursive workflows, stuck agents, retries, or expensive model calls exhaust resources.

Controls:

- Rate limits, quotas, bounded fan-out, and payload limits.
- Workflow deadlines, budgets, cancellation, and stuck-state detection.
- Idempotency keys and bounded retry policies.
- Queue isolation and operational metrics.

### TM-11: Supply-Chain Compromise

A dependency, action, container, model, or connector update introduces malicious behavior.

Controls:

- Dependency pinning and automated vulnerability review.
- Minimal CI permissions and reviewed workflow changes.
- Artifact provenance and reproducible or verifiable builds where practical.
- Connector allowlists and versioned adapter behavior.

### TM-12: Verification or Rollback Failure

The system reports success without validating the intended outcome, or rollback cannot restore a safe state.

Controls:

- Verification criteria defined before approval.
- Independent postcondition checks rather than executor success alone.
- Backup validation and explicit rollback preconditions.
- Stop and escalate when verification is ambiguous or rollback fails.

### TM-13: Agent Identity, Handoff, or Delegation Abuse

A compromised or misconfigured agent impersonates another capability, expands permissions through a handoff, creates recursive delegation, or causes downstream agents to trust unsupported conclusions.

Controls:

- Resolve agents through a versioned capability registry.
- Bind every Agent run and handoff to Flow, Task, actor, scope, and evidence identifiers.
- Use schema-validated handoffs through the orchestrator rather than direct peer messaging.
- Recompute effective permissions for every receiving Task; permissions never expand through delegation.
- Enforce invocation, depth, time, token, and tool-call budgets with cycle and stuck-state detection.
- Preserve conflicting results independently and require deterministic or human resolution.
- Prevent Supervisors from approving actions, raising autonomy, or bypassing the Tool Gateway.

### TM-14: Scope Interpretation or Approval Confusion

Blank, ambiguous, or adversarial natural-language instructions are interpreted as broad permission, or an approval is reused after scope changes.

Controls:

- Require typed allow rules, exclusions, expiry, and numeric execution limits for active validation.
- Treat AI interpretation as an unapproved draft with confidence, source rationale, conflicts, and unresolved questions.
- Compile policy deterministically and show the effective policy before human confirmation.
- Bind approval to immutable scope version and canonical policy hash.
- Default deny when scope is blank, ambiguous, expired, unapproved, or conflicts with higher-level policy.

### TM-15: Target Identity and Scope Escape

DNS rebinding, cross-origin redirects, discovered services, wildcard confusion, or cloud-resource indirection causes the scanner to contact an unauthorized target.

Controls:

- Use typed, normalized matchers for exact hosts, domain suffixes, URL origins, IP addresses, CIDR ranges, and cloud-resource identities.
- Define wildcard and apex semantics explicitly; deny rules override allow rules.
- Recheck normalized hostname, resolved IP, port, protocol, redirect destination, and discovered target before access.
- Treat discovery as evidence only; require a new scope version and approval before expansion.
- Stop on policy timeout, evaluator error, DNS anomaly, or unresolved target identity.

## Safe Failure Rules

The system must stop, pause for review, or roll back when:

- authorization is missing, ambiguous, expired, or out of scope
- policy evaluation fails or is unavailable
- evidence is missing or integrity validation fails
- model confidence is insufficient for the requested decision
- an approval is absent, expired, revoked, or bound to another plan version
- tool input does not match a typed schema or allowlist
- verification fails or produces an ambiguous result

Logging a blocked action is required, but sensitive values must be redacted.

## Assumptions and Residual Risk

- Authorized administrators and approvers can still make harmful decisions; separation of duties and review reduce but do not eliminate this risk.
- Models can hallucinate or be manipulated; they remain advisory even with structured output.
- Target and external-source data can be adversarial at any time.
- Rollback is not always technically possible, so some actions must remain proposal-only.
- A modular-monolith deployment shares a failure domain; isolation should increase as execution capability and tenant count grow.

## Review Triggers

Review this threat model when adding a new executor, agent integration mode, authentication model, tenant model, AI provider, active validation capability, sensitive data class, deployment boundary, or autonomy level.
