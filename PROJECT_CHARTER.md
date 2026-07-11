# Project Charter: SecAgent RiskOps

## Mission

Build an AI-assisted SOC, GRC, and controlled-remediation platform that reduces alert fatigue, turns technical security findings into risk-based incidents and compliance evidence, and executes approved remediation with verification and rollback.

## Problem Statement

Small security teams often lack enough analyst capacity to continuously monitor alerts, investigate incidents, maintain compliance evidence, and safely remediate issues. Traditional dashboards expose more data but do not reliably reduce operational burden or preserve the reasoning behind decisions.

SecAgent RiskOps addresses this by combining deterministic security processing, evidence-grounded AI assistance, policy enforcement, human approval, and typed execution.

## Target Users

- SOC analysts who need a smaller, prioritized review queue.
- Security engineers who need traceable investigation and remediation workflows.
- GRC analysts who need technical findings converted into controls, risks, and evidence.
- DevSecOps engineers who need safe patch and pull-request workflows.
- Small security teams operating with limited human capacity.
- Students and researchers working in explicitly authorized or isolated lab environments.

## Product Outcomes

The product should:

1. Reduce repeated alerts into evidence-preserving alert groups.
2. Explain why an alert or finding matters without inventing unsupported claims.
3. Convert confirmed incidents and findings into control mappings and risk records.
4. Produce structured remediation plans before any write action occurs.
5. Enforce target, tool, risk, and approval policies independently of AI output.
6. Verify outcomes, support rollback, and retain a complete audit trail.
7. Promote operational learning only through reviewed, versioned knowledge.

## Product Scope

### In Scope

- Ingesting authorized alerts, findings, logs, and security documents.
- Normalization, deduplication, grouping, enrichment, and risk scoring.
- Evidence-grounded AI triage with deterministic validation and human review.
- Incident creation, timelines, and MITRE ATT&CK context.
- GRC control mapping, evidence packages, and risk-register entries.
- Structured remediation planning, policy evaluation, approval, typed execution, verification, and rollback.
- Candidate-based knowledge ingestion with provenance, confidence, TTL, and review.
- Read-only security validation of explicitly authorized targets.
- Agent, tool-call, approval, evidence, and state-transition audit records.

### Out of Scope

- Unauthorized scanning, monitoring, testing, or remediation.
- General-purpose SIEM storage and search at enterprise scale.
- Replacing human incident commanders, control owners, or risk owners.
- Unrestricted autonomous shell or arbitrary command execution.
- Exploit execution, brute force, credential attacks, payload delivery, persistence, or lateral movement by default.
- Unreviewed permanent suppression or direct activation of AI-generated knowledge.
- Unapproved medium- or high-risk production changes.
- Claims of compliance certification or risk acceptance on behalf of an organization.

## Core Modules

### SOC

Owns alert ingestion, normalization, deduplication, grouping, enrichment, scoring, triage, disposition, incidents, analyst review, and daily briefing.

Primary outputs:

- normalized alerts and alert groups
- evidence-grounded triage decisions
- incidents and investigation timelines
- suppression candidates and tuning suggestions

The SOC module may recommend a disposition, but it may not silently discard source evidence or activate high-impact suppression without policy evaluation.

### GRC

Owns control libraries, finding-to-control mapping, evidence packages, control gaps, risk-register entries, and audit-oriented exports.

Primary outputs:

- control mappings with confidence and evidence references
- control-gap explanations
- risk statements, owners, treatment status, and residual risk
- reviewable evidence packages

The GRC module assists analysis; it does not certify compliance or accept risk on behalf of a human owner.

### Remediation

Owns ActionPlans, policy evaluation, approvals, typed executor adapters, preflight checks, backups, verification, rollback, and remediation reports.

Primary outputs:

- structured and risk-classified ActionPlans
- policy and approval decisions
- execution, verification, and rollback records
- final remediation reports

AI may propose an action. Only the policy engine and an authorized approver may permit it, and only a typed executor may perform it.

### Knowledge

Owns detection, suppression, remediation, control-mapping, and intelligence knowledge across candidate, reviewed, active, rejected, expired, and superseded states.

Primary outputs:

- provenance-preserving knowledge candidates
- reviewed and versioned active knowledge
- TTL, conflict, and freshness decisions
- reusable defensive patterns

AI and external content may create candidates only. Promotion to active knowledge requires validation or explicit approval.

### Cross-Cutting Platform Services

The following services support all four modules:

- Evidence Vault and artifact storage
- Flow / Task / Step / ToolCall runtime
- Agent contract, registry, provider boundary, and structured handoff
- Policy and authorization engine
- Audit trail and agent observability
- Asset, identity, and source registries
- Authentication, role-based access, and secret handling

## Authorized-Use Boundary

Every operation must have an authorized actor, an allowed purpose, and an allowed data or target scope.

Active validation or remediation additionally requires:

- a recorded authorization or assessment scope
- an allowlisted target and permitted action type
- a validity window and safety level
- tool and parameter validation
- risk classification and any required human approval
- evidence and audit logging

Missing, ambiguous, expired, or conflicting authorization must fail closed. Possession of credentials or network reachability does not by itself constitute authorization.

See [Security Policy](./SECURITY.md) and [Current Capability Boundaries](./docs/capability-boundaries.md).

## Autonomy Policy

| Level | Name | Maximum permitted behavior |
|---|---|---|
| 0 | Report Only | Read approved data and produce reports. No remediation proposal or write action. |
| 1 | Suggest Only | Produce structured recommendations and ActionPlan drafts. No external write action. |
| 2 | Create Patch / PR | Create reviewable changes in an isolated branch or pull request. No merge or target-system change. |
| 3 | Execute After Approval | Execute a typed action only after a valid policy decision and explicit approval. |
| 4 | Auto-Fix Low Risk | Execute pre-approved, reversible low-risk typed actions; medium/high-risk actions still require approval. |
| 5 | Lab-Only Full Autonomy | Broader autonomous operation only inside an isolated, explicitly designated lab scope. Safety policy and audit logging still apply. |

The configured level is a maximum, not an entitlement. A policy decision can always reduce capability or block an action. Production defaults should be Level 1 or Level 2 until the policy engine, verification, rollback, and audit controls are proven.

See [Autonomy Levels](./docs/autonomy-levels.md).

Agents are replaceable task executors and never own authorization or direct tool access. See [Agent Integration Boundary](./docs/agent-integration.md).

## Design Principles

1. Evidence precedes conclusions.
2. Deterministic controls precede probabilistic assistance.
3. AI proposes; policy decides; authorized tools act.
4. Human accountability remains explicit.
5. Untrusted content is data, never policy or instruction.
6. High-impact decisions are reversible where technically possible.
7. Safe failure means stop, request review, or roll back.

## Initial Success Criteria

The first end-to-end MVP is successful when it can:

1. ingest a sanitized sample alert
2. preserve the raw input as evidence
3. normalize, group, and score the alert
4. produce a structured, evidence-linked triage recommendation
5. create an incident that an analyst can inspect
6. map the incident to at least one control and risk candidate
7. create, but not automatically execute, a remediation ActionPlan
8. replay the workflow from retained inputs and audit records

## Governance

- Architecture changes that alter trust boundaries, autonomy, or execution permissions require documented review.
- Safety controls must not depend solely on model prompts.
- Examples committed to the public repository must be sanitized.
- Current implementation limits must be documented separately from long-term product intent.
