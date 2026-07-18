# SecAgent RiskOps System Architecture

## Purpose

This document defines the initial logical architecture, system boundary, trust boundaries, module responsibilities, and decision controls for SecAgent RiskOps. It describes the target architecture; implementation status is documented separately in [Current Capability Boundaries](./docs/capability-boundaries.md).

## System Context

```text
Authorized users and systems
        |
        v
API / Web UI / Connector boundary
        |
        v
SecAgent RiskOps control plane
  - SOC
  - GRC
  - Remediation
  - Knowledge
        |
        +----> PostgreSQL / evidence and artifact storage
        +----> approved AI provider
        +----> approved intelligence sources
        +----> typed executor adapters
                          |
                          v
                 explicitly authorized targets
```

SecAgent RiskOps is a control and decision platform. External sources, AI providers, and target systems remain outside its trust boundary and must be accessed through validated adapters.

## Logical Architecture

```text
Data Sources
├── Code scanner and manual findings
├── Linux / Windows logs
├── Suricata / Zeek / Packetbeat
├── Cloud and GitHub security alerts
├── Approved external intelligence sources
└── Authorized manual uploads

Ingress and Validation
├── Authentication and authorization
├── Authorization evidence and scope-draft validation
├── Rules of Engagement compilation and approval
├── Parser and schema validation
├── Secret / PII / malicious-content screening
└── Raw evidence capture

Core Processing
├── Normalization and deduplication
├── Correlation and enrichment
├── Deterministic rules and risk scoring
├── Flow / Task / Step runtime
└── Evidence and artifact linkage

Product Modules
├── SOC
├── GRC
├── Remediation
└── Knowledge

Control Plane
├── Policy engine
├── Approval service
├── Immutable scope-version registry
├── Typed tool registry
├── Autonomy-level enforcement
└── Audit and observability

Persistence
├── PostgreSQL system of record
├── Evidence / artifact storage
├── Immutable or append-oriented audit records
└── Secrets stored outside application records
```

## Core Module Boundaries

| Module | Owns | Consumes | Produces | Must not do |
|---|---|---|---|---|
| SOC | alerts, groups, triage, incidents | telemetry, assets, intelligence, evidence | dispositions, incidents, tuning candidates | destroy source evidence or silently activate risky suppression |
| GRC | controls, mappings, gaps, risks | confirmed findings/incidents and evidence | control mappings, evidence packages, risk records | certify compliance or accept risk autonomously |
| Remediation | ActionPlans, approvals, execution lifecycle | findings, risks, policy and target context | verified changes, rollback and reports | execute raw model output or bypass policy |
| Knowledge | candidate and active knowledge lifecycle | reviewed operational learning and external content | versioned defensive knowledge | activate unreviewed content |

Cross-cutting services such as assets, identities, evidence, workflow runtime, policy, authorization, and audit are platform capabilities rather than separate product outcomes.

## Primary Data Flow

```text
Authorized input
  -> validate source and scope
  -> retain raw evidence
  -> normalize and correlate
  -> deterministic scoring
  -> evidence-grounded AI assistance
  -> policy/skeptic validation
  -> human-reviewable incident or candidate
  -> GRC mapping and risk candidate
  -> structured remediation plan
  -> policy evaluation and approval
  -> typed execution
  -> independent verification
  -> rollback on failure
  -> reviewed knowledge candidate
```

The flow is not required to continue through every stage. A policy failure, insufficient evidence, low confidence, expired authorization, or failed verification stops or pauses processing.

## Evidence and Audit Model

Evidence is not a final child of an incident; it is a cross-cutting record that can support alerts, findings, triage decisions, incidents, control mappings, approvals, tool calls, and verification results.

Every material decision should record:

- actor or agent identity
- input and evidence references
- policy and model version where applicable
- structured output and confidence
- timestamp and workflow state
- approval or rejection decision
- tool input/output with sensitive values redacted

Raw evidence should be content-addressed or integrity-protected. Audit records should be append-oriented and corrections should create new records rather than silently rewriting history.

## Trust Boundaries

### 1. User and API Boundary

Requests are untrusted until authenticated, authorized, schema-validated, rate-limited, and checked against tenant and role scope.

### 2. Ingestion Boundary

Logs, alerts, documents, repository content, and external intelligence are untrusted data. They may contain malformed content, secrets, personal data, or prompt injection.

### 3. Model Boundary

AI providers are probabilistic external processors. Model output is never an authorization decision and cannot directly invoke an executor.

### 4. Tool and Target Boundary

All target access crosses a high-risk boundary. The policy engine must validate actor, target, tool, parameters, immutable scope version, policy hash, Rules of Engagement, risk, autonomy level, and approval before dispatch. It repeats checks after DNS resolution and before redirects, discovered-target access, and credential use. Discovery never expands scope.

### 5. Persistence Boundary

Application records, sensitive evidence, credentials, and audit records have different retention and access requirements. Secrets must use a dedicated secret store and must not be copied into prompts, normal logs, or audit payloads.

## Decision and Execution Control

```text
Agent recommendation
        |
        v
Structured schema validation
        |
        v
Policy evaluation ---- blocked ----> audit + stop
        |
        v
Approval if required -- rejected ---> audit + stop
        |
        v
Typed tool dispatch
        |
        v
Verification ---------- failed -----> stop / rollback / review
```

The policy engine is independent of the agent that proposes the action. Executor adapters accept typed operations and validated parameters, not arbitrary instructions from retrieved content or model output.

## Assessment Authorization Gate

```text
Authorization attestation and evidence
        +
Structured scope / Rules of Engagement
        +
Optional natural-language instructions
        |
        v
AI interpretation draft (non-authoritative)
        |
        v
Schema, ambiguity, and conflict validation
        |
        v
Platform + tenant policy overlay
        |
        v
Effective-policy preview and human approval
        |
        v
Canonical hash + immutable active scope version
        |
        v
Runtime policy evaluation at every target boundary
```

Blank or ambiguous scope cannot pass this gate for active validation. Material changes create a new scope version and invalidate approvals tied to the previous policy hash. See [Assessment Authorization and Rules of Engagement](./docs/assessment-authorization-and-rules-of-engagement.md).

## Workflow Runtime

```text
Flow
  -> Task
    -> Step
      -> ToolCall
        -> Evidence / Artifact
```

The runtime supports SOC investigations, GRC mapping, remediation, approval, knowledge review, and replay. Every state transition must be validated and auditable. See [Agent Workflow Runtime](./docs/workflow-runtime.md).

## Agent Integration Boundary

Agents are replaceable executors inside the Flow runtime. Product modules request an agent capability through a registry; they do not import a provider-specific implementation or call a model SDK directly.

The stable integration seams are:

- Agent Contract for metadata, bounded context, and structured result
- Agent Registry for capability and version resolution
- Model Provider boundary for vendor-neutral inference
- Tool Gateway for policy-controlled typed operations
- Structured Handoff for orchestrator-mediated multi-agent cooperation
- Supervisor constraints for scheduling without privileged bypass

Single-agent and multi-agent workflows use the same Flow / Task / Step model. Agents cannot communicate or execute tools outside the orchestrator, policy, evidence, and audit boundaries.

See [Agent Integration Boundary](./docs/agent-integration.md).

## Initial Technical Architecture

- Backend API: FastAPI and Pydantic.
- System of record: PostgreSQL with explicit migrations.
- Frontend: React and TypeScript.
- Live updates: SSE first; WebSocket only where bidirectional communication is required.
- Background work: durable job abstraction with explicit retry, timeout, cancellation, and idempotency semantics.
- Agent orchestration: internal workflow runtime before adopting a general agent framework.
- Evidence storage: PostgreSQL metadata plus an object-storage-compatible artifact interface.
- Search: PostgreSQL first; introduce OpenSearch or ClickHouse only when measured requirements justify it.
- Executors: GitHub patch/PR adapter first; restricted Linux lab adapter later.
- Secrets: external secret manager or environment injection, never database plaintext.

## Deployment Boundaries

The first deployment may be a modular monolith: one API service, one worker process, PostgreSQL, artifact storage, and a frontend. Module boundaries should be enforced in code and data ownership before splitting services.

This avoids premature distributed-system complexity while preserving clear seams for later scaling.

## Core Design Principles

1. Evidence first.
2. Deterministic detection and policy controls before probabilistic assistance.
3. AI proposes; policy decides; typed executors act.
4. Authorization is explicit, scoped, time-bound, and auditable.
5. High-risk actions require human accountability.
6. Suppression is scoped, explainable, reversible, and time-limited.
7. Knowledge promotion requires validation.
8. Safe failure means stop, request review, or roll back.

## Related Architecture Extensions

- [Agent Integration Boundary](./docs/agent-integration.md)
- [External Intelligence Ingestion](./docs/external-intelligence-ingestion.md)
- [Authorized Security Validation](./docs/authorized-security-validation.md)
- [Assessment Authorization and Rules of Engagement](./docs/assessment-authorization-and-rules-of-engagement.md)
- [Curated Knowledge Intake](./docs/curated-knowledge-intake.md)
- [Controlled Remediation Workflow](./docs/remediation-workflow.md)
