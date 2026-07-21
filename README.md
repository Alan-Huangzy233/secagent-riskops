# SecAgent RiskOps

SecAgent RiskOps reduces alert fatigue, converts security incidents into compliance evidence, and safely executes approved remediation with verification and rollback.

> **Status: early development (`v0.2`).** Most documents in this repository
> describe the *target design*. One **runnable, tested end-to-end vertical
> slice** now exists (the "walking skeleton"). See
> [Implementation Status](./docs/implementation-status.md) for exactly what is
> implemented in code versus still design-only.

## Quickstart (walking skeleton)

```bash
make install   # or: pip install -e .[dev]
make test      # 22 tests, incl. adversarial policy-enforcement suite
make demo      # end-to-end run on the bundled sample alerts
make run       # FastAPI dev server on :8000  (GET /docs)
```

The demo ingests the sanitized sample alerts, retains raw evidence, groups and
scores them, runs evidence-grounded AI triage, opens an incident, maps it to a
control and a risk, drafts a remediation ActionPlan, and then has the
**independent policy engine deny execution** (fail-closed) — proving the
"AI proposes; policy decides; typed executors act" boundary in code. It finishes
by replaying the whole flow from retained evidence and confirming reproduction.

## Vision

SecAgent RiskOps is an AI-assisted SOC, GRC, and controlled remediation platform for small security teams and security engineers operating with limited human capacity.

The system is designed to transform noisy alerts and technical findings into risk-based incidents, compliance evidence, remediation plans, and reusable security knowledge.

## Core Capabilities

- Alert reduction and SOC inbox
- AI-assisted incident triage
- Evidence-grounded incident investigation
- MITRE ATT&CK mapping
- GRC control mapping
- Risk register generation
- Controlled remediation with approval, verification, and rollback
- Knowledge base for detection, suppression, control mapping, and remediation patterns
- Agent, tool-call, approval, and remediation audit trail

## Product Workflow

```text
Telemetry / Findings
  ↓
Normalize
  ↓
Deduplicate
  ↓
Correlate
  ↓
Enrich
  ↓
Score
  ↓
AI Triage
  ↓
Incident
  ↓
GRC Evidence
  ↓
Remediation Plan
  ↓
Approval
  ↓
Execution
  ↓
Verification
  ↓
Knowledge Update
```

## Initial Roadmap

See [ROADMAP.md](./ROADMAP.md).

## Architecture Baseline

- [Project Charter](./PROJECT_CHARTER.md)
- [System Architecture](./SYSTEM_ARCHITECTURE.md)
- [Threat Model](./THREAT_MODEL.md)
- [Security Policy](./SECURITY.md)
- [Autonomy Levels](./docs/autonomy-levels.md)
- [Agent Integration Boundary](./docs/agent-integration.md)

## Authorized Use

SecAgent RiskOps is intended only for authorized security assessment, monitoring, compliance, and remediation workflows. It must not be used against systems without explicit permission.

## Repository Structure

```text
backend/       FastAPI backend, schemas, agents, tools, storage
frontend/      SOC Inbox, GRC, remediation, and knowledge UI
docs/          Product, architecture, workflow, and security documentation
examples/      Sample alerts, findings, and reports
scripts/       GitHub/bootstrap helper scripts
.github/       Issue templates
```

## Current Capability Boundaries

SecAgent RiskOps is currently an early-stage AI-assisted security operations platform prototype.

Current boundaries:

- It is not a SIEM replacement.
- It does not provide unrestricted autonomous shell access.
- It does not execute medium/high-risk remediation without approval.
- It is intended only for authorized environments.
- AI triage decisions must be evidence-grounded and auditable.
- Suppression rules must be scoped, explainable, reversible, and time-limited.
- The system prioritizes analyst assistance and controlled automation over fully autonomous security operations.

See [Current Capability Boundaries](./docs/capability-boundaries.md) and [Security Policy](./SECURITY.md).

The configured autonomy level is only a maximum capability. Role, target, tool, risk, and approval policies may further restrict every action.

## External Intelligence Ingestion

SecAgent RiskOps includes an External Intelligence Ingestion Layer for collecting trusted external security knowledge such as CVEs, CISA KEV status, EPSS scores, ATT&CK techniques, GitHub Security Advisories, OSV advisories, and vendor security advisories.

External intelligence is treated as untrusted input until validated. Connectors and crawlers create knowledge candidates, not active knowledge. Candidate promotion requires provenance, confidence, TTL, and validation.

See:
- [External Intelligence Ingestion](./docs/external-intelligence-ingestion.md)
- [Crawler Safety and Intelligence Governance](./docs/crawler-safety-governance.md)
- [Source Registry](./docs/source-registry.md)

## Authorized Security Validation

SecAgent RiskOps includes an Authorized Security Validation Layer for safely checking explicitly authorized targets.

This layer supports read-only service discovery, web security baseline checks, configuration validation, evidence collection, external intelligence enrichment, finding generation, GRC mapping, and remediation planning.

Default boundaries:

- explicit scope required
- blank or ambiguous scope fails closed; it never means unrestricted access
- target allowlist required
- AI may draft scope but cannot authorize, approve, or expand it
- approved scope and Rules of Engagement are immutable, versioned, and time-bound
- DNS results, redirects, discovered targets, and every target-facing tool call are rechecked at runtime
- read-only by default
- no exploit execution by default
- no brute force
- no payload upload
- no lateral movement
- all checks must be auditable

See:
- [Authorized Security Validation](./docs/authorized-security-validation.md)
- [Assessment Authorization and Rules of Engagement](./docs/assessment-authorization-and-rules-of-engagement.md)
- [Validation Safety Policy](./docs/validation-safety-policy.md)
- [Assessment Scope Model](./docs/assessment-scope-model.md)
- [Security Validation Workflow](./docs/security-validation-workflow.md)

## Curated Knowledge Intake

SecAgent RiskOps supports secure manual submission of authorized security documents, lab writeups, advisories, rules, remediation guidance, pasted text, and source URLs.

Manual submissions pass through security and privacy scanning, parsing, deduplication, cross-validation, and human review before becoming active knowledge.

See:
- [Curated Knowledge Intake](./docs/curated-knowledge-intake.md)
- [Manual Upload Security](./docs/manual-upload-security.md)
- [Public Repository Security](./docs/public-repository-security.md)
