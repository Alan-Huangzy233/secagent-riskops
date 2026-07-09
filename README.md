# SecAgent RiskOps

SecAgent RiskOps reduces alert fatigue, converts security incidents into compliance evidence, and safely executes approved remediation with verification and rollback.

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

## External Intelligence Ingestion

SecAgent RiskOps includes an External Intelligence Ingestion Layer for collecting trusted external security knowledge such as CVEs, CISA KEV status, EPSS scores, ATT&CK techniques, GitHub Security Advisories, OSV advisories, and vendor security advisories.

External intelligence is treated as untrusted input until validated. Connectors and crawlers create knowledge candidates, not active knowledge. Candidate promotion requires provenance, confidence, TTL, and validation.

See:
- [External Intelligence Ingestion](./docs/external-intelligence-ingestion.md)
- [Crawler Safety and Intelligence Governance](./docs/crawler-safety-governance.md)
- [Source Registry](./docs/source-registry.md)
