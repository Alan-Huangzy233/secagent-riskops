# Authorized Security Validation Layer

## Purpose

The Authorized Security Validation Layer allows SecAgent RiskOps to safely check explicitly authorized target systems and convert results into findings, evidence, risks, controls, and remediation plans.

This layer preserves the useful security-assessment part of agentic pentest platforms while keeping SecAgent RiskOps defensive, scoped, auditable, and non-destructive by default.

## Position in Architecture

```text
Data Sources
  ↓
Ingestion Layer
  ↓
Agent Workflow Runtime
  ↓
External Intelligence Ingestion
  ↓
Authorized Security Validation
  ↓
SOC Layer
  ↓
GRC Layer
  ↓
Controlled Remediation
  ↓
Knowledge Loop
  ↓
Evaluation Layer
```

## Core Workflow

```text
Assessment Request
  ↓
Authorization Verification
  ↓
Scope and Rules of Engagement Draft
  ↓
AI-Assisted Interpretation and Human Review
  ↓
Scope Compilation, Approval, and Activation
  ↓
Safety Policy Check
  ↓
Validation Flow Created
  ↓
Service Discovery
  ↓
Safe Configuration Checks
  ↓
External Intelligence Enrichment
  ↓
Finding Generation
  ↓
Evidence Package
  ↓
Risk Scoring
  ↓
GRC Control Mapping
  ↓
Remediation ActionPlan
```

## First-Version Check Types

The first version should be read-only and non-destructive.

Recommended checks:

- host reachability
- port discovery
- service fingerprinting
- banner capture
- HTTP security header checks
- TLS configuration checks
- HTTP method checks
- redirect behavior checks
- CORS configuration checks
- directory listing signal checks
- GitHub security posture checks
- cloud security event ingestion
- service/version to CVE candidate mapping

## Out of Scope by Default

The validation layer must not perform the following by default:

- exploit execution
- brute force
- credential attacks
- payload upload
- lateral movement
- privilege escalation
- destructive checks
- scanning targets outside the approved scope
- uncontrolled high-rate scanning

## Core Objects

```text
AssessmentTarget
AssessmentScope
AssessmentScopeVersion
ScopeApproval
ValidationJob
ValidationCheck
ScanResult
ValidationFinding
```

## Object Relationships

```text
Asset
  ↓
AssessmentTarget
  ↓
AssessmentScope
  ↓
ValidationJob
  ↓
ValidationCheck
  ↓
ToolCall / Evidence / Finding
```

## Design Rules

1. Every validation job must reference an approved scope version and canonical policy hash.
2. Blank, ambiguous, expired, or unapproved scope fails closed and never means unrestricted access.
3. Every target must match a typed allow rule and must not match an exclusion.
4. AI may draft and explain scope but cannot authorize, approve, or expand it.
5. DNS results, redirects, discovered services, ports, protocols, and credentials are revalidated at runtime.
6. Every tool call must be logged with a stable policy decision reason.
7. Every result must link to evidence.
8. Every generated finding must preserve target, scope version, policy hash, and tool provenance.
9. No exploit execution is allowed by default.
10. External intelligence enrichment must include source references.
11. Scope expansion requires a new version and approval; emergency stop takes effect immediately.
12. Validation output should feed SOC, GRC, remediation, and knowledge workflows.

See [Assessment Authorization and Rules of Engagement](./assessment-authorization-and-rules-of-engagement.md) for the full preflight, policy compilation, and runtime enforcement design.
