# Security Validation Workflow

## End-to-End Flow

```text
User requests validation
  ↓
Authorization is attested and verified
  ↓
Structured scope and Rules of Engagement are selected or entered
  ↓
AI optionally parses natural-language instructions into a draft
  ↓
User reviews ambiguity, exclusions, limits, and effective policy
  ↓
Immutable scope version is approved and activated
  ↓
Policy engine checks target and allowed actions
  ↓
Validation flow is created
  ↓
Scanner orchestrator schedules checks
  ↓
Read-only checks run as ToolCalls
  ↓
Raw output is stored as Evidence
  ↓
Results are normalized
  ↓
Findings are generated
  ↓
External intelligence enriches service/version context
  ↓
Risk scoring prioritizes findings
  ↓
Findings map to GRC controls
  ↓
ActionPlans are proposed
  ↓
Knowledge candidates are created from repeated patterns
```

Blank scope, unresolved ambiguity that could broaden access, missing authorization, or policy conflict stops the flow before active validation. Passive import may continue under Safety Level 0.

## Scope Preflight

```text
Authorization evidence
  + structured scope / RoE
  + optional natural-language instructions
  ↓
AI draft with confidence and unresolved questions
  ↓
Deterministic schema validation and policy compilation
  ↓
Effective-policy preview
  ↓
Human confirmation / required approval
  ↓
Canonical policy hash and immutable active version
```

Any material change, including adding a target, port, technique, credential profile, or execution window, creates a new version and repeats approval.

## Example: Web Service Validation

```text
Target: https://web-01.example.internal

Checks:
- HTTP reachability
- TLS certificate inspection
- security header check
- redirect behavior check
- allowed HTTP methods
- CORS configuration
- service/version enrichment

Outputs:
- Evidence package
- Missing security headers finding
- Weak TLS finding if applicable
- Control mapping candidate
- Risk register candidate
- Remediation ActionPlan candidate
```

## Example: Service Discovery

```text
Target: 192.0.2.10

Checks:
- host reachability
- allowed port discovery
- banner capture
- service fingerprinting
- version-to-CVE candidate mapping

Outputs:
- open service evidence
- service exposure finding
- CVE candidate enrichment
- risk scoring input
```

## AI Role

AI should not directly execute arbitrary commands.

AI can:

- parse natural-language scope into a structured draft
- identify ambiguity and conflicts
- explain the effective scope and exclusions
- suggest validation plan
- prioritize safe checks
- summarize evidence
- explain findings
- map findings to controls
- propose remediation plan

AI must not:

- treat blank or ambiguous input as unrestricted permission
- infer ownership or authorization
- approve or expand its own scope
- bypass scope
- run unregistered tools
- execute exploit code by default
- ignore policy engine
- create high-confidence findings without evidence

## Runtime Boundary Checks

The policy engine rechecks the approved scope before each target-facing tool call and whenever target identity changes. DNS answers, cross-origin redirects, discovered services, and links remain out of scope unless independently matched by an explicit allow rule. A discovered target may generate a scope-extension proposal but cannot be contacted until a new scope version is approved.
