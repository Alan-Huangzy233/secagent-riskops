# Security Validation Workflow

## End-to-End Flow

```text
User requests validation
  ↓
Assessment scope is selected or created
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

- suggest validation plan
- prioritize safe checks
- summarize evidence
- explain findings
- map findings to controls
- propose remediation plan

AI must not:

- bypass scope
- run unregistered tools
- execute exploit code by default
- ignore policy engine
- create high-confidence findings without evidence
