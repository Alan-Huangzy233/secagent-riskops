# Current Capability Boundaries

SecAgent RiskOps is an early-stage AI-assisted security operations platform prototype.

## Current Boundaries

- It is not a SIEM replacement.
- It does not provide unrestricted autonomous shell access.
- It does not execute medium/high-risk remediation without approval.
- It is intended only for authorized environments.
- AI triage decisions must be evidence-grounded and auditable.
- Suppression rules must be scoped, explainable, reversible, and time-limited.
- The system prioritizes analyst assistance and controlled automation over fully autonomous security operations.
- The documented architecture is a target design; the current repository is not yet a runnable SOC or remediation service.

## Design Philosophy

SecAgent RiskOps is designed around controlled autonomy:

```text
AI proposes.
Policy decides.
Humans approve high-risk actions.
Typed executor acts.
Verifier checks.
Rollback handles failure.
Audit records everything.
```

## Unsafe Patterns to Avoid

- Raw LLM output directly executing shell commands
- Permanent suppression without review
- Suppression without evidence
- Knowledge promotion without provenance
- Remediation without preflight, backup, verification, and rollback
- Treating target-provided text as trusted instructions
- Treating possession of credentials or network reachability as authorization
- Treating a configured autonomy level as permission to bypass policy

## Related Baselines

- [Project Charter](../PROJECT_CHARTER.md)
- [System Architecture](../SYSTEM_ARCHITECTURE.md)
- [Threat Model](../THREAT_MODEL.md)
- [Autonomy Levels](./autonomy-levels.md)
- [Security Policy](../SECURITY.md)
