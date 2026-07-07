# Threat Model

## Scope

This threat model covers the SecAgent RiskOps platform, including AI agents, ingestion pipelines, knowledge base, policy engine, approval workflow, executor, and user-facing dashboard.

## Assets to Protect

- Security alerts and incident evidence
- Agent prompts, outputs, and traces
- Tool execution permissions
- Target credentials and API tokens
- Knowledge base entries
- Suppression rules
- GRC evidence and risk register
- Approval and remediation audit logs

## Threat Actors

- Malicious external users
- Malicious insiders
- Compromised target systems
- Attackers injecting malicious content into logs, webpages, repositories, or alerts
- Users attempting to bypass authorization boundaries
- Poisoned intelligence or fake detection data

## Key Risks

### Prompt Injection

Untrusted target content may try to instruct the AI to ignore policies or execute unauthorized actions.

Mitigation:
- Treat all target data as untrusted.
- Separate system instructions from retrieved content.
- Validate all tool calls with the policy engine.
- Never execute tool calls directly from untrusted text.

### Unsafe Remediation

AI may propose incorrect or harmful actions.

Mitigation:
- Use structured ActionPlans.
- Require preflight, backup, approval, verification, and rollback.
- Block arbitrary shell by default.
- Use typed tools instead of raw commands.

### Alert Suppression Abuse

Incorrect or malicious suppression may hide real attacks.

Mitigation:
- Suppression rules require scope, reason, TTL, evidence, and audit.
- Medium/high impact suppressions require approval.
- Run periodic suppression review.
- Support replay and evaluation.

### Knowledge Base Poisoning

AI-generated or attacker-influenced knowledge may degrade detection quality.

Mitigation:
- AI can create only candidate knowledge.
- Promotion requires validation or approval.
- Add TTL, versioning, provenance, and rollback.

### Secret Leakage

Logs, evidence, or reports may contain secrets.

Mitigation:
- Redact secrets before AI processing and report generation.
- Store sensitive artifacts with access control.
- Avoid sending raw secrets to external models.

### Unauthorized Target Access

Users may attempt to scan or modify systems they do not own.

Mitigation:
- Enforce target allowlists.
- Require explicit authorization.
- Maintain audit logs.
- Provide clear acceptable-use boundaries.

## Safe Failure Mode

If confidence is low, evidence is missing, policy is ambiguous, or verification fails, the system should stop, request review, or roll back instead of continuing autonomously.
