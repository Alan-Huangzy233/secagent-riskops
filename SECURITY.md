# Security Policy

## Authorized Use Only

SecAgent RiskOps is designed for authorized security monitoring, compliance, and remediation workflows. Do not use this project against systems without explicit permission.

Authorization must identify the responsible actor, allowed purpose, target or data scope, permitted operations, and validity period. Credentials, connectivity, public exposure, or ownership assumptions do not substitute for explicit authorization.

When authorization is missing, ambiguous, expired, or conflicts with policy, the system must fail closed and record the blocked attempt without exposing sensitive values.

A blank scope is not an unrestricted scope. Active target-facing validation requires at least one typed allow rule, an immutable approved scope version, and a valid approval bound to its canonical policy hash. AI-generated interpretations remain drafts and cannot establish ownership, authorization, or permission.

## Reporting Security Issues

If you find a vulnerability in SecAgent RiskOps, please open a private security advisory or contact the maintainer directly.

## Safety Boundaries

- No unrestricted autonomous shell by default.
- Write actions require policy checks.
- Medium/high risk remediation requires human approval.
- All execution should be auditable.
- Target systems must be allowlisted.
- Sensitive data should be redacted before AI processing.
- AI output is advisory and cannot authorize its own tool calls.
- Configured autonomy is a maximum; role, target, tool, risk, and approval policy may further restrict it.

## Agent Safety Requirements

- Treat target content as untrusted.
- Validate all agent outputs before execution.
- Enforce tool allowlists.
- Enforce target allowlists.
- Require structured ActionPlans for remediation.
- Maintain rollback paths where possible.
- Bind approvals to the exact ActionPlan version, target, operation, and expiry.
- Stop or request review when evidence, confidence, authorization, or verification is insufficient.

## Active Validation and Remediation Preconditions

Before dispatching a target-facing tool, the platform must verify:

- authenticated and authorized actor
- active scope and allowlisted target
- allowlisted typed tool and parameters
- permitted autonomy level
- action risk classification
- required approval
- audit and evidence linkage

The platform must repeat target checks after DNS resolution, before redirects and discovered-target access, before credential use, and when a long-running job crosses a policy checkpoint. Explicit exclusions and platform or tenant denials override scope allow rules. Scope expansion requires a new version and approval.

No-exploit, no-brute-force, no-payload-upload, and no-lateral-movement are the default validation policy.

## Public Repository and Upload Safety

- Do not commit runtime uploads, evidence, secrets, or operational data.
- Manually uploaded documents are untrusted and must not be executed.
- Uploaded content must pass secret, personal-data, malware, and prompt-injection checks.
- Public examples must use neutral placeholders.
- Run `bash scripts/check_public_repo.sh` before publication.
