# Security Policy

## Authorized Use Only

SecAgent RiskOps is designed for authorized security monitoring, compliance, and remediation workflows. Do not use this project against systems without explicit permission.

## Reporting Security Issues

If you find a vulnerability in SecAgent RiskOps, please open a private security advisory or contact the maintainer directly.

## Safety Boundaries

- No unrestricted autonomous shell by default.
- Write actions require policy checks.
- Medium/high risk remediation requires human approval.
- All execution should be auditable.
- Target systems must be allowlisted.
- Sensitive data should be redacted before AI processing.

## Agent Safety Requirements

- Treat target content as untrusted.
- Validate all agent outputs before execution.
- Enforce tool allowlists.
- Enforce target allowlists.
- Require structured ActionPlans for remediation.
- Maintain rollback paths where possible.

## Public Repository and Upload Safety

- Do not commit runtime uploads, evidence, secrets, or operational data.
- Manually uploaded documents are untrusted and must not be executed.
- Uploaded content must pass secret, personal-data, malware, and prompt-injection checks.
- Public examples must use neutral placeholders.
- Run `bash scripts/check_public_repo.sh` before publication.
