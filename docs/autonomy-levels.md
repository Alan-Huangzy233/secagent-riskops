# Autonomy Levels

Autonomy levels define the maximum behavior a workflow may perform. They do not override role permissions, target scope, tool policy, risk policy, or approval requirements. The effective permission is always the most restrictive applicable control.

| Level | Name | Allowed | Always prohibited |
|---|---|---|---|
| 0 | Report Only | Read approved data, correlate evidence, and report | remediation planning intended for execution; external writes |
| 1 | Suggest Only | Create recommendations and structured ActionPlan drafts | tool dispatch that changes an external system |
| 2 | Create Patch / PR | Create reviewable patches, branches, or pull requests in an approved repository | merge, deploy, or direct target-system changes |
| 3 | Execute After Approval | Run a typed action after policy evaluation and plan-bound approval | unapproved execution or actions outside the approved plan |
| 4 | Auto-Fix Low Risk | Run pre-approved, reversible, low-risk typed actions | autonomous medium/high-risk action |
| 5 | Lab-Only Full Autonomy | Run broader workflows inside an isolated, explicitly designated lab | production use, scope escape, or bypass of audit and safety policy |

## Enforcement Rules

Before a tool call, the policy engine must evaluate:

- authenticated actor and role
- tenant or project boundary
- configured autonomy level
- active authorization and target scope
- tool and operation allowlist
- normalized and validated parameters
- risk classification
- required approval and approval binding
- rate, time, and resource limits

Changing the autonomy level must be authorized and audited. A workflow retains the level and policy version under which it was created; a higher level must not be applied retroactively without reevaluation.

## Recommended Defaults

- Development with sanitized data: Level 1.
- GitHub patch demonstrations: Level 2.
- Controlled remediation tests: Level 3 in an isolated environment.
- Production: no higher than Level 2 until policy, approval, verification, rollback, and audit controls have passed defined tests.
- Level 4 requires a documented allowlist of low-risk operations and a tested rollback path.
- Level 5 is never a production mode.

## Examples

- Summarizing an alert group is Level 0.
- Drafting an nginx-hardening ActionPlan is Level 1.
- Opening a pull request with a configuration patch is Level 2.
- Reloading an approved lab nginx configuration after validation is Level 3.
- Rotating an approved low-risk test artifact under a pre-approved policy may be Level 4.
- Running a complete autonomous exercise in a disposable cyber range is Level 5.
