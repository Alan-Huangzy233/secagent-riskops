# Controlled Remediation Workflow

```text
Finding
  ↓
ActionPlan
  ↓
Policy Evaluation
  ↓
Preflight
  ↓
Approval
  ↓
Backup
  ↓
Execution
  ↓
Verification
  ↓
Rollback if needed
  ↓
Report
```

## Required ActionPlan Fields

- target_id
- finding_id
- action_type
- risk_level
- reason
- preconditions
- dry_run
- backup
- execution
- verification
- rollback

## Rule

AI should not execute arbitrary shell commands. The executor should use typed tools and validated parameters.
