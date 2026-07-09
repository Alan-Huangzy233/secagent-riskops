# SecAgent RiskOps v0.1.7 Update Instructions

This package adds the Authorized Security Validation roadmap and GitHub planning updates.

## What This Adds

New docs:
- `docs/authorized-security-validation.md`
- `docs/validation-safety-policy.md`
- `docs/assessment-scope-model.md`
- `docs/security-validation-workflow.md`

New examples:
- `examples/validation/assessment-scope.example.json`
- `examples/validation/validation-job.example.json`
- `examples/validation/validation-finding.example.json`

Updated local repo files through script:
- `README.md`
- `ROADMAP.md`
- `SYSTEM_ARCHITECTURE.md`
- `docs/product-vision.md` if present
- `github-milestones.json`
- `github-issues.json`

New GitHub creation data:
- `github-milestones-v017.json`
- `github-issues-v017.json`

New scripts:
- `scripts/apply_v017_update.py`
- `scripts/create_v017_github_items.ps1`
- `scripts/create_v017_github_items.sh`

## Windows PowerShell Workflow

From your repo root:

```powershell
cd G:\secagent\secagent-riskops
```

Copy this package's files into the repo root, then run:

```powershell
python scripts/apply_v017_update.py

git status
git add .
git commit -m "Add authorized security validation roadmap"
git pull --rebase origin main
git push origin main
```

Then create the new GitHub milestone and issues:

```powershell
python scripts/create_milestones.py Alan-Huangzy233/secagent-riskops github-milestones-v017.json
python scripts/create_issues.py Alan-Huangzy233/secagent-riskops github-issues-v017.json
```

Or run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\create_v017_github_items.ps1
```

## New Milestone

- `v0.1.7 Authorized Security Validation`

## New Issues

- Design authorized security validation layer
- Implement assessment scope and authorization model
- Implement scanner orchestrator skeleton
- Implement safe service discovery checks
- Implement web security baseline checks
- Integrate validation findings with external intelligence
- Convert validation results into normalized findings
- Define and enforce no-exploit default policy

## Recommended Placement

This milestone should sit between:

```text
v0.1.6 External Intelligence Ingestion
v0.1.7 Authorized Security Validation
v0.2 AI SOC Inbox
```
