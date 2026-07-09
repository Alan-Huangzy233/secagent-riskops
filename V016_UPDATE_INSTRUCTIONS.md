# SecAgent RiskOps v0.1.6 Update Instructions

This package adds the External Intelligence Ingestion roadmap and GitHub planning updates.

## Windows PowerShell Workflow

From your repo root:

```powershell
cd G:\secagent\secagent-riskops
```

Copy this package's files into the repo root, then run:

```powershell
python scripts/apply_v016_update.py

git status
git add .
git commit -m "Add external intelligence ingestion roadmap"
git push
```

Then create the new GitHub milestone and issues:

```powershell
python scripts/create_milestones.py Alan-Huangzy233/secagent-riskops github-milestones-v016.json
python scripts/create_issues.py Alan-Huangzy233/secagent-riskops github-issues-v016.json
```

Or run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\create_v016_github_items.ps1
```

## New Milestone

- `v0.1.6 External Intelligence Ingestion`

## New Issues

- Design external intelligence ingestion layer
- Implement source registry for approved intelligence sources
- Implement raw intelligence document and extracted entity schemas
- Implement NVD and CISA KEV connectors
- Implement EPSS enrichment connector
- Implement MITRE ATT&CK enrichment importer
- Design crawler safety and governance policy
- Implement knowledge candidate review queue
- Integrate external intelligence into risk scoring design

## Recommended Placement

```text
v0.1.5 Agent Workflow Runtime
v0.1.6 External Intelligence Ingestion
v0.2 AI SOC Inbox
```
