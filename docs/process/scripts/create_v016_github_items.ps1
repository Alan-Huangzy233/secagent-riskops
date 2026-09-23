# Usage from repo root:
#   powershell -ExecutionPolicy Bypass -File .\scripts\create_v016_github_items.ps1

$Repo = "Alan-Huangzy233/secagent-riskops"
python scripts/create_milestones.py $Repo github-milestones-v016.json
python scripts/create_issues.py $Repo github-issues-v016.json
