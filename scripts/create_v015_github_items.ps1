# Usage from repo root:
#   powershell -ExecutionPolicy Bypass -File .\scripts\create_v015_github_items.ps1

$Repo = "Alan-Huangzy233/secagent-riskops"

python scripts/create_milestones.py $Repo github-milestones-v015.json
python scripts/create_issues.py $Repo github-issues-v015.json
