# Usage from repo root:
#   powershell -ExecutionPolicy Bypass -File .\scripts\create_v017_github_items.ps1

$Repo = "Alan-Huangzy233/secagent-riskops"

python scripts/create_milestones.py $Repo github-milestones-v017.json
python scripts/create_issues.py $Repo github-issues-v017.json
