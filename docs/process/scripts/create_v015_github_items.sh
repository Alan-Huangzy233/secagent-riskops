#!/usr/bin/env bash
set -euo pipefail

REPO="${1:-Alan-Huangzy233/secagent-riskops}"

if command -v python3 >/dev/null 2>&1; then
  python3 scripts/create_milestones.py "$REPO" github-milestones-v015.json
  python3 scripts/create_issues.py "$REPO" github-issues-v015.json
else
  python scripts/create_milestones.py "$REPO" github-milestones-v015.json
  python scripts/create_issues.py "$REPO" github-issues-v015.json
fi
