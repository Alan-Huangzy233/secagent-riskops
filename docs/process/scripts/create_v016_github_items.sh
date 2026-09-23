#!/usr/bin/env bash
set -euo pipefail
REPO="${1:-Alan-Huangzy233/secagent-riskops}"
python3 scripts/create_milestones.py "$REPO" github-milestones-v016.json || python scripts/create_milestones.py "$REPO" github-milestones-v016.json
python3 scripts/create_issues.py "$REPO" github-issues-v016.json || python scripts/create_issues.py "$REPO" github-issues-v016.json
