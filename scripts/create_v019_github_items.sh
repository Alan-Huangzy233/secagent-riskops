#!/usr/bin/env bash
set -euo pipefail

REPO="${1:-}"
if [[ -z "$REPO" ]]; then
  echo "Usage: bash scripts/create_v019_github_items.sh OWNER/REPO" >&2
  exit 2
fi

python3 scripts/create_milestones.py "$REPO" github-milestones-v019.json
python3 scripts/create_issues.py "$REPO" github-issues-v019.json
