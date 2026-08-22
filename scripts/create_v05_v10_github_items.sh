#!/usr/bin/env bash
set -euo pipefail

REPO="${1:-}"
if [[ -z "$REPO" ]]; then
  echo "Usage: bash scripts/create_v05_v10_github_items.sh OWNER/REPO" >&2
  exit 2
fi

# v0.5 and v1.0 already exist as milestones; only the issues are new.
python3 scripts/create_issues.py "$REPO" github-issues-v05-v10.json
