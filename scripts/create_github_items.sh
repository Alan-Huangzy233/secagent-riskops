#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   gh auth login
#   ./scripts/create_github_items.sh Alan-Huangzy233/secagent-riskops
#
# This script creates labels, milestones, and issues.
# It does not create GitHub Projects custom fields because GitHub Projects configuration
# is easier to set up manually in the GitHub UI for the first version.

REPO="${1:-}"
if [[ -z "$REPO" ]]; then
  echo "Usage: $0 owner/repo"
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Creating labels..."
python3 "$ROOT/scripts/create_labels.py" "$REPO" "$ROOT/github-labels.json"

echo "Creating milestones..."
python3 "$ROOT/scripts/create_milestones.py" "$REPO" "$ROOT/github-milestones.json"

echo "Creating issues..."
python3 "$ROOT/scripts/create_issues.py" "$REPO" "$ROOT/github-issues.json"

echo "Done."
