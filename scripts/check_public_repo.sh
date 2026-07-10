#!/usr/bin/env bash
set -euo pipefail

if [[ ! -d .git ]]; then
  echo "Run this script from the repository root." >&2
  exit 3
fi

echo "== Git identity =="
git config user.name || true
git config user.email || true

echo
echo "== Tracked files and commit metadata =="
python3 scripts/public_repo_audit.py --fail-on high

echo
echo "== Reachable Git history =="
python3 scripts/public_repo_audit.py --history --fail-on high

echo
echo "Review all MEDIUM findings manually before pushing."
