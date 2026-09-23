#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path.cwd()


def merge_json_list(path: Path, new_items: list[dict], key: str) -> None:
    existing = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
    existing_keys = {item.get(key) for item in existing}
    added = 0

    for item in new_items:
        if item.get(key) in existing_keys:
            continue
        existing.append(item)
        existing_keys.add(item.get(key))
        added += 1

    path.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
    print(f"[update] {path}: added {added} item(s)")


def main() -> None:
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    marker = "## v0.1.9 Assessment Authorization and Rules of Engagement"
    if marker not in roadmap:
        raise SystemExit("ROADMAP.md is missing the v0.1.9 section; apply the design update first")

    milestones = json.loads((ROOT / "github-milestones-v019.json").read_text(encoding="utf-8"))
    issues = json.loads((ROOT / "github-issues-v019.json").read_text(encoding="utf-8"))

    merge_json_list(ROOT / "github-milestones.json", milestones, "title")
    merge_json_list(ROOT / "github-issues.json", issues, "title")

    print("\nDone. Next:")
    print("  bash scripts/check_public_repo.sh")
    print("  git status")
    print("  bash scripts/create_v019_github_items.sh OWNER/REPO")


if __name__ == "__main__":
    main()
