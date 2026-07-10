#!/usr/bin/env python3
from __future__ import annotations

import getpass
import re
from pathlib import Path

ROOT = Path.cwd()
CURRENT_USER = getpass.getuser()
HOME = str(Path.home())

TEXT_SUFFIXES = {
    ".md", ".txt", ".json", ".yaml", ".yml", ".py",
    ".sh", ".ps1", ".toml", ".ini", ".cfg", ".xml", ".html", ".js", ".ts"
}

KEY_PATTERN = re.compile(
    r'("(?:authorized_by|requested_by|uploaded_by|submitted_by)"\s*:\s*")([^"]+)(")'
)

changed = 0
for path in ROOT.rglob("*"):
    if not path.is_file() or ".git" in path.parts:
        continue
    if path.suffix.lower() not in TEXT_SUFFIXES:
        continue
    try:
        original = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue

    updated = original

    # Remove machine-specific home paths from public text.
    if HOME:
        updated = updated.replace(HOME + "/", "/home/example-user/")
        updated = updated.replace(HOME + "\\", "C:\\Users\\example-user\\")

    # Neutralize identity-like fields in public example fixtures.
    if "examples" in path.parts:
        updated = KEY_PATTERN.sub(r'\1security-operator\3', updated)

    if updated != original:
        path.write_text(updated, encoding="utf-8")
        print(f"[sanitize] {path.relative_to(ROOT)}")
        changed += 1

print(f"Sanitization complete: {changed} file(s) changed.")
