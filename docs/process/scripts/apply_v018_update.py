#!/usr/bin/env python3
from __future__ import annotations
import json
import shutil
from pathlib import Path

ROOT = Path.cwd()
PACKAGE = Path(__file__).resolve().parent.parent

def read(path):
    return path.read_text(encoding="utf-8") if path.exists() else ""

def write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip() + "\n", encoding="utf-8")

def append(path, marker, content):
    current = read(path)
    if marker in current:
        print(f"[skip] {path} already contains marker: {marker}")
        return
    separator = "\n\n" if current.strip() else ""
    write(path, current.rstrip() + separator + content.strip())
    print(f"[update] appended to {path}")

def copy(rel):
    source = PACKAGE / rel
    destination = ROOT / rel
    if destination.exists():
        print(f"[skip] {destination} already exists")
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    print(f"[create] {destination}")

def merge(path, new_items, key):
    existing = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
    known = {item.get(key) for item in existing}
    added = 0
    for item in new_items:
        if item.get(key) not in known:
            existing.append(item)
            known.add(item.get(key))
            added += 1
    path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    print(f"[update] {path}: added {added} item(s)")

for rel in [
    "docs/curated-knowledge-intake.md",
    "docs/manual-upload-security.md",
    "docs/public-repository-security.md",
    "examples/intake/upload-batch.example.json",
    "examples/intake/uploaded-document.example.json",
    "examples/intake/manual-knowledge-candidate.example.json",
    "scripts/public_repo_audit.py",
    "scripts/check_public_repo.sh",
    "scripts/sanitize_public_examples.py",
    ".github/workflows/public-repo-audit.yml",
]:
    copy(rel)

gitignore = ROOT / ".gitignore"
entries = [
    ".env", ".env.*", "!.env.example",
    "*.pem", "*.key", "*.p12", "*.pfx",
    "credentials.json", "secrets.json",
    "runtime-data/", "uploads/", "evidence/", "artifacts/",
    ".local-audit/", ".DS_Store",
]
current = read(gitignore)
current_lines = set(current.splitlines())
new_entries = [entry for entry in entries if entry not in current_lines]
if new_entries:
    write(
        gitignore,
        current.rstrip() + "\n\n# Public repository safety\n" + "\n".join(new_entries)
    )
    print(f"[update] {gitignore}: added {len(new_entries)} ignore rule(s)")

exec(
    (ROOT / "scripts/sanitize_public_examples.py").read_text(encoding="utf-8"),
    {"__name__": "__main__"},
)

append(ROOT / "README.md", "## Curated Knowledge Intake", """
## Curated Knowledge Intake

SecAgent RiskOps supports secure manual submission of authorized security documents, lab writeups, advisories, rules, remediation guidance, pasted text, and source URLs.

Manual submissions pass through security and privacy scanning, parsing, deduplication, cross-validation, and human review before becoming active knowledge.

See:
- [Curated Knowledge Intake](./docs/curated-knowledge-intake.md)
- [Manual Upload Security](./docs/manual-upload-security.md)
- [Public Repository Security](./docs/public-repository-security.md)
""")

append(ROOT / "ROADMAP.md", "## v0.1.8 Curated Knowledge Intake", """
## v0.1.8 Curated Knowledge Intake

Goal: Build a secure manual upload, parsing, review, and promotion workflow for user-provided security documents, authorized lab writeups, advisories, rules, and remediation guidance.

Deliverables:
- UploadBatch, UploadedDocument, and DocumentChunk schemas
- Secure manual upload API
- Safe parser pipeline
- Defensive entity extraction
- Candidate preview and editing
- Manual review queue
- Malware, secret, PII, and prompt-injection screening
- Lab-writeup-to-defensive-knowledge transformation
- Deduplication and cross-source validation
- Public repository privacy and secret audit
""")

append(ROOT / "SYSTEM_ARCHITECTURE.md", "## Curated Knowledge Intake Layer", """
## Curated Knowledge Intake Layer

```text
External Connector ──────┐
Manual Upload / Paste ───┼─> Raw Document
Internal Learning ───────┘
                              ↓
                         Parse / Extract
                              ↓
                         Deduplicate
                              ↓
                      Knowledge Candidate
                              ↓
                    Validation / Human Review
                              ↓
                     Active Knowledge Base
```

Uploaded content is untrusted, candidate-only, and must pass security, privacy, provenance, and rights checks before promotion.
""")

append(ROOT / "SECURITY.md", "## Public Repository and Upload Safety", """
## Public Repository and Upload Safety

- Do not commit runtime uploads, evidence, secrets, or operational data.
- Manually uploaded documents are untrusted and must not be executed.
- Uploaded content must pass secret, personal-data, malware, and prompt-injection checks.
- Public examples must use neutral placeholders.
- Run `bash scripts/check_public_repo.sh` before publication.
""")

milestone_file = ROOT / "github-milestones-v018.json"
issue_file = ROOT / "github-issues-v018.json"
merge(
    ROOT / "github-milestones.json",
    json.loads(milestone_file.read_text(encoding="utf-8")),
    "title",
)
merge(
    ROOT / "github-issues.json",
    json.loads(issue_file.read_text(encoding="utf-8")),
    "title",
)

print("\nDone. Next:")
print("  bash scripts/check_public_repo.sh")
print("  git status")
print("  git add .")
print('  git commit -m "Add curated knowledge intake and public repo audit"')
print("  git pull --rebase origin main")
print("  git push origin main")
