from __future__ import annotations

import json
import shutil
from pathlib import Path

ROOT = Path.cwd()
PACKAGE_ROOT = Path(__file__).resolve().parent.parent

def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""

def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip() + "\n", encoding="utf-8")

def append_if_missing(path: Path, marker: str, content: str) -> None:
    current = read_text(path)
    if marker in current:
        print(f"[skip] {path} already contains marker: {marker}")
        return
    sep = "\n\n" if current.strip() else ""
    write_text(path, current.rstrip() + sep + content.strip())
    print(f"[update] appended to {path}")

def merge_json_list(path: Path, new_items: list[dict], key: str) -> None:
    existing = []
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8"))
    existing_keys = {item.get(key) for item in existing}
    added = 0
    for item in new_items:
        if item.get(key) not in existing_keys:
            existing.append(item)
            existing_keys.add(item.get(key))
            added += 1
    path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    print(f"[update] {path}: added {added} item(s)")

def copy_file(rel_path: str) -> None:
    src = PACKAGE_ROOT / rel_path
    dst = ROOT / rel_path
    if dst.exists():
        print(f"[skip] {dst} already exists")
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    print(f"[create] {dst}")

def main() -> None:
    for rel_path in [
        "docs/authorized-security-validation.md",
        "docs/validation-safety-policy.md",
        "docs/assessment-scope-model.md",
        "docs/security-validation-workflow.md",
        "examples/validation/assessment-scope.example.json",
        "examples/validation/validation-job.example.json",
        "examples/validation/validation-finding.example.json",
    ]:
        copy_file(rel_path)

    readme_section = """
## Authorized Security Validation

SecAgent RiskOps includes an Authorized Security Validation Layer for safely checking explicitly authorized targets.

This layer supports read-only service discovery, web security baseline checks, configuration validation, evidence collection, external intelligence enrichment, finding generation, GRC mapping, and remediation planning.

Default boundaries:

- explicit scope required
- target allowlist required
- read-only by default
- no exploit execution by default
- no brute force
- no payload upload
- no lateral movement
- all checks must be auditable

See:
- [Authorized Security Validation](./docs/authorized-security-validation.md)
- [Validation Safety Policy](./docs/validation-safety-policy.md)
- [Assessment Scope Model](./docs/assessment-scope-model.md)
- [Security Validation Workflow](./docs/security-validation-workflow.md)
"""
    append_if_missing(ROOT / "README.md", "## Authorized Security Validation", readme_section)

    roadmap_section = """
## v0.1.7 Authorized Security Validation

Goal: Build a safe, scoped, read-only validation layer that checks authorized targets and converts results into findings, evidence, risks, controls, and remediation plans.

Deliverables:
- Authorized Security Validation architecture
- AssessmentTarget schema
- AssessmentScope schema
- ValidationJob schema
- ValidationCheck schema
- Scanner orchestrator skeleton
- Safe service discovery checks
- Web security baseline checks
- External intelligence enrichment for validation findings
- No-exploit default policy
"""
    append_if_missing(ROOT / "ROADMAP.md", "## v0.1.7 Authorized Security Validation", roadmap_section)

    arch_section = """
## Authorized Security Validation Layer

The Authorized Security Validation Layer allows SecAgent RiskOps to actively check explicitly authorized systems while remaining defensive, scoped, read-only by default, and auditable.

```text
Assessment Request
  ↓
Scope Validation
  ↓
Safety Policy Check
  ↓
Validation Flow Created
  ↓
Service Discovery
  ↓
Safe Configuration Checks
  ↓
External Intelligence Enrichment
  ↓
Finding Generation
  ↓
Evidence Package
  ↓
Risk Scoring
  ↓
GRC Control Mapping
  ↓
Remediation ActionPlan
```

Design rule: validation jobs require explicit scope and must not execute exploits, brute force, upload payloads, or perform lateral movement by default.

See [Authorized Security Validation](./docs/authorized-security-validation.md).
"""
    append_if_missing(ROOT / "SYSTEM_ARCHITECTURE.md", "## Authorized Security Validation Layer", arch_section)

    product_vision = ROOT / "docs" / "product-vision.md"
    if product_vision.exists():
        product_section = """
## Authorized Security Validation

SecAgent RiskOps should support safe target validation in addition to passive alert ingestion.

This allows the platform to answer:
- What services are exposed on an authorized target?
- Are safe baseline checks passing?
- Are any known-risk services or configurations present?
- Which findings map to controls and risks?
- What remediation plan should be proposed?

The validation layer must remain scoped, auditable, and no-exploit by default.
"""
        append_if_missing(product_vision, "## Authorized Security Validation", product_section)

    milestones_path = ROOT / "github-milestones-v017.json"
    issues_path = ROOT / "github-issues-v017.json"

    if milestones_path.exists():
        merge_json_list(ROOT / "github-milestones.json", json.loads(milestones_path.read_text(encoding="utf-8")), "title")
    else:
        print("[warn] github-milestones-v017.json not found")

    if issues_path.exists():
        merge_json_list(ROOT / "github-issues.json", json.loads(issues_path.read_text(encoding="utf-8")), "title")
    else:
        print("[warn] github-issues-v017.json not found")

    print("\nDone. Next:")
    print("  git status")
    print("  git add .")
    print('  git commit -m "Add authorized security validation roadmap"')
    print("  git push")
    print("  python scripts/create_milestones.py Alan-Huangzy233/secagent-riskops github-milestones-v017.json")
    print("  python scripts/create_issues.py Alan-Huangzy233/secagent-riskops github-issues-v017.json")

if __name__ == "__main__":
    main()
