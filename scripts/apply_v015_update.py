from __future__ import annotations

import json
from pathlib import Path
import shutil

ROOT = Path.cwd()

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

def copy_doc(name: str) -> None:
    src = Path(__file__).resolve().parent.parent / "docs" / name
    dst = ROOT / "docs" / name
    if dst.exists():
        print(f"[skip] {dst} already exists")
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    print(f"[create] {dst}")

def main() -> None:
    for doc in ["workflow-runtime.md", "evaluation-replay.md", "capability-boundaries.md"]:
        copy_doc(doc)

    roadmap_section = """
## v0.1.5 Agent Workflow Runtime

Goal: Build the Flow / Task / Step / ToolCall / Artifact runtime that powers SOC investigations, GRC mapping, remediation workflows, and knowledge review.

Deliverables:
- Flow / Task / Step / ToolCall / Artifact model
- Workflow state machine
- Agent activity timeline
- Memory model for SOC, GRC, and remediation
- Supervisor agent and stuck-state detection
- Evaluation and replay framework design
"""
    append_if_missing(ROOT / "ROADMAP.md", "## v0.1.5 Agent Workflow Runtime", roadmap_section)

    readme_section = """
## Current Capability Boundaries

SecAgent RiskOps is currently an early-stage AI-assisted security operations platform prototype.

Current boundaries:

- It is not a SIEM replacement.
- It does not provide unrestricted autonomous shell access.
- It does not execute medium/high-risk remediation without approval.
- It is intended only for authorized environments.
- AI triage decisions must be evidence-grounded and auditable.
- Suppression rules must be scoped, explainable, reversible, and time-limited.
- The system prioritizes analyst assistance and controlled automation over fully autonomous security operations.

See [Current Capability Boundaries](./docs/capability-boundaries.md) and [Security Policy](./SECURITY.md).
"""
    append_if_missing(ROOT / "README.md", "## Current Capability Boundaries", readme_section)

    arch_section = """
## Agent Workflow Runtime

SecAgent RiskOps uses a Flow-based runtime inspired by security automation platforms, but adapted for defensive SOC, GRC, and controlled remediation workflows.

```text
Flow
  ↓
Task
  ↓
Step
  ↓
ToolCall
  ↓
Evidence / Artifact
```

This runtime supports:
- SOC investigations
- GRC mapping
- Remediation planning
- Approval workflows
- Knowledge review
- Replay/evaluation runs

See [Agent Workflow Runtime](./docs/workflow-runtime.md).
"""
    append_if_missing(ROOT / "SYSTEM_ARCHITECTURE.md", "## Agent Workflow Runtime", arch_section)

    if (ROOT / "github-milestones-v015.json").exists():
        merge_json_list(ROOT / "github-milestones.json", json.loads((ROOT / "github-milestones-v015.json").read_text(encoding="utf-8")), "title")
    else:
        print("[warn] github-milestones-v015.json not found")

    if (ROOT / "github-issues-v015.json").exists():
        merge_json_list(ROOT / "github-issues.json", json.loads((ROOT / "github-issues-v015.json").read_text(encoding="utf-8")), "title")
    else:
        print("[warn] github-issues-v015.json not found")

    print("\nDone. Next:")
    print("  git add .")
    print('  git commit -m "Add agent workflow runtime and evaluation roadmap"')
    print("  git push")
    print("  python scripts/create_milestones.py Alan-Huangzy233/secagent-riskops github-milestones-v015.json")
    print("  python scripts/create_issues.py Alan-Huangzy233/secagent-riskops github-issues-v015.json")

if __name__ == "__main__":
    main()
