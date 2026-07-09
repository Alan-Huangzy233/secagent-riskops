from __future__ import annotations
import json, shutil
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
        "docs/external-intelligence-ingestion.md",
        "docs/crawler-safety-governance.md",
        "docs/source-registry.md",
        "examples/intelligence/source-registry.example.json",
        "examples/intelligence/knowledge-candidate.example.json",
    ]:
        copy_file(rel_path)

    readme_section = """
## External Intelligence Ingestion

SecAgent RiskOps includes an External Intelligence Ingestion Layer for collecting trusted external security knowledge such as CVEs, CISA KEV status, EPSS scores, ATT&CK techniques, GitHub Security Advisories, OSV advisories, and vendor security advisories.

External intelligence is treated as untrusted input until validated. Connectors and crawlers create knowledge candidates, not active knowledge. Candidate promotion requires provenance, confidence, TTL, and validation.

See:
- [External Intelligence Ingestion](./docs/external-intelligence-ingestion.md)
- [Crawler Safety and Intelligence Governance](./docs/crawler-safety-governance.md)
- [Source Registry](./docs/source-registry.md)
"""
    append_if_missing(ROOT / "README.md", "## External Intelligence Ingestion", readme_section)

    roadmap_section = """
## v0.1.6 External Intelligence Ingestion

Goal: Build the source registry, connector, crawler-safety, raw document, extracted entity, and knowledge candidate foundation for external security intelligence enrichment.

Deliverables:
- External intelligence ingestion architecture
- Source Registry
- Raw Intelligence Document schema
- Extracted Entity schema
- Knowledge Candidate schema
- NVD and CISA KEV connector skeletons
- EPSS enrichment design
- ATT&CK enrichment design
- Crawler safety and governance policy
- External intelligence integration into risk scoring design
"""
    append_if_missing(ROOT / "ROADMAP.md", "## v0.1.6 External Intelligence Ingestion", roadmap_section)

    arch_section = """
## External Intelligence Ingestion Layer

The External Intelligence Ingestion Layer expands SecAgent RiskOps with trusted external security knowledge.

```text
External Source
  ↓
Connector / Fetcher
  ↓
Raw Intelligence Document
  ↓
Parser / Extractor
  ↓
Entity Resolver
  ↓
Deduplication
  ↓
Source Reputation Check
  ↓
Knowledge Candidate
  ↓
Validation / Human Review / TTL
  ↓
Active Knowledge Base
```

Initial source priorities:
- NVD CVE API
- CISA KEV
- FIRST EPSS
- MITRE ATT&CK
- GitHub Security Advisories
- OSV.dev
- CWE / CAPEC
- Vendor security advisories

Design rule: external intelligence can enrich SOC triage, GRC mapping, risk scoring, and remediation planning, but raw external content must never directly become active knowledge.

See [External Intelligence Ingestion](./docs/external-intelligence-ingestion.md).
"""
    append_if_missing(ROOT / "SYSTEM_ARCHITECTURE.md", "## External Intelligence Ingestion Layer", arch_section)

    product_vision = ROOT / "docs" / "product-vision.md"
    if product_vision.exists():
        product_section = """
## External Intelligence Expansion

SecAgent RiskOps should combine internal security telemetry with validated external security intelligence.

This enables the platform to answer questions such as:
- Is this CVE known to be exploited?
- How likely is exploitation according to EPSS?
- Which ATT&CK techniques are relevant?
- Which control gaps and risks should be prioritized?
- Is there vendor guidance or a patched version?

The ingestion layer must use allowlisted sources, provenance, TTL, confidence scoring, and candidate review before knowledge promotion.
"""
        append_if_missing(product_vision, "## External Intelligence Expansion", product_section)

    milestones_path = ROOT / "github-milestones-v016.json"
    issues_path = ROOT / "github-issues-v016.json"
    if milestones_path.exists():
        merge_json_list(ROOT / "github-milestones.json", json.loads(milestones_path.read_text(encoding="utf-8")), "title")
    else:
        print("[warn] github-milestones-v016.json not found")
    if issues_path.exists():
        merge_json_list(ROOT / "github-issues.json", json.loads(issues_path.read_text(encoding="utf-8")), "title")
    else:
        print("[warn] github-issues-v016.json not found")

    print("\nDone. Next:")
    print("  git status")
    print("  git add .")
    print('  git commit -m "Add external intelligence ingestion roadmap"')
    print("  git push")
    print("  python scripts/create_milestones.py Alan-Huangzy233/secagent-riskops github-milestones-v016.json")
    print("  python scripts/create_issues.py Alan-Huangzy233/secagent-riskops github-issues-v016.json")

if __name__ == "__main__":
    main()
