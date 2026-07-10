#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import re
import subprocess
from pathlib import Path

ROOT = Path.cwd()
MAX_FILE_BYTES = 2_000_000
SKIP = {"scripts/public_repo_audit.py"}
SKIP_PREFIXES = (
    ".git/", ".venv/", "venv/", "node_modules/",
    "runtime-data/", "uploads/", "evidence/", "artifacts/", ".local-audit/"
)
PLACEHOLDERS = (
    "replace_me", "example.com", "example.internal",
    "cve-yyyy-nnnn", "placeholder", "security-operator",
    "users.noreply.github.com"
)

PATTERNS = [
    ("HIGH", "private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("HIGH", "github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("HIGH", "aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("HIGH", "openai-style-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("HIGH", "slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("HIGH", "google-api-key", re.compile(r"\bAIza[A-Za-z0-9_-]{30,}\b")),
    ("HIGH", "jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("HIGH", "credential-assignment", re.compile(
        r'(?ix)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b'
        r'\s*[:=]\s*["\']?([^\s"\'`]{8,})["\']?'
    )),
    ("MEDIUM", "email-address", re.compile(
        r"\b[A-Za-z0-9._%+-]+@(?!example\.com\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )),
    ("MEDIUM", "mac-local-path", re.compile(r"/Users/[A-Za-z0-9._-]+/")),
    ("MEDIUM", "windows-local-path", re.compile(r"[A-Za-z]:\\Users\\[A-Za-z0-9._-]+\\")),
    ("MEDIUM", "private-ipv4", re.compile(
        r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.(?:\d{1,3}\.)\d{1,3}|"
        r"172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3})\b"
    )),
]

def git(args):
    p = subprocess.run(
        ["git", *args], capture_output=True, text=True,
        encoding="utf-8", errors="replace"
    )
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip())
    return p.stdout

def scan_text(text, location):
    findings = []
    for line_no, line in enumerate(text.splitlines(), 1):
        lower = line.lower()
        if any(value in lower for value in PLACEHOLDERS):
            continue
        for severity, rule, pattern in PATTERNS:
            for match in pattern.finditer(line):
                if rule == "credential-assignment":
                    candidate = match.group(2).lower()
                    if candidate in {"true", "false", "none", "null", "required", "configured"}:
                        continue
                findings.append({
                    "severity": severity,
                    "rule": rule,
                    "location": location,
                    "line": line_no,
                    "match": match.group(0)[:160],
                })
    return findings

def tracked_files():
    files = []
    for item in git(["ls-files"]).splitlines():
        normalized = item.replace("\\", "/")
        if not item or normalized in SKIP or normalized.startswith(SKIP_PREFIXES):
            continue
        files.append(Path(item))
    return files

def scan_worktree():
    findings = []
    for rel in tracked_files():
        path = ROOT / rel
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            continue
        data = path.read_bytes()
        if b"\x00" in data[:8192]:
            continue
        findings.extend(scan_text(data.decode("utf-8", "replace"), str(rel)))
    return findings

def scan_metadata():
    findings = []
    seen = set()
    for line in git(["log", "--all", "--format=%H%x09%an%x09%ae"]).splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        commit_hash, name, email = parts
        if (name, email) in seen:
            continue
        seen.add((name, email))
        if email.endswith("@users.noreply.github.com"):
            continue
        severity = "HIGH" if email.endswith(".local") or ".local@" in email else "MEDIUM"
        findings.append({
            "severity": severity,
            "rule": "commit-author-email",
            "location": f"git-commit:{commit_hash[:12]}",
            "line": 0,
            "match": f"{name} <{email}>",
        })
    return findings

def scan_history():
    text = git(["log", "-p", "--all", "--no-ext-diff", "--text"])
    if len(text.encode("utf-8", "ignore")) > 25_000_000:
        return [{
            "severity": "INFO",
            "rule": "history-scan-skipped",
            "location": "git-history",
            "line": 0,
            "match": "History patch exceeds 25 MB",
        }]
    return scan_text(text, "git-history-patch")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--history", action="store_true")
    parser.add_argument("--fail-on", choices=["high", "medium", "never"], default="high")
    parser.add_argument("--json-output", default=".local-audit/public-repo-audit.json")
    args = parser.parse_args()

    findings = scan_worktree() + scan_metadata()
    if args.history:
        findings += scan_history()

    order = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
    findings.sort(key=lambda item: (
        order.get(item["severity"], 9), item["location"], item["line"]
    ))

    report = ROOT / args.json_output
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(findings, indent=2), encoding="utf-8")

    counts = {"HIGH": 0, "MEDIUM": 0, "INFO": 0}
    for item in findings:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1
        print(
            f'[{item["severity"]}] {item["rule"]} '
            f'{item["location"]}:{item["line"]} -> {item["match"]}'
        )

    print(
        f"\nAudit complete: {counts['HIGH']} high, "
        f"{counts['MEDIUM']} medium, {counts['INFO']} info."
    )
    print(f"Report: {report}")

    if args.fail_on == "high" and counts["HIGH"]:
        return 2
    if args.fail_on == "medium" and (counts["HIGH"] or counts["MEDIUM"]):
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
