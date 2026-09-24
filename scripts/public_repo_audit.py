#!/usr/bin/env python3
"""Scan publishable files without copying suspected credentials into reports."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

ROOT = Path.cwd()
MAX_FILE_BYTES = 2_000_000
MAX_HISTORY_BYTES = 25_000_000
PRIVATE_RECORDS = frozenset({
    "docs/live-telemetry-deployment.md", "docs/sshd-parser-and-refresh.md",
    "docs/ip-lookup-and-pagination.md",
})

# Exceptions apply to one credential value in one reviewed fixture file. They
# must never suppress the rest of a line or another token rule on that line.
FIXTURE_CREDENTIALS = {
    "backend/tests/test_live_api.py": frozenset({
        "test-password-only-1234567890", "must-never-appear-in-error",
    }),
    "backend/tests/test_operator_auth.py": frozenset({
        "test-only-operator-password-123456", "incorrect",
    }),
    "backend/tests/test_manual_control.py": frozenset({
        "operator-control-tests-only",
    }),
    "backend/tests/test_collection_integrity.py": frozenset({
        "integrity-test-password-1234567890",
    }),
}
# These are unquoted references in existing test function calls, not literals.
CODE_REFERENCES = {
    "backend/tests/test_operator_auth.py": frozenset({"PASSWORD", "password"}),
}

PATTERNS = [
    ("HIGH", "private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("HIGH", "github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("HIGH", "aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("HIGH", "openai-style-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("HIGH", "slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("HIGH", "google-api-key", re.compile(r"\bAIza[A-Za-z0-9_-]{30,}\b")),
    ("HIGH", "jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("HIGH", "credential-assignment", re.compile(
        r'''(?ix)(?<![a-z0-9_])(?:[a-z0-9]+_)*'''
        r'''(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)'''
        r'''\b["']?\s*[:=](?!=)\s*(?P<quote>["']?)'''
        r'''(?P<value>[^\s"'`,;)\]}]{8,})'''
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


def finding(severity, rule, location, line=0):
    # Keep the former report schema, but never include a matched value.
    return {"severity": severity, "rule": rule, "location": location,
            "line": line, "match": "[REDACTED]"}


def git_bytes(args):
    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True)
    if result.returncode:
        # Git errors can contain paths, credentials in URLs, or supplied text.
        raise RuntimeError("Git audit command failed")
    return result.stdout


def git(args):
    return git_bytes(args).decode("utf-8", "replace")


def scan_text(text, location, *, fixture_path=None):
    findings = []
    rel = (fixture_path or location).replace("\\", "/")
    for line_no, line in enumerate(text.splitlines(), 1):
        for severity, rule, pattern in PATTERNS:
            for match in pattern.finditer(line):
                if rule == "credential-assignment":
                    candidate = match.group("value")
                    if candidate in FIXTURE_CREDENTIALS.get(rel, ()):
                        continue
                    if not match.group("quote") and candidate in CODE_REFERENCES.get(rel, ()):
                        continue
                    # Explicit deployment placeholders only; substring matches
                    # such as "test" or identifier-looking values are unsafe.
                    if candidate in {"REPLACE_ME", "<REPLACE_ME>"}:
                        continue
                if rule == "email-address" and match.group(0).endswith("@users.noreply.github.com"):
                    continue
                findings.append(finding(severity, rule, location, line_no))
    return findings


def tracked_files():
    # No path-based exclusion here: an ignored private file can still be added
    # with git add -f. --exclude-standard applies only to untracked files.
    names = git(["ls-files", "--cached", "--others", "--exclude-standard", "-z"])
    return [Path(name) for name in dict.fromkeys(names.split("\0")) if name]


def private_path(rel):
    normalized = rel.replace("\\", "/").lower()
    parts = normalized.split("/")
    name = parts[-1]
    return (normalized in PRIVATE_RECORDS
            or any(part in {".local-audit", ".venv", "venv", "node_modules",
                         "runtime-data", "uploads", "evidence", "artifacts"}
                for part in parts[:-1])
            or "handoff" in name or name in {".env", "id_rsa", "id_ed25519"}
            or name.endswith((".sqlite", ".sqlite3", ".db", ".pem", ".key",
                              ".sqlite-wal", ".sqlite-shm", ".sqlite3-wal", ".sqlite3-shm",
                              ".db-wal", ".db-shm", ".zip", ".tar", ".tar.gz",
                              ".tgz", ".7z", ".tar.zst", ".tar.xz", ".tar.bz2")))


def scan_file(data, location, *, fixture_path=None):
    findings = []
    if private_path(fixture_path or location):
        findings.append(finding("HIGH", "private-runtime-file", location))
    if len(data) > MAX_FILE_BYTES:
        findings.append(finding("HIGH", "file-scan-size-limit", location))
        return findings
    # Scan binary bytes too: silently ignoring NUL-containing files would let
    # a secret be hidden in an accidentally added database or archive.
    findings.extend(scan_text(data.decode("utf-8", "replace"), location,
                              fixture_path=fixture_path))
    return findings


def scan_worktree():
    findings = []
    for rel in tracked_files():
        path = ROOT / rel
        if path.is_symlink():
            findings.append(finding("HIGH", "symlink-review-required", rel.as_posix()))
        elif path.is_file():
            findings.extend(scan_file(path.read_bytes(), rel.as_posix()))
    return findings


def scan_staged():
    """Audit actual index blobs, including forced additions and staged secrets."""
    findings = []
    for entry in git(["ls-files", "--stage", "-z"]).split("\0"):
        if not entry:
            continue
        metadata, rel = entry.split("\t", 1)
        mode, object_id, stage = metadata.split()
        if stage != "0" or mode not in {"100644", "100755"}:
            findings.append(finding("HIGH", "index-entry-review-required", rel))
            continue
        data = git_bytes(["cat-file", "blob", object_id])
        findings.extend(scan_file(data, rel))
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
        findings.append(finding(severity, "commit-author-email", f"git-commit:{commit_hash[:12]}"))
    return findings


def scan_history():
    patch = git(["-c", "core.quotepath=false", "log", "-p", "--all",
                 "--format=AUDIT-COMMIT:%H", "--no-ext-diff", "--text", "--unified=0"])
    if len(patch.encode("utf-8", "ignore")) > MAX_HISTORY_BYTES:
        return [finding("HIGH", "history-scan-size-limit", "git-history")]
    findings = []
    commit = "unknown"
    path = "unknown"
    source_line = 0
    in_hunk = False
    for line in patch.splitlines():
        if line.startswith("AUDIT-COMMIT:"):
            commit = line.removeprefix("AUDIT-COMMIT:")[:12]
            in_hunk = False
        elif line.startswith("diff --git "):
            in_hunk = False
        elif not in_hunk and line.startswith(("--- a/", "+++ b/")):
            path = line[6:]
        elif line.startswith("@@ "):
            in_hunk = True
            source_line = 0
        elif in_hunk and line.startswith(("+", "-", " ")):
            source_line += 1
            location = f"git-history:{commit}:{path}"
            hits = scan_text(line[1:], location, fixture_path=path)
            for hit in hits:
                hit["line"] = source_line
            findings.extend(hits)
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--history", action="store_true")
    parser.add_argument("--staged", action="store_true",
                        help="Scan index contents instead of working files")
    parser.add_argument("--fail-on", choices=["high", "medium", "never"], default="high")
    parser.add_argument("--json-output", default=".local-audit/public-repo-audit.json")
    args = parser.parse_args(argv)

    findings = (scan_staged() if args.staged else scan_worktree()) + scan_metadata()
    if args.history:
        findings += scan_history()
    order = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
    findings.sort(key=lambda item: (order.get(item["severity"], 9), item["location"], item["line"]))

    report = ROOT / args.json_output
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(findings, indent=2), encoding="utf-8")

    counts = {"HIGH": 0, "MEDIUM": 0, "INFO": 0}
    for item in findings:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1
        print(f'[{item["severity"]}] {item["rule"]} {item["location"]}:{item["line"]}')
    print(f"\nAudit complete: {counts['HIGH']} high, {counts['MEDIUM']} medium, {counts['INFO']} info.")
    print(f"Report: {report}")
    if args.fail_on == "high" and counts["HIGH"]:
        return 2
    if args.fail_on == "medium" and (counts["HIGH"] or counts["MEDIUM"]):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
