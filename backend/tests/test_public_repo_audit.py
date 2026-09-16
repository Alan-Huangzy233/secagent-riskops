"""Regression checks for publication scanning; all credentials are synthetic."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess

import pytest


SPEC = importlib.util.spec_from_file_location(
    "public_repo_audit", Path(__file__).resolve().parents[2] / "scripts/public_repo_audit.py"
)
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def assignment(value, *, quote='"', name="api" + "_key"):
    return name + " = " + quote + value + quote


def rules(findings):
    return {item["rule"] for item in findings}


@pytest.mark.parametrize("marker", [
    "test-only", "test-password", "secret-key", "example.com", "placeholder",
    "replace_me", "security-operator", "fixture", "users.noreply.github.com",
])
def test_placeholder_on_same_line_does_not_hide_credential(marker):
    token = "ghp_" + "X7a" * 12
    findings = audit.scan_text(marker + " " + token, "config.txt")
    assert "github-token" in rules(findings)
    assert token not in json.dumps(findings)


@pytest.mark.parametrize("value", [
    "a" + "3bc" * 24, "lowercase_identifier_like_credential",
    "UPPERCASE_IDENTIFIER_LIKE_CREDENTIAL", "some_test_credential_value",
    "contains_fixture_but_is_secret", "contains_example_but_is_secret",
    "REPLACE_ME_with_real_suffix", "prefix_placeholder_suffix",
])
@pytest.mark.parametrize("quote", ["", '"', "'"])
def test_credential_values_are_not_exempted_by_spelling(value, quote):
    findings = audit.scan_text(assignment(value, quote=quote), "config.env")
    assert "credential-assignment" in rules(findings)
    assert value not in json.dumps(findings)


@pytest.mark.parametrize("name", ["api" + "_key", "operator" + "_password", "auth" + "_token"])
def test_quoted_json_keys_are_scanned(name):
    text = json.dumps({name: "synthetic-value-123456"})
    assert "credential-assignment" in rules(audit.scan_text(text, "config.json"))


def test_exact_fixture_exception_is_scoped_to_path_and_match():
    value = next(iter(audit.FIXTURE_CREDENTIALS["backend/tests/test_live_api.py"]))
    token = "ghp_" + "X8b" * 12
    text = assignment(value, name="password")
    assert not audit.scan_text(text, "backend/tests/test_live_api.py")
    assert "credential-assignment" in rules(audit.scan_text(text, "config.env"))
    assert "credential-assignment" in rules(audit.scan_text(assignment(value + "extra"), "backend/tests/test_live_api.py"))
    assert "github-token" in rules(audit.scan_text(text + " # " + token, "backend/tests/test_live_api.py"))


def test_unquoted_reference_exception_never_applies_to_literal():
    rel = "backend/tests/test_operator_auth.py"
    assert not audit.scan_text(assignment("PASSWORD", quote="", name="password"), rel)
    assert audit.scan_text(assignment("PASSWORD", name="password"), rel)
    assert audit.scan_text(assignment("PASSWORD", quote="", name="password"), "config.env")


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "ROOT", tmp_path)

    def git(*args):
        result = subprocess.run(["git", *args], cwd=tmp_path, capture_output=True)
        assert result.returncode == 0, "Test Git operation failed"
        return result.stdout

    git("init", "-q")
    git("config", "user.name", "Audit Test")
    git("config", "user.email", "audit-test@users.noreply.github.com")
    git("commit", "--allow-empty", "-m", "Initial test repository", "-q")
    return tmp_path, git


def test_untracked_publishable_files_are_scanned(repo):
    path, _ = repo
    (path / "new.py").write_text(assignment("synthetic-untracked-value"))
    assert "credential-assignment" in rules(audit.scan_worktree())


def test_staged_scans_index_even_after_worktree_is_sanitized(repo):
    path, git = repo
    target = path / "config.py"
    target.write_text(assignment("synthetic-staged-value"))
    git("add", "config.py")
    target.write_text("# sanitized working copy\n")
    assert not audit.scan_worktree()
    assert "credential-assignment" in rules(audit.scan_staged())


def test_staged_ignores_unstaged_secret_in_worktree(repo):
    path, git = repo
    target = path / "config.py"
    target.write_text("# clean index\n")
    git("add", "config.py")
    target.write_text(assignment("synthetic-worktree-value"))
    assert "credential-assignment" in rules(audit.scan_worktree())
    assert not audit.scan_staged()


def test_forced_ignored_private_file_is_never_skipped(repo):
    path, git = repo
    (path / ".gitignore").write_text(".local-audit/\n")
    private = path / ".local-audit" / "credentials.txt"
    private.parent.mkdir()
    private.write_text(assignment("synthetic-private-value"))
    assert not audit.scan_worktree()
    git("add", "-f", ".local-audit/credentials.txt")
    for scan in (audit.scan_staged, audit.scan_worktree):
        assert {"private-runtime-file", "credential-assignment"} <= rules(scan())


@pytest.mark.parametrize("relative", [
    "HANDOFF.md", "docs/live-telemetry-deployment.md", "docs/sshd-parser-and-refresh.md",
    "docs/ip-lookup-and-pagination.md", "live.sqlite-wal", "live.sqlite3-shm",
    "live.db-wal", "release.tar.gz", "release.zip",
])
def test_staged_private_data_is_rejected_even_without_credentials(repo, relative):
    path, git = repo
    target = path / relative
    target.parent.mkdir(exist_ok=True)
    target.write_text("Private operational notes")
    git("add", relative)
    assert "private-runtime-file" in rules(audit.scan_staged())


def test_file_size_limit_is_a_failure_and_binary_does_not_hide_token(monkeypatch):
    monkeypatch.setattr(audit, "MAX_FILE_BYTES", 20)
    assert "file-scan-size-limit" in rules(audit.scan_file(b"x" * 21, "large.txt"))
    monkeypatch.setattr(audit, "MAX_FILE_BYTES", 1000)
    token = "ghp_" + "R2d" * 12
    assert "github-token" in rules(audit.scan_file(b"\x00" + token.encode(), "binary.dat"))


def test_removed_secret_is_still_found_in_history(repo):
    path, git = repo
    target = path / "config.py"
    target.write_text(assignment("synthetic-historical-value"))
    git("add", "config.py")
    git("commit", "-m", "Synthetic history fixture", "-q")
    target.write_text("# now clean\n")
    git("add", "config.py")
    git("commit", "-m", "Remove fixture", "-q")
    assert not audit.scan_worktree()
    findings = audit.scan_history()
    assert "credential-assignment" in rules(findings)
    assert "synthetic-historical-value" not in json.dumps(findings)


def test_history_size_limit_is_a_failure(monkeypatch):
    monkeypatch.setattr(audit, "git", lambda args: "x" * 30)
    monkeypatch.setattr(audit, "MAX_HISTORY_BYTES", 20)
    assert audit.scan_history()[0]["severity"] == "HIGH"


def test_metadata_never_copies_name_or_email(monkeypatch):
    name = "Synthetic Private Person"
    email = "operator" + "@private.invalid"
    monkeypatch.setattr(audit, "git", lambda args: "a" * 40 + "\t" + name + "\t" + email)
    report = json.dumps(audit.scan_metadata())
    assert name not in report and email not in report


def test_cli_and_json_never_echo_secret(repo, capsys):
    path, git = repo
    value = "synthetic-cli-secret-value"
    (path / "config.py").write_text(assignment(value))
    git("add", "config.py")
    report = path / "report.json"
    assert audit.main(["--staged", "--fail-on", "high", "--json-output", str(report)]) == 2
    assert value not in capsys.readouterr().out
    assert value not in report.read_text()
    assert all(item["match"] == "[REDACTED]" for item in json.loads(report.read_text()))
