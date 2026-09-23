"""The pulling node verifies a package before it publishes or confirms it."""
from __future__ import annotations

from contextlib import closing
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys

import pytest

SCRIPTS = Path(__file__).parents[2] / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


puller = _load("pull_recovery_packages")
recovery = _load("recovery_package")

FAKE_SSH = '''#!/usr/bin/env python3
"""Stands in for ssh: sshd hands the last argument to the forced command."""
import importlib.util, os, sys

request = sys.argv[-1]
reply = os.environ.get("FAKE_SSH_LIST_REPLY")
if request == "list" and reply:
    sys.stdout.write(reply)
    raise SystemExit(0)
broken = os.environ.get("FAKE_SSH_FAIL_FETCH")
if broken and request.startswith("fetch ") and broken in request:
    sys.stderr.write("backup_export: the connection dropped\\n")
    raise SystemExit(255)
spec = importlib.util.spec_from_file_location("backup_export", os.environ["FAKE_SSH_HELPER"])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
raise SystemExit(module.main(["--store", os.environ["FAKE_SSH_STORE"], "--peer", "nas",
                              "--request", request]))
'''


@pytest.fixture
def control(tmp_path, monkeypatch) -> dict:
    """A control node holding two finished packages, reachable through a fake ssh."""
    live, state, store = tmp_path / "lib", tmp_path / "collector", tmp_path / "store"
    live.mkdir()
    state.mkdir()
    with closing(sqlite3.connect(live / "live.sqlite")) as database:
        database.execute("CREATE TABLE events (message TEXT)")
        database.execute("INSERT INTO events VALUES ('one')")
        database.commit()
    (state / "bwh.state.json").write_text(json.dumps({"cursor": "c1"}), encoding="utf-8")
    config = tmp_path / "package.json"
    config.write_text(json.dumps({"host_id": "test-host", "components": [
        {"name": "collector", "kind": "state_dir", "path": str(state), "patterns": ["*.state.json"]},
        {"name": "telemetry", "kind": "sqlite", "path": str(live / "live.sqlite")}]}), encoding="utf-8")
    for index in range(2):
        assert recovery.main(["build", "--config", str(config), "--output-dir", str(store),
                              "--allow-unencrypted", "--label", f"generation {index}"]) == 0
    ssh = tmp_path / "fake-ssh"
    ssh.write_text(FAKE_SSH, encoding="utf-8")
    ssh.chmod(0o700)
    monkeypatch.setenv("FAKE_SSH_STORE", str(store))
    monkeypatch.setenv("FAKE_SSH_HELPER", str(SCRIPTS / "backup_export.py"))
    packages = sorted(path for path in store.iterdir() if path.name.startswith("rp-"))
    return {"store": store, "ssh": ssh, "destination": tmp_path / "node", "packages": packages}


def pull(control: dict, *arguments: str, capsys, expect: int = 0) -> dict:
    code = puller.main(["--target", "backup@control", "--destination", str(control["destination"]),
                        "--ssh", str(control["ssh"]), *arguments])
    report = json.loads(capsys.readouterr().out)
    assert code == expect, report
    return report


def confirmations(package: Path) -> list[str]:
    directory = package / "confirmations"
    return sorted(path.stem for path in directory.iterdir()) if directory.is_dir() else []


def test_a_node_pulls_verifies_and_confirms_every_package(control, capsys):
    report = pull(control, capsys=capsys)
    assert report["ok"] is True and len(report["pulled"]) == 2 and report["failed"] == []
    for package in control["packages"]:
        copy = control["destination"] / package.name
        for name in ("manifest.json", "SHA256SUMS"):
            assert (copy / name).read_bytes() == (package / name).read_bytes()
        stored = json.loads((package / "manifest.json").read_text(encoding="utf-8"))["stored_object"]
        assert (copy / stored).read_bytes() == (package / stored).read_bytes()
        assert confirmations(package) == ["nas"]


def test_a_second_run_keeps_what_the_node_already_holds(control, capsys):
    pull(control, capsys=capsys)
    before = {path: path.stat().st_mtime_ns for path in control["destination"].rglob("*") if path.is_file()}
    report = pull(control, capsys=capsys)
    assert report["pulled"] == [] and sorted(report["skipped"]) == [path.name for path in control["packages"]]
    after = {path: path.stat().st_mtime_ns for path in control["destination"].rglob("*") if path.is_file()}
    assert before == after


def test_an_object_that_does_not_match_its_checksums_is_never_published(control, capsys):
    package = control["packages"][0]
    stored = json.loads((package / "manifest.json").read_text(encoding="utf-8"))["stored_object"]
    (package / stored).write_bytes((package / stored).read_bytes() + b"tampered")
    report = pull(control, "--keep-going", capsys=capsys, expect=1)
    assert [item["backup_id"] for item in report["failed"]] == [package.name]
    assert "SHA256SUMS" in report["failed"][0]["problem"]
    assert not (control["destination"] / package.name).exists()
    assert not list(control["destination"].glob(".*partial"))
    assert confirmations(package) == []
    # The healthy package in the same run still arrives.
    assert [item["backup_id"] for item in report["pulled"]] == [control["packages"][1].name]


def test_a_listing_that_names_a_path_is_refused_before_anything_is_written(control, capsys, monkeypatch):
    monkeypatch.setenv("FAKE_SSH_LIST_REPLY", json.dumps({"peer": "nas", "packages": [
        {"backup_id": "../../escape", "stored_object": "x.tar.zst", "files": ["x.tar.zst"],
         "sha256": "0" * 64}]}))
    report = pull(control, capsys=capsys, expect=1)
    assert "unusable backup id" in report["error"]
    assert not control["destination"].exists() or list(control["destination"].iterdir()) == []


def test_a_listing_offering_a_file_name_with_a_path_is_refused(control, capsys, monkeypatch):
    monkeypatch.setenv("FAKE_SSH_LIST_REPLY", json.dumps({"peer": "nas", "packages": [
        {"backup_id": "rp-20260101T000000Z-abcdef12", "stored_object": "../../etc/passwd",
         "files": ["../../etc/passwd"], "sha256": "0" * 64}]}))
    report = pull(control, capsys=capsys, expect=1)
    assert "unusable object name" in report["error"]


def test_no_confirm_pulls_without_telling_the_control_node(control, capsys):
    report = pull(control, "--no-confirm", capsys=capsys)
    assert len(report["pulled"]) == 2
    assert all("confirmed" not in item for item in report["pulled"])
    assert all(confirmations(package) == [] for package in control["packages"])


def test_a_transfer_that_fails_stops_the_run_unless_told_to_continue(control, capsys, monkeypatch):
    monkeypatch.setenv("FAKE_SSH_FAIL_FETCH", control["packages"][0].name)
    report = pull(control, capsys=capsys, expect=1)
    assert report["pulled"] == [] and len(report["failed"]) == 1
    assert "error" in report
    report = pull(control, "--keep-going", capsys=capsys, expect=1)
    assert [item["backup_id"] for item in report["pulled"]] == [control["packages"][1].name]
    assert [item["backup_id"] for item in report["failed"]] == [control["packages"][0].name]
    assert confirmations(control["packages"][0]) == []
    assert confirmations(control["packages"][1]) == ["nas"]
