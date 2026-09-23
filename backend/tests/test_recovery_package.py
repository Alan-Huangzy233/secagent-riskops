"""A recovery package must prove what it holds before anyone restores from it."""
from __future__ import annotations

from contextlib import closing
import grp
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess

import pytest


_SPEC = importlib.util.spec_from_file_location(
    "recovery_package", Path(__file__).parents[2] / "scripts" / "recovery_package.py"
)
recovery = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(recovery)

GPG = shutil.which("gpg")
needs_gpg = pytest.mark.skipif(GPG is None, reason="gpg is not installed")


def write_database(path: Path, rows: int, *, wal: bool = False) -> None:
    with closing(sqlite3.connect(path)) as database:
        if wal:
            database.execute("PRAGMA journal_mode=WAL")
            database.execute("PRAGMA wal_autocheckpoint=0")
        database.execute("CREATE TABLE events (event_id INTEGER PRIMARY KEY, message TEXT NOT NULL)")
        database.executemany("INSERT INTO events (message) VALUES (?)",
                             [(f"event {index}",) for index in range(rows)])
        database.commit()


@pytest.fixture
def deployment(tmp_path: Path) -> dict:
    """A miniature of the production layout: two databases and a cursor directory."""
    live, state, store = tmp_path / "lib", tmp_path / "collector", tmp_path / "store"
    live.mkdir()
    state.mkdir()
    write_database(live / "live.sqlite", 5)
    write_database(live / "control.sqlite", 1)
    (state / "bwh.state.json").write_text(json.dumps({"cursor": "cursor-1"}), encoding="utf-8")
    (state / "collector.lock").write_text("", encoding="utf-8")
    config = tmp_path / "package.json"
    config.write_text(json.dumps({
        "host_id": "test-host",
        "description": "unit test deployment",
        "components": [
            {"name": "telemetry", "kind": "sqlite", "path": str(live / "live.sqlite")},
            {"name": "control", "kind": "sqlite", "path": str(live / "control.sqlite")},
            {"name": "collector", "kind": "state_dir", "path": str(state),
             "patterns": ["*.state.json", "*.pending.json"]},
            {"name": "release", "kind": "reference", "path": str(live)},
        ]}), encoding="utf-8")
    return {"config": config, "store": store, "live": live, "state": state}


def build(deployment: dict, *arguments: str) -> dict:
    assert recovery.main(["build", "--config", str(deployment["config"]),
                          "--output-dir", str(deployment["store"]), *arguments]) == 0
    package = next(path for path in deployment["store"].iterdir() if path.name.startswith("rp-"))
    return {"package": package, "manifest": json.loads((package / "manifest.json").read_text(encoding="utf-8"))}


def verify(package: Path, *arguments: str, expect: int = 0) -> None:
    assert recovery.main(["verify", str(package), *arguments]) == expect


def test_package_round_trip_restores_every_captured_component(deployment, tmp_path, capsys):
    result = build(deployment, "--allow-unencrypted", "--census")
    capsys.readouterr()
    restored = tmp_path / "drill"
    verify(result["package"], "--into", str(restored))
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True and report["extracted_to"] == str(restored)
    assert {item["name"] for item in report["components"]} == {"telemetry", "control", "collector", "release"}
    with closing(sqlite3.connect(restored / "telemetry.sqlite")) as database:
        assert database.execute("SELECT count(*) FROM events").fetchone()[0] == 5
    assert json.loads((restored / "collector" / "bwh.state.json").read_text(encoding="utf-8")) == {"cursor": "cursor-1"}
    # The lock file is the running collector's own state, not a cursor to restore.
    assert not (restored / "collector" / "collector.lock").exists()
    names = {component["name"]: component for component in result["manifest"]["components"]}
    assert names["telemetry"]["table_rows"] == {"events": 5}
    assert names["release"]["points_to"] == str(deployment["live"])
    assert result["manifest"]["encryption"] is None


def test_cursors_are_captured_before_the_snapshots_they_belong_to(deployment, monkeypatch):
    """A cursor ahead of its snapshot loses events; behind it only replays them."""
    original = recovery.snapshot_database

    def ingest_then_snapshot(spec, contents, census):
        if spec["name"] == "telemetry":
            with closing(sqlite3.connect(deployment["live"] / "live.sqlite")) as database:
                database.execute("INSERT INTO events (message) VALUES ('arrived after the cursor')")
                database.commit()
            (deployment["state"] / "bwh.state.json").write_text(json.dumps({"cursor": "cursor-2"}), encoding="utf-8")
        return original(spec, contents, census)

    monkeypatch.setattr(recovery, "snapshot_database", ingest_then_snapshot)
    result = build(deployment, "--allow-unencrypted", "--census")
    restored = deployment["store"] / "unpacked"
    verify(result["package"], "--into", str(restored))
    with closing(sqlite3.connect(restored / "telemetry.sqlite")) as database:
        assert database.execute("SELECT count(*) FROM events").fetchone()[0] == 6
    assert json.loads((restored / "collector" / "bwh.state.json").read_text(encoding="utf-8")) == {"cursor": "cursor-1"}
    consistency = result["manifest"]["consistency"]
    assert consistency["state_captured_at"] <= consistency["snapshots_started_at"]
    assert consistency["collection_paused"] is False


def test_uncommitted_writes_stay_out_of_the_snapshot(deployment):
    database = deployment["live"] / "live.sqlite"
    database.unlink()
    write_database(database, 2, wal=True)
    with closing(sqlite3.connect(database)) as writer:
        writer.execute("INSERT INTO events (message) VALUES ('never committed')")
        result = build(deployment, "--allow-unencrypted", "--census")
        writer.rollback()
    telemetry = next(item for item in result["manifest"]["components"] if item["name"] == "telemetry")
    assert telemetry["table_rows"] == {"events": 2}
    verify(result["package"], "--deep")


def test_plaintext_storage_requires_an_explicit_opt_in(deployment):
    assert recovery.main(["build", "--config", str(deployment["config"]),
                          "--output-dir", str(deployment["store"])]) == 2
    assert not deployment["store"].exists() or not list(deployment["store"].iterdir())


def test_recipients_must_be_full_fingerprints(deployment):
    assert recovery.main(["build", "--config", str(deployment["config"]), "--output-dir",
                          str(deployment["store"]), "--recipient", "backup@example.invalid"]) == 2
    assert not deployment["store"].exists() or not list(deployment["store"].iterdir())


def test_a_failed_build_publishes_nothing_and_keeps_earlier_packages(deployment):
    kept = build(deployment, "--allow-unencrypted")["package"]
    (deployment["live"] / "control.sqlite").write_bytes(b"this is not a database" * 50)
    with pytest.raises(sqlite3.DatabaseError):
        recovery.main(["build", "--config", str(deployment["config"]),
                       "--output-dir", str(deployment["store"]), "--allow-unencrypted"])
    assert [path.name for path in deployment["store"].iterdir()] == [kept.name]
    verify(kept, "--deep")


def test_a_missing_compressor_fails_the_build_without_leaving_scratch_files(deployment):
    assert recovery.main(["--zstd-binary", str(deployment["store"] / "absent-zstd"), "build",
                          "--config", str(deployment["config"]), "--output-dir",
                          str(deployment["store"]), "--allow-unencrypted"]) == 2
    assert list(deployment["store"].iterdir()) == []


def test_a_cursor_that_settles_after_a_retry_is_captured_with_its_final_content(deployment, monkeypatch):
    copyfile, rewritten = shutil.copyfile, []

    def rewrite_once(source, target, **kwargs):
        result = copyfile(source, target, **kwargs)
        if str(source).endswith("bwh.state.json") and not rewritten:
            rewritten.append(True)
            Path(source).write_text(json.dumps({"cursor": "cursor-2"}), encoding="utf-8")
        return result

    monkeypatch.setattr(recovery.shutil, "copyfile", rewrite_once)
    result = build(deployment, "--allow-unencrypted")
    restored = deployment["store"] / "unpacked"
    verify(result["package"], "--into", str(restored))
    assert json.loads((restored / "collector" / "bwh.state.json").read_text(encoding="utf-8")) == {"cursor": "cursor-2"}


def test_state_directories_refuse_entries_that_are_not_regular_files(deployment):
    (deployment["state"] / "dmit1.state.json").symlink_to(deployment["live"] / "live.sqlite")
    assert recovery.main(["build", "--config", str(deployment["config"]),
                          "--output-dir", str(deployment["store"]), "--allow-unencrypted"]) == 2
    assert list(deployment["store"].iterdir()) == []


def test_a_cursor_that_never_settles_fails_instead_of_being_packaged(deployment, monkeypatch):
    copyfile, writes = shutil.copyfile, iter(range(recovery.STABLE_READ_ATTEMPTS + 1))

    def rewrite_after_copy(source, target, **kwargs):
        result = copyfile(source, target, **kwargs)
        if str(source).endswith("bwh.state.json"):
            Path(source).write_text(json.dumps({"cursor": f"cursor-{next(writes)}"}), encoding="utf-8")
        return result

    monkeypatch.setattr(recovery.shutil, "copyfile", rewrite_after_copy)
    assert recovery.main(["build", "--config", str(deployment["config"]),
                          "--output-dir", str(deployment["store"]), "--allow-unencrypted"]) == 2
    assert list(deployment["store"].iterdir()) == []


def test_verify_detects_a_stored_object_that_changed_on_the_node(deployment):
    result = build(deployment, "--allow-unencrypted")
    archive = result["package"] / result["manifest"]["stored_object"]
    archive.write_bytes(archive.read_bytes()[:-8] + b"tampered")
    verify(result["package"], expect=1)


def test_deep_verify_reports_a_component_that_does_not_match_the_manifest(deployment):
    result = build(deployment, "--allow-unencrypted")
    manifest_path = result["package"] / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    telemetry = next(item for item in manifest["components"] if item["name"] == "telemetry")
    telemetry["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    recovery.write_checksums(result["package"], [manifest["stored_object"], "manifest.json"])
    verify(result["package"], "--deep", expect=1)


def test_deep_verify_rejects_a_manifest_that_does_not_belong_to_the_archive(deployment):
    result = build(deployment, "--allow-unencrypted")
    manifest_path = result["package"] / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["inner_manifest_sha256"] = "1" * 64
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    recovery.write_checksums(result["package"], [manifest["stored_object"], "manifest.json"])
    verify(result["package"], "--deep", expect=2)


def test_restore_drills_use_a_fresh_directory(deployment, tmp_path):
    result = build(deployment, "--allow-unencrypted")
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "live.sqlite").write_text("a database someone is using", encoding="utf-8")
    verify(result["package"], "--into", str(occupied), expect=2)
    assert (occupied / "live.sqlite").read_text(encoding="utf-8") == "a database someone is using"


def test_list_reports_what_each_package_costs_on_this_node(deployment, capsys):
    build(deployment, "--allow-unencrypted", "--label", "before the drill")
    capsys.readouterr()
    assert recovery.main(["list", str(deployment["store"])]) == 0
    listing = json.loads(capsys.readouterr().out)
    assert len(listing["packages"]) == 1
    entry = listing["packages"][0]
    assert entry["label"] == "before the drill" and entry["usable"] is True
    assert entry["encrypted"] is False and entry["host_id"] == "test-host"
    assert 0 < entry["stored_bytes"] < entry["captured_bytes"]
    assert listing["stored_bytes_total"] == entry["stored_bytes"]


def test_configuration_errors_name_the_offending_field(tmp_path):
    config = tmp_path / "package.json"
    config.write_text(json.dumps({"host_id": "host", "components": [
        {"name": "telemetry", "kind": "sqlite", "path": "relative/live.sqlite"}]}), encoding="utf-8")
    with pytest.raises(recovery.PackageError, match="absolute path"):
        recovery.load_config(config)
    config.write_text(json.dumps({"host_id": "host", "components": [
        {"name": "collector", "kind": "state_dir", "path": "/var/lib/collector", "patterns": ["../*.json"]}]}),
        encoding="utf-8")
    with pytest.raises(recovery.PackageError, match="patterns select files"):
        recovery.load_config(config)
    config.write_text(json.dumps({"host_id": "host", "components": [
        {"name": "collector", "kind": "state_dir", "path": "/var/lib/collector", "patterns": ["*.json"]}]}),
        encoding="utf-8")
    with pytest.raises(recovery.PackageError, match="at least one sqlite"):
        recovery.load_config(config)
    sqlite_component = {"name": "telemetry", "kind": "sqlite", "path": "/var/lib/live.sqlite"}
    config.write_text(json.dumps({"host_id": "host", "recipients": "A" * 40,
                                  "components": [sqlite_component]}), encoding="utf-8")
    with pytest.raises(recovery.PackageError, match="recipients must be a list"):
        recovery.load_config(config)
    config.write_text(json.dumps({"host_id": "host", "recipients": ["short-key-id"],
                                  "components": [sqlite_component]}), encoding="utf-8")
    with pytest.raises(recovery.PackageError, match="recipient is not a valid identifier"):
        recovery.load_config(config)


@pytest.fixture
def signing_key(tmp_path, monkeypatch):
    home = tmp_path / "gnupg"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("GNUPGHOME", str(home))
    subprocess.run([GPG, "--batch", "--yes", "--quiet", "--passphrase", "", "--quick-gen-key",
                    "riskops-backup@example.invalid", "default", "default", "never"], check=True,
                   capture_output=True)
    listing = subprocess.run([GPG, "--list-keys", "--with-colons", "riskops-backup@example.invalid"],
                             check=True, capture_output=True, text=True).stdout
    yield next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
    # gpg starts an agent per home directory and leaves it running.
    for directory in (home, tmp_path / "no-keys"):
        if directory.is_dir():
            subprocess.run(["gpgconf", "--homedir", str(directory), "--kill", "gpg-agent"], capture_output=True)


@needs_gpg
def test_encrypted_packages_survive_a_signed_round_trip(deployment, signing_key, tmp_path):
    result = build(deployment, "--recipient", signing_key.lower(), "--sign-key", signing_key, "--census")
    manifest = result["manifest"]
    assert manifest["encryption"]["recipients"] == [signing_key]
    assert manifest["stored_object"].endswith(".tar.zst.gpg")
    assert not (result["package"] / manifest["archive"]["name"]).exists()
    with (result["package"] / manifest["stored_object"]).open("rb") as handle:
        assert b"SQLite format 3" not in handle.read()
    restored = tmp_path / "drill"
    verify(result["package"], "--into", str(restored))
    with closing(sqlite3.connect(restored / "telemetry.sqlite")) as database:
        assert database.execute("SELECT count(*) FROM events").fetchone()[0] == 5
    assert not list(result["package"].glob("*.tar.zst"))


@needs_gpg
def test_a_manifest_edited_after_signing_fails_verification(deployment, signing_key):
    result = build(deployment, "--recipient", signing_key, "--sign-key", signing_key)
    manifest_path = result["package"] / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["host_id"] = "somewhere-else"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    recovery.write_checksums(result["package"], [manifest["stored_object"], "manifest.json",
                                                 "manifest.json.asc"])
    verify(result["package"], expect=2)
    verify(result["package"], "--skip-signature", expect=0)


@needs_gpg
def test_deep_verify_without_the_private_key_reports_instead_of_pretending(deployment, signing_key, monkeypatch,
                                                                          tmp_path):
    result = build(deployment, "--recipient", signing_key)
    empty = tmp_path / "no-keys"
    empty.mkdir(mode=0o700)
    monkeypatch.setenv("GNUPGHOME", str(empty))
    verify(result["package"], "--skip-signature", expect=0)
    verify(result["package"], "--deep", "--skip-signature", expect=2)


def build_many(deployment: dict, count: int, *arguments: str) -> list[Path]:
    """Packages in age order, oldest first."""
    for index in range(count):
        assert recovery.main(["build", "--config", str(deployment["config"]), "--output-dir",
                              str(deployment["store"]), *(arguments or ("--allow-unencrypted",)),
                              "--label", f"generation {index}"]) == 0
    packages = [path for path in deployment["store"].iterdir() if path.name.startswith("rp-")]
    return sorted(packages, key=lambda path: json.loads((path / "manifest.json").read_text(encoding="utf-8"))["created_at"])


def confirm(package: Path, peer: str, digest: str | None = None) -> None:
    """Write what backup_export.py writes when a pulling node proves it has a copy."""
    manifest = json.loads((package / "manifest.json").read_text(encoding="utf-8"))
    sealed = manifest["encryption"] or manifest["archive"]
    directory = package / "confirmations"
    directory.mkdir(exist_ok=True)
    (directory / f"{peer}.json").write_text(json.dumps(
        {"peer": peer, "backup_id": manifest["backup_id"], "sha256": digest or sealed["sha256"]}), encoding="utf-8")


def prune(deployment: dict, *arguments: str, capsys=None, expect: int = 0) -> dict:
    assert recovery.main(["prune", str(deployment["store"]), *arguments]) == expect
    return json.loads(capsys.readouterr().out)


def test_prune_never_deletes_a_package_no_independent_copy_protects(deployment, capsys):
    packages = build_many(deployment, 3)
    capsys.readouterr()
    report = prune(deployment, "--keep", "1", "--apply", capsys=capsys)
    assert report["removed"] == [] and report["reclaimed_bytes"] == 0
    assert {item["backup_id"] for item in report["kept"]} == {path.name for path in packages}
    assert all(path.exists() for path in packages)


def test_prune_removes_confirmed_packages_below_the_local_floor(deployment, capsys):
    oldest, middle, newest = build_many(deployment, 3)
    for package in (oldest, middle, newest):
        confirm(package, "nas")
    capsys.readouterr()
    report = prune(deployment, "--keep", "2", "--require-confirmations", "1", "--apply", capsys=capsys)
    assert [item["backup_id"] for item in report["removed"]] == [oldest.name]
    assert report["reclaimed_bytes"] > 0 and report["applied"] is True
    assert not oldest.exists() and middle.exists() and newest.exists()
    # The confirmations the tool wrote go with the package; nothing else is touched.
    assert sorted(path.name for path in deployment["store"].iterdir()) == sorted([middle.name, newest.name])


def test_prune_reports_before_it_is_allowed_to_delete(deployment, capsys):
    oldest, _, _ = build_many(deployment, 3)
    confirm(oldest, "nas")
    capsys.readouterr()
    report = prune(deployment, "--keep", "1", capsys=capsys)
    assert report["applied"] is False
    assert [item["backup_id"] for item in report["removed"]] == [oldest.name]
    assert report["removed"][0]["removed"] is False and oldest.exists()


def test_prune_refuses_to_leave_nothing_behind(deployment, capsys):
    build_many(deployment, 2)
    capsys.readouterr()
    assert recovery.main(["prune", str(deployment["store"]), "--keep", "0", "--apply"]) == 2
    assert len([path for path in deployment["store"].iterdir() if path.name.startswith("rp-")]) == 2


def test_a_confirmation_naming_another_object_protects_nothing(deployment, capsys):
    oldest, _, _ = build_many(deployment, 3)
    confirm(oldest, "nas", digest="9" * 64)
    capsys.readouterr()
    report = prune(deployment, "--keep", "1", "--apply", capsys=capsys)
    assert report["removed"] == [] and oldest.exists()
    assert any("0 of 1" in item["reason"] for item in report["kept"] if item["backup_id"] == oldest.name)


def test_prune_leaves_a_package_that_holds_files_it_does_not_manage(deployment, capsys):
    oldest, _, _ = build_many(deployment, 3)
    confirm(oldest, "nas")
    (oldest / "operator-note.txt").write_text("why this one was kept", encoding="utf-8")
    capsys.readouterr()
    report = prune(deployment, "--keep", "1", "--apply", capsys=capsys)
    assert report["removed"] == [] and (oldest / "operator-note.txt").exists()
    assert any("unmanaged" in item["reason"] for item in report["kept"])


def test_prune_keeps_a_package_whose_manifest_it_cannot_read(deployment, capsys):
    oldest, _, newest = build_many(deployment, 3)
    confirm(oldest, "nas")
    (oldest / "manifest.json").write_text("{not json", encoding="utf-8")
    capsys.readouterr()
    report = prune(deployment, "--keep", "1", "--apply", capsys=capsys)
    assert report["removed"] == [] and oldest.exists()
    assert any(item["backup_id"] == oldest.name and item["kept"] for item in report["kept"])


def test_prune_requires_every_configured_independent_copy(deployment, capsys):
    oldest, _, _ = build_many(deployment, 3)
    confirm(oldest, "nas")
    capsys.readouterr()
    report = prune(deployment, "--keep", "1", "--require-confirmations", "2", "--apply", capsys=capsys)
    assert report["removed"] == [] and oldest.exists()
    confirm(oldest, "offsite")
    report = prune(deployment, "--keep", "1", "--require-confirmations", "2", "--apply", capsys=capsys)
    assert [item["backup_id"] for item in report["removed"]] == [oldest.name]
    assert report["removed"][0]["confirmed_by"] == ["nas", "offsite"] and not oldest.exists()


def test_an_interrupted_confirmation_does_not_block_rotation_forever(deployment, capsys):
    oldest, _, _ = build_many(deployment, 3)
    confirm(oldest, "nas")
    (oldest / "confirmations" / ".nas.abcd.tmp").write_text("half written", encoding="utf-8")
    capsys.readouterr()
    report = prune(deployment, "--keep", "1", "--apply", capsys=capsys)
    assert [item["backup_id"] for item in report["removed"]] == [oldest.name]
    assert not oldest.exists()


def own_group() -> str:
    return grp.getgrgid(os.getgid()).gr_name


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@needs_gpg
def test_a_shared_package_opens_only_what_the_pulling_account_needs(deployment, signing_key):
    result = build(deployment, "--recipient", signing_key, "--share-group", own_group())
    package = result["package"]
    assert mode(package) == 0o750 and package.stat().st_gid == os.getgid()
    published = {path.name: path for path in package.iterdir()}
    assert set(published) == {"manifest.json", "SHA256SUMS", result["manifest"]["stored_object"], "confirmations"}
    for name, path in published.items():
        assert path.stat().st_gid == os.getgid()
        assert mode(path) == (0o770 if name == "confirmations" else 0o640)
    assert list(published["confirmations"].iterdir()) == []
    verify(package, "--deep")


def test_a_shared_package_must_be_encrypted(deployment):
    assert recovery.main(["build", "--config", str(deployment["config"]), "--output-dir", str(deployment["store"]),
                          "--allow-unencrypted", "--share-group", own_group()]) == 2
    assert not deployment["store"].exists() or not list(deployment["store"].iterdir())


def test_an_unknown_share_group_fails_before_anything_is_captured(deployment, monkeypatch):
    def captured(*_arguments):
        raise AssertionError("nothing may be captured for a package nobody can read")

    monkeypatch.setattr(recovery, "capture_state_dir", captured)
    monkeypatch.setattr(recovery, "snapshot_database", captured)
    assert recovery.main(["build", "--config", str(deployment["config"]), "--output-dir", str(deployment["store"]),
                          "--recipient", "A" * 40, "--share-group", "riskops-no-such-group"]) == 2
    assert not deployment["store"].exists() or not list(deployment["store"].iterdir())


@needs_gpg
def test_recipients_come_from_the_configuration_unless_given_on_the_command_line(deployment, signing_key):
    config = json.loads(deployment["config"].read_text(encoding="utf-8"))
    config["recipients"] = [signing_key.lower()]
    deployment["config"].write_text(json.dumps(config), encoding="utf-8")
    assert build(deployment)["manifest"]["encryption"]["recipients"] == [signing_key]
    shutil.rmtree(deployment["store"])
    # A configured key this keyring lacks would fail the build; the command line replaces it.
    config["recipients"] = ["B" * 40]
    deployment["config"].write_text(json.dumps(config), encoding="utf-8")
    assert build(deployment, "--recipient", signing_key)["manifest"]["encryption"]["recipients"] == [signing_key]


@needs_gpg
def test_prune_retires_a_shared_package_together_with_its_confirmations(deployment, signing_key, capsys):
    oldest, newest = build_many(deployment, 2, "--recipient", signing_key, "--share-group", own_group())
    confirm(oldest, "nas")
    capsys.readouterr()
    report = prune(deployment, "--keep", "1", "--apply", capsys=capsys)
    assert [item["backup_id"] for item in report["removed"]] == [oldest.name]
    assert not oldest.exists() and (newest / "confirmations").is_dir()
