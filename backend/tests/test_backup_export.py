"""A pulling backup node may read finished packages and confirm copies, nothing else."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[2] / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


export = _load("backup_export")
recovery = _load("recovery_package")


@pytest.fixture
def store(tmp_path, monkeypatch) -> Path:
    """Three finished packages plus the noise a real directory collects."""
    # The production check refuses a store under a world-writable parent, which
    # every temporary directory has; it is exercised on its own below.
    monkeypatch.setattr(export, "secure_directory", lambda path: path)
    live, state, directory = tmp_path / "lib", tmp_path / "collector", tmp_path / "store"
    live.mkdir()
    state.mkdir()
    import sqlite3
    from contextlib import closing
    with closing(sqlite3.connect(live / "live.sqlite")) as database:
        database.execute("CREATE TABLE events (message TEXT)")
        database.execute("INSERT INTO events VALUES ('one')")
        database.commit()
    (state / "bwh.state.json").write_text(json.dumps({"cursor": "c1"}), encoding="utf-8")
    config = tmp_path / "package.json"
    config.write_text(json.dumps({"host_id": "test-host", "components": [
        {"name": "collector", "kind": "state_dir", "path": str(state), "patterns": ["*.state.json"]},
        {"name": "telemetry", "kind": "sqlite", "path": str(live / "live.sqlite")}]}), encoding="utf-8")
    for index in range(3):
        assert recovery.main(["build", "--config", str(config), "--output-dir", str(directory),
                              "--allow-unencrypted", "--label", f"package {index}"]) == 0
    (directory / ".incoming-rp-20260101T000000Z-deadbeef").mkdir()
    (directory / "notes.txt").write_text("not a package", encoding="utf-8")
    return directory


def run(store: Path, request: str | None, peer: str = "nas") -> int:
    arguments = ["--store", str(store), "--peer", peer]
    if request is not None:
        arguments += ["--request", request]
    return export.main(arguments)


def listing(store: Path, capture, peer: str = "nas") -> dict:
    assert run(store, "list", peer=peer) == 0
    return json.loads(capture.readouterr().out.decode("utf-8"))


def package_of(store: Path, capture, index: int = 0) -> dict:
    return listing(store, capture)["packages"][index]


def test_list_shows_finished_packages_and_ignores_everything_else(store, capfdbinary):
    result = listing(store, capfdbinary)
    assert result["peer"] == "nas" and len(result["packages"]) == 3
    entry = result["packages"][0]
    assert entry["backup_id"].startswith("rp-") and entry["encrypted"] is False
    assert entry["files"] == ["manifest.json", "SHA256SUMS", entry["stored_object"]]
    assert entry["stored_bytes"] > 0 and len(entry["sha256"]) == 64
    assert entry["confirmed_by_you"] is False


def test_fetch_returns_exactly_the_published_bytes(store, capfdbinary):
    entry = package_of(store, capfdbinary)
    for name in entry["files"]:
        assert run(store, f"fetch {entry['backup_id']} {name}") == 0
        assert capfdbinary.readouterr().out == (store / entry["backup_id"] / name).read_bytes()
    # The compressed object is binary and is the whole point of the transfer.
    stored = (store / entry["backup_id"] / entry["stored_object"]).read_bytes()
    assert stored.startswith(b"\x28\xb5\x2f\xfd") and len(stored) == entry["stored_bytes"]


@pytest.mark.parametrize("request_text", [
    "fetch {id} ../../../etc/passwd",
    "fetch {id} /etc/passwd",
    "fetch {id} confirmations/nas.json",
    "fetch {id} SHA256SUMS.tmp",
    "fetch ../{id} manifest.json",
    "fetch rp-20990101T000000Z-aaaaaaaa manifest.json",
    "fetch {id}",
    "list extra",
    "ack {id} not-a-digest",
    "bash -i",
    "",
])
def test_requests_outside_the_contract_are_refused(store, capfdbinary, request_text):
    entry = package_of(store, capfdbinary)
    assert run(store, request_text.format(id=entry["backup_id"])) == 2
    output = capfdbinary.readouterr()
    assert output.err.startswith(b"backup_export:") and output.out == b""


def test_a_key_without_a_command_gets_no_shell(store, capfdbinary, monkeypatch):
    monkeypatch.delenv("SSH_ORIGINAL_COMMAND", raising=False)
    assert run(store, None) == 2
    assert b"fixed command" in capfdbinary.readouterr().err


def test_the_request_comes_from_the_client_command_sshd_passed_in(store, capfdbinary, monkeypatch):
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", "list")
    assert run(store, None) == 0
    assert len(json.loads(capfdbinary.readouterr().out.decode("utf-8"))["packages"]) == 3


def test_an_oversized_request_is_refused_before_anything_is_read(store, capfdbinary):
    assert run(store, "fetch " + "a" * export.MAX_COMMAND_BYTES) == 2
    assert b"too long" in capfdbinary.readouterr().err


def test_confirmation_needs_the_digest_that_was_published(store, capfdbinary):
    entry = package_of(store, capfdbinary)
    assert run(store, f"ack {entry['backup_id']} {'0' * 64}") == 2
    assert b"does not match" in capfdbinary.readouterr().err
    assert not (store / entry["backup_id"] / "confirmations").exists()
    assert run(store, f"ack {entry['backup_id']} {entry['sha256']}") == 0
    record = json.loads(capfdbinary.readouterr().out.decode("utf-8"))["confirmed"]
    assert record["peer"] == "nas" and record["sha256"] == entry["sha256"]
    written = json.loads((store / entry["backup_id"] / "confirmations" / "nas.json").read_text(encoding="utf-8"))
    assert written == record
    assert package_of(store, capfdbinary)["confirmed_by_you"] is True


def test_a_peer_can_only_write_its_own_confirmation(store, capfdbinary):
    entry = package_of(store, capfdbinary)
    for peer in ("nas", "offsite", "nas"):
        assert run(store, f"ack {entry['backup_id']} {entry['sha256']}", peer=peer) == 0
        capfdbinary.readouterr()
    directory = store / entry["backup_id"] / "confirmations"
    assert sorted(path.name for path in directory.iterdir()) == ["nas.json", "offsite.json"]
    assert listing(store, capfdbinary, peer="offsite")["packages"][0]["confirmed_by_you"] is True
    assert not list(directory.glob(".*"))


def test_a_peer_name_the_administrator_did_not_set_is_refused(store, capfdbinary):
    assert run(store, "list", peer="../root") == 2
    assert b"invalid peer name" in capfdbinary.readouterr().err


def test_a_symlinked_package_is_not_served(store, capfdbinary):
    entry = package_of(store, capfdbinary)
    impostor = store / "rp-20260101T000000Z-aaaaaaaa"
    impostor.symlink_to(store / entry["backup_id"], target_is_directory=True)
    assert run(store, f"fetch {impostor.name} manifest.json") == 2
    assert b"unknown backup" in capfdbinary.readouterr().err
    assert len(listing(store, capfdbinary)["packages"]) == 3


def test_a_package_this_account_cannot_read_does_not_hide_the_others(store, capfdbinary, monkeypatch):
    unreadable, *readable = sorted(path.name for path in store.iterdir() if path.name.startswith("rp-"))
    original = export.read_manifest

    def denied(package):
        if package.name == unreadable:
            raise PermissionError(13, "Permission denied")
        return original(package)

    monkeypatch.setattr(export, "read_manifest", denied)
    assert [entry["backup_id"] for entry in listing(store, capfdbinary)["packages"]] == readable


def test_a_confirmation_lands_in_the_directory_the_build_prepared(store, capfdbinary):
    entry = package_of(store, capfdbinary)
    prepared = store / entry["backup_id"] / "confirmations"
    prepared.mkdir(mode=0o770)
    assert run(store, f"ack {entry['backup_id']} {entry['sha256']}") == 0
    capfdbinary.readouterr()
    assert json.loads((prepared / "nas.json").read_text(encoding="utf-8"))["sha256"] == entry["sha256"]
    assert package_of(store, capfdbinary)["confirmed_by_you"] is True


@pytest.mark.skipif(os.geteuid() != 0, reason="handing a directory to another user needs root")
def test_the_store_check_refuses_a_directory_another_account_owns(tmp_path):
    foreign = tmp_path / "store"
    foreign.mkdir(mode=0o755)
    os.chown(foreign, 65534, -1)
    with pytest.raises(export.ExportError, match="unsafe"):
        export.secure_directory(foreign)


def test_the_store_check_refuses_directories_anyone_could_swap(tmp_path):
    with pytest.raises(export.ExportError, match="absolute"):
        export.secure_directory(Path("relative/store"))
    safe = tmp_path / "store"
    safe.mkdir(mode=0o700)
    # /tmp is world-writable but sticky, so a directory under it that belongs to
    # root or to the account running the export cannot be renamed away by
    # anybody else.
    assert export.secure_directory(safe) == safe
    link = tmp_path / "link"
    link.symlink_to(safe, target_is_directory=True)
    with pytest.raises(export.ExportError, match="unsafe"):
        export.secure_directory(link)
    os.chmod(safe, 0o777)
    with pytest.raises(export.ExportError, match="unsafe"):
        export.secure_directory(safe)
    os.chmod(safe, 0o700)
    loose = tmp_path / "loose"
    loose.mkdir()
    os.chmod(loose, 0o777)  # mkdir honours the umask; this is the permission under test
    nested = loose / "store"
    nested.mkdir(mode=0o700)
    with pytest.raises(export.ExportError, match="unsafe"):
        export.secure_directory(nested)
