from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
from unittest.mock import patch

import pytest

from app.telemetry.store import TelemetryStore


_SCRIPTS = Path(__file__).parents[2] / "scripts"
_SPEC = importlib.util.spec_from_file_location("rebuild_ssh_detections", _SCRIPTS / "rebuild_ssh_detections.py")
cli = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
with patch.object(sys, "path", [str(_SCRIPTS), *sys.path]):
    _SPEC.loader.exec_module(cli)


@pytest.fixture
def database(tmp_path):
    path = tmp_path / "live.sqlite"
    store = TelemetryStore(path)
    at = datetime.now(timezone.utc) - timedelta(hours=1)
    rows = [{"event_id": f"cursor-{index}", "timestamp": (at + timedelta(seconds=index)).isoformat(),
             "message": "Connection closed by authenticating user admin 198.51.100.2 port 2200 [preauth]",
             "identifier": "sshd", "unit": "ssh.service", "priority": "6"} for index in range(3)]
    store.ingest("source-a", "trusted-host", "batch", rows)
    return path


@pytest.fixture
def unchanged_rebuild(monkeypatch):
    def rebuild(self):
        with closing(sqlite3.connect(self.path)) as db:
            count = db.execute("SELECT count(*) FROM events").fetchone()[0]
        return {"events_evaluated": count, "incidents_created": 0, "incidents_merged": 0, "evidence_added": 0}

    monkeypatch.setattr(cli.TelemetryStore, "rebuild_detections", rebuild, raising=False)


@pytest.mark.parametrize("explicit", [False, True])
def test_dry_run_only_initializes_temporary_copy(database, monkeypatch, capsys, unchanged_rebuild, explicit):
    before_bytes = database.read_bytes()
    before_mtime = database.stat().st_mtime_ns
    before = cli._fingerprint(database)
    real_store = cli.TelemetryStore
    opened = []

    def copy_store(path):
        path = Path(path)
        assert path.resolve() != database.resolve()
        opened.append(path)
        store = real_store(path)
        with closing(sqlite3.connect(path)) as db:
            db.execute("CREATE TABLE preview_only_schema (value TEXT)")
            db.commit()
        return store

    monkeypatch.setattr(cli, "TelemetryStore", copy_store)
    cli.main(["--database", str(database), *(["--dry-run"] if explicit else [])])
    output = json.loads(capsys.readouterr().out)
    assert output["mode"] == "dry_run" and output["verified"] is True
    assert output["planned"]["events_evaluated"] == 3
    assert "backup" not in output and "database" not in output
    assert all(secret not in json.dumps(output) for secret in ("198.51.100.2", "admin", "cursor-", "trusted-host"))
    assert opened and all(not path.exists() for path in opened)
    assert cli._fingerprint(database) == before
    assert database.read_bytes() == before_bytes
    assert database.stat().st_mtime_ns == before_mtime
    with closing(sqlite3.connect(database)) as db:
        assert not db.execute("SELECT name FROM sqlite_master WHERE name='preview_only_schema'").fetchall()


def test_apply_makes_verified_unique_snapshots_before_writable_store(database, tmp_path, monkeypatch, unchanged_rebuild):
    directory = tmp_path / "recovery"
    directory.mkdir()
    before = cli._fingerprint(database)
    real_store = cli.TelemetryStore
    snapshots = []

    def checked_store(path):
        assert Path(path) == database
        files = list(directory.glob("ssh-detections-recovery-*.sqlite"))
        assert len(files) == len(snapshots) + 1
        snapshot = next(item for item in files if item not in snapshots)
        assert cli._fingerprint(snapshot) == before
        snapshots.append(snapshot)
        return real_store(path)

    monkeypatch.setattr(cli, "TelemetryStore", checked_store)
    for _ in range(2):
        result = cli.run(database, backup_directory=directory, apply=True)
        assert result["verified"] is True and result["mode"] == "apply"
        assert result["changes"]["events_evaluated"] == 3
        assert Path(result["backup"]) == snapshots[-1]
        assert result["before"] == result["after"]
    assert len(snapshots) == 2 and snapshots[0] != snapshots[1]
    assert cli._fingerprint(database) == before
    assert not list(directory.glob(".*.tmp"))
    if os.name != "nt":
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in snapshots)


@pytest.mark.parametrize("choice", ["missing", "relative", "absent", "file"])
def test_apply_requires_existing_absolute_backup_directory(database, tmp_path, monkeypatch, choice):
    directories = {"missing": None, "relative": Path("recovery"),
                   "absent": tmp_path / "missing", "file": database}
    before = database.read_bytes()
    monkeypatch.setattr(cli, "TelemetryStore", lambda *_: pytest.fail("writable store opened before validation"))
    with pytest.raises(cli.ReparseError, match="backup"):
        cli.run(database, backup_directory=directories[choice], apply=True)
    assert database.read_bytes() == before


@pytest.mark.parametrize("choice", ["relative", "missing", "directory"])
def test_invalid_database_path_cannot_initialize_store(tmp_path, monkeypatch, choice):
    paths = {"relative": Path("live.sqlite"), "missing": tmp_path / "missing.sqlite", "directory": tmp_path}
    monkeypatch.setattr(cli, "TelemetryStore", lambda *_: pytest.fail("initialized an invalid database"))
    with pytest.raises(cli.ReparseError, match="database must"):
        cli.run(paths[choice])


@pytest.mark.parametrize("mutation", ["raw_event", "event_enrichment", "receipt", "batch",
                                      "raw_evidence", "evidence_enrichment", "incident_identity"])
def test_apply_rejects_record_changes_and_preserves_recovery(database, tmp_path, monkeypatch, mutation):
    before = cli._fingerprint(database)
    directory = tmp_path / "recovery"
    directory.mkdir()

    def incorrect(self):
        with closing(sqlite3.connect(self.path)) as db:
            if mutation in {"raw_event", "event_enrichment"}:
                for key, encoded in db.execute("SELECT event_id,record_json FROM events").fetchall():
                    row = json.loads(encoded)
                    row["message" if mutation == "raw_event" else "event_type"] = "changed"
                    db.execute("UPDATE events SET record_json=? WHERE event_id=?", (json.dumps(row), key))
            elif mutation in {"raw_evidence", "evidence_enrichment"}:
                for key, encoded in db.execute("SELECT event_id,snapshot_json FROM incident_evidence").fetchall():
                    row = json.loads(encoded)
                    row["message" if mutation == "raw_evidence" else "event_type"] = "changed"
                    db.execute("UPDATE incident_evidence SET snapshot_json=? WHERE event_id=?", (json.dumps(row), key))
            elif mutation == "receipt":
                db.execute("UPDATE event_receipts SET record_hash='changed'")
            elif mutation == "batch":
                db.execute("UPDATE batches SET response_json='changed'")
            else:
                db.execute("DELETE FROM incidents")
            db.commit()
        return {"events_evaluated": 3, "incidents_created": 0, "incidents_merged": 0, "evidence_added": 0}

    monkeypatch.setattr(cli.TelemetryStore, "rebuild_detections", incorrect, raising=False)
    with pytest.raises(cli.ReparseError):
        cli.run(database, backup_directory=directory, apply=True)
    [backup] = directory.glob("*.sqlite")
    assert cli._fingerprint(backup) == before
    assert cli._fingerprint(database) != before


def test_failed_dry_run_leaves_original_and_cleans_copy(database, monkeypatch):
    before = cli._fingerprint(database)
    copies = []

    def broken(self):
        copies.append(Path(self.path))
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("DELETE FROM event_receipts")
            db.commit()
        return {"events_evaluated": 3, "incidents_created": 0, "incidents_merged": 0, "evidence_added": 0}

    monkeypatch.setattr(cli.TelemetryStore, "rebuild_detections", broken, raising=False)
    with pytest.raises(cli.ReparseError, match="immutable records"):
        cli.run(database)
    assert cli._fingerprint(database) == before
    assert copies and all(not path.exists() for path in copies)


def test_preview_cleanup_retries_transient_file_lock(database, monkeypatch, unchanged_rebuild):
    cleanup = cli.tempfile.TemporaryDirectory.cleanup
    attempts = []

    def locked_once(self):
        attempts.append(Path(self.name))
        if len(attempts) == 1:
            raise OSError("temporary sidecar lock")
        return cleanup(self)

    monkeypatch.setattr(cli.tempfile.TemporaryDirectory, "cleanup", locked_once)
    result = cli.run(database)
    assert result["verified"] and len(attempts) == 2
    assert attempts[0] == attempts[1] and not attempts[0].exists()


@pytest.mark.parametrize("changes", [{}, {"events_evaluated": "private text"},
                                    {"events_evaluated": True, "incidents_created": 0,
                                     "incidents_merged": 0, "evidence_added": 0}])
def test_rebuild_summary_cannot_leak_arbitrary_values(database, monkeypatch, capsys, changes):
    monkeypatch.setattr(cli.TelemetryStore, "rebuild_detections", lambda _: changes, raising=False)
    with pytest.raises(SystemExit, match="invalid summary") as error:
        cli.main(["--database", str(database)])
    assert "private text" not in str(error.value)
    assert capsys.readouterr().out == ""


def test_unexpected_failure_has_no_private_exception_text(database, monkeypatch, capsys):
    def broken(*args, **kwargs):
        raise RuntimeError("private log payload from 198.51.100.2")

    monkeypatch.setattr(cli, "run", broken)
    with pytest.raises(SystemExit, match="detection rebuild failed") as error:
        cli.main(["--database", str(database)])
    assert "198.51.100.2" not in str(error.value)
    assert "private log" not in str(error.value)
    assert capsys.readouterr().out == ""


def test_modes_are_mutually_exclusive(database, capsys):
    with pytest.raises(SystemExit) as error:
        cli.main(["--database", str(database), "--dry-run", "--apply"])
    assert error.value.code == 2
    assert "not allowed" in capsys.readouterr().err


@pytest.mark.parametrize("pattern", ["slow_scan", "cross_source"])
def test_real_historical_rebuild_matches_preview_and_is_idempotent(tmp_path, monkeypatch, pattern):
    path = tmp_path / "historical.sqlite"
    recovery = tmp_path / "recovery"
    recovery.mkdir()
    at = datetime.now(timezone.utc) - timedelta(hours=3)
    store = TelemetryStore(path)
    # Model already retained rows from the previous detector, whose only rule
    # was three failures on one source within five minutes.
    with monkeypatch.context() as context:
        context.setattr(TelemetryStore, "_detect_advanced", lambda *args: set())
        if pattern == "slow_scan":
            sources, count = ["source-a"], 24
        else:
            sources, count = ["source-a", "source-b", "source-c"], 2
        for source in sources:
            rows = [{"event_id": f"event-{index}",
                     "timestamp": (at + timedelta(seconds=index * 5700 / 23)).isoformat(),
                     "message": f"Connection closed by authenticating user user{index % 6} 198.51.100.2 port 2200 [preauth]",
                     "identifier": "sshd", "unit": "ssh.service", "priority": "6"} for index in range(count)]
            store.ingest(source, source, "historical", rows)
    assert store.list_incidents() == []
    before = cli._fingerprint(path)
    preview = cli.run(path)
    assert preview["planned"]["events_evaluated"] == len(sources) * count
    assert preview["planned"]["incidents_created"] == 1
    assert preview["planned"]["evidence_added"] == len(sources) * count
    assert cli._fingerprint(path) == before
    applied = cli.run(path, backup_directory=recovery, apply=True)
    assert applied["changes"] == preview["planned"]
    assert cli._fingerprint(Path(applied["backup"])) == before
    cli._validate_rebuild(before, cli._fingerprint(path))
    assert len(store.list_incidents()) == 1
    after = cli._fingerprint(path)
    again = cli.run(path, backup_directory=recovery, apply=True)
    assert again["changes"] == {"events_evaluated": len(sources) * count,
                                "incidents_created": 0, "incidents_merged": 0, "evidence_added": 0}
    assert cli._fingerprint(path) == after


def test_invalid_incident_references_stop_before_backup(database, tmp_path, monkeypatch):
    with closing(sqlite3.connect(database)) as db:
        db.execute("UPDATE events SET incident_id='missing-incident'")
        db.commit()
    monkeypatch.setattr(cli, "create_backup", lambda *_: pytest.fail("backup should not start for broken references"))
    with pytest.raises(cli.ReparseError, match="invalid incident references"):
        cli.run(database, backup_directory=tmp_path, apply=True)


def test_corrupt_database_error_is_redacted_and_no_backup_is_created(tmp_path, capsys):
    path = tmp_path / "bad.sqlite"
    path.write_bytes(b"private source log, not a SQLite file")
    recovery = tmp_path / "recovery"
    recovery.mkdir()
    with pytest.raises(SystemExit, match="detection rebuild failed") as error:
        cli.main(["--database", str(path), "--apply", "--backup-directory", str(recovery)])
    assert "private source" not in str(error.value)
    assert list(recovery.iterdir()) == []
    assert capsys.readouterr().out == ""
