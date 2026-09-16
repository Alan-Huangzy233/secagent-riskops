from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import sqlite3

import pytest

from app.telemetry.store import TelemetryStore


_SPEC = importlib.util.spec_from_file_location(
    "reparse_ssh_telemetry", Path(__file__).parents[2] / "scripts" / "reparse_ssh_telemetry.py"
)
cli = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(cli)


@pytest.fixture
def database(tmp_path):
    database = tmp_path / "live.sqlite"
    store = TelemetryStore(database)
    at = datetime.now(timezone.utc).isoformat()
    rows = [{"event_id": f"cursor-{index}", "timestamp": at,
             "message": f"Connection closed by authenticating user root 198.51.100.2 port {2200 + index} [preauth]",
             "identifier": "sshd", "unit": "ssh.service", "priority": "6"} for index in range(3)]
    store.ingest("source-a", "trusted-host", "batch", rows)
    # Model the old parser's retained records, without modifying their raw hashes.
    with closing(sqlite3.connect(database)) as db:
        db.execute("DELETE FROM incident_evidence")
        for table in ("incident_sources", "incident_rules", "incident_details"):
            db.execute(f"DELETE FROM {table}")
        db.execute("UPDATE events SET incident_id=NULL")
        db.execute("DELETE FROM incidents")
        for event_id, encoded in db.execute("SELECT event_id,record_json FROM events").fetchall():
            value = json.loads(encoded)
            value.update(event_type="other", src_ip=None, ssh_user=None)
            db.execute("UPDATE events SET event_type='other',src_ip=NULL,ssh_user=NULL,record_json=? WHERE event_id=?",
                       (json.dumps(value), event_id))
        db.commit()
    return database


def test_dry_run_does_not_construct_store_or_change_database(database, monkeypatch, capsys):
    before = database.read_bytes()
    original = cli.fingerprint(database)
    monkeypatch.setattr(cli, "TelemetryStore", lambda *_: pytest.fail("dry run constructed a writable store"))
    cli.main(["--database", str(database)])
    output = json.loads(capsys.readouterr().out)
    assert output["mode"] == "dry_run"
    assert output["planned"]["changed_events"] == output["planned"]["newly_detectable"] == 3
    assert cli.fingerprint(database) == original
    assert database.read_bytes() == before
    assert "198.51.100.2" not in json.dumps(output)
    assert "authenticating user" not in json.dumps(output)


def test_apply_keeps_raw_receipts_and_verified_independent_backup(database, tmp_path):
    backup = tmp_path / "manual-parser-recovery.sqlite"
    before = cli.fingerprint(database)
    result = cli.run(database, backup=backup, apply=True)
    assert result["verified"] is True
    assert result["changes"]["changed_events"] == 3
    assert result["changes"]["newly_detectable"] == 3
    assert cli.fingerprint(backup) == before
    with closing(sqlite3.connect(backup)) as db:
        assert db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        assert db.execute("SELECT count(*) FROM events WHERE event_type='other'").fetchone()[0] == 3
    after = cli.fingerprint(database)
    for table in ("events", "batches", "event_receipts"):
        assert after["digests"][table] == before["digests"][table]
    assert after["counts"]["incidents"] == 1
    assert after["counts"]["incident_evidence"] == 3
    assert not list(tmp_path.glob(".*.tmp"))
    if os.name != "nt":
        assert backup.stat().st_mode & 0o777 == 0o600


def test_second_apply_is_idempotent_and_keeps_incident_identity(database, tmp_path):
    cli.run(database, backup=tmp_path / "first.sqlite", apply=True)
    before = cli.fingerprint(database)
    result = cli.run(database, backup=tmp_path / "second.sqlite", apply=True)
    assert result["changes"] == {"changed_events": 0, "changed_evidence": 0, "newly_detectable": 0}
    assert cli.fingerprint(database) == before


@pytest.mark.parametrize("choice", ["existing", "same", "missing", "relative"])
def test_apply_refuses_unsafe_backup_paths(database, tmp_path, choice):
    existing = tmp_path / "exists.sqlite"
    existing.write_bytes(b"must not overwrite")
    backup = {"existing": existing, "same": database, "missing": None, "relative": Path("relative.sqlite")}[choice]
    before = cli.fingerprint(database)
    with pytest.raises(cli.ReparseError):
        cli.run(database, backup=backup, apply=True)
    assert existing.read_bytes() == b"must not overwrite"
    assert cli.fingerprint(database) == before


def test_atomic_backup_publication_refuses_target_created_while_copying(database, tmp_path, monkeypatch):
    target = tmp_path / "race.sqlite"
    real_link = cli.os.link

    def competing_link(source, destination):
        Path(destination).write_bytes(b"concurrent backup")
        return real_link(source, destination)

    monkeypatch.setattr(cli.os, "link", competing_link)
    with pytest.raises(cli.ReparseError, match="already exists"):
        cli.create_backup(database, target)
    assert target.read_bytes() == b"concurrent backup"
    assert not list(tmp_path.glob(".*.tmp"))


def test_failed_migration_retains_backup_without_automatic_restore(database, tmp_path, monkeypatch):
    backup = tmp_path / "keep-on-failure.sqlite"
    before = cli.fingerprint(database)

    def incorrect_migration(self):
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("UPDATE event_receipts SET record_hash='unexpected mutation'")
            db.commit()
        return {"changed_events": 0, "changed_evidence": 0, "newly_detectable": 0}

    monkeypatch.setattr(cli.TelemetryStore, "reparse_sshd", incorrect_migration)
    with pytest.raises(cli.ReparseError, match="immutable records changed"):
        cli.run(database, backup=backup, apply=True)
    assert cli.fingerprint(backup) == before
    assert cli.fingerprint(database) != before


def test_evidence_fingerprint_allows_merge_but_rejects_loss_or_raw_mutation(database, tmp_path):
    cli.run(database, backup=tmp_path / "initial.sqlite", apply=True)
    before = cli.fingerprint(database)
    after = {**before, "evidence": dict(before["evidence"])}
    first = next(iter(after["evidence"]))
    after["evidence"].pop(first)
    with pytest.raises(cli.ReparseError, match="evidence changed or disappeared"):
        cli._validate(before, after)
    after = {**before, "incident_ids": set()}
    with pytest.raises(cli.ReparseError, match="incident identities"):
        cli._validate(before, after)


def test_corrupt_database_does_not_publish_a_backup(tmp_path):
    database, backup = tmp_path / "bad.sqlite", tmp_path / "not-published.sqlite"
    database.write_bytes(b"not a SQLite file" * 100)
    with pytest.raises(sqlite3.DatabaseError):
        cli.create_backup(database, backup)
    assert not backup.exists()
    assert not list(tmp_path.glob(".*.tmp"))
