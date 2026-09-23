from __future__ import annotations

from contextlib import closing
import importlib.util
from pathlib import Path
import sqlite3
import sys

import pytest


_SPEC = importlib.util.spec_from_file_location(
    "backup_telemetry", Path(__file__).parents[2] / "scripts" / "backup_telemetry.py"
)
backup = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(backup)


def invoke(monkeypatch, database, directory):
    monkeypatch.setattr(sys, "argv", ["backup", "--database", str(database), "--directory", str(directory)])
    backup.main()


def test_backup_reads_committed_wal_and_excludes_uncommitted_data(tmp_path, monkeypatch):
    database, directory = tmp_path / "live.sqlite", tmp_path / "backups"
    with closing(sqlite3.connect(database)) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("CREATE TABLE events (message TEXT NOT NULL)")
        writer.execute("INSERT INTO events VALUES ('committed in WAL')")
        writer.commit()
        assert Path(str(database) + "-wal").stat().st_size > 0
        writer.execute("INSERT INTO events VALUES ('not committed')")
        invoke(monkeypatch, database, directory)
        with closing(sqlite3.connect(next(directory.glob('live-*.sqlite')))) as restored:
            assert restored.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            assert restored.execute("SELECT message FROM events").fetchall() == [("committed in WAL",)]
        writer.rollback()
    assert not list(directory.glob(".*.tmp"))


def test_corrupt_source_preserves_old_backup_and_removes_partial_copy(tmp_path, monkeypatch):
    database, directory = tmp_path / "live.sqlite", tmp_path / "backups"
    database.write_bytes(b"not a SQLite database" * 100)
    directory.mkdir()
    old = directory / "live-20260101T000000000000.sqlite"
    old.write_bytes(b"existing backup must remain")
    with pytest.raises(sqlite3.DatabaseError):
        invoke(monkeypatch, database, directory)
    assert old.read_bytes() == b"existing backup must remain"
    assert list(directory.iterdir()) == [old]


def test_retention_keeps_seven_valid_snapshots_and_unrelated_files(tmp_path, monkeypatch):
    database, directory = tmp_path / "live.sqlite", tmp_path / "backups"
    with closing(sqlite3.connect(database)) as writer:
        writer.execute("CREATE TABLE events (message TEXT)")
    directory.mkdir()
    unrelated = directory / "manual-recovery.sqlite"
    unrelated.write_bytes(b"keep")
    for _ in range(9):
        invoke(monkeypatch, database, directory)
    snapshots = list(directory.glob("live-*.sqlite"))
    assert len(snapshots) == 7
    for path in snapshots:
        with closing(sqlite3.connect(path)) as restored:
            assert restored.execute("SELECT count(*) FROM events").fetchone()[0] == 0
    assert unrelated.read_bytes() == b"keep"


def test_rotation_removes_the_sidecars_of_backups_it_deleted(tmp_path, monkeypatch):
    database, directory = tmp_path / "live.sqlite", tmp_path / "backups"
    with closing(sqlite3.connect(database)) as writer:
        writer.execute("CREATE TABLE events (message TEXT)")
    directory.mkdir()
    orphan = directory / "live-20260101T000000000000.sqlite-shm"
    orphan.write_bytes(b"\0" * 32768)
    (directory / "live-20260101T000000000000.sqlite-wal").write_bytes(b"")
    for _ in range(8):
        invoke(monkeypatch, database, directory)
    assert not orphan.exists() and not list(directory.glob("*-wal"))
    # Sidecars appear when something reads a backup; the oldest copy is the one
    # the next run rotates out, the newest stays in the retention set.
    oldest, newest = sorted(directory.glob("live-*.sqlite"))[0], sorted(directory.glob("live-*.sqlite"))[-1]
    for path in (oldest, newest):
        (directory / f"{path.name}-shm").write_bytes(b"\0" * 32768)
    invoke(monkeypatch, database, directory)
    assert not oldest.exists() and not (directory / f"{oldest.name}-shm").exists()
    assert newest.exists() and (directory / f"{newest.name}-shm").exists()


def test_missing_source_fails_without_creating_a_backup(tmp_path, monkeypatch):
    directory = tmp_path / 'backups'
    with pytest.raises(SystemExit, match='database does not exist'):
        invoke(monkeypatch, tmp_path / 'missing.sqlite', directory)
    assert not directory.exists()
