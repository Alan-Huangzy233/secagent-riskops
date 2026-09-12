#!/usr/bin/env python3
"""Preview or apply SSH enrichment to a retained telemetry database.

Stop the API and collector before --apply and keep them stopped until this
command finishes. The backup is an independent recovery snapshot and is never
subject to the scheduled backup helper's retention policy. Dry runs use only
read-only SQLite connections and do not instantiate TelemetryStore.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from typing import Any

from app.telemetry.store import FAILURE_KINDS, TelemetryStore, _FAILURE_TYPES, _classify


_DERIVED = frozenset({"event_type", "src_ip", "ssh_user", "event_kind", "peer_ip", "username"})


class ReparseError(RuntimeError):
    """A fixed operator-facing message that contains no log content."""


def _encode(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_encode(value)).hexdigest()


def _raw(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in snapshot.items() if key not in _DERIVED}


def _read(database: Path) -> sqlite3.Connection:
    db = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA query_only=ON")
    db.execute("BEGIN")
    return db


def fingerprint(database: Path) -> dict[str, Any]:
    """Fingerprint immutable values; retain only hashes and identity sets."""
    result: dict[str, Any] = {"counts": {}, "digests": {}}
    with closing(_read(database)) as db:
        for table, ordering in (("events", "source_id,event_id"),
                                ("event_receipts", "source_id,event_id"),
                                ("batches", "source_id,batch_id")):
            digest = hashlib.sha256()
            count = 0
            for row in db.execute(f"SELECT * FROM {table} ORDER BY {ordering}"):
                value = dict(row)
                if table == "events":
                    value = {key: item for key, item in value.items()
                             if key not in _DERIVED and key != "incident_id"}
                    value["record_json"] = _raw(json.loads(value["record_json"]))
                encoded = _encode(value)
                digest.update(len(encoded).to_bytes(8, "big"))
                digest.update(encoded)
                count += 1
            result["counts"][table] = count
            result["digests"][table] = digest.hexdigest()
        evidence = {}
        for row in db.execute("SELECT * FROM incident_evidence ORDER BY source_id,event_id"):
            value = dict(row)
            key = (value["source_id"], value["event_id"])
            value.pop("incident_id")  # Existing evidence may move to a merged incident.
            value["snapshot_json"] = _raw(json.loads(value["snapshot_json"]))
            evidence[key] = _digest(value)
        result["evidence"] = evidence
        result["incident_ids"] = {row[0] for row in db.execute("SELECT incident_id FROM incidents")}
        result["counts"]["incident_evidence"] = len(evidence)
        result["counts"]["incidents"] = len(result["incident_ids"])
        result["digests"]["incident_evidence"] = _digest(sorted(evidence.items()))
        foreign_keys = len(db.execute("PRAGMA foreign_key_check").fetchall())
        # events.incident_id and merged_into predate explicit schema foreign keys.
        foreign_keys += db.execute("""SELECT count(*) FROM events e LEFT JOIN incidents i
            ON i.incident_id=e.incident_id WHERE e.incident_id IS NOT NULL AND i.incident_id IS NULL""").fetchone()[0]
        foreign_keys += db.execute("""SELECT count(*) FROM incidents a LEFT JOIN incidents b
            ON b.incident_id=a.merged_into WHERE a.merged_into IS NOT NULL AND b.incident_id IS NULL""").fetchone()[0]
        result["foreign_key_errors"] = foreign_keys
    return result


def preview(database: Path) -> dict[str, int]:
    counts = {"changed_events": 0, "changed_evidence": 0, "newly_detectable": 0,
              "conflicting_evidence": 0}
    with closing(_read(database)) as db:
        for table, column in (("events", "record_json"), ("incident_evidence", "snapshot_json")):
            for row in db.execute(f"SELECT * FROM {table}"):
                old = json.loads(row[column])
                kind, peer, user = _classify(old["message"], old.get("identifier") or "", old.get("unit") or "")
                updated = {**old, "event_type": kind, "src_ip": peer, "ssh_user": user}
                for alias, value in (("event_kind", kind), ("peer_ip", peer), ("username", user)):
                    if alias in updated:
                        updated[alias] = value
                changed = old != updated
                if table == "events":
                    changed |= (row["event_type"], row["src_ip"], row["ssh_user"]) != (kind, peer, user)
                if not changed:
                    continue
                counts["changed_events" if table == "events" else "changed_evidence"] += 1
                if table == "events":
                    if row["incident_id"] and (row["src_ip"] != peer or kind not in _FAILURE_TYPES):
                        counts["conflicting_evidence"] += 1
                    if kind in FAILURE_KINDS and peer is not None and (row["event_type"] not in _FAILURE_TYPES or row["src_ip"] != peer):
                        counts["newly_detectable"] += 1
                elif old.get("src_ip") != peer or kind not in _FAILURE_TYPES:
                    counts["conflicting_evidence"] += 1
    return counts


def create_backup(database: Path, target: Path) -> None:
    """Publish one verified, mode-0600 snapshot without overwriting any file."""
    if os.path.lexists(target):
        raise ReparseError("backup target already exists; choose a new path")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    temporary = Path(temporary_name)
    os.close(fd)
    try:
        os.chmod(temporary, 0o600)
        with closing(_read(database)) as source, closing(sqlite3.connect(temporary)) as destination:
            source.backup(destination)
            if destination.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise ReparseError("backup integrity check failed")
        # Windows FlushFileBuffers requires a writable handle.
        with temporary.open("r+b") as stream:
            os.fsync(stream.fileno())
        # A same-directory hard link atomically publishes the completed file and
        # fails if the target appeared during copying. os.replace would overwrite
        # that competing file on POSIX. The temporary name is removed below.
        try:
            os.link(temporary, target)
        except FileExistsError:
            raise ReparseError("backup target already exists; choose a new path") from None
        if os.name != "nt":
            directory_fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _validate(before: dict[str, Any], after: dict[str, Any]) -> None:
    if any(before["digests"][table] != after["digests"][table]
           or before["counts"][table] != after["counts"][table]
           for table in ("events", "event_receipts", "batches")):
        raise ReparseError("immutable records changed; retain the backup and review before restarting services")
    if not before["incident_ids"].issubset(after["incident_ids"]):
        raise ReparseError("existing incident identities were removed; retain the backup and review")
    if any(after["evidence"].get(key) != value for key, value in before["evidence"].items()):
        raise ReparseError("existing raw evidence changed or disappeared; retain the backup and review")
    if after["foreign_key_errors"]:
        raise ReparseError("incident references are invalid; retain the backup and review")


def run(database: Path, *, backup: Path | None = None, apply: bool = False) -> dict[str, Any]:
    if not database.is_absolute() or not database.is_file():
        raise ReparseError("database must be an absolute path to an existing file")
    database = database.resolve(strict=True)
    if apply and backup is None:
        raise ReparseError("--backup is required with --apply")
    if backup is not None:
        if not backup.is_absolute() or not backup.parent.is_dir():
            raise ReparseError("backup must be an absolute path with an existing parent directory")
        if backup.resolve() == database or os.path.lexists(backup):
            raise ReparseError("backup target must be a new file distinct from the database")
        backup = backup.parent.resolve(strict=True) / backup.name
    before = fingerprint(database)
    if before["foreign_key_errors"]:
        raise ReparseError("database already has invalid incident references; review before applying")
    planned = preview(database)
    result = {"mode": "apply" if apply else "dry_run", "database": str(database),
              "before": {"counts": before["counts"], "digests": before["digests"]},
              "planned": planned}
    if not apply:
        return result
    assert backup is not None
    create_backup(database, backup)
    _validate(before, fingerprint(backup))
    result["backup"] = str(backup)
    result["changes"] = TelemetryStore(database).reparse_sshd()
    after = fingerprint(database)
    _validate(before, after)
    result["after"] = {"counts": after["counts"], "digests": after["digests"]}
    result["verified"] = True
    return result


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--backup", type=Path, help="new absolute backup filename; required with --apply")
    parser.add_argument("--apply", action="store_true", help="apply after making and checking the required backup")
    args = parser.parse_args(argv)
    try:
        result = run(args.database, backup=args.backup, apply=args.apply)
    except ReparseError as exc:
        raise SystemExit(str(exc)) from None
    except (OSError, sqlite3.Error, ValueError, KeyError, TypeError):
        # Exceptions may embed a source record. Keep stderr safe for audit logs.
        raise SystemExit("reparse failed; retain any created backup and review before restarting services") from None
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
