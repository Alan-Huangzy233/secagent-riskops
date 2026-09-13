#!/usr/bin/env python3
"""Preview or rebuild SSH detections from retained telemetry events.

The default is --dry-run: copy the database through SQLite's read-only backup
API, then run schema migration and detection only on that temporary copy.
Stop the API and collector before --apply and leave them stopped until this
command finishes. Apply requires an existing absolute --backup-directory and
creates a verified, independent recovery snapshot before opening a writable
store. The snapshot is outside scheduled backup retention. This command never
reparses, deletes or imports raw events and prints only summary counts.
"""
from __future__ import annotations

import argparse
from contextlib import closing, contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import time
from typing import Any
import uuid

from app.telemetry.store import TelemetryStore
from reparse_ssh_telemetry import (
    ReparseError, _encode, _read, _validate, create_backup, fingerprint,
)


_CHANGE_KEYS = frozenset({
    "events_evaluated", "incidents_created", "incidents_merged", "evidence_added",
})


@contextmanager
def _preview_directory():
    directory = tempfile.TemporaryDirectory(prefix="riskops-detection-preview-")
    try:
        yield Path(directory.name)
    finally:
        # Windows scanners can briefly hold a just-closed SQLite sidecar. Retry
        # this uniquely created directory only; do not ignore persistent errors.
        for attempt in range(3):
            try:
                directory.cleanup()
                break
            except OSError:
                if attempt == 2:
                    raise
                time.sleep(0.05 * (attempt + 1))


def _fingerprint(database: Path) -> dict[str, Any]:
    """Extend raw-record checks to preserve existing enrichment verbatim."""
    result = fingerprint(database)
    events = hashlib.sha256()
    evidence = {}
    with closing(_read(database)) as db:
        for table in ("events", "incident_evidence"):
            for row in db.execute(f"SELECT * FROM {table} ORDER BY source_id,event_id"):
                value = dict(row)
                value.pop("incident_id", None)
                encoded = _encode(value)
                if table == "events":
                    events.update(len(encoded).to_bytes(8, "big"))
                    events.update(encoded)
                else:
                    evidence[(value["source_id"], value["event_id"])] = hashlib.sha256(encoded).hexdigest()
    result["complete_events"] = events.hexdigest()
    result["complete_evidence"] = evidence
    return result


def _validate_rebuild(before: dict[str, Any], after: dict[str, Any]) -> None:
    _validate(before, after)
    if before["complete_events"] != after["complete_events"]:
        raise ReparseError("existing event enrichment changed; retain the backup and review before restarting services")
    if any(after["complete_evidence"].get(key) != digest
           for key, digest in before["complete_evidence"].items()):
        raise ReparseError("existing evidence enrichment changed; retain the backup and review before restarting services")


def _rebuild(database: Path) -> dict[str, int]:
    changes = TelemetryStore(database).rebuild_detections()
    if not isinstance(changes, dict) or set(changes) != _CHANGE_KEYS or any(
            type(value) is not int or value < 0 for value in changes.values()):
        raise ReparseError("detection rebuild returned an invalid summary; retain the backup and review")
    return changes


def run(database: Path, *, backup_directory: Path | None = None,
        apply: bool = False) -> dict[str, Any]:
    if not database.is_absolute() or not database.is_file():
        raise ReparseError("database must be an absolute path to an existing file")
    database = database.resolve(strict=True)
    if apply and backup_directory is None:
        raise ReparseError("--backup-directory is required with --apply")
    if backup_directory is not None:
        if not backup_directory.is_absolute() or not backup_directory.is_dir():
            raise ReparseError("backup directory must be an absolute path to an existing directory")
        backup_directory = backup_directory.resolve(strict=True)
    before = _fingerprint(database)
    if before["foreign_key_errors"]:
        raise ReparseError("database already has invalid incident references; review before applying")
    result: dict[str, Any] = {"mode": "apply" if apply else "dry_run", "before": before["counts"]}
    if not apply:
        with _preview_directory() as directory:
            copy = directory / "preview.sqlite"
            create_backup(database, copy)
            _validate_rebuild(before, _fingerprint(copy))
            result["planned"] = _rebuild(copy)
            after = _fingerprint(copy)
            _validate_rebuild(before, after)
            result["after"] = after["counts"]
        # Catch concurrent ingestion without attempting to restore or modify it.
        _validate_rebuild(before, _fingerprint(database))
    else:
        assert backup_directory is not None
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup = backup_directory / f"ssh-detections-recovery-{stamp}-{uuid.uuid4().hex}.sqlite"
        create_backup(database, backup)
        _validate_rebuild(before, _fingerprint(backup))
        result["backup"] = str(backup)
        result["changes"] = _rebuild(database)
        after = _fingerprint(database)
        _validate_rebuild(before, after)
        result["after"] = after["counts"]
    result["verified"] = True
    return result


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="preview on a temporary database copy (default)")
    mode.add_argument("--apply", action="store_true", help="rebuild after stopping the API and collector")
    parser.add_argument("--backup-directory", type=Path,
                        help="existing absolute directory for an independent recovery snapshot; required with --apply")
    args = parser.parse_args(argv)
    try:
        result = run(args.database, backup_directory=args.backup_directory, apply=args.apply)
    except ReparseError as exc:
        raise SystemExit(str(exc)) from None
    except Exception:
        # Database, validation and filesystem errors can contain private data.
        raise SystemExit("detection rebuild failed; retain any created backup and review before restarting services") from None
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
