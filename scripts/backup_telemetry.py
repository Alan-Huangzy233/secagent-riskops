#!/usr/bin/env python3
"""Create a consistent SQLite backup; this is a local recovery copy, not offsite."""
import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3

DEFAULT_KEEP = 7


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True, type=Path)
    parser.add_argument('--directory', required=True, type=Path)
    # The environment default lets one systemd drop-in set retention for every
    # ExecStart line of the unit without repeating them.
    parser.add_argument('--keep', type=int, default=int(os.environ.get('RISKOPS_BACKUP_KEEP', DEFAULT_KEEP)),
                        help=f'newest snapshots to retain (default: $RISKOPS_BACKUP_KEEP or {DEFAULT_KEEP})')
    args = parser.parse_args()
    if args.keep < 1:
        raise SystemExit('--keep must retain at least one snapshot')
    if not args.database.is_file():
        raise SystemExit('database does not exist')
    os.umask(0o077)
    args.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    name = datetime.now(timezone.utc).strftime('live-%Y%m%dT%H%M%S%f.sqlite')
    target = args.directory / name
    # Keep incomplete copies out of the retention set.  A power loss or a
    # failed SQLite backup can otherwise leave a file named like a verified
    # snapshot, which makes recovery selection ambiguous.
    temporary = args.directory / f'.{name}.tmp'
    source = destination = None
    try:
        source = sqlite3.connect(args.database.as_uri() + '?mode=ro', uri=True)
        try:
            destination = sqlite3.connect(temporary)
            source.backup(destination)
            if destination.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                raise RuntimeError('backup integrity check failed')
        finally:
            # sqlite3.Connection.__exit__ commits but does not close the
            # handle.  Close both explicitly before the atomic rename; this
            # matters on Windows and also releases WAL sidecars.
            if destination is not None:
                destination.close()
            if source is not None:
                source.close()
        os.replace(temporary, target)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    # Only remove files created by this helper within the explicitly named directory.
    for old in sorted(args.directory.glob('live-*.sqlite'), reverse=True)[args.keep:]:
        if old.is_file() and not old.is_symlink():
            old.unlink()
    # A reader of a backup leaves SQLite's -shm/-wal sidecars behind.  Rotation
    # used to drop only the database, so the orphans accumulated forever; they
    # are meaningless once the database they describe is gone.
    for sidecar in sorted(args.directory.glob('live-*.sqlite-*')):
        suffix = sidecar.name.rsplit('-', 1)[-1]
        if suffix in ('shm', 'wal') and sidecar.is_file() and not sidecar.is_symlink():
            if not sidecar.with_name(sidecar.name[:-len(suffix) - 1]).exists():
                sidecar.unlink()
    print('SQLite backup verified:', target.name)


if __name__ == '__main__':
    main()
