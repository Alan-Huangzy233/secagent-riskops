#!/usr/bin/env python3
"""Forced-command export of finished recovery packages to a pulling backup node.

The backup node opens the connection and takes its own copies; this host holds
no credential for it. A control node that is taken over therefore cannot reach
into the node and delete the history it already pulled, which is exactly what a
push-based design would hand an intruder.

Install root-owned and invoke with /usr/bin/python3 -I as the only thing the
node's key may run, from a dedicated account whose authorized_keys file it
cannot edit:

    restrict,command="/usr/bin/python3 -I /opt/secagent-riskops/current/scripts/backup_export.py --store <directory> --peer <name>" ssh-ed25519 AAAA... backup-node

The store stays root-owned; ``recovery_package.py build --share-group`` makes
each published package readable by that account's group and gives it write
access to the package's ``confirmations/`` directory only.

The peer name comes from the key's own command line, never from the client. The
client supplies a backup id and one of the file names that package's manifest
already lists; it can never supply a path. Its only write is a confirmation
record under its own name, which is what lets local rotation know an
independent copy exists before it deletes anything.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

BACKUP_ID_RE = re.compile(r'rp-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
PEER_RE = re.compile(r'[a-z0-9][a-z0-9_-]{0,31}\Z')
DIGEST_RE = re.compile(r'[0-9a-f]{64}\Z')
FILE_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
MANIFEST_NAME = 'manifest.json'
CHECKSUM_NAME = 'SHA256SUMS'
SIGNATURE_NAME = 'manifest.json.asc'
CONFIRMATIONS = 'confirmations'
MAX_COMMAND_BYTES = 512
MAX_ARGUMENTS = 3
SEND_CHUNK = 1 << 20


class ExportError(Exception):
    """The request was refused; the client only ever sees this one line."""


def reply(payload: dict) -> None:
    """Answer on the same byte stream the fetched object uses, so a mixed
    text/binary buffer can never reorder a reply."""
    sys.stdout.buffer.write(json.dumps(payload, sort_keys=True).encode('utf-8') + b'\n')
    sys.stdout.buffer.flush()


def secure_directory(path: Path) -> Path:
    """Refuse a store that a third party could swap under us.

    As with sshd's StrictModes, the store and every ancestor must belong to root
    or to the account running the export, and must not be writable by anyone
    else. A world-writable ancestor is only disqualifying when it is not sticky:
    the sticky bit is exactly what stops a non-owner renaming or removing an
    entry it does not own, which is the substitution this check exists to
    prevent.
    """
    if not path.is_absolute():
        raise ExportError('store must be an absolute path')
    trusted = {0, os.geteuid()}
    for item in (path, *path.parents):
        info = item.lstat()
        swappable = info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX
        if stat.S_ISLNK(info.st_mode) or info.st_uid not in trusted or swappable:
            raise ExportError('unsafe store directory')
    if not path.is_dir():
        raise ExportError('store directory does not exist')
    return path


def package_directory(store: Path, backup_id: str) -> Path:
    if not BACKUP_ID_RE.fullmatch(backup_id):
        raise ExportError('invalid backup id')
    package = store / backup_id
    info = package.lstat() if package.exists() else None
    if info is None or stat.S_ISLNK(info.st_mode) or not package.is_dir():
        raise ExportError('unknown backup')
    return package


def read_manifest(package: Path) -> dict:
    path = package / MANIFEST_NAME
    if path.is_symlink() or not path.is_file():
        raise ExportError('backup has no manifest')
    try:
        manifest = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as error:
        raise ExportError('backup manifest is unreadable') from error
    if not isinstance(manifest, dict) or not isinstance(manifest.get('stored_object'), str):
        raise ExportError('backup manifest is unusable')
    if not FILE_RE.fullmatch(manifest['stored_object']):
        raise ExportError('backup manifest names an unusable object')
    return manifest


def published_names(package: Path, manifest: dict) -> list[str]:
    """Exactly what a puller may ask for: the manifest, its checksums, its
    signature when one exists, and the single stored object."""
    names = [MANIFEST_NAME, CHECKSUM_NAME, manifest['stored_object']]
    if (package / SIGNATURE_NAME).is_file():
        names.insert(2, SIGNATURE_NAME)
    return [name for name in names if (package / name).is_file()]


def stored_digest(manifest: dict) -> str | None:
    sealed = manifest.get('encryption') or manifest.get('archive') or {}
    digest = sealed.get('sha256') if isinstance(sealed, dict) else None
    return digest if isinstance(digest, str) and DIGEST_RE.fullmatch(digest) else None


def confirmations(package: Path) -> dict[str, dict]:
    directory = package / CONFIRMATIONS
    found = {}
    if not directory.is_dir() or directory.is_symlink():
        return found
    for path in sorted(directory.glob('*.json')):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            record = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(record, dict) and isinstance(record.get('peer'), str):
            found[record['peer']] = record
    return found


def action_list(store: Path, peer: str) -> int:
    packages = []
    for entry in sorted(store.iterdir()):
        if entry.is_symlink() or not entry.is_dir() or not BACKUP_ID_RE.fullmatch(entry.name):
            continue
        try:
            manifest = read_manifest(entry)
            stored = entry / manifest['stored_object']
            if not stored.is_file():
                continue
            packages.append({'backup_id': manifest.get('backup_id', entry.name),
                             'created_at': manifest.get('created_at', ''),
                             'host_id': manifest.get('host_id', ''),
                             'retention_class': manifest.get('retention_class', ''),
                             'encrypted': bool(manifest.get('encryption')),
                             'stored_object': manifest['stored_object'],
                             'stored_bytes': stored.stat().st_size,
                             'sha256': stored_digest(manifest),
                             'files': published_names(entry, manifest),
                             'confirmed_by_you': peer in confirmations(entry)})
        except (ExportError, OSError):
            # A package this account cannot read (built without --share-group)
            # is skipped rather than hiding every other package from the node.
            continue
    reply({'peer': peer, 'packages': packages})
    return 0


def action_fetch(store: Path, peer: str, backup_id: str, name: str) -> int:
    package = package_directory(store, backup_id)
    manifest = read_manifest(package)
    if not FILE_RE.fullmatch(name) or name not in published_names(package, manifest):
        raise ExportError('unknown file')
    path = package / name
    if path.is_symlink() or not path.is_file():
        raise ExportError('unknown file')
    with path.open('rb') as handle:
        while chunk := handle.read(SEND_CHUNK):
            sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
    return 0


def action_ack(store: Path, peer: str, backup_id: str, digest: str) -> int:
    """Record that the puller holds this object; local rotation reads this."""
    if not DIGEST_RE.fullmatch(digest):
        raise ExportError('invalid digest')
    package = package_directory(store, backup_id)
    manifest = read_manifest(package)
    expected = stored_digest(manifest)
    if expected is None:
        raise ExportError('backup manifest records no digest')
    if digest != expected:
        # The puller's copy is not the object published here.  Recording it
        # would let rotation delete the only good copy.
        raise ExportError('digest does not match the published object')
    directory = package / CONFIRMATIONS
    directory.mkdir(mode=0o700, exist_ok=True)
    for stale in directory.glob(f'.{peer}.*.tmp'):
        # An interrupted confirmation must not sit here forever: rotation reads
        # this directory and refuses a package holding files it does not own.
        if stale.is_file() and not stale.is_symlink():
            stale.unlink()
    record = {'peer': peer, 'backup_id': manifest.get('backup_id', backup_id), 'sha256': digest,
              'stored_object': manifest['stored_object'],
              'confirmed_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'}
    handle, temporary = tempfile.mkstemp(dir=directory, prefix=f'.{peer}.', suffix='.tmp')
    try:
        with os.fdopen(handle, 'w', encoding='utf-8') as stream:
            json.dump(record, stream, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, directory / f'{peer}.json')
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    reply({'confirmed': record})
    return 0


def refuse(message: str) -> None:
    sys.stderr.write(f'backup_export: {message}\n')
    sys.stderr.flush()


def parse_request(raw: str | None) -> list[str]:
    if raw is None:
        raise ExportError('this key runs a fixed command; pass one of: list, fetch, ack')
    if len(raw.encode('utf-8')) > MAX_COMMAND_BYTES:
        raise ExportError('request is too long')
    arguments = raw.split()
    if not arguments or len(arguments) > MAX_ARGUMENTS:
        raise ExportError('request is not understood')
    return arguments


def dispatch(store: Path, peer: str, arguments: list[str]) -> int:
    action, rest = arguments[0], arguments[1:]
    if action == 'list' and not rest:
        return action_list(store, peer)
    if action == 'fetch' and len(rest) == 2:
        return action_fetch(store, peer, *rest)
    if action == 'ack' and len(rest) == 2:
        return action_ack(store, peer, *rest)
    raise ExportError('usage: list | fetch <backup-id> <file> | ack <backup-id> <sha256>')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--store', required=True, type=Path)
    parser.add_argument('--peer', required=True)
    parser.add_argument('--request', default=None,
                        help='request text; defaults to the client command sshd passed in')
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if not PEER_RE.fullmatch(args.peer):
            raise ExportError('invalid peer name')
        store = secure_directory(args.store)
        request = args.request if args.request is not None else os.environ.get('SSH_ORIGINAL_COMMAND')
        return dispatch(store, args.peer, parse_request(request))
    except ExportError as error:
        refuse(str(error))
        return 2
    except OSError as error:
        refuse(error.strerror or 'request failed')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
