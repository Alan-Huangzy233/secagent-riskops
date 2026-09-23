#!/usr/bin/env python3
"""Pull finished recovery packages from a RiskOps control node onto this machine.

This runs on the backup node, not on the control node. The node opens the
connection, takes copies, verifies them and only then tells the control node a
copy exists; the control node holds no credential for this machine and cannot
reach in to delete what has already been pulled.

    pull_recovery_packages.py --target backup@control-node --destination /srv/riskops-backups

The control node's reply is data from another machine, so every identifier it
sends is checked against a pattern before it is used as a path, and every file
is checked against the package's own SHA256SUMS before it is published locally.
Nothing here ever deletes a package.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

BACKUP_ID_RE = re.compile(r'rp-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
FILE_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
DIGEST_RE = re.compile(r'[0-9a-f]{64}\Z')
CHECKSUM_NAME = 'SHA256SUMS'
READ_CHUNK = 1 << 20
CONTROL_TIMEOUT = 120


class PullError(RuntimeError):
    """The transfer was refused or could not be trusted."""


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def ssh_command(args: argparse.Namespace, request: str) -> list[str]:
    return [args.ssh, '-o', 'BatchMode=yes', '-o', f'ConnectTimeout={args.connect_timeout}',
            *args.ssh_option, args.target, request]


def ask(args: argparse.Namespace, request: str) -> dict:
    result = subprocess.run(ssh_command(args, request), capture_output=True, timeout=CONTROL_TIMEOUT)
    if result.returncode != 0:
        detail = result.stderr.decode('utf-8', 'replace').strip().splitlines()
        raise PullError(f'{request.split()[0]} failed: {detail[-1] if detail else "no detail"}')
    try:
        reply = json.loads(result.stdout.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PullError(f'{request.split()[0]} returned something that is not JSON') from error
    if not isinstance(reply, dict):
        raise PullError(f'{request.split()[0]} returned an unexpected reply')
    return reply


def download(args: argparse.Namespace, backup_id: str, name: str, target: Path) -> tuple[str, int]:
    sha, size = hashlib.sha256(), 0
    with target.open('wb') as handle:
        process = subprocess.Popen(ssh_command(args, f'fetch {backup_id} {name}'),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert process.stdout is not None
        while chunk := process.stdout.read(READ_CHUNK):
            sha.update(chunk)
            size += len(chunk)
            handle.write(chunk)
        process.stdout.close()
        error = process.stderr.read().decode('utf-8', 'replace').strip() if process.stderr else ''
        if process.stderr is not None:
            process.stderr.close()
        if process.wait() != 0:
            raise PullError(f'fetching {name} failed: {error.splitlines()[-1] if error else "no detail"}')
    return sha.hexdigest(), size


def checksum_lines(path: Path) -> dict[str, str]:
    listed = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        digest, _, name = line.partition('  ')
        if not DIGEST_RE.fullmatch(digest) or not FILE_RE.fullmatch(name):
            raise PullError(f'{CHECKSUM_NAME} is malformed')
        listed[name] = digest
    if not listed:
        raise PullError(f'{CHECKSUM_NAME} is empty')
    return listed


def validated(entry: object) -> dict:
    """Treat the control node's listing as input, not as instructions."""
    if not isinstance(entry, dict):
        raise PullError('listing holds an unexpected entry')
    backup_id, stored = entry.get('backup_id'), entry.get('stored_object')
    files, digest = entry.get('files'), entry.get('sha256')
    if not isinstance(backup_id, str) or not BACKUP_ID_RE.fullmatch(backup_id):
        raise PullError('listing holds an unusable backup id')
    if not isinstance(stored, str) or not FILE_RE.fullmatch(stored):
        raise PullError(f'{backup_id}: listing holds an unusable object name')
    if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
        raise PullError(f'{backup_id}: listing holds an unusable digest')
    if not isinstance(files, list) or stored not in files:
        raise PullError(f'{backup_id}: listing does not offer its own object')
    for name in files:
        if not isinstance(name, str) or not FILE_RE.fullmatch(name):
            raise PullError(f'{backup_id}: listing holds an unusable file name')
    return {'backup_id': backup_id, 'stored_object': stored, 'files': list(files), 'sha256': digest,
            'created_at': entry.get('created_at', ''), 'encrypted': bool(entry.get('encrypted')),
            'confirmed_by_you': bool(entry.get('confirmed_by_you'))}


def collect(args: argparse.Namespace, entry: dict, destination: Path) -> dict:
    """Download into a partial directory and publish it only once it verifies."""
    partial = destination / f'.{entry["backup_id"]}.partial'
    if partial.exists():
        shutil.rmtree(partial)
    partial.mkdir(mode=0o700, parents=True)
    try:
        digests = {}
        for name in entry['files']:
            digests[name] = download(args, entry['backup_id'], name, partial / name)
        if CHECKSUM_NAME not in digests:
            raise PullError(f'{entry["backup_id"]}: the package published no {CHECKSUM_NAME}')
        listed = checksum_lines(partial / CHECKSUM_NAME)
        for name, digest in listed.items():
            if name not in digests:
                raise PullError(f'{entry["backup_id"]}: {name} is listed but was not offered')
            if digests[name][0] != digest:
                raise PullError(f'{entry["backup_id"]}: {name} does not match {CHECKSUM_NAME}')
        if digests[entry['stored_object']][0] != entry['sha256']:
            raise PullError(f'{entry["backup_id"]}: the object does not match the digest the listing gave')
        os.replace(partial, destination / entry['backup_id'])
    except BaseException:
        shutil.rmtree(partial, ignore_errors=True)
        raise
    return {'backup_id': entry['backup_id'], 'bytes': digests[entry['stored_object']][1],
            'sha256': entry['sha256'], 'files': sorted(digests)}


def already_held(destination: Path, entry: dict) -> bool:
    stored = destination / entry['backup_id'] / entry['stored_object']
    return stored.is_file() and stored.stat().st_size > 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--target', required=True, help='ssh destination of the control node, e.g. backup@host')
    parser.add_argument('--destination', required=True, type=Path)
    parser.add_argument('--ssh', default='ssh')
    parser.add_argument('--ssh-option', action='append', default=[], metavar='OPTION',
                        help='extra argument passed to ssh, e.g. -i or a key path; repeatable')
    parser.add_argument('--connect-timeout', type=int, default=30)
    parser.add_argument('--limit', type=int, default=0, help='stop after this many new packages (0 = no limit)')
    parser.add_argument('--no-confirm', action='store_true',
                        help='do not tell the control node a copy exists; its rotation then keeps the package')
    parser.add_argument('--keep-going', action='store_true', help='continue after a package fails')
    args = parser.parse_args(argv)
    os.umask(0o077)
    report = {'target': args.target, 'started_at': utc_now(), 'pulled': [], 'skipped': [], 'failed': []}
    try:
        args.destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        listing = ask(args, 'list')
        entries = listing.get('packages')
        if not isinstance(entries, list):
            raise PullError('the control node did not return a package list')
        for raw in entries:
            entry = validated(raw)
            if already_held(args.destination, entry):
                if not entry['confirmed_by_you'] and not args.no_confirm:
                    ask(args, f'ack {entry["backup_id"]} {entry["sha256"]}')
                report['skipped'].append(entry['backup_id'])
                continue
            if args.limit and len(report['pulled']) >= args.limit:
                report['skipped'].append(entry['backup_id'])
                continue
            try:
                collected = collect(args, entry, args.destination)
            except (PullError, OSError, subprocess.SubprocessError) as error:
                report['failed'].append({'backup_id': entry['backup_id'], 'problem': str(error)})
                if not args.keep_going:
                    raise PullError(str(error)) from error
                continue
            if not args.no_confirm:
                ask(args, f'ack {entry["backup_id"]} {entry["sha256"]}')
                collected['confirmed'] = True
            report['pulled'].append(collected)
    except (PullError, OSError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
    report['finished_at'] = utc_now()
    report['ok'] = 'error' not in report and not report['failed']
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
