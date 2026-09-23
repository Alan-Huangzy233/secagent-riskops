#!/usr/bin/env python3
"""Build, verify and extract an encrypted RiskOps recovery package.

``backup_telemetry.py`` keeps a plain local copy of one database. A recovery
package is the unit that can leave this host: it bundles consistent database
snapshots with the collector cursors that match them, compresses the bundle,
encrypts it to a recipient whose private key lives somewhere else, and records
a manifest that lets a restorer prove what it holds before trusting it.

Capture order is the consistency guarantee. ``telemetry_collector.py`` rewrites
``<source>.state.json`` only after the API acknowledges a durable batch, so a
cursor captured *before* a database snapshot can never point past the events
that snapshot already contains. Restoring such a pair replays a little journal
that the receipt table rejects as duplicate; the reverse order would skip
events for good. The guarantee needs no maintenance window, so building a
package does not interrupt collection.
"""
from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile

MANIFEST_VERSION = 1
TOOL_VERSION = 1
NAME_RE = re.compile(r'[a-z0-9][a-z0-9._-]{0,63}\Z')
FINGERPRINT_RE = re.compile(r'[0-9A-F]{40}\Z')
BACKUP_ID_RE = re.compile(r'rp-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
KINDS = ('sqlite', 'state_dir', 'reference')
READ_CHUNK = 1 << 20
MAX_STATE_FILE_BYTES = 64 << 20
STABLE_READ_ATTEMPTS = 5
MANIFEST_NAME = 'manifest.json'
CHECKSUM_NAME = 'SHA256SUMS'
SIGNATURE_NAME = 'manifest.json.asc'
CONFIRMATIONS = 'confirmations'
CONSISTENCY_RULE = ('Collector cursors are captured before the database snapshots. The collector '
                    'advances a cursor only after a durable acknowledgement, so a restored cursor '
                    'never points past the restored events; the replayed overlap is rejected by the '
                    'receipt table instead of being lost.')


class PackageError(RuntimeError):
    """A package could not be built, verified or extracted."""


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def digest_file(path: Path) -> tuple[str, int]:
    """Hash a file without holding it in memory; sizes here reach gigabytes."""
    sha, size = hashlib.sha256(), 0
    with path.open('rb') as handle:
        while chunk := handle.read(READ_CHUNK):
            sha.update(chunk)
            size += len(chunk)
    return sha.hexdigest(), size


def _text(value: object, field: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise PackageError(f'{field} must be a non-empty string')
    if pattern is not None and not pattern.fullmatch(value):
        raise PackageError(f'{field} is not a valid identifier: {value!r}')
    return value


def _absolute(value: object, field: str) -> str:
    path = _text(value, field)
    if not path.startswith('/') or '..' in Path(path).parts:
        raise PackageError(f'{field} must be an absolute path without ".." segments')
    return path


def _fingerprint(value: object) -> str:
    return _text(value.upper() if isinstance(value, str) else value, 'recipient', FINGERPRINT_RE)


def validate_component(raw: object, seen: set[str]) -> dict:
    allowed = {'name', 'kind', 'path', 'restore_path', 'patterns', 'description'}
    if not isinstance(raw, dict) or set(raw) - allowed:
        raise PackageError(f'component must be an object with keys {sorted(allowed)}')
    name = _text(raw.get('name'), 'component name', NAME_RE)
    if name in seen:
        raise PackageError(f'duplicate component name: {name}')
    seen.add(name)
    kind = _text(raw.get('kind'), 'component kind')
    if kind not in KINDS:
        raise PackageError(f'unsupported component kind: {kind}')
    component = {'name': name, 'kind': kind, 'path': _absolute(raw.get('path'), 'component path'),
                 'description': raw.get('description') or ''}
    if not isinstance(component['description'], str):
        raise PackageError('component description must be a string')
    component['restore_path'] = _absolute(raw['restore_path'], 'restore_path') if 'restore_path' in raw else component['path']
    if kind == 'state_dir':
        patterns = raw.get('patterns')
        if not isinstance(patterns, list) or not patterns:
            raise PackageError('state_dir components need a non-empty patterns list')
        for pattern in patterns:
            text = _text(pattern, 'pattern')
            if '/' in text or '..' in text:
                raise PackageError('patterns select files in the directory itself, not sub-paths')
        component['patterns'] = list(patterns)
    elif 'patterns' in raw:
        raise PackageError('patterns apply to state_dir components only')
    return component


def load_config(path: Path) -> dict:
    try:
        raw = json.loads(path.read_text(encoding='utf-8'))
    except json.JSONDecodeError as error:
        raise PackageError(f'configuration is not valid JSON: {error}') from error
    allowed = {'host_id', 'description', 'components', 'recipients'}
    if not isinstance(raw, dict) or set(raw) - allowed:
        raise PackageError(f'configuration must be an object with keys {sorted(allowed)}')
    components, seen = [], set()
    items = raw.get('components')
    if not isinstance(items, list) or not items:
        raise PackageError('components must be a non-empty list')
    for item in items:
        components.append(validate_component(item, seen))
    if not any(item['kind'] == 'sqlite' for item in components):
        raise PackageError('a recovery package needs at least one sqlite component')
    recipients = raw.get('recipients', [])
    if not isinstance(recipients, list):
        raise PackageError('recipients must be a list of 40-hex fingerprints')
    return {'host_id': _text(raw.get('host_id'), 'host_id', NAME_RE),
            'description': raw.get('description') or '', 'components': components,
            'recipients': [_fingerprint(item) for item in recipients]}


def stable_copy(source: Path, target: Path) -> dict:
    """Copy a file another process may rewrite, and prove the copy is a real state.

    The collector publishes cursor files with ``os.replace``, and a rewrite can
    land inside one filesystem timestamp tick, so mtime and size cannot settle
    this. Re-reading the source and comparing digests can: equal digests mean
    the copy holds content that actually existed, whichever inode carried it.
    """
    for _ in range(STABLE_READ_ATTEMPTS):
        if source.stat().st_size > MAX_STATE_FILE_BYTES:
            raise PackageError(f'{source.name} is larger than the state file limit')
        shutil.copyfile(source, target)
        sha, size = digest_file(target)
        if (sha, size) == digest_file(source):
            modified = datetime.fromtimestamp(source.stat().st_mtime, timezone.utc)
            return {'name': source.name, 'bytes': size, 'sha256': sha,
                    'modified_at': modified.isoformat().replace('+00:00', 'Z')}
    raise PackageError(f'{source.name} kept changing while it was copied')


def capture_state_dir(spec: dict, contents: Path) -> dict:
    source = Path(spec['path'])
    if source.is_symlink() or not source.is_dir():
        raise PackageError(f'{spec["name"]}: {source} is not a directory')
    target = contents / spec['name']
    target.mkdir(mode=0o700)
    captured_at = utc_now()
    files: dict[str, dict] = {}
    for pattern in spec['patterns']:
        for path in sorted(source.glob(pattern)):
            if path.name in files:
                continue
            if path.is_symlink() or not path.is_file():
                raise PackageError(f'{spec["name"]}: refusing to capture {path.name}, not a regular file')
            files[path.name] = stable_copy(path, target / path.name)
    return {'name': spec['name'], 'kind': 'state_dir', 'description': spec['description'],
            'source_path': spec['path'], 'restore_path': spec['restore_path'],
            'stored_as': spec['name'], 'captured_at': captured_at,
            'patterns': spec['patterns'], 'file_count': len(files),
            'files': [files[name] for name in sorted(files)],
            'bytes': sum(entry['bytes'] for entry in files.values())}


def _table_counts(database: sqlite3.Connection) -> dict[str, int]:
    names = [row[0] for row in database.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    return {name: database.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0] for name in names}


def snapshot_database(spec: dict, contents: Path, census: bool) -> dict:
    """Copy a live database with the SQLite backup API and describe the result."""
    source = Path(spec['path'])
    if source.is_symlink() or not source.is_file():
        raise PackageError(f'{spec["name"]}: {source} is not a regular file')
    stored_as = f'{spec["name"]}.sqlite'
    target = contents / stored_as
    started_at = utc_now()
    with closing(sqlite3.connect(f'{source.as_uri()}?mode=ro', uri=True)) as origin:
        with closing(sqlite3.connect(target)) as copy:
            origin.backup(copy)
            if copy.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                raise PackageError(f'{spec["name"]}: snapshot failed its integrity check')
            page_size = copy.execute('PRAGMA page_size').fetchone()[0]
            page_count = copy.execute('PRAGMA page_count').fetchone()[0]
            freelist = copy.execute('PRAGMA freelist_count').fetchone()[0]
            statements = sorted(row[0] for row in copy.execute(
                'SELECT sql FROM sqlite_master WHERE sql IS NOT NULL'))
            schema_sha256 = hashlib.sha256('\n'.join(statements).encode('utf-8')).hexdigest()
            counts = _table_counts(copy) if census else None
    # A clean close checkpoints and removes the WAL that the copied header
    # advertises.  Empty leftovers are SQLite's own sidecars; a populated one
    # would mean unflushed pages, so refuse to package the snapshot.
    for suffix in ('-wal', '-shm'):
        sidecar = target.with_name(target.name + suffix)
        if sidecar.exists():
            if sidecar.stat().st_size:
                raise PackageError(f'{spec["name"]}: snapshot left a non-empty {suffix} sidecar')
            sidecar.unlink()
    sha, size = digest_file(target)
    return {'name': spec['name'], 'kind': 'sqlite', 'description': spec['description'],
            'source_path': spec['path'], 'restore_path': spec['restore_path'],
            'stored_as': stored_as, 'captured_at': started_at, 'finished_at': utc_now(),
            'bytes': size, 'sha256': sha, 'page_size': page_size, 'page_count': page_count,
            'freelist_count': freelist, 'schema_sha256': schema_sha256, 'table_rows': counts}


def capture_reference(spec: dict) -> dict:
    """Record where a deployment pointer aimed without copying the release."""
    source = Path(spec['path'])
    target = None
    if source.is_symlink():
        target = os.readlink(source)
    elif source.exists():
        target = str(source.resolve())
    return {'name': spec['name'], 'kind': 'reference', 'description': spec['description'],
            'source_path': spec['path'], 'restore_path': spec['restore_path'],
            'captured_at': utc_now(), 'exists': source.exists(), 'points_to': target}


def compress(contents: Path, archive: Path, zstd_binary: str, level: int) -> None:
    """Stream a tar into zstd so the uncompressed bundle never hits the disk."""
    command = [zstd_binary, '-q', '-T0', f'-{level}', '-o', str(archive)]
    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE)
    except OSError as error:
        raise PackageError(f'cannot run {zstd_binary}: {error}') from error
    failure = None
    try:
        with tarfile.open(fileobj=process.stdin, mode='w|') as tar:
            for path in sorted(contents.rglob('*')):
                info = tar.gettarinfo(path, arcname=str(path.relative_to(contents)))
                info.uid = info.gid = 0
                info.uname = info.gname = ''
                if info.isfile():
                    with path.open('rb') as handle:
                        tar.addfile(info, handle)
                else:
                    tar.addfile(info)
    except Exception as error:  # noqa: BLE001 - reported after zstd is reaped
        failure = error
    finally:
        if process.stdin is not None:
            try:
                process.stdin.close()
            except BrokenPipeError:
                pass
        code = process.wait()
    if failure is not None:
        raise PackageError(f'archiving failed: {failure}') from failure
    if code != 0:
        raise PackageError(f'{zstd_binary} exited with status {code}')


def run_gpg(arguments: list[str], gpg_binary: str, action: str, *, show_output: bool = False) -> str:
    """Run gpg, optionally letting it talk to the terminal.

    Decryption may need a passphrase, and the agent's prompt only makes sense
    if the operator can see it. Swallowing gpg's output there turns a question
    into what looks like a hang, so that one call lets stderr through.
    """
    try:
        result = subprocess.run([gpg_binary, '--batch', '--yes', *arguments], text=True, check=False,
                                stdout=subprocess.PIPE,
                                stderr=None if show_output else subprocess.PIPE)
    except OSError as error:
        raise PackageError(f'cannot run {gpg_binary}: {error}') from error
    if result.returncode != 0:
        detail = ((result.stderr or '') or result.stdout or '').strip().splitlines()
        raise PackageError(f'{action} failed: {detail[-1] if detail else "see the gpg output above"}')
    return result.stdout


def encrypt(archive: Path, recipients: list[str], gpg_binary: str) -> Path:
    """Encrypt to full fingerprints; a name lookup can silently select a stale key."""
    target = archive.with_name(archive.name + '.gpg')
    arguments = ['--trust-model', 'always', '--encrypt', '--output', str(target)]
    for recipient in recipients:
        arguments += ['--recipient', recipient]
    run_gpg([*arguments, str(archive)], gpg_binary, 'encryption')
    return target


def sign_manifest(manifest_path: Path, key: str, gpg_binary: str) -> Path:
    signature = manifest_path.with_name(SIGNATURE_NAME)
    run_gpg(['--armor', '--local-user', key, '--detach-sign', '--output', str(signature),
             str(manifest_path)], gpg_binary, 'manifest signing')
    return signature


def write_checksums(directory: Path, names: list[str]) -> None:
    lines = []
    for name in names:
        sha, _ = digest_file(directory / name)
        lines.append(f'{sha}  {name}')
    (directory / CHECKSUM_NAME).write_text('\n'.join(lines) + '\n', encoding='utf-8')


def restore_plan(components: list[dict]) -> dict:
    return {'order': [component['name'] for component in components if component['kind'] == 'state_dir']
                     + [component['name'] for component in components if component['kind'] == 'sqlite'],
            'notes': [
                'Restore into an empty directory first and compare the manifest digests before '
                'replacing anything a service is using.',
                'Stop the collector and the API before overwriting live paths; a running writer '
                'invalidates the restored cursors.',
                'File ownership and mode are not carried in the package: recreate them from the '
                'deployment record after restoring.',
                'Reference components record where a pointer aimed; the release itself is rebuilt '
                'from the repository, not from this package.']}


def shared_group(name: str, encrypted: bool) -> int:
    """Resolve the group a pulling account reads published packages through."""
    if not encrypted:
        raise PackageError('--share-group hands packages to another account; they must be encrypted')
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError as error:
        raise PackageError(f'group {name!r} does not exist') from error


def share_with_group(workdir: Path, gid: int) -> None:
    """Open a finished package to the pulling account just before it is published.

    That account may read the files the manifest publishes and write only into
    ``confirmations/``. The plaintext snapshots are gone by now and were never
    anything but 0700 root.
    """
    confirmations = workdir / CONFIRMATIONS
    confirmations.mkdir()
    for path in workdir.iterdir():
        os.chown(path, -1, gid)
        os.chmod(path, 0o770 if path == confirmations else 0o640)
    os.chown(workdir, -1, gid)
    os.chmod(workdir, 0o750)


def build(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    # Recipients on the command line replace the configured ones.
    recipients = [_fingerprint(item) for item in args.recipient] or config['recipients']
    if not recipients and not args.allow_unencrypted:
        raise PackageError('configure recipients, pass --recipient <fingerprint> '
                           'or accept the risk with --allow-unencrypted')
    # Resolved before the snapshots so a wrong group fails in seconds, not minutes.
    shared_gid = shared_group(args.share_group, bool(recipients)) if args.share_group else None
    os.umask(0o077)
    store = args.output_dir
    store.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup_id = f'rp-{datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")}-{secrets.token_hex(4)}'
    package, workdir = store / backup_id, store / f'.incoming-{backup_id}'
    if package.exists() or workdir.exists():
        raise PackageError(f'{backup_id} already exists in {store}')
    workdir.mkdir(mode=0o700)
    try:
        contents = workdir / 'contents'
        contents.mkdir(mode=0o700)
        state_specs = [item for item in config['components'] if item['kind'] == 'state_dir']
        rest = [item for item in config['components'] if item['kind'] != 'state_dir']
        started_at = utc_now()
        components = [capture_state_dir(spec, contents) for spec in state_specs]
        snapshots_started_at = utc_now()
        for spec in rest:
            components.append(snapshot_database(spec, contents, args.census) if spec['kind'] == 'sqlite'
                              else capture_reference(spec))
        manifest = {
            'manifest_version': MANIFEST_VERSION, 'backup_id': backup_id, 'host_id': config['host_id'],
            'description': config['description'], 'created_at': started_at,
            'label': args.label or '', 'retention_class': args.retention_class,
            'tool': {'name': 'recovery_package.py', 'version': TOOL_VERSION,
                     'python': sys.version.split()[0], 'sqlite': sqlite3.sqlite_version},
            'consistency': {'rule': CONSISTENCY_RULE, 'state_captured_at': started_at,
                            'snapshots_started_at': snapshots_started_at, 'snapshots_finished_at': utc_now(),
                            'collection_paused': False},
            'components': components, 'restore': restore_plan(components)}
        inner = contents / MANIFEST_NAME
        inner.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        manifest['inner_manifest_sha256'] = digest_file(inner)[0]
        archive = workdir / f'{backup_id}.tar.zst'
        compress(contents, archive, args.zstd_binary, args.compression_level)
        sha, size = digest_file(archive)
        plain_bytes = sum(component.get('bytes', 0) for component in components)
        manifest['archive'] = {'name': archive.name, 'compression': f'zstd -{args.compression_level}',
                               'bytes': size, 'sha256': sha, 'captured_bytes': plain_bytes}
        # The uncompressed snapshots are the largest thing on this disk; drop
        # them as soon as the archive holds them so a build needs the smallest
        # possible peak.
        shutil.rmtree(contents)
        stored = archive
        if recipients:
            stored = encrypt(archive, recipients, args.gpg_binary)
            archive.unlink()
            sealed_sha, sealed_size = digest_file(stored)
            manifest['encryption'] = {'tool': 'gpg', 'recipients': recipients, 'object': stored.name,
                                      'bytes': sealed_size, 'sha256': sealed_sha}
        else:
            manifest['encryption'] = None
        manifest['stored_object'] = stored.name
        manifest_path = workdir / MANIFEST_NAME
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        names = [stored.name, MANIFEST_NAME]
        if args.sign_key:
            names.append(sign_manifest(manifest_path, args.sign_key, args.gpg_binary).name)
        write_checksums(workdir, names)
        if shared_gid is not None:
            share_with_group(workdir, shared_gid)
        os.replace(workdir, package)
    except BaseException:
        shutil.rmtree(workdir, ignore_errors=True)
        raise
    print(json.dumps({'backup_id': backup_id, 'package': str(package), 'stored_object': manifest['stored_object'],
                      'stored_bytes': manifest['encryption']['bytes'] if manifest['encryption'] else manifest['archive']['bytes'],
                      'captured_bytes': manifest['archive']['captured_bytes'],
                      'encrypted': bool(manifest['encryption']),
                      'components': [item['name'] for item in components]}, sort_keys=True))
    return 0


def read_manifest(package: Path) -> dict:
    manifest_path = package / MANIFEST_NAME
    if not package.is_dir():
        raise PackageError(f'{package} is not a package directory')
    if not manifest_path.is_file():
        raise PackageError(f'{package} has no {MANIFEST_NAME}')
    try:
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        # A damaged manifest must not stop a store-wide scan, and it certainly
        # must not let rotation treat the package as understood.
        raise PackageError(f'{package}: manifest is unreadable ({error})') from error
    if not isinstance(manifest, dict) or manifest.get('manifest_version') != MANIFEST_VERSION:
        raise PackageError(f'{package}: unsupported manifest version')
    for field in ('backup_id', 'stored_object', 'archive', 'components'):
        if field not in manifest:
            raise PackageError(f'{package}: manifest is missing {field}')
    return manifest


def check_stored_objects(package: Path, manifest: dict) -> list[dict]:
    """Confirm the bytes on this node still match what the manifest published."""
    checks = []
    listed = {}
    checksum_path = package / CHECKSUM_NAME
    if not checksum_path.is_file():
        raise PackageError(f'{package} has no {CHECKSUM_NAME}')
    for line in checksum_path.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        sha, _, name = line.partition('  ')
        listed[name] = sha
    expected = {MANIFEST_NAME, manifest['stored_object']}
    if not expected <= set(listed):
        raise PackageError(f'{package}: {CHECKSUM_NAME} does not cover {sorted(expected - set(listed))}')
    for name, sha in sorted(listed.items()):
        path = package / name
        if not path.is_file() or path.is_symlink():
            raise PackageError(f'{package}: {name} is missing')
        actual, size = digest_file(path)
        checks.append({'name': name, 'bytes': size, 'sha256_matches': actual == sha})
    sealed = manifest['encryption'] or manifest['archive']
    stored = next(item for item in checks if item['name'] == manifest['stored_object'])
    if listed[manifest['stored_object']] != sealed['sha256'] or stored['bytes'] != sealed['bytes']:
        raise PackageError(f'{package}: {CHECKSUM_NAME} disagrees with the manifest')
    return checks


def verify_signature(package: Path, gpg_binary: str) -> str:
    signature = package / SIGNATURE_NAME
    if not signature.is_file():
        return 'absent'
    run_gpg(['--verify', str(signature), str(package / MANIFEST_NAME)], gpg_binary, 'manifest verification')
    return 'valid'


def _safe_members(tar: tarfile.TarFile, names: set[str]):
    for member in tar:
        if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
            raise PackageError(f'archive holds an unexpected entry: {member.name}')
        parts = Path(member.name).parts
        if member.name.startswith('/') or '..' in parts:
            raise PackageError(f'archive holds an unsafe path: {member.name}')
        if member.isfile():
            names.add(member.name)
        yield member


def sealed_bytes(manifest: dict) -> str:
    sealed = manifest.get('encryption') or manifest['archive']
    return f'{sealed["bytes"] / 1048576:.0f} MiB'


def step(message: str) -> None:
    """Progress goes to stderr; the report on stdout stays machine readable."""
    print(f'recovery_package: {message}', file=sys.stderr, flush=True)


def unpack(package: Path, manifest: dict, destination: Path, scratch: Path,
           zstd_binary: str, gpg_binary: str) -> set[str]:
    stored = package / manifest['stored_object']
    source = stored
    plaintext = None
    if manifest['encryption']:
        # Decrypt into the caller's scratch directory: a restore drill's target
        # stays clean, and a gigabyte of plaintext never lands somewhere the
        # operator did not name.
        plaintext = scratch / manifest['archive']['name']
        step(f'decrypting {stored.name} ({sealed_bytes(manifest)})')
        run_gpg(['--output', str(plaintext), '--decrypt', str(stored)], gpg_binary, 'decryption',
                show_output=True)
        actual, size = digest_file(plaintext)
        if actual != manifest['archive']['sha256'] or size != manifest['archive']['bytes']:
            raise PackageError('decrypted archive does not match the manifest digest')
        source = plaintext
    try:
        command = [zstd_binary, '-q', '-d', '-c', str(source)]
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE)
        except OSError as error:
            raise PackageError(f'cannot run {zstd_binary}: {error}') from error
        names: set[str] = set()
        step(f'unpacking into {destination}')
        try:
            with tarfile.open(fileobj=process.stdout, mode='r|') as tar:
                tar.extractall(path=destination, members=_safe_members(tar, names), filter='data')
        finally:
            if process.stdout is not None:
                process.stdout.close()
            code = process.wait()
        if code != 0:
            raise PackageError(f'{zstd_binary} exited with status {code} while decompressing')
        return names
    finally:
        if plaintext is not None and plaintext.exists():
            plaintext.unlink()


def inspect_component(component: dict, root: Path) -> dict:
    result = {'name': component['name'], 'kind': component['kind'], 'ok': True, 'problems': []}
    if component['kind'] == 'reference':
        return result
    if component['kind'] == 'state_dir':
        directory = root / component['stored_as']
        for entry in component['files']:
            path = directory / entry['name']
            if not path.is_file():
                result['problems'].append(f'{entry["name"]} is missing')
                continue
            sha, size = digest_file(path)
            if sha != entry['sha256'] or size != entry['bytes']:
                result['problems'].append(f'{entry["name"]} does not match the manifest digest')
        extra = sorted(path.name for path in directory.iterdir()) if directory.is_dir() else []
        listed = sorted(entry['name'] for entry in component['files'])
        if extra != listed:
            result['problems'].append('the stored directory holds files the manifest does not list')
        result['files'] = len(component['files'])
    else:
        path = root / component['stored_as']
        if not path.is_file():
            result['problems'] = ['the snapshot is missing']
            result['ok'] = False
            return result
        sha, size = digest_file(path)
        if sha != component['sha256'] or size != component['bytes']:
            result['problems'].append('the snapshot does not match the manifest digest')
        # immutable=1 keeps the check from creating -wal/-shm sidecars beside a
        # restored snapshot; packages never carry a populated WAL, so the
        # promise the flag makes is one the builder already enforced.
        with closing(sqlite3.connect(f'{path.as_uri()}?mode=ro&immutable=1', uri=True)) as database:
            integrity = database.execute('PRAGMA integrity_check').fetchone()[0]
            if integrity != 'ok':
                result['problems'].append(f'integrity_check reported {integrity}')
            statements = sorted(row[0] for row in database.execute(
                'SELECT sql FROM sqlite_master WHERE sql IS NOT NULL'))
            if hashlib.sha256('\n'.join(statements).encode('utf-8')).hexdigest() != component['schema_sha256']:
                result['problems'].append('the schema differs from the one recorded at capture time')
            if component.get('table_rows'):
                counts = _table_counts(database)
                if counts != component['table_rows']:
                    result['problems'].append('table row counts differ from the recorded census')
                result['table_rows'] = counts
        result['integrity_check'] = integrity
    result['ok'] = not result['problems']
    return result


def verify(args: argparse.Namespace) -> int:
    os.umask(0o077)
    package = args.package
    manifest = read_manifest(package)
    report = {'backup_id': manifest['backup_id'], 'package': str(package),
              'encrypted': bool(manifest['encryption']), 'deep': bool(args.deep or args.into),
              'stored_objects': check_stored_objects(package, manifest),
              'signature': verify_signature(package, args.gpg_binary) if not args.skip_signature else 'skipped'}
    report['ok'] = all(item['sha256_matches'] for item in report['stored_objects'])
    if report['deep']:
        destination = args.into
        if destination is not None:
            destination.mkdir(parents=True, exist_ok=True, mode=0o700)
            if any(destination.iterdir()):
                raise PackageError(f'{destination} is not empty; restore drills use a fresh directory')
        holder = tempfile.TemporaryDirectory(prefix='riskops-verify-', dir=args.work_dir)
        scratch = Path(holder.name)
        work = destination
        if work is None:
            work = scratch / 'contents'
            work.mkdir(mode=0o700)
        try:
            names = unpack(package, manifest, work, scratch, args.zstd_binary, args.gpg_binary)
            inner = work / MANIFEST_NAME
            if MANIFEST_NAME not in names or not inner.is_file():
                raise PackageError('the archive does not carry its own manifest')
            if 'inner_manifest_sha256' in manifest and digest_file(inner)[0] != manifest['inner_manifest_sha256']:
                raise PackageError('the archived manifest does not match the published one')
            components = []
            for component in manifest['components']:
                if component['kind'] != 'reference':
                    step(f'checking {component["name"]}'
                         + (' (integrity_check reads the whole database)' if component['kind'] == 'sqlite' else ''))
                components.append(inspect_component(component, work))
            report['components'] = components
            report['ok'] = report['ok'] and all(item['ok'] for item in report['components'])
            if destination is not None:
                report['extracted_to'] = str(destination)
        finally:
            holder.cleanup()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report['ok'] else 1


def read_confirmations(package: Path, manifest: dict) -> dict[str, dict]:
    """Count only confirmations that name the object this package published.

    ``backup_export.py`` writes one file per pulling peer after the peer proves
    it holds the stored object.  A record for some other digest is ignored: it
    cannot protect the bytes that are here.
    """
    directory = package / CONFIRMATIONS
    sealed = manifest.get('encryption') or manifest['archive']
    found: dict[str, dict] = {}
    if not directory.is_dir() or directory.is_symlink():
        return found
    for path in sorted(directory.glob('*.json')):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            record = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(record, dict) or not isinstance(record.get('peer'), str):
            continue
        if record.get('sha256') != sealed['sha256'] or record.get('backup_id') != manifest['backup_id']:
            continue
        found[record['peer']] = record
    return found


def managed_contents(package: Path, manifest: dict) -> tuple[list[Path], list[str]]:
    """Separate the files this tool published from anything else in the directory.

    Rotation deletes file by file rather than emptying a directory, so a package
    that somebody added their own notes to is reported instead of removed.
    """
    expected = {MANIFEST_NAME, CHECKSUM_NAME, SIGNATURE_NAME, manifest['stored_object']}
    managed, unexpected = [], []
    for entry in sorted(package.iterdir()):
        if entry.name in expected and entry.is_file() and not entry.is_symlink():
            managed.append(entry)
        elif entry.name == CONFIRMATIONS and entry.is_dir() and not entry.is_symlink():
            for record in sorted(entry.iterdir()):
                # A confirmation, or the temporary file an interrupted one left
                # behind; neither should outlive the package.
                own = record.name.endswith('.json') or (record.name.startswith('.')
                                                        and record.name.endswith('.tmp'))
                if own and record.is_file() and not record.is_symlink():
                    managed.append(record)
                else:
                    unexpected.append(f'{CONFIRMATIONS}/{record.name}')
            managed.append(entry)
        else:
            unexpected.append(entry.name)
    return managed, unexpected


def prune(args: argparse.Namespace) -> int:
    """Delete local packages only where a confirmed independent copy exists.

    A confirmation says a peer claims to hold the published object; since the
    listing already tells a peer that digest, it is not proof of retention. The
    real floor is ``--keep``: no number of confirmations, honest or not, takes
    the store below that many local generations.
    """
    if args.keep < 1:
        raise PackageError('--keep must leave at least one local package')
    if args.require_confirmations < 1:
        raise PackageError('--require-confirmations must be at least one')
    os.umask(0o077)
    store = args.store
    readable, unreadable = [], []
    for entry in sorted(store.iterdir() if store.is_dir() else []):
        if entry.is_symlink() or not entry.is_dir() or not BACKUP_ID_RE.fullmatch(entry.name):
            continue
        try:
            manifest = read_manifest(entry)
        except PackageError as error:
            unreadable.append({'backup_id': entry.name, 'kept': True, 'reason': str(error)})
            continue
        sealed = manifest.get('encryption') or manifest['archive']
        readable.append({'backup_id': manifest['backup_id'], 'path': entry, 'manifest': manifest,
                         'created_at': manifest.get('created_at', ''), 'stored_bytes': sealed['bytes'],
                         'confirmed_by': sorted(read_confirmations(entry, manifest))})
    ordered = sorted(readable, key=lambda item: (item['created_at'], item['backup_id']), reverse=True)
    kept, removed = list(unreadable), []
    for position, item in enumerate(ordered):
        row = {'backup_id': item['backup_id'], 'created_at': item['created_at'],
               'stored_bytes': item['stored_bytes'], 'confirmed_by': item['confirmed_by']}
        if position < args.keep:
            kept.append({**row, 'kept': True, 'reason': f'newest {args.keep} stay for local recovery'})
            continue
        if len(item['confirmed_by']) < args.require_confirmations:
            kept.append({**row, 'kept': True,
                         'reason': f'{len(item["confirmed_by"])} of {args.require_confirmations} '
                                   'independent copies confirmed'})
            continue
        managed, unexpected = managed_contents(item['path'], item['manifest'])
        if unexpected:
            kept.append({**row, 'kept': True, 'reason': f'directory holds unmanaged files: {unexpected}'})
            continue
        if args.apply:
            for path in managed:
                path.rmdir() if path.is_dir() else path.unlink()
            item['path'].rmdir()
        removed.append({**row, 'removed': args.apply})
    report = {'store': str(store), 'applied': bool(args.apply), 'keep': args.keep,
              'require_confirmations': args.require_confirmations, 'kept': kept, 'removed': removed,
              'reclaimed_bytes': sum(row['stored_bytes'] for row in removed)}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def list_packages(args: argparse.Namespace) -> int:
    rows = []
    for entry in sorted(args.store.iterdir() if args.store.is_dir() else []):
        if not entry.is_dir() or entry.name.startswith('.') or not BACKUP_ID_RE.fullmatch(entry.name):
            continue
        try:
            manifest = read_manifest(entry)
        except PackageError as error:
            rows.append({'backup_id': entry.name, 'usable': False, 'problem': str(error)})
            continue
        stored = entry / manifest['stored_object']
        rows.append({'backup_id': manifest['backup_id'], 'created_at': manifest['created_at'],
                     'host_id': manifest['host_id'], 'label': manifest.get('label', ''),
                     'retention_class': manifest.get('retention_class', ''),
                     'encrypted': bool(manifest['encryption']), 'usable': stored.is_file(),
                     'stored_bytes': stored.stat().st_size if stored.is_file() else 0,
                     'captured_bytes': manifest['archive'].get('captured_bytes', 0)})
    print(json.dumps({'store': str(args.store), 'packages': rows,
                      'stored_bytes_total': sum(row.get('stored_bytes', 0) for row in rows)},
                     indent=2, sort_keys=True))
    return 0


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--zstd-binary', default='zstd')
    parser.add_argument('--gpg-binary', default='gpg')
    commands = parser.add_subparsers(dest='command', required=True)

    builder = commands.add_parser('build', help='create a recovery package')
    builder.add_argument('--config', required=True, type=Path)
    builder.add_argument('--output-dir', required=True, type=Path)
    builder.add_argument('--recipient', action='append', default=[],
                         help='gpg recipient given as a full 40-hex fingerprint; repeatable, '
                              'replaces the recipients in the configuration')
    builder.add_argument('--allow-unencrypted', action='store_true',
                         help='store the package without encryption (local staging only)')
    builder.add_argument('--share-group', default=None,
                         help='group of the pulling account: the published package becomes group-readable '
                              'with a group-writable confirmations directory (encrypted packages only)')
    builder.add_argument('--sign-key', default=None, help='gpg key that signs the published manifest')
    builder.add_argument('--compression-level', type=int, default=3, choices=range(1, 20), metavar='1..19')
    builder.add_argument('--census', action='store_true',
                         help='record per-table row counts; this reads every table and is slow on large databases')
    builder.add_argument('--label', default='', help='free-text note stored in the manifest')
    builder.add_argument('--retention-class', default='daily')
    builder.set_defaults(handler=build)

    checker = commands.add_parser('verify', help='check a stored package')
    checker.add_argument('package', type=Path)
    checker.add_argument('--deep', action='store_true',
                         help='decrypt, unpack and check every component (needs the private key)')
    checker.add_argument('--into', type=Path, default=None,
                         help='keep the unpacked contents in this empty directory (implies --deep)')
    checker.add_argument('--work-dir', type=Path, default=None, help='scratch directory for --deep')
    checker.add_argument('--skip-signature', action='store_true')
    checker.set_defaults(handler=verify)

    listing = commands.add_parser('list', help='summarise the packages in a store directory')
    listing.add_argument('store', type=Path)
    listing.set_defaults(handler=list_packages)

    pruner = commands.add_parser('prune', help='drop local packages that a confirmed remote copy protects')
    pruner.add_argument('store', type=Path)
    pruner.add_argument('--keep', type=int, default=2,
                        help='newest packages to keep locally whatever the confirmations say')
    pruner.add_argument('--require-confirmations', type=int, default=1,
                        help='distinct pulling peers that must have confirmed a copy')
    pruner.add_argument('--apply', action='store_true', help='delete; without it the run only reports')
    pruner.set_defaults(handler=prune)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_arguments(argv)
    try:
        return args.handler(args)
    except PackageError as error:
        print(f'recovery_package: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
