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
package needs no service shutdown. HTTP and network require explicit paired
WAL cohorts and all local collector locks until the read snapshots are pinned.
Their stricter checkpoints cannot use the generic SSH capture-order guarantee.
Writer/collector locks are released before the bulk copies.
"""
from __future__ import annotations

import argparse
from contextlib import closing, contextmanager, ExitStack
from datetime import datetime, timezone
import grp
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

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


def validate_http_recovery(raw: object, components: list[dict]) -> dict:
    """An explicit same-host cohort; it cannot silently omit cursor/spool files."""
    allowed = {'http_database', 'console_database', 'collector_states', 'lock_timeout_seconds'}
    if not isinstance(raw, dict) or set(raw) - allowed:
        raise PackageError('http_recovery has invalid fields')
    by_name = {item['name']: item for item in components}
    result = {}
    for role in ('http_database', 'console_database'):
        name = raw.get(role)
        if not isinstance(name, str) or name not in by_name or by_name[name]['kind'] != 'sqlite':
            raise PackageError(f'http_recovery {role} must name a sqlite component')
        result[role] = name
    paths = [Path(by_name[result[role]]['path']).resolve() for role in ('http_database', 'console_database')]
    if paths[0] == paths[1]:
        raise PackageError('HTTP and console recovery databases must be separate')
    states = raw.get('collector_states')
    if not isinstance(states, list) or not states or any(not isinstance(v, str) for v in states) or len(set(states)) != len(states):
        raise PackageError('http_recovery needs distinct local collector state components')
    for name in states:
        spec = by_name.get(name)
        if not spec or spec['kind'] != 'state_dir' or set(spec['patterns']) != {'*.state.json', '*.pending.json'}:
            raise PackageError('HTTP collector components must include exactly *.state.json and *.pending.json')
    if len({str(Path(by_name[name]['path']).resolve()) for name in states}) != len(states):
        raise PackageError('HTTP collector state paths must be distinct')
    seconds = raw.get('lock_timeout_seconds', 5)
    if type(seconds) is not int or not 1 <= seconds <= 10:
        raise PackageError('HTTP snapshot lock timeout must be 1-10 seconds')
    return {**result, 'collector_states': states, 'lock_timeout_seconds': seconds}


def load_config(path: Path) -> dict:
    try:
        raw = json.loads(path.read_text(encoding='utf-8'))
    except json.JSONDecodeError as error:
        raise PackageError(f'configuration is not valid JSON: {error}') from error
    allowed = {'host_id', 'description', 'components', 'recipients', 'http_recovery', 'network_recovery'}
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
    result = {'host_id': _text(raw.get('host_id'), 'host_id', NAME_RE),
              'description': raw.get('description') or '', 'components': components,
              'recipients': [_fingerprint(item) for item in recipients]}
    if 'http_recovery' in raw:
        result['http_recovery'] = validate_http_recovery(raw['http_recovery'], components)
    if 'network_recovery' in raw:
        if 'http_recovery' in raw:
            raise PackageError('Combined HTTP and network recovery cohorts are not supported yet')
        helper = network_helper()
        try:
            result['network_recovery'] = helper.validate(raw['network_recovery'], components)
        except helper.RecoveryError as error:
            raise PackageError(str(error)) from None
    return result


def network_helper():
    # The deployed recovery service uses the system Python without PYTHONPATH.
    # These helpers and their app modules use only the standard library.
    for path in (Path(__file__).resolve().parent, Path(__file__).resolve().parents[1] / 'backend'):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    import network_recovery
    return network_recovery


def capture_network_recovery(policy, specs, contents, census):
    helper = network_helper()
    by_name = {item['name']: item for item in specs}
    local_states = [by_name[item['state']] for item in policy['collectors']]
    pair = [by_name[policy[key]] for key in ('network_database', 'console_database')]
    try:
        with ExitStack() as locks:
            locks.enter_context(helper.locked_collectors(local_states))
            descriptors = helper.mappings(policy, specs)
            components = [capture_state_dir(spec, contents) for spec in local_states]
            with pinned_http_databases(pair, policy['lock_timeout_seconds']) as (readers, pinned_at):
                checks = helper.check_pair(readers[pair[0]['name']], readers[pair[1]['name']], descriptors, contents)
                if helper.mappings(policy, specs) != descriptors:
                    raise PackageError('Network collector mapping changed during capture')
                locks.close()
                for spec in pair:
                    origin = readers[spec['name']]
                    components.append(snapshot_database(spec, contents, census, origin=origin))
                    # Network writes require WAL truncation. Never retain its
                    # reader during the potentially very large console copy.
                    origin.close()
                cohort = {**policy, **checks, 'mappings': descriptors, 'pinned_at': pinned_at,
                          'collectors_locked_until_pin': True, 'writers_released_before_copy': True,
                          'network_reader_released_before_console_copy': True,
                          'scope': 'same-host collectors and paired WAL databases'}
                return components, cohort
    except helper.RecoveryError as error:
        raise PackageError(str(error)) from None


def inspect_network_recovery(manifest, directory):
    policy = manifest.get('consistency', {}).get('network_recovery')
    network_components = []
    try:
        for spec in manifest['components']:
            if spec['kind'] != 'sqlite':
                continue
            name = spec['name']
            if not NAME_RE.fullmatch(name) or spec['stored_as'] != name+'.sqlite':
                raise ValueError
            with closing(sqlite3.connect((directory / spec['stored_as']).as_uri()+
                                         '?mode=ro&immutable=1', uri=True)) as reader:
                if reader.execute("SELECT 1 FROM sqlite_master WHERE name='network_receipts'").fetchone():
                    network_components.append(name)
        if policy is None:
            if network_components:
                raise ValueError
            return None
        if network_components != [policy['network_database']]:
            raise ValueError
    except (KeyError, TypeError, ValueError, sqlite3.Error):
        raise PackageError('Network snapshots require their explicit matching recovery cohort') from None
    helper = network_helper()
    try:
        specs = {item['name']: item for item in manifest['components']}
        pair = [policy[key] for key in ('network_database', 'console_database')]
        descriptors = policy['mappings']
        states = [item['state'] for item in policy['collectors']]
        if (pair[0] == pair[1] or not states or len(set(states)) != len(states)
                or [item['state'] for item in descriptors] != states
                or len({item['source_id'] for item in descriptors}) != len(descriptors)
                or policy['collectors_locked_until_pin'] is not True
                or policy['network_reader_released_before_console_copy'] is not True):
            raise ValueError
        for name in states:
            spec = specs[name]
            if (not NAME_RE.fullmatch(name) or spec['kind'] != 'state_dir' or spec['stored_as'] != name
                    or set(spec['patterns']) != {'*.state.json', '*.pending.json'}):
                raise ValueError
        with ExitStack() as stack:
            readers = []
            for name in pair:
                spec = specs[name]
                if not NAME_RE.fullmatch(name) or spec['kind'] != 'sqlite' or spec['stored_as'] != name+'.sqlite':
                    raise ValueError
                readers.append(stack.enter_context(closing(sqlite3.connect(
                    (directory / spec['stored_as']).as_uri()+'?mode=ro&immutable=1', uri=True))))
            checks = helper.check_pair(*readers, descriptors, directory)
        if any(checks[key] != policy[key] for key in checks):
            raise ValueError
        return checks
    except (helper.RecoveryError, KeyError, ValueError, TypeError, sqlite3.Error):
        raise PackageError('Invalid network recovery cohort metadata or snapshots') from None


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


@contextmanager
def locked_http_collectors(specs: list[dict]):
    """Keep cursors/spools stable until both database read snapshots are pinned.

    A rotation creates a random file generation, so an older cursor alone is
    not enough: replay must not invent a new generation for already-saved rows.
    These locks are released before copying the databases or encrypting them.
    """
    with ExitStack() as stack:
        for spec in sorted(specs, key=lambda item: item['path']):
            source = Path(spec['path'])
            if source.is_symlink() or not source.is_dir():
                raise PackageError('HTTP collector state directory is unavailable')
            try:
                descriptor = os.open(source / 'collector.lock',
                                     os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
                lock = stack.enter_context(os.fdopen(descriptor, 'wb'))
                if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
                    raise OSError('not a regular lock file')
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise PackageError('HTTP collector is busy or its lock is unavailable; retry the package') from None
        yield


@contextmanager
def pinned_http_databases(specs: list[dict], timeout: int):
    """Pin both WAL read snapshots under brief writer locks, then release writers.

    SQLite's backup API then reads the pinned transactions while collection and
    delivery continue. Never copy from a connection holding a write transaction.
    """
    deadline = time.monotonic() + timeout
    writers = []
    with ExitStack() as stack:
        readers = {}
        try:
            files = [Path(spec['path']) for spec in specs]
            if any(path.is_symlink() or not path.is_file() for path in files):
                raise PackageError('HTTP recovery needs regular database files')
            if len({(path.stat().st_dev, path.stat().st_ino) for path in files}) != len(files):
                raise PackageError('HTTP recovery databases cannot alias the same file')
            for spec in sorted(specs, key=lambda item: item['path']):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PackageError('HTTP snapshot lock deadline exceeded')
                uri = Path(spec['path']).as_uri()
                writer = sqlite3.connect(uri + '?mode=rw', uri=True, timeout=remaining, isolation_level=None)
                writers.append(writer)
                if writer.execute('PRAGMA journal_mode').fetchone()[0] != 'wal':
                    raise PackageError('HTTP recovery requires WAL databases')
                writer.execute('BEGIN IMMEDIATE')
            for spec in specs:
                reader = stack.enter_context(closing(sqlite3.connect(
                    Path(spec['path']).as_uri() + '?mode=ro', uri=True,
                    timeout=max(0, deadline-time.monotonic()), isolation_level=None)))
                reader.execute('PRAGMA query_only=ON')
                reader.execute('BEGIN')
                reader.execute('SELECT count(*) FROM sqlite_master').fetchone()  # Establish the snapshot now.
                readers[spec['name']] = reader
            if time.monotonic() > deadline:
                raise PackageError('HTTP snapshot lock deadline exceeded')
            pinned_at = utc_now()
        except sqlite3.Error:
            raise PackageError('HTTP snapshot cohort is busy or unavailable; retry the package') from None
        finally:
            for writer in reversed(writers):
                try:
                    writer.rollback()
                finally:
                    writer.close()
        # The snapshots are simultaneous; writers are free before expensive copying/checks.
        yield readers, pinned_at


def check_http_pair(http: sqlite3.Connection, console: sqlite3.Connection) -> dict:
    """Detect restore cohorts that would suppress an unsent source revision."""
    try:
        row = http.execute("SELECT value FROM http_analysis_meta WHERE name='producer_id'").fetchone()
        producer = json.loads(row[0]) if row else None
        if not isinstance(producer, str) or not re.fullmatch('[0-9a-f]{32}', producer):
            raise ValueError
        prefix = 'http-import:http:' + producer + ':'
        imported = 0
        for topic, revision, pending in http.execute('SELECT topic,revision,pending FROM http_notice_outbox'):
            if not topic.startswith('http:'+producer+':') or type(revision) is not int or revision < 1 or pending not in (0, 1):
                raise ValueError
            row = console.execute('SELECT value FROM notification_meta WHERE name=?', ('http-import:'+topic,)).fetchone()
            value = json.loads(row[0]) if row else 0
            if type(value) is not int or not 0 <= value <= revision or (not pending and value != revision):
                raise ValueError
            imported += bool(value)
        for name, in console.execute('SELECT name FROM notification_meta WHERE name LIKE ?', (prefix+'%',)):
            topic = name.removeprefix('http-import:')
            if not http.execute('SELECT 1 FROM http_notice_outbox WHERE topic=?', (topic,)).fetchone():
                raise ValueError
        # These queues are part of the cohort even if no delivery has occurred yet.
        console.execute('SELECT 1 FROM notification_inbox LIMIT 1').fetchone()
        console.execute('SELECT 1 FROM notification_outbox LIMIT 1').fetchone()
    except (sqlite3.Error, ValueError, TypeError):
        raise PackageError('HTTP/console notification checkpoints are incompatible') from None
    return {'producer_id': producer, 'imported_topics': imported, 'notification_checkpoints': 'compatible'}


def inspect_http_recovery(manifest: dict, directory: Path) -> dict | None:
    policy = manifest.get('consistency', {}).get('http_recovery')
    if policy is None:
        return None
    try:
        specs = {item['name']: item for item in manifest['components']}
        with ExitStack() as stack:
            databases = []
            names = [policy[role] for role in ('http_database', 'console_database')]
            if names[0] == names[1]:
                raise ValueError
            for name in names:
                spec = specs[name]
                if spec['kind'] != 'sqlite' or not NAME_RE.fullmatch(name) or spec['stored_as'] != name+'.sqlite':
                    raise ValueError
                uri = (directory / spec['stored_as']).as_uri() + '?mode=ro&immutable=1'
                databases.append(stack.enter_context(closing(sqlite3.connect(uri, uri=True))))
            checks = check_http_pair(*databases)
            if checks['producer_id'] != policy['producer_id']:
                raise ValueError
            return checks
    except (KeyError, TypeError, ValueError, sqlite3.Error):
        raise PackageError('Invalid HTTP recovery cohort metadata') from None


def _table_counts(database: sqlite3.Connection) -> dict[str, int]:
    names = [row[0] for row in database.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    return {name: database.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0] for name in names}


def snapshot_database(spec: dict, contents: Path, census: bool, *, origin=None) -> dict:
    """Copy a live database with the SQLite backup API and describe the result."""
    source = Path(spec['path'])
    if source.is_symlink() or not source.is_file():
        raise PackageError(f'{spec["name"]}: {source} is not a regular file')
    stored_as = f'{spec["name"]}.sqlite'
    target = contents / stored_as
    started_at = utc_now()
    with ExitStack() as stack:
        if origin is None:
            origin = stack.enter_context(closing(sqlite3.connect(f'{source.as_uri()}?mode=ro', uri=True)))
            if origin.execute("SELECT 1 FROM sqlite_master WHERE name='http_receipts'").fetchone():
                raise PackageError('HTTP databases require an explicit http_recovery cohort')
            if origin.execute("SELECT 1 FROM sqlite_master WHERE name='network_receipts'").fetchone():
                raise PackageError('Network databases require an explicit network_recovery cohort')
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
                'from the repository, not from this package.',
                'After the restored telemetry database is back in service and the API has started on it '
                'once, run `recovery_package.py mark-restored <database> <package>` so the console shows '
                'the restore point in its collection history.']}


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
        policy = config.get('http_recovery')
        http_states = policy['collector_states'] if policy else []
        network_policy = config.get('network_recovery')
        network_states = [item['state'] for item in network_policy['collectors']] if network_policy else []
        components = [capture_state_dir(spec, contents) for spec in state_specs
                      if spec['name'] not in http_states + network_states]
        snapshots_started_at = utc_now()
        cohort = None
        captured = set()
        network_cohort = None
        if network_policy:
            network_components, network_cohort = capture_network_recovery(
                network_policy, config['components'], contents, args.census)
            components.extend(network_components)
            captured.update(item['name'] for item in network_components)
        if policy:
            by_name = {item['name']: item for item in config['components']}
            pair = [by_name[policy[role]] for role in ('http_database', 'console_database')]
            with ExitStack() as collector_locks:
                local_states = [by_name[name] for name in http_states]
                collector_locks.enter_context(locked_http_collectors(local_states))
                components.extend(capture_state_dir(spec, contents) for spec in local_states)
                with pinned_http_databases(pair, policy['lock_timeout_seconds']) as (readers, pinned_at):
                    collector_locks.close()  # No new generations between cursor capture and DB snapshot.
                    checks = check_http_pair(readers[policy['http_database']], readers[policy['console_database']])
                    cohort = {**policy, **checks, 'pinned_at': pinned_at, 'writers_released_before_copy': True,
                              'collectors_locked_until_pin': True, 'scope': 'same-host collectors and paired WAL databases'}
                    for spec in pair:
                        components.append(snapshot_database(spec, contents, args.census, origin=readers[spec['name']]))
                        captured.add(spec['name'])
        for spec in rest:
            if spec['name'] not in captured:
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
        if cohort:
            manifest['consistency']['http_recovery'] = cohort
            manifest['restore']['notes'].append('Restore the HTTP and console databases from this SAME package, '
                'together with its HTTP cursor/spool files. Keep the collector endpoint, source/service identities '
                'and log path mapping unchanged. Remote collectors need a separately coordinated recovery plan.')
            manifest['restore']['notes'].append('Before starting any restored API, collector or worker, run '
                '`recovery_package.py mark-http-restored <http-database> <console-database> <package>`. '
                'It checks both database snapshots and records a marker, not collector or log continuity.')
        if network_cohort:
            manifest['consistency']['network_recovery'] = network_cohort
            manifest['restore']['notes'].append(
                'Restore network and console databases together with ALL network cursor/pending directories '
                'from this SAME verified package before starting any collector or worker. Preserve collector '
                'endpoint, source/profile and SSH mapping paths/content. Deep verification checks paired '
                'checkpoints; it does not verify remote journal continuity or recover absent private configuration. '
                'Never VACUUM network receipts or combine a newer cursor with an older database.')
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
            # Tar stops at its end marker, before all padding or compressed
            # frames have been consumed. Drain bounded chunks so zstd can
            # finish and report stream errors instead of receiving SIGPIPE.
            while process.stdout.read(64 * 1024):
                pass
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
            if report['ok'] and manifest.get('consistency', {}).get('http_recovery'):
                report['http_recovery'] = inspect_http_recovery(manifest, work)
            if report['ok']:
                network_checks = inspect_network_recovery(manifest, work)
                if network_checks is not None:
                    report['network_recovery'] = network_checks
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


def _marker_file(path: Path) -> tuple[int, int, int, int, int]:
    """No following links or creating databases while validating restore inputs."""
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise PackageError('HTTP restore marking requires regular files, not symlinks')
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _marker_timestamp(value: object) -> str:
    if not isinstance(value, str) or not 20 <= len(value) <= 32:
        raise ValueError
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError
    return value


def _http_marker_package(package: Path, gpg_binary: str) -> tuple[dict, dict, str]:
    """Validate names before the shared checksum reader opens package objects."""
    manifest_path = package / MANIFEST_NAME
    _marker_file(manifest_path)
    before = digest_file(manifest_path)
    manifest = read_manifest(package)
    try:
        backup_id = manifest['backup_id']
        if not isinstance(backup_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', backup_id):
            raise ValueError
        digest_pattern = re.compile(r'[0-9a-f]{64}')
        object_pattern = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}')
        for field in ('archive', 'encryption'):
            sealed = manifest[field]
            if field == 'encryption' and sealed is None:
                continue
            if (not isinstance(sealed, dict) or not isinstance(sealed.get('sha256'), str)
                    or not digest_pattern.fullmatch(sealed['sha256'])
                    or type(sealed.get('bytes')) is not int or sealed['bytes'] < 1):
                raise ValueError
        stored_object = manifest['stored_object']
        if not isinstance(stored_object, str) or not object_pattern.fullmatch(stored_object):
            raise ValueError
        _marker_file(package / CHECKSUM_NAME)
        listed = set()
        for line in (package / CHECKSUM_NAME).read_text(encoding='utf-8').splitlines():
            if not line.strip():
                continue
            digest, separator, name = line.partition('  ')
            if not separator or not digest_pattern.fullmatch(digest) or not object_pattern.fullmatch(name) or name in listed:
                raise ValueError
            listed.add(name)
            _marker_file(package / name)
        if not {MANIFEST_NAME, stored_object} <= listed:
            raise ValueError
        if (package / SIGNATURE_NAME).exists() or (package / SIGNATURE_NAME).is_symlink():
            _marker_file(package / SIGNATURE_NAME)
        components = manifest['components']
        if not isinstance(components, list):
            raise ValueError
        specs = {}
        for spec in components:
            if (not isinstance(spec, dict) or not isinstance(spec.get('name'), str)
                    or not NAME_RE.fullmatch(spec['name']) or spec['name'] in specs
                    or spec.get('kind') not in KINDS):
                raise ValueError
            specs[spec['name']] = spec
        policy = manifest['consistency']['http_recovery']
        producer = policy['producer_id']
        if not isinstance(producer, str) or not re.fullmatch(r'[0-9a-f]{32}', producer):
            raise ValueError
        snapshot = _marker_timestamp(policy['pinned_at'])
        pair = [specs[policy[role]] for role in ('http_database', 'console_database')]
        if pair[0]['name'] == pair[1]['name']:
            raise ValueError
        for spec in pair:
            if (spec['kind'] != 'sqlite' or spec['stored_as'] != spec['name']+'.sqlite'
                    or not isinstance(spec.get('sha256'), str) or not digest_pattern.fullmatch(spec['sha256'])
                    or type(spec.get('bytes')) is not int or spec['bytes'] < 1):
                raise ValueError
        states = policy['collector_states']
        if (not isinstance(states, list) or not states or any(not isinstance(name, str) for name in states)
                or len(set(states)) != len(states) or any(specs[name]['kind'] != 'state_dir' for name in states)
                or policy['collectors_locked_until_pin'] is not True):
            raise ValueError
    except (KeyError, TypeError, ValueError, OverflowError):
        raise PackageError('Invalid HTTP restore package metadata') from None
    if not all(item['sha256_matches'] for item in check_stored_objects(package, manifest)):
        raise PackageError('HTTP restore package checksum verification failed')
    signature = verify_signature(package, gpg_binary)
    if digest_file(manifest_path) != before:
        raise PackageError('HTTP restore manifest changed during verification')
    expected = dict(schema_version=1, restore_id=before[0], backup_id=backup_id, producer_id=producer,
                    snapshot_at=snapshot, http_component=pair[0]['name'], console_component=pair[1]['name'],
                    http_sha256=pair[0]['sha256'], console_sha256=pair[1]['sha256'],
                    http_bytes=pair[0]['bytes'], console_bytes=pair[1]['bytes'],
                    verification_scope='paired_database_snapshots')
    return expected, manifest, signature


def _existing_http_marker(database: sqlite3.Connection, expected: dict) -> dict | None:
    row = database.execute('SELECT value FROM http_analysis_meta WHERE name=?',
                           ('restore:'+expected['backup_id'],)).fetchone()
    if row is None:
        return None
    try:
        record = json.loads(row[0])
        if not isinstance(record, dict) or any(type(record.get(key)) is not type(value) or record[key] != value
                                               for key, value in expected.items()):
            raise ValueError
        _marker_timestamp(record['marked_at'])
        if type(record['stream_count']) is not int or record['stream_count'] < 0 or record['signature'] not in ('valid', 'absent'):
            raise ValueError
        producer = database.execute("SELECT value FROM http_analysis_meta WHERE name='producer_id'").fetchone()
        if producer is None or json.loads(producer[0]) != expected['producer_id']:
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise PackageError('Existing HTTP restore marker conflicts with this package or producer') from None
    return record


def _http_marker_sidecars(paths: list[Path]) -> None:
    for path in paths:
        for suffix in ('-wal', '-journal'):
            sidecar = Path(str(path)+suffix)
            if sidecar.exists() or sidecar.is_symlink():
                info = sidecar.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_size:
                    raise PackageError('HTTP restore marking needs empty WAL/journal files; stop services and mark '
                                       'freshly restored snapshots before any new writes')


def mark_http_restored(args: argparse.Namespace) -> int:
    """Bind an operator's offline restore marker to two exact package snapshots.

    This records neither a collector/file-continuity guarantee nor the actual
    cutover time. A duplicate returns historical evidence without authenticating
    the current contents again; new writes after a recorded restore are allowed.
    """
    connections = {}
    recorded = False
    try:
        expected, _, signature = _http_marker_package(args.package, args.gpg_binary)
        paths = [args.http_database.absolute(), args.console_database.absolute()]
        identities = {path: _marker_file(path) for path in paths}
        if len(identities) != 2 or len({identity[:2] for identity in identities.values()}) != 2:
            raise PackageError('HTTP restore databases cannot alias the same file')
        # Reject unsafe sidecars before SQLite can follow a link or recover a
        # hot rollback journal. An existing marker may legitimately have WAL.
        for path in paths:
            for suffix in ('-wal', '-journal', '-shm'):
                sidecar = Path(str(path)+suffix)
                if sidecar.exists() or sidecar.is_symlink():
                    info = sidecar.lstat()
                    if not stat.S_ISREG(info.st_mode) or (suffix == '-journal' and info.st_size):
                        raise PackageError('HTTP restore marking requires safe, empty journal sidecars')
        # A read-only connection never checkpoints a populated WAL on rejection.
        with closing(sqlite3.connect(paths[0].as_uri()+'?mode=ro', uri=True, timeout=0)) as reader:
            existing = _existing_http_marker(reader, expected)
        if existing is None:
            _http_marker_sidecars(paths)
        deadline = time.monotonic()+5
        for path in sorted(paths):
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                raise PackageError('HTTP restore database lock deadline exceeded')
            database = sqlite3.connect(path.as_uri()+'?mode=rw', uri=True, timeout=remaining, isolation_level=None)
            connections[path] = database
            database.execute('PRAGMA synchronous=FULL')
            if database.execute('PRAGMA journal_mode').fetchone()[0] != 'wal':
                raise PackageError('HTTP restore marking requires WAL databases')
            database.execute('BEGIN IMMEDIATE')
        if time.monotonic() > deadline:
            raise PackageError('HTTP restore database lock deadline exceeded')
        http, console = (connections[path] for path in paths)
        record = _existing_http_marker(http, expected)
        if record is None:
            _http_marker_sidecars(paths)
            for role, path in zip(('http', 'console'), paths):
                if _marker_file(path) != identities[path]:
                    raise PackageError('HTTP restore database changed during verification')
                if digest_file(path) != (expected[role+'_sha256'], expected[role+'_bytes']):
                    raise PackageError('HTTP restore database does not match its package snapshot; '
                                       'mark before starting the API or any worker')
            checks = check_http_pair(http, console)
            if checks['producer_id'] != expected['producer_id']:
                raise PackageError('HTTP restore producer does not match the package')
            record = {**expected, 'marked_at': utc_now(), 'signature': signature,
                      'stream_count': http.execute('SELECT count(*) FROM http_streams').fetchone()[0]}
            # Check replacement/rename races once more immediately before writing.
            if any(_marker_file(path) != identities[path] for path in paths):
                raise PackageError('HTTP restore database changed during verification')
            if digest_file(args.package / MANIFEST_NAME)[0] != expected['restore_id']:
                raise PackageError('HTTP restore manifest changed during verification')
            http.execute('INSERT INTO http_analysis_meta(name,value) VALUES(?,?)',
                         ('restore:'+expected['backup_id'], json.dumps(record, sort_keys=True, separators=(',', ':'))))
            http.commit()
            recorded = True
        else:
            recorded = False
        print(json.dumps({'recorded': recorded, 'record': record,
                          'note': ('Paired snapshot marker recorded; collector state and log continuity are not verified.'
                                   if recorded else 'Existing historical marker returned; current database contents '
                                   'were not reauthenticated as these snapshots.')}, indent=2, sort_keys=True))
        return 0
    except PackageError:
        raise
    except (OSError, sqlite3.Error, UnicodeError, ValueError, TypeError, KeyError):
        if recorded:
            raise PackageError('HTTP restore marker committed but its result could not be returned; retry safely') from None
        raise PackageError('HTTP restore inputs are unavailable, invalid or busy; no marker was recorded') from None
    finally:
        for database in reversed(list(connections.values())):
            try:
                database.rollback()
            finally:
                database.close()


def mark_restored(args: argparse.Namespace) -> int:
    """Record a restore point in a telemetry database that is back in service.

    Everything between the snapshot and now was collected into the database
    that was replaced. The collector resumes from the restored cursors, so those
    records come back from the source journals if they still hold them; if not,
    the collector reports a retention gap on its own. This row makes the restore
    itself visible in the collection history, one per source.
    """
    manifest = read_manifest(args.package)
    captured = [component['captured_at'] for component in manifest['components']
                if component['kind'] == 'sqlite' and component.get('captured_at')]
    if not captured:
        raise PackageError('the package records no database snapshot time')
    snapshot, now = min(captured), utc_now()
    detail = (f"restored from recovery package {manifest['backup_id']} (snapshot {snapshot}); records collected "
              'after the snapshot are read again from the source journals where they still exist, and any '
              'the journals no longer hold appear as a retention gap.')
    with closing(sqlite3.connect(args.database)) as database:
        present = {row[0] for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'collection_issues', 'sources'} <= present:
            raise PackageError('this database has no collection history yet; start the API on it once, '
                               'which creates the tables, then run this again')
        sources = [row[0] for row in database.execute('SELECT source_id FROM sources ORDER BY source_id')]
        with database:
            database.executemany(
                'INSERT INTO collection_issues(source_id,kind,category,started_at,ended_at,detail,first_batch_id,'
                'last_batch_id,batches,opened_at,updated_at) VALUES(?,?,?,?,?,?,NULL,NULL,0,?,?)',
                [(source, 'restore', 'notice', snapshot, now, detail, now, now) for source in sources])
    print(json.dumps({'backup_id': manifest['backup_id'], 'snapshot': snapshot, 'marked_at': now,
                      'sources': sources}, indent=2, sort_keys=True))
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

    http_marker = commands.add_parser('mark-http-restored',
        help='record an HTTP restore before starting services, after checking both package snapshots')
    http_marker.add_argument('http_database', type=Path)
    http_marker.add_argument('console_database', type=Path)
    http_marker.add_argument('package', type=Path)
    http_marker.set_defaults(handler=mark_http_restored)

    marker = commands.add_parser('mark-restored',
                                 help='record a restore point in a telemetry database that is back in service')
    marker.add_argument('database', type=Path)
    marker.add_argument('package', type=Path)
    marker.set_defaults(handler=mark_restored)
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
