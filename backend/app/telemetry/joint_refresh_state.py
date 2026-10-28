"""Private bounded refresh checkpoints, separate from immutable evidence.

All writers share one advisory lock. Reads never create files; a missing or
invalid checkpoint cannot establish freshness. Evidence remains authoritative.
"""
from __future__ import annotations

from contextlib import contextmanager, suppress
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import uuid

from .joint_case_contract import CaseStoreError, ERROR_CODES
from .joint_case_store import _path

MAX_STATE_BYTES = 16 * 1024
VERSION = 1
_TIMES = ('last_attempt_at', 'last_complete_at', 'last_success_at', 'next_attempt_at')
_IDS = ('discovery_id', 'refresh_id', 'previous_discovery_id', 'previous_refresh_id')
_KEYS = {'version', 'binding', 'phase', 'state', 'qualified', 'resume_discovery',
         'error', *_TIMES, *_IDS}
PUBLIC_ERRORS = ERROR_CODES | frozenset({'network_source_unmapped', 'network_destination_unmapped',
    'network_profile_unmapped', 'network_observation_not_local_tcp'})


def reserved_paths(spec):
    path = _path(spec.database_path)
    return (Path(str(path) + '.refresh.lock'), Path(str(path) + '.refresh.json'))


def _separate(spec):
    paths = (_path(spec.database_path), *reserved_paths(spec))
    sources = [Path(value).resolve(strict=False) for value in
               (spec.ssh_database_path, spec.network_database_path, spec.http_database_path) if value]
    identities = set()
    for source in sources:
        try:
            entry = source.stat()
            identities.add((entry.st_dev, entry.st_ino))
        except FileNotFoundError:
            pass
    for path in paths:
        if path.resolve(strict=False) in sources:
            raise CaseStoreError('joint_source_alias')
        try:
            entry = path.stat()
            if (entry.st_dev, entry.st_ino) in identities:
                raise CaseStoreError('joint_source_alias')
        except FileNotFoundError:
            pass


def _checked(fd, path, *, maximum=None):
    entry = os.fstat(fd)
    current = path.lstat()
    if (not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1 or entry.st_uid != os.geteuid()
            or stat.S_IMODE(entry.st_mode) & 0o077 or stat.S_ISLNK(current.st_mode)
            or (entry.st_dev, entry.st_ino) != (current.st_dev, current.st_ino)
            or (maximum is not None and entry.st_size > maximum)):
        raise CaseStoreError('joint_store_unavailable')
    return entry


@contextmanager
def writer_lock(spec):
    """Serialize one local writer step; caller must explicitly prepare parents.

Never hold a SQLite write transaction while waiting for this lock or reading a
source. The fixed lock file is not unlinked on release, including after failure.
"""
    fd = None
    try:
        _separate(spec)
        path, _ = reserved_paths(spec)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NONBLOCK | os.O_NOFOLLOW, 0o600)
        _checked(fd, path, maximum=0)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise CaseStoreError('joint_store_busy') from None
        yield
    except OSError:
        raise CaseStoreError('joint_store_unavailable') from None
    finally:
        if fd is not None:
            os.close(fd)


def timestamp(value):
    if (type(value) is not str or len(value) > 40 or
            not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z', value)):
        raise ValueError('invalid_refresh_time')
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def utcnow():
    return datetime.now(timezone.utc)


def stamp(value):
    return value.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def binding(spec, base_status):
    return {'store_id': base_status['store_id'], 'query_epoch': base_status['query_epoch'],
            'config_sha256': spec.config_sha256}


def new_state(spec, base_status):
    return {'version': VERSION, 'binding': binding(spec, base_status), 'phase': 'idle',
            'state': 'not_started', 'qualified': False, 'resume_discovery': False,
            'error': None, **dict.fromkeys((*_TIMES, *_IDS))}


def _validate(value):
    if type(value) is not dict or set(value) != _KEYS or type(value['version']) is not int or value['version'] != VERSION:
        raise ValueError('invalid_refresh_state')
    identity = value['binding']
    if type(identity) is not dict or set(identity) != {'store_id', 'query_epoch', 'config_sha256'}:
        raise ValueError('invalid_refresh_identity')
    for key, length in (('store_id', 32), ('query_epoch', 32), ('config_sha256', 64)):
        if type(identity[key]) is not str or not re.fullmatch('[0-9a-f]{'+str(length)+'}', identity[key]):
            raise ValueError('invalid_refresh_identity')
    if (value['phase'] not in ('idle', 'discover', 'refresh') or
            value['state'] not in ('not_started', 'running', 'waiting', 'backoff', 'blocked') or
            type(value['qualified']) is not bool or type(value['resume_discovery']) is not bool or
            (value['error'] is not None and value['error'] not in PUBLIC_ERRORS)):
        raise ValueError('invalid_refresh_state')
    for key in _IDS:
        if value[key] is not None and (type(value[key]) is not str or not re.fullmatch('[0-9a-f]{32}', value[key])):
            raise ValueError('invalid_refresh_cycle')
    for key in _TIMES:
        if value[key] is not None:
            timestamp(value[key])
    return value


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_refresh_field')
        result[key] = value
    return result


def load_state(spec):
    """Return a validated checkpoint or None when absent. Never create files."""
    _, path = reserved_paths(spec)
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        _checked(fd, path, maximum=MAX_STATE_BYTES)
        raw = bytearray()
        while len(raw) <= MAX_STATE_BYTES:
            chunk = os.read(fd, min(4096, MAX_STATE_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        _checked(fd, path, maximum=MAX_STATE_BYTES)
        if len(raw) > MAX_STATE_BYTES:
            raise ValueError('oversized_refresh_state')
        return _validate(json.loads(raw.decode('ascii'), object_pairs_hook=_pairs))
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        raise CaseStoreError('joint_store_unavailable') from None
    finally:
        if fd is not None:
            os.close(fd)


def save_state(spec, value):
    """Atomic durable checkpoint; caller holds writer_lock. Never alter sources."""
    fd = directory = None
    temporary = None
    try:
        _validate(value)
        _separate(spec)
        _, path = reserved_paths(spec)
        # Refuse an unsafe existing file instead of replacing it with a good one.
        try:
            old = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        except FileNotFoundError:
            pass
        else:
            try:
                _checked(old, path, maximum=MAX_STATE_BYTES)
            finally:
                os.close(old)
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                         allow_nan=False).encode('ascii')
        if len(raw) > MAX_STATE_BYTES:
            raise ValueError('oversized_refresh_state')
        temporary = path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            fd = None
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        os.replace(temporary, path)
        os.fsync(directory)
    except (OSError, ValueError, TypeError, UnicodeError):
        raise CaseStoreError('joint_store_unavailable') from None
    finally:
        if fd is not None:
            os.close(fd)
        if directory is not None:
            os.close(directory)
        if temporary is not None:
            with suppress(FileNotFoundError):
                temporary.unlink()


def read_refresh_status(spec, base_status, *, now=None):
    """Safe local-console summary. No source reads, lock acquisition or writes."""
    settings = getattr(spec, 'refresh', None) if spec is not None else None
    enabled = settings is not None and settings.enabled
    result = {'enabled': enabled, 'state': 'not_started' if enabled else 'disabled',
        'phase': None, **dict.fromkeys(_TIMES), 'age_seconds': None, 'stale': bool(enabled),
        'stalled': False, 'pending': None, 'failed': None, 'error': None,
        'interval_seconds': settings.interval_seconds if settings else None,
        'stale_after_seconds': settings.stale_after_seconds if settings else None}
    if not enabled:
        return result
    current = now or utcnow()
    cycle = base_status.get('cycle') or {}
    counts = cycle.get('counts') or {}
    try:
        value = load_state(spec)
        if value is None:
            return result
        if value['binding'] != binding(spec, base_status):
            result['state'] = 'unavailable'
            result['error'] = 'joint_refresh_required'
            return result
        result.update({key: value[key] for key in (*_TIMES, 'phase', 'state', 'error')})
        result.update(pending=counts.get('pending'), failed=counts.get('failed'))
        # next_attempt is intentionally in the future; completed/attempt times are not.
        if any(timestamp(value[key]) > current for key in _TIMES[:-1] if value[key] is not None):
            result.update(state='unavailable', stale=True, stalled=True, error='joint_refresh_required')
            return result
        if value['last_success_at'] is not None:
            age = int((current-timestamp(value['last_success_at'])).total_seconds())
            result['age_seconds'] = age
            result['stale'] = age > settings.stale_after_seconds or bool(base_status.get('revalidation_pending'))
        last_attempt = value['last_attempt_at']
        if last_attempt is not None:
            age_attempt = (current-timestamp(last_attempt)).total_seconds()
            result['stalled'] = age_attempt > settings.stale_after_seconds
        if value['state'] == 'running' and result['stalled']:
            result['state'] = 'unavailable'
        # Manual CLI operations also change authoritative refresh health. An old
        # scheduler checkpoint must not hide a later failed or unfinished cycle.
        current_cycle = base_status.get('cycle') or {}
        discovery = base_status.get('discovery') or {}
        expected_discovery = value['discovery_id'] or value['previous_discovery_id']
        changed_discovery = bool(discovery and discovery['cycle_id'] != expected_discovery)
        unfinished_discovery = bool(discovery and not discovery['complete'])
        expected_cycle = value['refresh_id'] or value['previous_refresh_id']
        changed_cycle = bool(current_cycle and current_cycle['cycle_id'] != expected_cycle)
        unfinished = bool(current_cycle and not current_cycle['attempted_complete'])
        if base_status.get('error') or base_status.get('state') == 'unavailable':
            code = base_status.get('error')
            health = ('blocked' if code == 'joint_capacity_exceeded' else
                      'backoff' if value['state'] == 'backoff' and value['error'] == code else 'unavailable')
            result.update(state=health,
                          error=code if code in PUBLIC_ERRORS else 'joint_refresh_required', stale=True)
        elif base_status.get('revalidation_pending'):
            result.update(stale=True, error=result['error'] or 'joint_refresh_required')
        elif changed_cycle or unfinished or changed_discovery or unfinished_discovery:
            result.update(stale=True)
            if changed_cycle or changed_discovery:
                result.update(error='joint_refresh_required', state='waiting')
        if (changed_discovery or unfinished_discovery or
                (value['phase'] != 'idle' and value['refresh_id'] is None)):
            # Counts belong to a frozen refresh worklist, never a newer catalog.
            result.update(pending=None, failed=None)
        return result
    except (CaseStoreError, KeyError, TypeError, ValueError):
        result.update(state='unavailable', error='joint_store_unavailable')
        return result
