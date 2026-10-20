#!/usr/bin/env python3
"""Dedicated network collector: spool -> complete durable ACK -> cursor commit.

One source/profile and SSH alias per private state directory. Requires the
installed app package and sibling network_export/telemetry_collector helpers.
Pending metadata contains no API token or raw journal MESSAGE/MAC. Run with
--once --config /etc/secagent-riskops/network-collector.json.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from urllib.parse import urlsplit
import uuid

from app.telemetry.network_parse import MAX_REALTIME_US
from app.telemetry.network_protocol import (
    MAX_BATCH_BYTES, NetworkProtocolError, encode, fingerprint, profile_from_dict,
    validate_ack, validate_batch,
)
from network_export import (
    ExportError, command_chunks, decode, secure_file, wall_deadline,
)
from telemetry_collector import CollectorError, fsync_directory, post_batch

MAX_SPOOL_BYTES = 16 * 1024 * 1024
MAX_PENDING_BYTES = MAX_BATCH_BYTES + 4096
MAX_CONFIG_BYTES = 65536
_REQUIRED_CONFIG = {'version', 'endpoint', 'state_dir', 'profile', 'ssh_config', 'ssh_host', 'token'}
_DEFAULTS = {'ssh_timeout_seconds': 10, 'http_timeout_seconds': 10,
             'max_pages_per_run': 5, 'max_seconds_per_run': 20, 'max_spool_bytes': MAX_SPOOL_BYTES}
_ALIAS = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')


def _absolute(value):
    return isinstance(value, str) and 1 <= len(value) <= 4096 and '\x00' not in value and Path(value).is_absolute()


def validate_config(config):
    try:
        if (type(config) is not dict or not _REQUIRED_CONFIG <= config.keys()
                or set(config) - _REQUIRED_CONFIG - _DEFAULTS.keys()
                or type(config['version']) is not int or config['version'] != 1):
            raise ValueError
        endpoint = urlsplit(config['endpoint'])
        if (endpoint.scheme not in ('http', 'https') or not endpoint.hostname or endpoint.username
                or endpoint.password or endpoint.query or endpoint.fragment or endpoint.path != '/api/network/batches'
                or (endpoint.scheme == 'http' and endpoint.hostname not in ('127.0.0.1', 'localhost', '::1'))):
            raise ValueError
        if not _absolute(config['state_dir']) or not _absolute(config['ssh_config']):
            raise ValueError
        if not isinstance(config['ssh_host'], str) or not _ALIAS.fullmatch(config['ssh_host']):
            raise ValueError
        token = config['token']
        if not isinstance(token, str) or not 24 <= len(token) <= 512 or any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise ValueError
        profile_from_dict(config['profile'])
        result = dict(config)
        for key, maximum in _DEFAULTS.items():
            value = result.setdefault(key, maximum)
            if type(value) is not int or not (1024 if key == 'max_spool_bytes' else 1) <= value <= maximum:
                raise ValueError
        return result
    except (ValueError, TypeError, KeyError, AttributeError):
        raise CollectorError('invalid_network_config') from None


def load_config(path):
    try:
        return validate_config(decode(secure_file(Path(path), root_owned=False, secret=True)))
    except (OSError, ExportError):
        raise CollectorError('invalid_network_config') from None


def ssh_config_digest(path):
    try:
        raw = secure_file(Path(path), root_owned=False)
        text = raw.decode('utf-8')
        # Includes and executable conditions make the effective host mapping
        # depend on unbound files/processes. Dedicated SSH configuration must be
        # self-contained; no shell/remote command can hide inside that mapping.
        forbidden = {'include', 'match', 'proxycommand', 'localcommand', 'remotecommand', 'knownhostscommand'}
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith('#') and re.split(r'[\s=]', line, maxsplit=1)[0].lower() in forbidden:
                raise ValueError
        return fingerprint(text)
    except (OSError, ValueError, UnicodeError):
        raise CollectorError('unsafe_network_ssh_config') from None


def identity(config):
    profile = profile_from_dict(config['profile'])
    return fingerprint({'endpoint': config['endpoint'], 'source_id': profile.source_id,
                        'profile_revision': profile.revision, 'ssh_config': config['ssh_config'],
                        'ssh_host': config['ssh_host'], 'ssh_config_sha256': ssh_config_digest(config['ssh_config'])})


def ssh_command(config, timeout):
    return ['/usr/bin/ssh', '-T', '-F', config['ssh_config'], '-oBatchMode=yes',
            '-oStrictHostKeyChecking=yes', '-oClearAllForwardings=yes',
            '-oPermitLocalCommand=no', '-oRequestTTY=no', '-oControlMaster=no',
            '-oControlPath=none', '-oForwardAgent=no', '-oForwardX11=no',
            '-oConnectTimeout=' + str(max(1, min(10, int(timeout)))), config['ssh_host']]


def ssh_export(config, cursor, timeout):
    profile = profile_from_dict(config['profile'])
    request = encode({'source_id': profile.source_id, 'cursor': cursor}) + b'\n'
    try:
        chunks = command_chunks(ssh_command(config, timeout), deadline=time.monotonic() + timeout,
                                maximum=MAX_BATCH_BYTES + 1, input_data=request)
        return b''.join(chunks)
    except ExportError as exc:
        mapping = {'subprocess_deadline': 'ssh_timeout', 'subprocess_output_limit': 'ssh_output_limit'}
        raise CollectorError(mapping.get(str(exc), 'ssh_export_failed')) from None


def _secure_directory(directory):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    for item in (directory, *directory.parents):
        info = item.lstat()
        writable = info.st_mode & (0o077 if item == directory else 0o022)
        if item != directory and info.st_mode & stat.S_ISVTX:
            writable = False
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.geteuid()} or writable:
            raise CollectorError('unsafe_network_state_directory')



@contextmanager
def collector_lock(directory):
    fd = None
    try:
        try:
            fd = os.open(directory / 'collector.lock', os.O_RDWR | os.O_CREAT | os.O_NONBLOCK | os.O_NOFOLLOW, 0o600)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022:
                raise CollectorError('unsafe_network_lock')
        except OSError:
            raise CollectorError('unsafe_network_lock') from None
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise CollectorError('collector_locked') from None
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        if fd is not None:
            os.close(fd)


def atomic_write(path, value):
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(encode(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _read_state_file(path, *, maximum, code):
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0))
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.geteuid()}
                or info.st_mode & 0o077 or info.st_size > maximum):
            raise ValueError
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise ValueError
        return decode(raw)
    except (ValueError, OSError):
        raise CollectorError(code) from None
    finally:
        if fd is not None:
            os.close(fd)


def _cursor(cursor):
    return cursor is None or (isinstance(cursor, str) and 1 <= len(cursor) <= 2048
                              and all(32 <= ord(c) <= 126 for c in cursor))


def _load_state(path, expected_identity):
    if not path.exists() and not path.is_symlink():
        return {'cursor': None, 'last_batch_id': None, 'last_payload_hash': None}
    value = _read_state_file(path, maximum=8192, code='invalid_network_state')
    if (type(value) is not dict or set(value) != {'version', 'identity', 'cursor', 'last_batch_id', 'last_payload_hash', 'received_at_us'}
            or type(value['version']) is not int or value['version'] != 1 or value['identity'] != expected_identity
            or not _cursor(value['cursor']) or not isinstance(value['last_batch_id'], str)
            or not _ALIAS.fullmatch(value['last_batch_id']) or not isinstance(value['last_payload_hash'], str)
            or not re.fullmatch('[0-9a-f]{64}', value['last_payload_hash'])
            or type(value['received_at_us']) is not int or value['received_at_us'] < 0):
        raise CollectorError('network_state_identity_mismatch')
    return value


def _validate_pending(value, expected_identity, profile, state):
    try:
        if (type(value) is not dict or set(value) != {'version', 'identity', 'payload_hash', 'batch'}
                or type(value['version']) is not int or value['version'] != 1
                or value['identity'] != expected_identity or value['payload_hash'] != fingerprint(value['batch'])):
            raise ValueError
        batch = validate_batch(value['batch'], profile)
        after_state_commit = (state.get('last_batch_id') == batch['batch_id']
                              and state.get('last_payload_hash') == value['payload_hash']
                              and state['cursor'] == batch['cursor_after'])
        if state['cursor'] != batch['cursor_before'] and not after_state_commit:
            raise ValueError
        return batch
    except (ValueError, TypeError, KeyError):
        raise CollectorError('invalid_network_spool') from None


def _remaining(deadline, maximum, clock):
    remaining = deadline - clock()
    if remaining <= 0:
        raise CollectorError('run_deadline')
    return min(maximum, remaining)



def _spool_usage(directory):
    total = 0
    for count, path in enumerate(directory.iterdir(), 1):
        if count > 256:
            raise CollectorError('network_spool_capacity')
        if (path.name not in {'collector.lock', 'network.state.json', 'network.pending.json'}
                and not re.fullmatch(r'network\.(?:state|pending)\.json\.[0-9a-f]{32}\.tmp', path.name)):
            raise CollectorError('unsafe_network_spool_entry')
        info = path.lstat()
        mask = 0o022 if path.name == 'collector.lock' else 0o077
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.geteuid()} or info.st_mode & mask):
            raise CollectorError('unsafe_network_spool_entry')
        total += info.st_size
    return total


def _reserve_spool(directory, maximum, additional):
    # Include old state and orphaned atomic-write temporaries. A process killed
    # before replace cannot escape the next run's quota through leftover files.
    if _spool_usage(directory) + additional > maximum:
        raise CollectorError('network_spool_capacity')


def _next_state(mapping, body, received_at):
    return {'version': 1, 'identity': mapping, 'cursor': body['cursor_after'],
            'last_batch_id': body['batch_id'], 'last_payload_hash': fingerprint(body),
            'received_at_us': received_at}


def collect_page(config, *, deadline, fetch=ssh_export, send=post_batch, clock=time.monotonic):
    directory = Path(config['state_dir'])
    state_path, pending_path = directory / 'network.state.json', directory / 'network.pending.json'
    profile = profile_from_dict(config['profile'])
    mapping = identity(config)
    _reserve_spool(directory, config['max_spool_bytes'], 0)
    state = _load_state(state_path, mapping)
    if pending_path.exists() or pending_path.is_symlink():
        pending = _read_state_file(pending_path, maximum=MAX_PENDING_BYTES, code='invalid_network_spool')
        body = _validate_pending(pending, mapping, profile, state)
    else:
        raw = fetch(config, state['cursor'], _remaining(deadline, config['ssh_timeout_seconds'], clock))
        try:
            if not isinstance(raw, bytes) or len(raw) > MAX_BATCH_BYTES + 1:
                raise ValueError
            body = validate_batch(decode(raw), profile)
            if body['cursor_before'] != state['cursor']:
                raise ValueError
        except (ValueError, TypeError):
            raise CollectorError('invalid_network_export') from None
        if identity(config) != mapping:
            raise CollectorError('network_ssh_mapping_changed')
        pending = {'version': 1, 'identity': mapping, 'payload_hash': fingerprint(body), 'batch': body}
        state_reserve = len(encode(_next_state(mapping, body, MAX_REALTIME_US)))
        _reserve_spool(directory, config['max_spool_bytes'], len(encode(pending)) + state_reserve)
        atomic_write(pending_path, pending)
    _reserve_spool(directory, config['max_spool_bytes'], len(encode(_next_state(mapping, body, MAX_REALTIME_US))))
    ack = send(config['endpoint'], config['token'], body,
               _remaining(deadline, config['http_timeout_seconds'], clock))
    try:
        validate_ack(ack, body)
    except (ValueError, TypeError):
        raise CollectorError('invalid_network_ack') from None
    atomic_write(state_path, _next_state(mapping, body, ack['received_at_us']))
    # The durable state commit precedes unlink. A crash here must resend the
    # original batch, even though its cursor_before no longer equals state.
    pending_path.unlink()
    fsync_directory(directory)
    return {'source_id': profile.source_id, 'status': 'acknowledged', 'records': len(body['entries']),
            'caught_up': body['caught_up'], 'report_codes': body['reports'],
            'rejected_records': sum('rejection' in entry for entry in body['entries']),
            'rejection_codes': sorted({entry['rejection']['code'] for entry in body['entries'] if 'rejection' in entry}),
            'more': 'catching_up' in body['reports'] and 'profile_drift' not in body['reports']}


def run_once(config, fetch=ssh_export, send=post_batch, *, clock=time.monotonic):
    config = validate_config(config)
    directory = Path(config['state_dir'])
    _secure_directory(directory)
    profile = profile_from_dict(config['profile'])
    started = clock()
    deadline = started + config['max_seconds_per_run']
    pages = records = rejected = 0
    reports = set()
    rejection_codes = set()
    caught_up = False
    status, code = 'acknowledged', None
    try:
        with collector_lock(directory), wall_deadline(config['max_seconds_per_run'], CollectorError):
            while pages < config['max_pages_per_run']:
                page = collect_page(config, deadline=deadline, fetch=fetch, send=send, clock=clock)
                pages += 1
                records += page['records']
                rejected += page['rejected_records']
                rejection_codes.update(page['rejection_codes'])
                reports.update(page['report_codes'])
                caught_up = page['caught_up']
                if not page['more']:
                    break
                _remaining(deadline, config['max_seconds_per_run'], clock)
    except CollectorError as exc:
        status, code, caught_up = 'error', str(exc), False
    except (OSError, NetworkProtocolError):
        status, code, caught_up = 'error', 'local_network_storage_failed', False
    if status == 'acknowledged':
        if 'profile_drift' in reports:
            status, code = 'degraded', 'profile_drift'
        elif 'journal_cursor_unavailable' in reports:
            status, code = 'degraded', 'journal_cursor_unavailable'
        elif rejected:
            status, code = 'degraded', 'network_records_rejected'
    return {'source_id': profile.source_id, 'status': status, 'code': code, 'pages': pages,
            'records': records, 'rejected_records': rejected, 'rejection_codes': sorted(rejection_codes),
            'caught_up': caught_up, 'report_codes': sorted(reports),
            'duration_ms': round((clock() - started) * 1000)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--once', required=True, action='store_true')
    parser.add_argument('--config', type=Path, default=Path('/etc/secagent-riskops/network-collector.json'))
    args = parser.parse_args()
    try:
        result = run_once(load_config(args.config))
        print(json.dumps(result))
        return int(result['status'] != 'acknowledged')
    except (CollectorError, OSError):
        print(json.dumps({'status': 'error', 'code': 'network_collector_configuration_failed'}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
