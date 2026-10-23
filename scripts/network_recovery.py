"""Read-only consistency checks for a local network recovery cohort.

This module never contacts a collector or starts an API. Configuration secrets
stay in memory; the manifest carries only mapping hashes and public profiles.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat

from app.telemetry.network_protocol import fingerprint, profile_from_dict, validate_ack
from app.telemetry.network_store import NetworkStore
import network_collector as collector


class RecoveryError(ValueError):
    pass


def validate(raw, components):
    allowed = {'network_database', 'console_database', 'collectors', 'lock_timeout_seconds'}
    try:
        if type(raw) is not dict or set(raw) - allowed:
            raise ValueError
        by_name = {item['name']: item for item in components}
        pair = [raw[name] for name in ('network_database', 'console_database')]
        if (any(type(name) is not str or name not in by_name or by_name[name]['kind'] != 'sqlite' for name in pair)
                or len({Path(by_name[name]['path']).resolve() for name in pair}) != 2):
            raise ValueError
        entries = raw['collectors']
        if type(entries) is not list or not 1 <= len(entries) <= 16:
            raise ValueError
        for entry in entries:
            if type(entry) is not dict or set(entry) != {'state', 'config'}:
                raise ValueError
            spec = by_name[entry['state']]
            if (spec['kind'] != 'state_dir' or set(spec['patterns']) != {'*.state.json', '*.pending.json'}
                    or type(entry['config']) is not str or not Path(entry['config']).is_absolute()
                    or '..' in Path(entry['config']).parts):
                raise ValueError
        if (len({Path(by_name[e['state']]['path']).resolve() for e in entries}) != len(entries)
                or len({Path(e['config']).resolve() for e in entries}) != len(entries)):
            raise ValueError
        seconds = raw.get('lock_timeout_seconds', 5)
        if type(seconds) is not int or not 1 <= seconds <= 10:
            raise ValueError
        return {**raw, 'lock_timeout_seconds': seconds}
    except (ValueError, TypeError, KeyError):
        raise RecoveryError('Invalid network recovery cohort configuration') from None


def state_owner(path):
    """Trust only the protected directory's owner and root, never arbitrary UIDs."""
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077
            or (os.geteuid() != 0 and info.st_uid not in {0, os.geteuid()})):
        raise ValueError
    for parent in path.parents:
        ancestor = parent.lstat()
        writable = ancestor.st_mode & 0o022 and not ancestor.st_mode & stat.S_ISVTX
        if (not stat.S_ISDIR(ancestor.st_mode) or ancestor.st_uid not in {0, info.st_uid}
                or writable):
            raise ValueError
    return info.st_uid, info.st_gid


def trusted_file(path, uid, *, secret):
    """Bounded no-follow config read for root backing up a separate service UID."""
    if not path.is_absolute():
        raise ValueError
    for parent in path.parents:
        info = parent.lstat()
        writable = info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, uid} or writable:
            raise ValueError
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, uid}
                or info.st_mode & (0o077 if secret else 0o022) or info.st_size > collector.MAX_CONFIG_BYTES):
            raise ValueError
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(collector.MAX_CONFIG_BYTES + 1)
        if len(raw) > collector.MAX_CONFIG_BYTES:
            raise ValueError
        return raw
    finally:
        os.close(fd)


def mapping_identity(config, uid):
    # Exactly the collector's identity contract, with ownership anchored to its
    # protected state directory rather than the root backup process's UID.
    text = trusted_file(Path(config['ssh_config']), uid, secret=False).decode('utf-8')
    forbidden = {'include', 'match', 'proxycommand', 'localcommand', 'remotecommand', 'knownhostscommand'}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith('#') and re.split(r'[\s=]', line, maxsplit=1)[0].lower() in forbidden:
            raise ValueError
    profile = profile_from_dict(config['profile'])
    return fingerprint({'endpoint': config['endpoint'], 'source_id': profile.source_id,
                        'profile_revision': profile.revision, 'ssh_config': config['ssh_config'],
                        'ssh_host': config['ssh_host'], 'ssh_config_sha256': fingerprint(text)})


@contextmanager
def locked_collectors(specs):
    """Use service-owned locks even when root packages an unused new source."""
    with ExitStack() as stack:
        try:
            for spec in sorted(specs, key=lambda item: item['path']):
                directory = Path(spec['path'])
                uid, gid = state_owner(directory)
                path = directory / 'collector.lock'
                flags = os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW
                try:
                    fd = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
                except FileExistsError:
                    fd = os.open(path, flags)
                else:
                    # Only the freshly and exclusively created inode may change
                    # owner. Never repair/chown an existing untrusted lock.
                    try:
                        if os.geteuid() == 0:
                            os.fchown(fd, uid, gid)
                    except BaseException:
                        os.close(fd)
                        raise
                lock = stack.enter_context(os.fdopen(fd, 'r+b'))
                info = os.fstat(lock.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                        or info.st_mode & 0o077 or info.st_nlink != 1):
                    raise ValueError
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, ValueError):
            raise RecoveryError('Network collector is busy or its protected lock is unavailable') from None
        yield


def mappings(policy, components):
    """Bind each captured state directory to its exact live collector mapping."""
    by_name = {item['name']: item for item in components}
    result = []
    try:
        for entry in policy['collectors']:
            uid, _ = state_owner(Path(by_name[entry['state']]['path']))
            raw = trusted_file(Path(entry['config']), uid, secret=True)
            config = collector.validate_config(collector.decode(raw))
            if (state_owner(Path(config['state_dir']))[0] != uid
                    or Path(config['state_dir']).resolve() != Path(by_name[entry['state']]['path']).resolve()):
                raise ValueError
            result.append({'state': entry['state'], 'source_id': config['profile']['source_id'],
                           'profile': config['profile'], 'identity': mapping_identity(config, uid),
                           'config_sha256': hashlib.sha256(raw).hexdigest()})
        if len({item['source_id'] for item in result}) != len(result):
            raise ValueError
        return result
    except (ValueError, OSError, KeyError, collector.CollectorError):
        raise RecoveryError('Network collector configuration or mapping is unavailable') from None


def _last_batch(db, source):
    row = db.execute('SELECT batch_id,payload_hash,response_json FROM network_batches '
                     'WHERE source_id=? ORDER BY seq DESC LIMIT 1', (source,)).fetchone()
    return row


def _state_ack(db, source, state):
    if state['last_batch_id'] is None:
        if state['cursor'] is not None:
            raise ValueError
        return
    row = db.execute('SELECT payload_hash,response_json FROM network_batches WHERE source_id=? AND batch_id=?',
                     (source, state['last_batch_id'])).fetchone()
    if row is None:
        raise ValueError
    ack = json.loads(row[1])
    if (row[0] != state['last_payload_hash'] or ack['payload_hash'] != row[0]
            or ack['durable'] is not True or ack['source_id'] != source
            or ack['batch_id'] != state['last_batch_id'] or ack['cursor_after'] != state['cursor']
            or ack['received_at_us'] != state['received_at_us']):
        raise ValueError


def _pending_ack(db, source, body, row):
    ack = json.loads(row[1])
    if row[0] != fingerprint(body):
        raise ValueError
    validate_ack(ack, body)
    for entry in body['entries']:
        kind = 'event' if 'event' in entry else 'rejection'
        item = entry[kind]
        receipt = db.execute('SELECT content_hash,kind,code,record_hash FROM network_receipts '
                             'WHERE source_id=? AND event_id=?', (source, item['event_id'])).fetchone()
        expected = (item['content_hash'], kind, None if kind == 'event' else item['code'],
                    fingerprint({'kind': kind, 'record': item}))
        if receipt is None or tuple(receipt) != expected:
            raise ValueError


def check_states(db, descriptors, directory):
    """Accept exact checkpoints or the one original pending batch spanning ACK."""
    results = []
    sources = {row[0] for row in db.execute('SELECT source_id FROM network_sources')}
    if not sources <= {item['source_id'] for item in descriptors}:
        raise ValueError('missing collector')
    for item in descriptors:
        source = item['source_id']
        profile = profile_from_dict(item['profile'])
        if source != profile.source_id or not re.fullmatch('[0-9a-f]{64}', item['identity']):
            raise ValueError
        root = directory / item['state']
        if root.is_symlink() or not root.is_dir():
            raise ValueError
        if any(path.name not in {'network.state.json', 'network.pending.json'} for path in root.iterdir()):
            raise ValueError
        state = collector._load_state(root / 'network.state.json', item['identity'])
        _state_ack(db, source, state)
        row = db.execute('SELECT checkpoint,profile_revision,last_report_json FROM network_sources '
                         'WHERE source_id=?', (source,)).fetchone()
        checkpoint = row[0] if row else None
        latest = _last_batch(db, source)
        if (bool(row) != bool(latest) or (row and (row[1] != profile.revision
                or json.loads(row[2]) != json.loads(latest[2])))):
            raise ValueError
        pending = root / 'network.pending.json'
        committed = False
        if pending.exists() or pending.is_symlink():
            value = collector._read_state_file(pending, maximum=collector.MAX_PENDING_BYTES,
                                               code='invalid_network_spool')
            body = collector._validate_pending(value, item['identity'], profile, state)
            saved = db.execute('SELECT payload_hash,response_json FROM network_batches '
                               'WHERE source_id=? AND batch_id=?', (source, body['batch_id'])).fetchone()
            if saved:
                _pending_ack(db, source, body, saved)
                if checkpoint != body['cursor_after'] or latest[0] != body['batch_id']:
                    raise ValueError
                committed = True
            elif checkpoint != body['cursor_before'] or state['cursor'] != checkpoint:
                raise ValueError
        if not committed and (state['cursor'] != checkpoint
                or state['last_batch_id'] != (latest[0] if latest else None)):
            raise ValueError
        results.append({'state': item['state'], 'source_id': source, 'checkpoint': checkpoint,
                        'pending': pending.exists(), 'pending_committed': committed})
    return results


def check_pair(network, console, descriptors, directory):
    try:
        # Validate without constructing a writable store or running migrations.
        NetworkStore.__new__(NetworkStore)._validate_schema(network)
        checkpoints = check_states(network, descriptors, directory)
        row = network.execute("SELECT value FROM network_analysis_meta WHERE name='producer_id'").fetchone()
        producer = json.loads(row[0]) if row else None
        if type(producer) is not str or not re.fullmatch('[0-9a-f]{32}', producer):
            raise ValueError
        prefix = 'network:' + producer + ':'
        imported = 0
        for topic, revision, pending in network.execute('SELECT topic,revision,pending FROM network_notice_outbox'):
            if not topic.startswith(prefix) or type(revision) is not int or revision < 1 or pending not in (0, 1):
                raise ValueError
            row = console.execute('SELECT value FROM notification_meta WHERE name=?', ('network-import:'+topic,)).fetchone()
            value = json.loads(row[0]) if row else 0
            if type(value) is not int or not 0 <= value <= revision or (not pending and value != revision):
                raise ValueError
            imported += bool(value)
        for name, in console.execute("SELECT name FROM notification_meta WHERE name LIKE 'network-import:%'"):
            topic = name.removeprefix('network-import:')
            if not network.execute('SELECT 1 FROM network_notice_outbox WHERE topic=?', (topic,)).fetchone():
                raise ValueError
        console.execute('SELECT 1 FROM notification_inbox LIMIT 1').fetchone()
        console.execute('SELECT 1 FROM notification_outbox LIMIT 1').fetchone()
        return {'producer_id': producer, 'imported_topics': imported,
                'notification_checkpoints': 'compatible', 'checkpoints': checkpoints}
    except (ValueError, TypeError, KeyError, IndexError, OSError, sqlite3.Error, collector.CollectorError):
        raise RecoveryError('Network recovery checkpoints, pending batches or notification pair are incompatible') from None
