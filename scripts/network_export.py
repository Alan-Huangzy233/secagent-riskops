#!/usr/bin/env python3
"""Dedicated read-only kernel exporter; install as an SSH forced command.

Requires the installed project package and sibling journal_export.py. Only the
fixed root-owned /etc/secagent-riskops/network-export.json supplies identity,
profile and firewall context. No relay, command, filename or filter is accepted
from the caller. Output is normalized metadata, never raw journal messages.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid

from app.telemetry.network_parse import FULL_GUARD, LEGACY_GUARD, MAX_CURSOR_BYTES, MAX_REALTIME_US
from app.telemetry.network_protocol import (
    MAX_BATCH_BYTES, MAX_ENTRIES, encode, fingerprint, journal_entry,
    profile_from_dict, validate_batch,
)
from journal_export import cursor_exists

CONFIG_PATH = Path('/etc/secagent-riskops/network-export.json')
MAX_CONFIG_BYTES = 65536
MAX_REQUEST_BYTES = 4096
MAX_RAW_LINE_BYTES = 65536
MAX_RAW_PAGE_BYTES = 4 * 1024 * 1024
MAX_EXPORT_SECONDS = 10
FIELDS = ('_TRANSPORT', '_BOOT_ID', '__CURSOR', '__REALTIME_TIMESTAMP', '__MONOTONIC_TIMESTAMP', 'MESSAGE')


class ExportError(ValueError):
    """Safe reason code only; no external output or supplied values."""


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ExportError('duplicate_json_field')
        result[key] = value
    return result


def decode(data):
    try:
        return json.loads(data, object_pairs_hook=unique_fields,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise ExportError('invalid_json') from None


def secure_file(path: Path, *, root_owned: bool, secret: bool = False):
    """Reject symlinks, nonregular files and replaceable ancestor directories."""
    if not path.is_absolute():
        raise ExportError('unsafe_configuration')
    owners = {0} if root_owned else {0, os.geteuid()}
    for parent in path.parents:
        info = parent.lstat()
        writable = info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in owners or writable):
            raise ExportError('unsafe_configuration')
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0))
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in owners
                or info.st_mode & (0o077 if secret else 0o022) or info.st_size > MAX_CONFIG_BYTES):
            raise ExportError('unsafe_configuration')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(MAX_CONFIG_BYTES + 1)
        if len(raw) > MAX_CONFIG_BYTES:
            raise ExportError('unsafe_configuration')
        return raw
    finally:
        os.close(fd)


def load_config(path: Path = CONFIG_PATH):
    try:
        value = decode(secure_file(path, root_owned=True))
        if type(value) is not dict or set(value) != {'version', 'profile', 'profile_valid_from_us'}:
            raise ValueError
        profile = profile_from_dict(value['profile'])
        valid_from = value['profile_valid_from_us']
        if (type(value['version']) is not int or value['version'] != 1
                or type(valid_from) is not int or not 0 <= valid_from <= MAX_REALTIME_US
                or (profile.guard_version == FULL_GUARD and valid_from != profile.profile_valid_from_us)):
            raise ValueError
        return value, profile
    except (OSError, ValueError, TypeError, KeyError):
        raise ExportError('invalid_export_config') from None


def validate_request(value, profile):
    if (type(value) is not dict or set(value) != {'source_id', 'cursor'}
            or value['source_id'] != profile.source_id):
        raise ExportError('invalid_export_request')
    cursor = value['cursor']
    if cursor is not None and (not isinstance(cursor, str) or not 1 <= len(cursor) <= MAX_CURSOR_BYTES
                               or any(ord(char) < 32 or ord(char) > 126 for char in cursor)):
        raise ExportError('invalid_export_request')
    return value


@contextmanager
def wall_deadline(seconds, error_factory=ExportError):
    """Hard CLI wall bound, also covering blocking stdin/HTTP/library calls."""
    if threading.current_thread() is not threading.main_thread():
        raise error_factory('deadline_requires_main_thread')
    before_handler = signal.getsignal(signal.SIGALRM)
    before_timer = signal.getitimer(signal.ITIMER_REAL)
    if before_timer[0]:
        raise error_factory('deadline_already_active')
    def expired(signum, frame):
        raise error_factory('run_deadline')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, before_handler)


def _stop(process):
    # Descendants may retain stdout after their direct parent has exited. The
    # process group, not only the Popen child, owns this command's deadline.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=1)


def command_chunks(command, *, deadline, maximum, input_data=b''):
    """Bound bytes and wall time; close the generator to stop an unread tail."""
    process = None
    selector = selectors.DefaultSelector()
    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, start_new_session=True,
                                   env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC'})
        process.stdin.write(input_data)
        process.stdin.close()
        selector.register(process.stdout, selectors.EVENT_READ)
        size = 0
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ExportError('subprocess_deadline')
            ready = selector.select(remaining)
            if not ready:
                raise ExportError('subprocess_deadline')
            chunk = os.read(process.stdout.fileno(), 8192)
            if not chunk:
                selector.unregister(process.stdout)
                break
            size += len(chunk)
            if size > maximum:
                raise ExportError('subprocess_output_limit')
            yield chunk
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ExportError('subprocess_deadline')
        if process.wait(timeout=remaining) != 0:
            raise ExportError('subprocess_failed')
    except (OSError, subprocess.SubprocessError):
        raise ExportError('subprocess_failed') from None
    finally:
        selector.close()
        if process is not None:
            _stop(process)
            process.stdin.close()
            process.stdout.close()


def run_command(command, *, deadline, maximum):
    return b''.join(command_chunks(command, deadline=deadline, maximum=maximum))


def normalized_rules(raw, *, strict=False):
    try:
        rules = []
        in_table = False
        for line in raw.decode('utf-8').splitlines():
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            tokens = shlex.split(line)
            if strict:
                if len(tokens) == 1 and re.fullmatch(r'\*[A-Za-z0-9_]{1,32}', tokens[0]):
                    if in_table:
                        raise ValueError
                    in_table = True
                elif tokens == ['COMMIT']:
                    if not in_table:
                        raise ValueError
                    in_table = False
                elif tokens[0].startswith(':'):
                    if (not in_table or len(tokens) != 3
                            or not re.fullmatch(r'\[[0-9]+:[0-9]+\]', tokens[-1])):
                        raise ValueError
                elif not in_table or len(tokens) < 3 or tokens[0] != '-A':
                    raise ValueError
            # Our fixed save command has no -c flag: only a chain declaration's
            # trailing counters are dynamic. Rule option values can themselves
            # resemble counters or options, so retain them without rewriting.
            if (len(tokens) == 3 and tokens[0].startswith(':')
                    and re.fullmatch(r'\[[0-9]+:[0-9]+\]', tokens[-1])):
                tokens = tokens[:-1]
            rules.append(tokens)
        if strict and in_table:
            raise ValueError
        return rules
    except (ValueError, UnicodeError):
        raise ExportError('invalid_rules_snapshot') from None


# Every path and argument is fixed; enrollment cannot select a reduced view.
FULL_RULE_COMMANDS = (
    ('nft', ('/usr/sbin/nft', '--json', '--handle', '--numeric', 'list', 'ruleset')),
    ('iptables-default', ('/usr/sbin/iptables-save',)),
    ('ip6tables-default', ('/usr/sbin/ip6tables-save',)),
    ('iptables-nft', ('/usr/sbin/iptables-nft-save',)),
    ('ip6tables-nft', ('/usr/sbin/ip6tables-nft-save',)),
    ('iptables-legacy', ('/usr/sbin/iptables-legacy-save',)),
    ('ip6tables-legacy', ('/usr/sbin/ip6tables-legacy-save',)),
)
_NFT_OBJECTS = frozenset({'table', 'chain', 'rule', 'set', 'map', 'element', 'counter',
                          'quota', 'limit', 'flowtable', 'ct helper', 'ct timeout',
                          'ct expectation', 'synproxy'})
_NFT_FAMILIES = frozenset({'ip', 'ip6', 'inet', 'arp', 'bridge', 'netdev'})


def normalized_nft_rules(raw):
    """Drop only known display metadata and exact packet/byte counter values.

    Expression order, set elements, timeouts/expirations, quota usage, comments
    and unknown nested expression content remain bound. Stateful sets may thus
    cause conservative drift; silently omitting them would weaken provenance.
    Unknown top-level objects/schema versions fail closed.
    """
    try:
        if not isinstance(raw, bytes) or len(raw) > MAX_RAW_PAGE_BYTES:
            raise ValueError
        value = decode(raw)
        if type(value) is not dict or set(value) != {'nftables'} or type(value['nftables']) is not list:
            raise ValueError
        pending, nodes = [(value, 0)], 0
        while pending:
            item, depth = pending.pop()
            nodes += 1
            if depth > 32 or nodes > 100_000:
                raise ValueError
            if type(item) is dict:
                pending.extend((child, depth + 1) for child in item.values())
            elif type(item) is list:
                pending.extend((child, depth + 1) for child in item)
        result, metadata = [], 0
        for wrapper in value['nftables']:
            if type(wrapper) is not dict or len(wrapper) != 1:
                raise ValueError
            kind, obj = next(iter(wrapper.items()))
            if type(obj) is not dict:
                raise ValueError
            if kind == 'metainfo':
                metadata += 1
                if (metadata != 1 or type(obj.get('json_schema_version')) is not int
                        or obj['json_schema_version'] != 1
                        or set(obj) - {'version', 'release_name', 'json_schema_version'}):
                    raise ValueError
                continue
            if (kind not in _NFT_OBJECTS or obj.get('family') not in _NFT_FAMILIES
                    or (kind != 'table' and not isinstance(obj.get('table'), str))
                    or (kind not in {'rule', 'element'} and not isinstance(obj.get('name'), str))):
                raise ValueError
            obj = dict(obj)
            if 'handle' in obj:
                if type(obj['handle']) is not int or obj['handle'] < 0:
                    raise ValueError
                del obj['handle']
            if kind == 'rule':
                if not isinstance(obj.get('chain'), str) or type(obj.get('expr')) is not list:
                    raise ValueError
                expressions = []
                for expr in obj['expr']:
                    if type(expr) is not dict or len(expr) != 1:
                        raise ValueError
                    if 'counter' in expr and type(expr['counter']) is dict:
                        counter = expr['counter']
                        if set(counter) == {'packets', 'bytes'}:
                            if any(type(v) is not int or v < 0 for v in counter.values()):
                                raise ValueError
                            expr = {'counter': {}}
                    expressions.append(expr)
                obj['expr'] = expressions
            if kind == 'counter':
                if not {'packets', 'bytes'} <= obj.keys():
                    raise ValueError
                for key in ('packets', 'bytes'):
                    if type(obj[key]) is not int or obj[key] < 0:
                        raise ValueError
                    del obj[key]
            result.append({kind: obj})
        if metadata != 1:
            raise ValueError
        return result
    except (ValueError, TypeError, RecursionError):
        raise ExportError('invalid_nft_rules_snapshot') from None


def ruleset_fingerprint(*, deadline, run=run_command, guard_version=LEGACY_GUARD):
    if guard_version == LEGACY_GUARD:
        snapshots = {}
        for family, executable in ((4, '/usr/sbin/iptables-save'), (6, '/usr/sbin/ip6tables-save')):
            raw = run([executable], deadline=min(deadline, time.monotonic() + 2), maximum=MAX_RAW_PAGE_BYTES)
            snapshots[str(family)] = normalized_rules(raw)
        return fingerprint(snapshots)
    if guard_version != FULL_GUARD:
        raise ExportError('unsupported_profile_guard')
    snapshots = {'guard_version': FULL_GUARD}
    for name, command in FULL_RULE_COMMANDS:
        if not os.access(command[0], os.X_OK):
            raise ExportError('firewall_guard_tool_unavailable')
        try:
            raw = run(list(command), deadline=min(deadline, time.monotonic() + 2), maximum=MAX_RAW_PAGE_BYTES)
        except ExportError as exc:
            if str(exc) in {'subprocess_deadline', 'subprocess_output_limit'}:
                raise
            raise ExportError('firewall_guard_snapshot_failed') from None
        snapshots[name] = normalized_nft_rules(raw) if name == 'nft' else normalized_rules(raw, strict=True)
    return fingerprint(snapshots)


def journal_command(profile, cursor, *, valid_cursor, since_us):
    command = ['/usr/bin/journalctl', '--no-pager', '--quiet', '--all', '--output=json',
               '--output-fields=' + ','.join(FIELDS), '_TRANSPORT=kernel',
               '--grep=^(?:' + '|'.join(re.escape(label) for label in profile.log_labels) + ') ']
    if cursor is not None and valid_cursor:
        command.append('--after-cursor=' + cursor)
    else:
        at = datetime.fromtimestamp(since_us / 1_000_000, timezone.utc)
        command.append('--since=' + at.strftime('%Y-%m-%d %H:%M:%S.%f UTC'))
    return command


def journal_records(command, *, deadline):
    chunks = command_chunks(command, deadline=deadline, maximum=MAX_RAW_PAGE_BYTES)
    pending = b''
    try:
        for chunk in chunks:
            pending += chunk
            while b'\n' in pending:
                line, pending = pending.split(b'\n', 1)
                if len(line) > MAX_RAW_LINE_BYTES:
                    raise ExportError('journal_line_limit')
                yield decode(line)
            if len(pending) > MAX_RAW_LINE_BYTES:
                raise ExportError('journal_line_limit')
        if pending:
            raise ExportError('partial_journal_line')
    finally:
        chunks.close()


def enrolled_message(message, labels):
    if isinstance(message, str):
        return any(message.startswith(label + ' ') for label in labels)
    # Journal JSON uses byte arrays for non-UTF8 fields. An enrolled ASCII
    # prefix still identifies the filtered source, but the parser must reject
    # the unsupported encoding without retaining raw bytes in the batch.
    if (type(message) is list and len(message) <= MAX_RAW_LINE_BYTES
            and all(type(byte) is int and 0 <= byte <= 255 for byte in message)):
        return any(message[:len(label) + 1] == list((label + ' ').encode('ascii')) for label in labels)
    return False


def export_page(config, request, *, now_us=None, clock=time.monotonic,
                exists=cursor_exists, rules=ruleset_fingerprint, read=journal_records):
    profile = profile_from_dict(config['profile'])
    validate_request(request, profile)
    if (profile.guard_version == FULL_GUARD
            and config['profile_valid_from_us'] != profile.profile_valid_from_us):
        raise ExportError('profile_validity_mismatch')
    now_us = time.time_ns() // 1000 if now_us is None else now_us
    deadline = clock() + MAX_EXPORT_SECONDS
    cursor = request['cursor']
    batch = {'version': 1, 'source_id': profile.source_id, 'profile_revision': profile.revision,
             'batch_id': uuid.uuid4().hex, 'collected_at_us': now_us, 'cursor_before': cursor,
             'cursor_after': cursor, 'entries': [], 'reports': [], 'caught_up': False}
    if config['profile_valid_from_us'] > now_us:
        raise ExportError('profile_not_yet_valid')
    if rules(deadline=deadline, guard_version=profile.guard_version) != profile.ruleset_sha256:
        batch['reports'] = ['profile_drift']
        return validate_batch(batch, profile)
    valid = cursor is not None and exists(cursor)
    if cursor is None:
        batch['reports'].append('coverage_start')
    elif not valid:
        batch['reports'].append('journal_cursor_unavailable')
    since = max(now_us - 600_000_000, config['profile_valid_from_us'], 0)
    if not valid and since == config['profile_valid_from_us']:
        batch['reports'].append('profile_boundary')
    command = journal_command(profile, cursor, valid_cursor=valid, since_us=since)
    records = read(command, deadline=deadline)
    limited = False
    try:
        for record in records:
            if clock() >= deadline:
                raise ExportError('run_deadline')
            # Even with fixed journalctl filters, independently check the trust
            # boundary and label before normalization. Unexpected data is fatal.
            if (type(record) is not dict or record.get('_TRANSPORT') != 'kernel'
                    or not enrolled_message(record.get('MESSAGE'), profile.log_labels)):
                raise ExportError('unexpected_journal_record')
            timestamp = record.get('__REALTIME_TIMESTAMP')
            try:
                too_old = int(timestamp) < config['profile_valid_from_us']
            except (ValueError, TypeError):
                raise ExportError('invalid_journal_identity') from None
            entry = journal_entry(record, profile, rejection_code='profile_context_unavailable' if too_old else None)
            if too_old and 'profile_boundary' not in batch['reports']:
                batch['reports'].append('profile_boundary')
            content = entry.get('event', entry.get('rejection'))
            previous = batch['cursor_after']
            batch['entries'].append(entry)
            batch['cursor_after'] = content['journal_cursor']
            if len(encode(batch)) > MAX_BATCH_BYTES - 1024:
                batch['entries'].pop()
                batch['cursor_after'] = previous
                if not batch['entries']:
                    raise ExportError('record_exceeds_batch_limit')
                limited = True
                break
            if len(batch['entries']) == MAX_ENTRIES:
                limited = True
                break
    finally:
        if hasattr(records, 'close'):
            records.close()
    # Do not release a page observed across changing rules, even if all rows
    # independently parse. Discard its content and retain the caller's cursor.
    if rules(deadline=deadline, guard_version=profile.guard_version) != profile.ruleset_sha256:
        batch.update(entries=[], cursor_after=cursor, reports=['profile_drift'], caught_up=False)
    elif valid and not exists(cursor):
        # Journal vacuum may race the initial exact check and the seek/read.
        # Never silently trust a nearest surviving position in that race.
        batch.update(entries=[], cursor_after=cursor, reports=['journal_cursor_unavailable'], caught_up=False)
    else:
        if limited:
            batch['reports'].append('catching_up')
        batch['caught_up'] = not limited and 'journal_cursor_unavailable' not in batch['reports']
    return validate_batch(batch, profile)


def main():
    if len(sys.argv) != 1 or os.environ.get('SSH_ORIGINAL_COMMAND', ''):
        raise ExportError('remote_commands_disabled')
    with wall_deadline(MAX_EXPORT_SECONDS):
        config, profile = load_config()
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ExportError('request_limit')
        request = validate_request(decode(raw), profile)
        batch = export_page(config, request)
        sys.stdout.buffer.write(encode(batch) + b'\n')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        code = str(exc) if isinstance(exc, ExportError) else 'network_export_failed'
        print(json.dumps({'status': 'error', 'code': code}), file=sys.stderr)
        raise SystemExit(1)
