#!/usr/bin/env python3
"""Bounded, read-only journal export for an SSH forced-command key.

The root-owned configuration selects the local source and optional fixed SSH
relay targets. No client-supplied command, filename, unit or host is executed.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

CONFIG_PATH = Path('/etc/secagent-riskops/export.json')
FIELDS = ('__CURSOR', '__REALTIME_TIMESTAMP', 'MESSAGE', '_SYSTEMD_UNIT',
          'SYSLOG_IDENTIFIER', 'PRIORITY')
CURSOR_RE = re.compile(r'[A-Za-z0-9;=_:\-]{1,2048}\Z')
SOURCE_ID_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z')
MAX_OUTPUT_BYTES = 3 * 1024 * 1024


def validate_request(request: object, allowed_sources: set[str] | frozenset[str]) -> dict:
    if not isinstance(request, dict) or set(request) - {'source_id', 'cursor', 'limit', 'since_minutes'}:
        raise ValueError('invalid request fields')
    source_id = request.get('source_id')
    if not isinstance(source_id, str) or not SOURCE_ID_RE.fullmatch(source_id) or source_id not in allowed_sources:
        raise ValueError('unknown source')
    cursor = request.get('cursor')
    if cursor is not None and (not isinstance(cursor, str) or not CURSOR_RE.fullmatch(cursor)):
        raise ValueError('invalid cursor')
    limit = request.get('limit', 200)
    since = request.get('since_minutes', 10)
    if type(limit) is not int or not 1 <= limit <= 200:
        raise ValueError('invalid limit')
    if type(since) is not int or not 1 <= since <= 60:
        raise ValueError('invalid initial window')
    return {'source_id': request['source_id'], 'cursor': cursor,
            'limit': limit, 'since_minutes': since}


def cursor_exists(cursor: str) -> bool:
    """Seeking a vacuumed journal cursor may succeed; test exact presence."""
    lib = ctypes.CDLL(ctypes.util.find_library('systemd') or 'libsystemd.so.0')
    handle = ctypes.c_void_p()
    lib.sd_journal_open.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_int]
    lib.sd_journal_seek_cursor.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.sd_journal_next.argtypes = [ctypes.c_void_p]
    lib.sd_journal_test_cursor.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.sd_journal_close.argtypes = [ctypes.c_void_p]
    if lib.sd_journal_open(ctypes.byref(handle), 0) < 0:
        raise RuntimeError('journal open failed')
    try:
        raw = cursor.encode('ascii')
        if lib.sd_journal_seek_cursor(handle, raw) < 0:
            return False
        if lib.sd_journal_next(handle) <= 0:
            return False
        return lib.sd_journal_test_cursor(handle, raw) == 1
    finally:
        lib.sd_journal_close(handle)


def journal_command(request: dict, valid_cursor: bool) -> list[str]:
    command = ['/usr/bin/journalctl', '--no-pager', '--quiet', '--output=json',
               '--output-fields=' + ','.join(FIELDS)]
    if request['cursor'] and valid_cursor:
        command += ['--after-cursor=' + request['cursor']]
    else:
        command += ['--since=-' + str(request['since_minutes']) + 'min']
    # No -n: it returns the newest records and would skip an unread backlog.
    command += ['SYSLOG_FACILITY=4', '+', 'SYSLOG_FACILITY=10', '+',
                'SYSLOG_IDENTIFIER=sshd', '+', 'SYSLOG_IDENTIFIER=sshd-session', '+',
                'SYSLOG_IDENTIFIER=sshd-auth', '+', '_SYSTEMD_UNIT=ssh.service', '+',
                '_SYSTEMD_UNIT=sshd.service', '+', 'SYSLOG_IDENTIFIER=fail2ban']
    return command


def local_export(request: dict) -> None:
    valid = bool(request['cursor']) and cursor_exists(request['cursor'])
    status = 'ok' if valid else ('reset' if request['cursor'] else 'initial')
    process = subprocess.Popen(journal_command(request, valid), stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env={**os.environ, 'LC_ALL': 'C'})
    records = []
    output_size = 0
    limited = False
    try:
        assert process.stdout is not None
        while len(records) < request['limit']:
            line = process.stdout.readline(65537)
            if not line:
                break
            if len(line) > 65536:
                raise ValueError('journal record exceeds export limit')
            record = json.loads(line)
            if not isinstance(record.get('__CURSOR'), str) or 'MESSAGE' not in record:
                raise ValueError('journal record missing required fields')
            exported = {k: record[k] for k in FIELDS if k in record}
            encoded_size = len(json.dumps(exported, ensure_ascii=False, separators=(',', ':')).encode('utf-8')) + 1
            # Return the oldest bounded prefix, so the collector can advance
            # and fetch the remainder without exceeding relay/collector limits.
            if output_size + encoded_size > MAX_OUTPUT_BYTES - 4096:
                limited = True
                break
            records.append(exported)
            output_size += encoded_size
        if (limited or len(records) == request['limit']) and process.poll() is None:
            process.terminate()
        _, stderr = process.communicate(timeout=5)
        if process.returncode not in (0, -15) and not limited and len(records) != request['limit']:
            raise RuntimeError('journalctl failed')
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    for record in records:
        print(json.dumps(record, ensure_ascii=False, separators=(',', ':')))
    checkpoint = records[-1]['__CURSOR'] if records else (request['cursor'] if valid else None)
    print(json.dumps({'__riskops_checkpoint__': checkpoint, 'cursor_status': status,
                      'gap_reason': 'journal_cursor_unavailable' if status == 'reset' else None}))


def main() -> int:
    # A forced-command key cannot be used as a shell/SFTP/forwarding credential.
    if os.environ.get('SSH_ORIGINAL_COMMAND', ''):
        raise ValueError('remote commands are disabled')
    raw = sys.stdin.buffer.read(8193)
    if len(raw) > 8192:
        raise ValueError('request too large')
    config = json.loads(CONFIG_PATH.read_text())
    if not isinstance(config, dict):
        raise ValueError('invalid configuration')
    local_source = config.get('local_source_id')
    relays = config.get('relays', {})
    if (not isinstance(local_source, str) or not SOURCE_ID_RE.fullmatch(local_source)
            or not isinstance(relays, dict)
            or any(not SOURCE_ID_RE.fullmatch(source_id) for source_id in relays)):
        raise ValueError('invalid configuration')
    allowed_sources = {local_source, *relays}
    request = validate_request(json.loads(raw), allowed_sources)
    if request['source_id'] == config['local_source_id']:
        local_export(request)
    else:
        target = config.get('relays', {}).get(request['source_id'])
        if not target:
            raise ValueError('source not served here')
        # Both the config path and alias come only from root-owned configuration.
        command = ['/usr/bin/ssh', '-T', '-F', target['ssh_config'], target['host']]
        result = subprocess.run(command, input=json.dumps(request).encode(),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        if result.returncode or len(result.stdout) > 4 * 1024 * 1024:
            raise RuntimeError('downstream export failed')
        sys.stdout.buffer.write(result.stdout)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        # Never print SSH stderr, raw records, credentials or request contents.
        print('riskops export failed: ' + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
