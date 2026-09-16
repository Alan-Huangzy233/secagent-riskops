#!/usr/bin/env python3
"""Unprivileged forced-command gateway with administrator-pinned relay targets.

Install root-owned and invoke with /usr/bin/python3 -I. Only the local fixed
helper is allowed by sudoers. Dedicated relay keys cannot open shells or tunnels.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

CONFIG = Path('/etc/riskops-control/gateway.json')
SAFE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z')
MAX_RESPONSE = 512 * 1024


def secure_file(path):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('invalid path')
    for item in (path, *path.parents):
        st = item.lstat()
        if st.st_uid != 0 or st.st_mode & 0o022 or stat.S_ISLNK(st.st_mode):
            raise ValueError('unsafe gateway configuration')


def command_for(config, request):
    if (not isinstance(config, dict) or set(config) != {'local_source_id', 'ssh_config', 'relays'}
            or not isinstance(config['relays'], dict)):
        raise ValueError('invalid configuration')
    if not isinstance(request, dict) or set(request) - {'version', 'source_id', 'action', 'request_id', 'ip', 'channel', 'expires_at', 'ttl_seconds'}:
        raise ValueError('invalid request')
    if type(request.get('version')) is not int or request['version'] != 1 or request.get('action') not in ('add', 'delete', 'status', 'check'):
        raise ValueError('invalid request')
    source = request.get('source_id')
    if not isinstance(source, str) or not SAFE.fullmatch(source):
        raise ValueError('invalid source')
    if source == config['local_source_id']:
        return ['/usr/bin/sudo', '-n', '/usr/bin/python3', '-I', '/usr/local/sbin/riskops-ssh-control']
    alias = config['relays'].get(source)
    if not isinstance(alias, str) or not SAFE.fullmatch(alias):
        raise ValueError('unknown source')
    secure_file(config['ssh_config'])
    return ['/usr/bin/ssh', '-T', '-F', config['ssh_config'], '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=8', alias]


def main():
    try:
        if sys.argv[1:] or os.environ.get('SSH_ORIGINAL_COMMAND', ''):
            raise ValueError('commands disabled')
        raw = sys.stdin.buffer.read(4097)
        if len(raw) > 4096:
            raise ValueError('request too large')
        secure_file(CONFIG)
        config = json.loads(CONFIG.read_text())
        request = json.loads(raw)
        command = command_for(config, request)
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            result = subprocess.run(command, input=raw, stdout=out, stderr=err, timeout=25,
                                    env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
                                         'SSH_CONNECTION': os.environ.get('SSH_CONNECTION', '')})
            out.seek(0)
            response = out.read(MAX_RESPONSE + 1)
            if result.returncode not in (0, 1) or len(response) > MAX_RESPONSE:
                raise ValueError('control unavailable')
            payload = json.loads(response)
            if payload.get('source_id') != request.get('source_id') or payload.get('request_id') != request.get('request_id'):
                raise ValueError('identity mismatch')
            sys.stdout.buffer.write(response)
            return result.returncode
    except Exception:
        # Never reveal SSH stderr, configuration, credentials or raw requests.
        print('{"version":1,"status":"error","code":"gateway_unavailable"}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
