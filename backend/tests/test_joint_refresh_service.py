"""Exercise the optional unit's flock wrapper using disposable local processes."""
from __future__ import annotations

from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time

import pytest

try:
    import fcntl
except ImportError:
    fcntl = None

UNIT = Path(__file__).parents[2] / 'deploy/systemd/secagent-riskops-joint-refresh.service'
LOCK = '/run/secagent-riskops-backup/maintenance.lock'
pytestmark = pytest.mark.skipif(fcntl is None or not shutil.which('flock'),
                                reason='Requires POSIX advisory locks and flock')


def wrapped(lock, body):
    line = next(line for line in UNIT.read_text().splitlines() if line.startswith('ExecStart='))
    command = shlex.split(line.split('=', 1)[1])
    index = command.index(LOCK)
    return command[:index] + [str(lock)] + body


def test_exclusive_maintenance_skips_body_and_propagates_other_exit_codes(tmp_path):
    lock = tmp_path / 'maintenance.lock'
    lock.touch(mode=0o600)
    marker = tmp_path / 'executed'
    body = [sys.executable, '-c',
            'import pathlib,sys;pathlib.Path(sys.argv[1]).touch();sys.exit(23)', str(marker)]
    with lock.open('rb') as holder:
        fcntl.flock(holder.fileno(), fcntl.LOCK_EX)
        skipped = subprocess.run(wrapped(lock, body), capture_output=True, timeout=3)
        assert skipped.returncode == 75 and not marker.exists()
    executed = subprocess.run(wrapped(lock, body), capture_output=True, timeout=3)
    assert executed.returncode == 23 and marker.exists()


def test_shared_wrapper_blocks_exclusive_maintenance_until_process_exits(tmp_path):
    lock = tmp_path / 'maintenance.lock'
    lock.touch(mode=0o600)
    started = tmp_path / 'started'
    body = [sys.executable, '-c',
            'import pathlib,sys,time;pathlib.Path(sys.argv[1]).touch();time.sleep(30)', str(started)]
    process = subprocess.Popen(wrapped(lock, body), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 3
        while not started.exists():
            assert process.poll() is None and time.monotonic() < deadline
            time.sleep(.01)
        with lock.open('rb') as competing:
            with pytest.raises(BlockingIOError):
                fcntl.flock(competing.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Other cooperating readers may coexist; the separate writer lock
            # remains responsible for serializing actual derived-store updates.
            fcntl.flock(competing.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
            fcntl.flock(competing.fileno(), fcntl.LOCK_UN)
        process.terminate()
        process.wait(timeout=3)
        with lock.open('rb') as successor:
            fcntl.flock(successor.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=3)
