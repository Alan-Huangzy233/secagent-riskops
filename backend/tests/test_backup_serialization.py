"""Exercise the shipped flock commands with disposable files and processes only."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time

import pytest


ROOT = Path(__file__).parents[2]
UNITS = ROOT / 'deploy' / 'systemd'
LOCK = '/run/secagent-riskops-backup/maintenance.lock'
PLAIN = 'secagent-riskops-backup.service'
RECOVERY = 'secagent-riskops-recovery-package.service'
pytestmark = pytest.mark.skipif(sys.platform != 'linux' or not shutil.which('flock'),
                                reason='Linux systemd/flock deployment')


def directives(path, key):
    source = path.read_text().replace('\\\n', '')
    return [shlex.split(line.split('=', 1)[1]) for line in source.splitlines()
            if line.startswith(key+'=')]


def wrapped(unit, lock, command, *, wait='2', index=0):
    argv = directives(UNITS / unit, 'ExecStart')[index]
    at = argv.index(LOCK)
    prefix = argv[:at] + [str(lock)]
    prefix[prefix.index('--timeout')+1] = wait
    return prefix + command


def preflight(unit, lock, **credentials):
    for command in directives(UNITS / unit, 'ExecStartPre'):
        result = subprocess.run([str(lock) if arg == LOCK else arg for arg in command],
                                capture_output=True, **credentials)
        if result.returncode:
            return result.returncode
    return 0


@pytest.fixture
def files():
    # Cross-account tests need traversable ancestors; pytest's own temporary
    # root is deliberately private. This directory contains synthetic files only.
    with tempfile.TemporaryDirectory(prefix='riskops-backup-lock-') as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        directory = root / 'coordination'
        directory.mkdir(mode=0o750)
        directory.chmod(0o750)
        lock = directory / 'maintenance.lock'
        lock.touch(mode=0o660)
        lock.chmod(0o660)
        journal = root / 'events.jsonl'
        journal.touch(mode=0o660)
        journal.chmod(0o660)
        yield root, directory, lock, journal


BODY = r'''
import json, os, sys, time
path, label, duration = sys.argv[1:]
def record(stage):
    with open(path, 'a') as output:
        output.write(json.dumps({'label': label, 'stage': stage, 'uid': os.getuid()})+'\n')
record('start')
time.sleep(float(duration))
record('end')
'''


def body(journal, label, duration='0'):
    return ['/usr/bin/python3', '-c', BODY, str(journal), label, duration]


def events(journal):
    return [json.loads(line) for line in journal.read_text().splitlines()]


def wait_started(journal):
    deadline = time.monotonic()+3
    while not journal.stat().st_size:
        if time.monotonic() >= deadline:
            raise AssertionError('synthetic holder did not start')
        time.sleep(0.01)


def finish(*processes):
    for process in processes:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=3)


def test_all_shipped_and_optional_commands_share_lock_and_keep_original_arguments():
    plain = directives(UNITS / PLAIN, 'ExecStart')
    recovery = directives(UNITS / RECOVERY, 'ExecStart')
    extra = UNITS / 'backup-extra-databases.conf.example'
    commands = plain + recovery + directives(extra, 'ExecStart')
    optional = [shlex.split(line.removeprefix('# ExecStart=')) for line in extra.read_text().splitlines()
                if line.startswith('# ExecStart=')]
    assert len(plain) == 1 and len(recovery) == 2 and len(commands) == 4 and len(optional) == 1
    for command in commands + optional:
        assert command[:8] == ['/usr/bin/flock', '--exclusive', '--timeout', '10800',
                               '--conflict-exit-code', '75', '--no-fork', LOCK]
        assert command[8:10] == ['/usr/bin/python3', '/opt/secagent-riskops/current/scripts/'+
                                ('recovery_package.py' if 'recovery_package.py' in command[9] else 'backup_telemetry.py')]
    assert plain[0][-4:] == ['--database', '/var/lib/secagent-riskops/live.sqlite',
                             '--directory', '/var/backups/secagent-riskops']
    assert commands[-1][-4:] == ['--database', '/var/lib/secagent-riskops/control.sqlite',
                                '--directory', '/var/backups/secagent-riskops/control']
    assert recovery[0][10] == 'build'
    assert recovery[1][10:] == ['prune', '/var/backups/secagent-riskops-packages', '--keep', '2',
                                '--require-confirmations', '1', '--apply']
    for name in (PLAIN, RECOVERY):
        contents = (UNITS / name).read_text()
        assert 'ProtectSystem=strict' in contents and 'PrivateTmp=true' in contents
        assert directives(UNITS / name, 'ReadWritePaths')[-1] == [LOCK]
        assert 'TimeoutStartSec=infinity' in contents and 'KillMode=control-group' in contents
        assert not directives(UNITS / name, 'SuccessExitStatus')
        assert not directives(UNITS / name, 'RuntimeDirectory')
    assert directives(UNITS / PLAIN, 'User') == [['riskops']]
    assert not directives(UNITS / RECOVERY, 'User')  # system service default stays root


def test_lock_preflight_rejects_missing_and_symlink_files_without_creating_them(files):
    root, _, lock, journal = files
    for unit in (PLAIN, RECOVERY):
        assert preflight(unit, lock) == 0
        missing = lock.with_name('missing.lock')
        assert preflight(unit, missing) != 0 and not missing.exists()
        link = root / 'linked.lock'
        link.symlink_to(lock)
        assert preflight(unit, link) != 0
        link.unlink()
    assert not events(journal)


def test_overlapping_plain_and_recovery_jobs_are_serial(files):
    _, _, lock, journal = files
    first = subprocess.Popen(wrapped(PLAIN, lock, body(journal, 'plain', '0.3')))
    second = None
    try:
        wait_started(journal)
        second = subprocess.Popen(wrapped(RECOVERY, lock, body(journal, 'recovery')))
        assert first.wait(timeout=3) == 0 and second.wait(timeout=3) == 0
        assert [(e['label'], e['stage']) for e in events(journal)] == [
            ('plain', 'start'), ('plain', 'end'), ('recovery', 'start'), ('recovery', 'end')]
    finally:
        finish(*[p for p in (first, second) if p is not None])


def test_lock_timeout_does_not_run_body_or_touch_prior_backups(files):
    root, _, lock, journal = files
    prior = root / 'verified.sqlite'
    prior.write_bytes(b'previous verified backup')
    first = subprocess.Popen(wrapped(PLAIN, lock, body(journal, 'holder', '0.4')))
    try:
        wait_started(journal)
        result = subprocess.run(wrapped(RECOVERY, lock, body(journal, 'must-not-run'), wait='0.05'), timeout=2)
        assert result.returncode == 75
        assert all(row['label'] == 'holder' for row in events(journal))
        assert prior.read_bytes() == b'previous verified backup'
        assert first.wait(timeout=3) == 0
    finally:
        finish(first)


def test_command_exit_status_and_retention_environment_pass_through(files):
    _, _, lock, _ = files
    command = ['/usr/bin/python3', '-c',
               "import os,sys;sys.exit(23 if os.environ.get('RISKOPS_BACKUP_KEEP') == '3' else 99)"]
    result = subprocess.run(wrapped(RECOVERY, lock, command),
                            env={**os.environ, 'RISKOPS_BACKUP_KEEP': '3'}, timeout=3)
    assert result.returncode == 23
    assert subprocess.run(wrapped(PLAIN, lock, ['/usr/bin/true']), timeout=3).returncode == 0


def test_stopping_a_waiter_never_starts_its_backup(files):
    _, _, lock, journal = files
    first = subprocess.Popen(wrapped(RECOVERY, lock, body(journal, 'holder', '0.4')))
    waiter = None
    try:
        wait_started(journal)
        waiter = subprocess.Popen(wrapped(PLAIN, lock, body(journal, 'stopped-waiter')), start_new_session=True)
        time.sleep(0.05)
        os.killpg(waiter.pid, signal.SIGTERM)
        assert waiter.wait(timeout=2) == -signal.SIGTERM
        assert first.wait(timeout=3) == 0
        assert all(row['label'] == 'holder' for row in events(journal))
    finally:
        finish(*[p for p in (first, waiter) if p is not None])


def test_explicit_process_group_cleanup_finishes_before_followup_job(files):
    root, _, lock, journal = files
    child_file = root / 'child.pid'
    command = ['/usr/bin/python3', '-c',
               "import pathlib,subprocess,sys,time;child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
               "pathlib.Path(sys.argv[1]).write_text(str(child.pid));time.sleep(30)", str(child_file)]
    holder = subprocess.Popen(wrapped(RECOVERY, lock, command), start_new_session=True)
    try:
        deadline = time.monotonic()+3
        while not child_file.exists():
            assert time.monotonic() < deadline
            time.sleep(0.01)
        child_pid = int(child_file.read_text())
        os.killpg(holder.pid, signal.SIGTERM)
        assert holder.wait(timeout=3) == -signal.SIGTERM
        deadline = time.monotonic()+3
        while (state := Path(f'/proc/{child_pid}/stat')).exists() and state.read_text().split()[2] != 'Z':
            assert time.monotonic() < deadline
            time.sleep(0.01)
        # Model the documented operator sequence: drain the old group before
        # starting a successor. This is not a claim about automatic systemd
        # cgroup/lock lifetime while a child delays its SIGTERM response.
        assert subprocess.run(wrapped(PLAIN, lock, body(journal, 'after-stop')), timeout=3).returncode == 0
    finally:
        try:
            os.killpg(holder.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        finish(holder)


@pytest.mark.skipif(os.geteuid() != 0, reason='Cross-account check runs in the separate privileged CI step')
def test_cross_account_root_and_unprivileged_user_share_protected_inode(files):
    _, directory, lock, journal = files
    # No user/group is created: only these disposable child processes change IDs.
    uid = gid = 65534
    for path in (directory, lock, journal):
        os.chown(path, 0, gid)
    before = lock.stat()
    credentials = dict(user=uid, group=gid, extra_groups=[])
    assert preflight(PLAIN, lock, **credentials) == 0
    assert preflight(RECOVERY, lock) == 0
    first = subprocess.Popen(wrapped(PLAIN, lock, body(journal, 'riskops', '0.3')), **credentials)
    second = None
    try:
        wait_started(journal)
        second = subprocess.Popen(wrapped(RECOVERY, lock, body(journal, 'root')))
        assert first.wait(timeout=3) == 0 and second.wait(timeout=3) == 0
        assert [(e['stage'], e['uid']) for e in events(journal)] == [('start', uid), ('end', uid), ('start', 0), ('end', 0)]
        assert (lock.stat().st_dev, lock.stat().st_ino) == (before.st_dev, before.st_ino)
        result = subprocess.run(['/usr/bin/python3', '-c', 'import os,sys;os.unlink(sys.argv[1])', str(lock)],
                                capture_output=True, **credentials)
        assert result.returncode != 0 and lock.exists()
        lock.chmod(0o640)
        assert preflight(PLAIN, lock, **credentials) != 0
    finally:
        finish(*[p for p in (first, second) if p is not None])


def test_tmpfiles_uses_stable_root_owned_inode_and_calendar_policy_is_unchanged():
    rules = (ROOT / 'deploy/tmpfiles.d/secagent-riskops-backup.conf').read_text()
    records = [shlex.split(line) for line in rules.splitlines() if line and not line.startswith('#')]
    assert records == [['d', '/run/secagent-riskops-backup', '0750', 'root', 'riskops', '-', '-'],
                       ['f', LOCK, '0660', 'root', 'riskops', '-', '-']]
    for unit, clock, delay in [(PLAIN, '03:15:00', '300'), (RECOVERY, '03:45:00', '600')]:
        timer = UNITS / unit.replace('.service', '.timer')
        assert directives(timer, 'OnCalendar') == [['*-*-*', clock, 'UTC']]
        assert directives(timer, 'RandomizedDelaySec') == [[delay]]
        assert directives(timer, 'Persistent') == [['true']]
