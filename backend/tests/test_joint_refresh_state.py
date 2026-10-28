"""Private checkpoints cannot create evidence, expose paths or assert false freshness."""
from dataclasses import replace
from datetime import timedelta
import json
import os
from pathlib import Path

import pytest

from app.telemetry import joint_refresh_state as state
from app.telemetry import joint_refresh as worker
from app.telemetry.joint_case_contract import CaseStoreError
from app.telemetry.joint_config import JointRefreshConfig
from test_joint_refresh import configured as configured, sources as sources, scheduled as scheduled, status, complete, NOW, store_clock as store_clock


def test_missing_checkpoint_status_is_read_only_and_disabled_does_no_io(scheduled, monkeypatch):
    _, spec = scheduled
    lock, checkpoint = state.reserved_paths(spec)
    before = set(Path(spec.database_path).parent.iterdir())
    result = state.read_refresh_status(spec, status(spec), now=NOW)
    assert result['state'] == 'not_started' and result['stale'] and result['last_success_at'] is None
    assert set(Path(spec.database_path).parent.iterdir()) == before
    assert not checkpoint.exists()
    monkeypatch.setattr(state, 'load_state', lambda *a: pytest.fail('disabled status I/O'))
    assert state.read_refresh_status(replace(spec, refresh=None), {})['state'] == 'disabled'
    assert state.read_refresh_status(replace(spec, refresh=JointRefreshConfig()), {})['state'] == 'disabled'


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'mode', 'owner', 'oversized', 'fifo', 'invalid_json', 'duplicate'])
def test_unsafe_or_invalid_checkpoint_is_unavailable(scheduled, kind):
    _, spec = scheduled
    complete(spec)
    checkpoint = state.reserved_paths(spec)[1]
    raw = checkpoint.read_bytes()
    other = checkpoint.with_suffix('.other')
    if kind in ('symlink', 'hardlink'):
        checkpoint.rename(other)
        if kind == 'symlink':
            checkpoint.symlink_to(other)
        else:
            os.link(other, checkpoint)
    elif kind == 'mode':
        checkpoint.chmod(0o644)
    elif kind == 'owner':
        if os.geteuid() != 0:
            pytest.skip('owner fixture requires root')
        os.chown(checkpoint, 12345, -1)
    elif kind == 'oversized':
        checkpoint.write_bytes(b' ' * (state.MAX_STATE_BYTES+1))
    elif kind == 'fifo':
        checkpoint.unlink()
        os.mkfifo(checkpoint, 0o600)
    elif kind == 'invalid_json':
        checkpoint.write_bytes(b'{')
    else:
        checkpoint.write_bytes(raw[:-1]+b',"version":1}')
    result = state.read_refresh_status(spec, status(spec), now=NOW+timedelta(seconds=2))
    assert result['state'] == 'unavailable' and result['stale']
    assert result['last_success_at'] is None


def test_invalid_checkpoint_reset_never_keeps_success_assertion(scheduled):
    _, spec = scheduled
    complete(spec)
    checkpoint = state.reserved_paths(spec)[1]
    checkpoint.write_bytes(b'{')
    result = worker.tick(spec, now=NOW+timedelta(seconds=4))
    assert result['last_success_at'] is None and result['stale']
    assert worker.tick(spec, now=NOW+timedelta(seconds=5))['last_success_at'] is not None


@pytest.mark.parametrize('key', ['store_id', 'query_epoch', 'config_sha256'])
def test_checkpoint_binding_mismatch_discards_all_success_claims(scheduled, key):
    _, spec = scheduled
    complete(spec)
    checkpoint = state.reserved_paths(spec)[1]
    value = json.loads(checkpoint.read_text())
    value['binding'][key] = 'f' * len(value['binding'][key])
    checkpoint.write_text(json.dumps(value))
    result = state.read_refresh_status(spec, status(spec), now=NOW+timedelta(seconds=2))
    assert result['state'] == 'unavailable' and result['error'] == 'joint_refresh_required'
    assert result['last_success_at'] is None
    fresh = worker.tick(spec, now=NOW+timedelta(seconds=3))
    assert fresh['last_success_at'] is None


def test_atomic_write_failure_preserves_existing_checkpoint(scheduled, monkeypatch):
    _, spec = scheduled
    complete(spec)
    path = state.reserved_paths(spec)[1]
    before = path.read_bytes()
    value = state.load_state(spec)
    value['last_attempt_at'] = state.stamp(NOW+timedelta(seconds=3))
    monkeypatch.setattr(state.os, 'replace', lambda *a: (_ for _ in ()).throw(OSError('private path')))
    with state.writer_lock(spec):
        with pytest.raises(CaseStoreError, match='joint_store_unavailable'):
            state.save_state(spec, value)
    assert path.read_bytes() == before
    assert not list(path.parent.glob(path.name+'.*.tmp'))


def test_status_marks_old_success_and_stopped_worker_separately(scheduled):
    _, spec = scheduled
    done = complete(spec)
    result = state.read_refresh_status(spec, status(spec), now=NOW+timedelta(seconds=1002))
    assert result['last_success_at'] == done['last_success_at']
    assert result['age_seconds'] == 1001 and result['stale'] and result['stalled']
    # A fresh heartbeat does not make a stale full-scope success recent.
    value = state.load_state(spec)
    value['last_attempt_at'] = state.stamp(NOW+timedelta(seconds=1001))
    with state.writer_lock(spec):
        state.save_state(spec, value)
    result = state.read_refresh_status(spec, status(spec), now=NOW+timedelta(seconds=1002))
    assert result['stale'] and not result['stalled'] and result['age_seconds'] == 1001


def test_clock_regression_is_unknown_then_restarts_without_future_success(scheduled):
    _, spec = scheduled
    complete(spec)
    result = state.read_refresh_status(spec, status(spec), now=NOW-timedelta(seconds=10))
    assert result['state'] == 'unavailable' and result['stale']
    after = worker.tick(spec, now=NOW-timedelta(seconds=9))
    assert after['last_success_at'] is None


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'mode', 'nonempty'])
def test_writer_lock_rejects_unsafe_fixed_file(scheduled, kind):
    _, spec = scheduled
    lock = state.reserved_paths(spec)[0]
    if kind in ('symlink', 'hardlink'):
        other = lock.with_suffix('.other')
        lock.rename(other)
        if kind == 'symlink':
            lock.symlink_to(other)
        else:
            os.link(other, lock)
    elif kind == 'mode':
        lock.chmod(0o644)
    else:
        lock.write_text('occupied')
    with pytest.raises(CaseStoreError, match='joint_store_unavailable'):
        with state.writer_lock(spec):
            pytest.fail('unsafe lock accepted')


def test_source_alias_is_rejected_before_sidecar_creation(scheduled):
    _, spec = scheduled
    lock, checkpoint = state.reserved_paths(spec)
    candidate = replace(spec, ssh_database_path=str(checkpoint))
    with pytest.raises(CaseStoreError, match='joint_source_alias'):
        with state.writer_lock(candidate):
            pytest.fail('source alias accepted')
    assert not checkpoint.exists()
