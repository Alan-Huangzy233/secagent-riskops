"""Finite scheduled steps over disposable synthetic source stores only."""
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3

import pytest

from app.telemetry import joint_cli as cli
from app.telemetry import joint_refresh as worker
from app.telemetry import joint_reconcile as reconcile
from app.telemetry import joint_case_store as store_module
from app.telemetry.joint_case_contract import CaseStoreError
from app.telemetry.joint_case_query import open_query
from app.telemetry.joint_config import JointRefreshConfig, compile_joint_config
from app.telemetry.joint_reader_io import EvidenceReadError
from app.telemetry.joint_refresh_state import load_state, reserved_paths, read_refresh_status, writer_lock, stamp, timestamp
from test_joint_catalog import configured as configured, clone_heads
from test_joint_reader import sources as sources, store_digest
from test_network_detection import REMOTE

NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def store_clock(monkeypatch):
    actual_tick = worker.tick
    def clocked_tick(spec, *, now=None):
        if now is not None:
            monkeypatch.setattr(store_module, '_now', lambda: stamp(now))
        return actual_tick(spec, now=now)
    monkeypatch.setattr(worker, 'tick', clocked_tick)


@pytest.fixture
def scheduled(configured):
    config, spec = configured
    cli.run(config, 'init')
    return config, replace(spec, refresh=JointRefreshConfig(enabled=True))


def status(spec):
    return open_query(spec.database_path, spec.scope, spec.limits,
                      catalog_min_seq=spec.catalog_min_seq).status()


def complete(spec, *, at=NOW):
    first = worker.tick(spec, now=at)
    assert first['phase'] == 'refresh' and first['last_success_at'] is None
    second = worker.tick(spec, now=at+timedelta(seconds=1))
    assert second['last_success_at'] is not None
    return second


def test_disabled_is_zero_io_and_missing_store_is_never_initialized(configured, monkeypatch):
    _, spec = configured
    monkeypatch.setattr(worker, 'writer_lock', lambda *a: pytest.fail('disabled lock'))
    assert worker.tick(spec) == {'enabled': False, 'state': 'disabled'}
    assert worker.tick(None) == {'enabled': False, 'state': 'disabled'}
    enabled = replace(spec, refresh=JointRefreshConfig(enabled=True))
    with pytest.raises(CaseStoreError, match='joint_store_unavailable'):
        worker.tick(enabled)
    assert not Path(spec.database_path).exists()
    assert not any(path.exists() for path in reserved_paths(spec))


def test_complete_round_and_cooldown_are_durable_without_source_mutation(scheduled, sources, monkeypatch):
    _, spec = scheduled
    before = [store_digest(path) for path in (sources[0].path, sources[1].path)]
    result = complete(spec)
    assert result['state'] == 'waiting' and not result['stale']
    assert result['last_complete_at'] == result['last_success_at']
    raw = reserved_paths(spec)[1].read_bytes()
    monkeypatch.setattr(cli, 'discover', lambda *a: pytest.fail('cooldown source read'))
    again = worker.tick(spec, now=NOW+timedelta(seconds=100))
    assert again['age_seconds'] == 99 and reserved_paths(spec)[1].read_bytes() == raw
    assert [store_digest(path) for path in (sources[0].path, sources[1].path)] == before


def test_finite_discovery_then_refresh_never_reopens_catalog_mid_cycle(scheduled, sources):
    _, spec = scheduled
    clone_heads(sources[0].path, 12)
    worker.tick(spec, now=NOW)
    discovery = status(spec)['discovery']['cycle_id']
    first = worker.tick(spec, now=NOW+timedelta(seconds=1))
    assert first['pending'] == 8 and first['failed'] == 4
    cycle = status(spec)['cycle']['cycle_id']
    clone_heads(sources[0].path, 1, start=900)
    second = worker.tick(spec, now=NOW+timedelta(seconds=2))
    assert second['pending'] == 3
    assert status(spec)['discovery']['cycle_id'] == discovery
    assert status(spec)['cycle']['cycle_id'] == cycle
    third = worker.tick(spec, now=NOW+timedelta(seconds=3))
    assert third['pending'] == 0 and third['last_complete_at'] is not None
    assert third['last_success_at'] is None and third['state'] == 'backoff'
    assert status(spec)['capacity']['registrations'] == 13


def test_discovery_barrier_survives_new_arrivals_between_ticks(scheduled, sources):
    _, spec = scheduled
    clone_heads(sources[0].path, 52)
    worker.tick(spec, now=NOW)
    first = status(spec)['discovery']
    assert first['scanned_count'] == 50 and not first['complete']
    clone_heads(sources[0].path, 1, start=900)
    result = worker.tick(spec, now=NOW+timedelta(seconds=1))
    after = status(spec)['discovery']
    assert after['cycle_id'] == first['cycle_id'] and after['target_seq'] == first['target_seq']
    assert after['complete'] and after['scanned_count'] == 53 and result['phase'] == 'refresh'


def test_late_ssh_only_evidence_is_revisited_and_success_survives_new_cycle(scheduled, sources):
    _, spec = scheduled
    first = complete(spec)
    sources[1].ingest('auth-a', 'example.invalid', 'late-refresh', [
        {'event_id': 'late-refresh', 'timestamp': (sources[4]+timedelta(seconds=24)).isoformat(),
         'identifier': 'sshd', 'message': f'Accepted publickey for exampleuser from {REMOTE} port 42000 ssh2'}])
    progress = worker.tick(spec, now=NOW+timedelta(seconds=302))
    assert progress['last_success_at'] == first['last_success_at']
    done = worker.tick(spec, now=NOW+timedelta(seconds=303))
    assert done['last_success_at'] != first['last_success_at']
    assert open_query(spec.database_path, spec.scope, spec.limits).list_cases()['items'][0]['revision'] == 2


def test_commit_then_checkpoint_failure_resumes_discovery_without_reopening(scheduled, monkeypatch):
    _, spec = scheduled
    real_save, calls = worker.save_state, []
    def interrupted(*args):
        calls.append(None)
        if len(calls) == 2:
            raise CaseStoreError('joint_store_unavailable')
        return real_save(*args)
    monkeypatch.setattr(worker, 'save_state', interrupted)
    with pytest.raises(CaseStoreError):
        worker.tick(spec, now=NOW)
    discovery = status(spec)['discovery']['cycle_id']
    assert load_state(spec)['discovery_id'] is None
    monkeypatch.setattr(worker, 'save_state', real_save)
    result = worker.tick(spec, now=NOW+timedelta(seconds=1))
    assert result['phase'] == 'refresh' and status(spec)['discovery']['cycle_id'] == discovery
    assert worker.tick(spec, now=NOW+timedelta(seconds=2))['last_success_at'] is not None


def test_killed_refresh_resumes_frozen_cycle_and_stall_is_visible(scheduled, monkeypatch):
    _, spec = scheduled
    worker.tick(spec, now=NOW)
    real = reconcile.read_joint_evidence
    monkeypatch.setattr(reconcile, 'read_joint_evidence', lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        worker.tick(spec, now=NOW+timedelta(seconds=1))
    cycle = status(spec)['cycle']['cycle_id']
    stalled = read_refresh_status(spec, status(spec), now=NOW+timedelta(seconds=1000))
    assert stalled['stalled'] and stalled['stale'] and stalled['last_success_at'] is None
    monkeypatch.setattr(reconcile, 'read_joint_evidence', real)
    done = worker.tick(spec, now=NOW+timedelta(seconds=1001))
    assert done['last_success_at'] is not None and status(spec)['cycle']['cycle_id'] == cycle


def test_failed_discovery_refreshes_old_anchors_without_full_success(scheduled, sources):
    _, spec = scheduled
    original = complete(spec)
    clone_heads(sources[0].path, 1)
    with closing(sqlite3.connect(sources[0].path)) as db:
        db.execute("UPDATE network_incidents SET payload_json='{' WHERE seq=2")
        db.commit()
    first = worker.tick(spec, now=NOW+timedelta(seconds=302))
    assert first['phase'] == 'refresh' and first['state'] == 'backoff'
    assert first['last_success_at'] == original['last_success_at']
    degraded = worker.tick(spec, now=NOW+timedelta(seconds=363))
    assert degraded['phase'] == 'discover' and degraded['last_success_at'] == original['last_success_at']
    assert status(spec)['cycle']['counts']['unchanged'] == 1
    assert status(spec)['revalidation_pending']


def test_capacity_failure_stops_future_source_work(configured, sources, monkeypatch):
    config, _ = configured
    config.joint_cases = config.joint_cases.model_copy(update={'store_limits': {'registration_limit': 1}})
    cli.run(config, 'init')
    spec = replace(compile_joint_config(config), refresh=JointRefreshConfig(enabled=True))
    complete(spec)
    clone_heads(sources[0].path, 1)
    blocked = worker.tick(spec, now=NOW+timedelta(seconds=302))
    assert blocked['state'] == 'blocked' and blocked['error'] == 'joint_capacity_exceeded'
    assert blocked['next_attempt_at'] is None
    monkeypatch.setattr(cli, 'discover', lambda *a: pytest.fail('blocked discovery'))
    monkeypatch.setattr(worker, 'reconcile_step', lambda *a, **k: pytest.fail('blocked refresh'))
    assert worker.tick(spec, now=NOW+timedelta(days=2))['state'] == 'blocked'


def test_manual_cli_and_worker_share_nonblocking_lock(scheduled):
    config, spec = scheduled
    with writer_lock(spec):
        with pytest.raises(CaseStoreError, match='joint_store_busy'):
            worker.tick(spec, now=NOW)
        with pytest.raises(CaseStoreError, match='joint_store_busy'):
            cli.run(config, 'discover')
    assert not reserved_paths(spec)[1].exists()
    assert worker.tick(spec, now=NOW)['phase'] == 'refresh'


def test_manual_replacement_cycle_is_not_mistaken_for_qualified_success(scheduled):
    config, spec = scheduled
    worker.tick(spec, now=NOW)
    cli.run(config, 'discover')
    first = worker.tick(spec, now=NOW+timedelta(seconds=1))
    assert first['last_success_at'] is None
    worker.tick(spec, now=NOW+timedelta(seconds=302))
    assert worker.tick(spec, now=NOW+timedelta(seconds=303))['last_success_at'] is not None


def test_restore_epoch_clears_freshness_and_runs_new_qualified_round(scheduled):
    _, spec = scheduled
    complete(spec)
    with closing(sqlite3.connect(spec.database_path)) as db:
        db.execute("UPDATE joint_runtime SET query_epoch=?,revalidation_pending=1,recovery_discovery_done=0,"
                   "recovery_refresh_cycle=NULL,recovery_discovery_cycle=NULL", ('a'*32,))
        db.execute('DELETE FROM joint_discovery')
        db.commit()
    bad = read_refresh_status(spec, status(spec), now=NOW+timedelta(seconds=4))
    assert bad['state'] == 'unavailable' and bad['last_success_at'] is None and bad['stale']
    assert worker.tick(spec, now=NOW+timedelta(seconds=5))['last_success_at'] is None
    assert worker.tick(spec, now=NOW+timedelta(seconds=6))['last_success_at'] is not None
    assert not status(spec)['revalidation_pending']


def test_empty_scope_cannot_claim_success_with_missing_ssh_schema(scheduled, sources):
    _, spec = scheduled
    with closing(sqlite3.connect(sources[0].path)) as db:
        db.execute('DELETE FROM network_incidents')
        db.commit()
    with closing(sqlite3.connect(sources[1].path)) as db:
        db.execute('DROP TABLE incident_evidence')
        db.commit()
    worker.tick(spec, now=NOW)
    result = worker.tick(spec, now=NOW+timedelta(seconds=1))
    assert result['last_success_at'] is None and result['state'] == 'backoff'
    assert status(spec)['revalidation_pending']


def test_committed_refresh_recovery_uses_old_completion_not_restart_time(scheduled, monkeypatch):
    _, spec = scheduled
    worker.tick(spec, now=NOW)
    real_save, calls = worker.save_state, []
    def crash_after_commit(*args):
        calls.append(None)
        if len(calls) == 3:
            raise CaseStoreError('joint_store_unavailable')
        return real_save(*args)
    monkeypatch.setattr(worker, 'save_state', crash_after_commit)
    with pytest.raises(CaseStoreError):
        worker.tick(spec, now=NOW+timedelta(seconds=1))
    completed = status(spec)['cycle']['finished_at']
    assert completed == stamp(NOW+timedelta(seconds=1))
    assert load_state(spec)['state'] == 'running'
    monkeypatch.setattr(worker, 'save_state', real_save)
    monkeypatch.setattr(worker, 'reconcile_step', lambda *a, **k: pytest.fail('completed cycle re-read'))
    result = worker.tick(spec, now=NOW+timedelta(days=1))
    assert result['last_complete_at'] == completed and result['last_success_at'] == completed
    assert result['age_seconds'] == 86399 and result['stale']


def test_manual_failed_cycle_overlays_old_scheduler_success(scheduled, monkeypatch):
    config, spec = scheduled
    original = complete(spec)
    def failed(*args, **kwargs):
        raise EvidenceReadError('source_busy')
    monkeypatch.setattr(reconcile, 'read_joint_evidence', failed)
    cli.run(config, 'refresh')
    result = read_refresh_status(spec, status(spec), now=NOW+timedelta(seconds=4))
    assert result['last_success_at'] == original['last_success_at']
    assert result['state'] == 'unavailable' and result['error'] == 'source_busy' and result['stale']


def test_real_process_termination_releases_lock_and_resumes_saved_cycle(scheduled, monkeypatch):
    import multiprocessing
    import time
    _, spec = scheduled
    worker.tick(spec, now=NOW)
    context = multiprocessing.get_context('fork')
    entered = context.Event()
    real = reconcile.read_joint_evidence
    def slow(*args, **kwargs):
        entered.set()
        time.sleep(30)
        return real(*args, **kwargs)
    monkeypatch.setattr(reconcile, 'read_joint_evidence', slow)
    process = context.Process(target=worker.tick, args=(spec,), kwargs={'now': NOW+timedelta(seconds=1)})
    process.start()
    try:
        assert entered.wait(5)
        cycle = status(spec)['cycle']['cycle_id']
        with pytest.raises(CaseStoreError, match='joint_store_busy'):
            worker.tick(spec, now=NOW+timedelta(seconds=2))
        process.terminate()
        process.join(5)
        assert not process.is_alive()
    finally:
        if process.is_alive():
            process.kill()
        process.join(5)
    monkeypatch.setattr(reconcile, 'read_joint_evidence', real)
    result = worker.tick(spec, now=NOW+timedelta(seconds=3))
    assert result['last_success_at'] is not None
    assert status(spec)['cycle']['cycle_id'] == cycle



def test_manual_discovery_invalidates_global_freshness_until_new_refresh(scheduled, sources):
    config, spec = scheduled
    original = complete(spec)
    clone_heads(sources[0].path, 1)
    cli.run(config, 'discover')
    base = status(spec)
    assert base['capacity']['registrations'] == 2 and base['cycle']['item_count'] == 1
    result = read_refresh_status(spec, base, now=NOW+timedelta(seconds=3))
    assert result['last_success_at'] == original['last_success_at']
    assert result['stale'] and result['error'] == 'joint_refresh_required'
    assert result['pending'] is None and result['failed'] is None



def test_retry_delay_begins_after_failed_read(scheduled, monkeypatch):
    _, spec = scheduled
    times = iter([NOW, NOW+timedelta(seconds=8), NOW+timedelta(seconds=8)])
    monkeypatch.setattr(worker, 'utcnow', lambda: next(times))
    def slow_failure(*a, **kw):
        raise EvidenceReadError('source_busy')
    monkeypatch.setattr(cli, 'discover', slow_failure)
    result = worker.tick(spec)
    assert result['state'] == 'backoff'
    assert timestamp(result['next_attempt_at']) == NOW+timedelta(seconds=8+spec.refresh.retry_seconds)
