"""A restored HTTP receipt, file generation and console checkpoint must agree."""
from contextlib import closing, contextmanager
import fcntl
import json
from pathlib import Path
import sqlite3
import time

import pytest

from app.telemetry.http_store import HttpStore
from app.telemetry.http_worker import publish
from app.telemetry.store import TelemetryStore
from test_http_incidents import NOW, drain, ingest, record, scan
from test_recovery_package import build, needs_gpg, recovery, signing_key as signing_key, verify


@pytest.fixture
def deployment(tmp_path):
    http = HttpStore(tmp_path / 'http.sqlite')
    console = TelemetryStore(tmp_path / 'console.sqlite')
    state = tmp_path / 'collector'
    state.mkdir()
    config = tmp_path / 'package.json'
    config.write_text(json.dumps(dict(host_id='http-test', components=[
        dict(name='http', kind='sqlite', path=str(http.path)),
        dict(name='telemetry', kind='sqlite', path=str(console.path)),
        dict(name='collector', kind='state_dir', path=str(state), patterns=['*.state.json', '*.pending.json'])],
        http_recovery=dict(http_database='http', console_database='telemetry', collector_states=['collector'],
                           lock_timeout_seconds=1))))
    return dict(config=config, store=tmp_path / 'packages', state=state, http=http, console=console)


def seed(deployment):
    ingest(deployment['http'], scan())
    drain(deployment['http'])
    publish(deployment['http'], deployment['console'], NOW)
    deployment['console'].run_notifications([], now=NOW)
    return deployment['http'].incidents()['items'][0]


def change_config(deployment, edit):
    config = json.loads(deployment['config'].read_text())
    edit(config)
    deployment['config'].write_text(json.dumps(config))


@pytest.mark.parametrize('change', [
    lambda c: c['http_recovery'].update(console_database='absent'),
    lambda c: c['http_recovery'].update(console_database='http'),
    lambda c: c['http_recovery'].update(collector_states=[]),
    lambda c: c['http_recovery'].update(collector_states=['collector', 'collector']),
    lambda c: c['http_recovery'].update(lock_timeout_seconds=True),
    lambda c: c['http_recovery'].update(lock_timeout_seconds=11),
    lambda c: c['components'][2].update(patterns=['*.state.json']),
])
def test_incomplete_http_cohorts_fail_before_publication(deployment, change):
    change_config(deployment, change)
    with pytest.raises(recovery.PackageError):
        recovery.load_config(deployment['config'])
    assert not deployment['store'].exists()


def test_http_database_cannot_silently_use_the_generic_backup_path(deployment):
    change_config(deployment, lambda c: c.pop('http_recovery'))
    assert recovery.main(['build', '--config', str(deployment['config']), '--output-dir',
                          str(deployment['store']), '--allow-unencrypted']) == 2
    assert list(deployment['store'].iterdir()) == []


def test_collector_locks_cover_capture_through_pin_but_not_database_copy(deployment, monkeypatch):
    pin, snapshot = recovery.pinned_http_databases, recovery.snapshot_database
    order = []

    @contextmanager
    def check_pin(specs, timeout):
        with (deployment['state'] / 'collector.lock').open('a+b') as lock:
            with pytest.raises(BlockingIOError):
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        order.append('locked')
        with pin(specs, timeout) as value:
            yield value

    def check_copy(*args, **kwargs):
        with (deployment['state'] / 'collector.lock').open('a+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        order.append('released')
        return snapshot(*args, **kwargs)

    monkeypatch.setattr(recovery, 'pinned_http_databases', check_pin)
    monkeypatch.setattr(recovery, 'snapshot_database', check_copy)
    result = build(deployment, '--allow-unencrypted')
    assert order == ['locked', 'released', 'released']
    verify(result['package'], '--deep')


def test_writers_can_advance_both_live_databases_while_copies_stay_at_the_same_point(deployment, monkeypatch, tmp_path):
    original = seed(deployment)
    snapshot = recovery.snapshot_database
    advanced = []

    def advance_then_copy(spec, contents, census, **kwargs):
        if not advanced:
            # These actual writes must succeed before either slow backup copy.
            ingest(deployment['http'], [record('late', path='/.env')], 'late')
            drain(deployment['http'])
            publish(deployment['http'], deployment['console'], NOW+1)
            advanced.append(True)
        return snapshot(spec, contents, census, **kwargs)

    monkeypatch.setattr(recovery, 'snapshot_database', advance_then_copy)
    result = build(deployment, '--allow-unencrypted', '--census')
    restored = tmp_path / 'restore'
    verify(result['package'], '--into', str(restored))
    saved = HttpStore(restored / 'http.sqlite')
    assert saved.incident(original['incident_id']) == original
    assert deployment['http'].incident(original['incident_id'])['revision'] == 2
    with saved.connection() as http, closing(sqlite3.connect(restored / 'telemetry.sqlite')) as console:
        assert recovery.check_http_pair(http, console)['imported_topics'] == 1
    assert result['manifest']['consistency']['http_recovery']['collectors_locked_until_pin']


def test_busy_collector_does_not_publish_and_preserves_previous_package(deployment):
    kept = build(deployment, '--allow-unencrypted')['package']
    with (deployment['state'] / 'collector.lock').open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        assert recovery.main(['build', '--config', str(deployment['config']), '--output-dir',
                              str(deployment['store']), '--allow-unencrypted']) == 2
    assert list(deployment['store'].iterdir()) == [kept]
    verify(kept, '--deep')


def test_busy_database_deadline_releases_already_acquired_locks(deployment):
    specs = recovery.load_config(deployment['config'])['components'][:2]
    with deployment['http'].connection(write=True):
        started = time.monotonic()
        with pytest.raises(recovery.PackageError, match='busy'):
            with recovery.pinned_http_databases(specs, 1):
                pytest.fail('must not get a partial cohort')
        assert time.monotonic() - started < 3
        # Console sorts first. Its reservation must have been rolled back.
        with closing(sqlite3.connect(deployment['console'].path, timeout=0.1)) as console:
            console.execute('BEGIN IMMEDIATE')


def test_non_wal_and_aliased_databases_are_rejected(deployment):
    specs = recovery.load_config(deployment['config'])['components'][:2]
    with closing(sqlite3.connect(deployment['http'].path)) as http:
        http.execute('PRAGMA journal_mode=DELETE')
    with pytest.raises(recovery.PackageError, match='WAL'):
        with recovery.pinned_http_databases(specs, 1):
            pytest.fail('rollback-journal cohort is unsafe')
    alias = Path(deployment['http'].path).with_name('alias.sqlite')
    alias.hardlink_to(deployment['http'].path)
    specs[1]['path'] = str(alias)
    with pytest.raises(recovery.PackageError, match='alias'):
        with recovery.pinned_http_databases(specs, 1):
            pytest.fail('aliased cohort is unsafe')


@pytest.mark.parametrize('checkpoint', [0, 2])
def test_mismatched_console_checkpoint_cannot_be_packaged(deployment, checkpoint):
    seed(deployment)
    with deployment['console']._connection(write=True) as db:
        db.execute("UPDATE notification_meta SET value=? WHERE name LIKE 'http-import:%'", (str(checkpoint),))
    assert recovery.main(['build', '--config', str(deployment['config']), '--output-dir',
                          str(deployment['store']), '--allow-unencrypted']) == 2
    assert list(deployment['store'].iterdir()) == []


@needs_gpg
def test_encrypted_restore_keeps_history_and_retries_import_without_a_second_notification(deployment, signing_key, tmp_path, capsys):
    original = seed(deployment)
    ingest(deployment['http'], [record('late', path='/.env')], 'late')
    drain(deployment['http'])

    def crash():
        raise RuntimeError('crash after console commit, before source acknowledgment')

    with pytest.raises(RuntimeError):
        publish(deployment['http'], deployment['console'], NOW+1, after_import=crash)
    # Raw expiry must not erase historical incident evidence on restore.
    with deployment['http'].connection(write=True) as db:
        db.execute('DELETE FROM http_events')
    result = build(deployment, '--recipient', signing_key, '--sign-key', signing_key, '--census')
    capsys.readouterr()
    restored = tmp_path / 'restore'
    verify(result['package'], '--into', str(restored))
    report = json.loads(capsys.readouterr().out)
    assert report['ok'] and report['http_recovery']['notification_checkpoints'] == 'compatible'
    saved, console = HttpStore(restored / 'http.sqlite'), TelemetryStore(restored / 'telemetry.sqlite')
    assert saved.incident(original['incident_id'], 1) == original
    assert saved.evidence(original['incident_id'], revision=1)['total'] == 20
    assert saved.evidence(original['incident_id'])['total'] == 21
    assert publish(saved, console, NOW+2) == 1
    console.run_notifications([], now=NOW+1000)
    total = console.list_notifications(kind='http_incident')['total']
    assert publish(saved, console, NOW+1001) == 0
    console.run_notifications([], now=NOW+2000)
    assert console.list_notifications(kind='http_incident')['total'] == total
    # A mislabelled producer must also fail deep verification.
    manifest = result['manifest']
    manifest['consistency']['http_recovery']['producer_id'] = '0'*32
    with pytest.raises(recovery.PackageError, match='metadata'):
        recovery.inspect_http_recovery(manifest, restored)
