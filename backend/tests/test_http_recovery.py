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


@pytest.mark.parametrize('phase', ['in_progress', 'imported', 'delivered'])
def test_paired_restore_resumes_briefing_and_never_delivers_it_twice(deployment, tmp_path, phase):
    from app.telemetry import http_briefings, http_incidents
    from test_http_incidents import BASE

    seed(deployment)
    report_now = max(NOW+1, (int(BASE//86400)+1)*86400+1)
    http, console = deployment['http'], deployment['console']
    assert http_briefings.advance(http, report_now, batch_size=3)
    if phase != 'in_progress':
        for _ in range(100):
            if not http_briefings.advance(http, report_now, batch_size=3):
                break
        else:
            pytest.fail('briefing did not finish')

        def crash():
            raise RuntimeError('lost source acknowledgment after console import')

        with pytest.raises(RuntimeError):
            publish(http, console, report_now, after_import=crash)
        if phase == 'delivered':
            console.run_notifications([], now=report_now)
    with http.connection() as db:
        checkpoint = http_incidents.meta(db, 'briefing_work')
        assert (checkpoint is not None) == (phase == 'in_progress')
    result = build(deployment, '--allow-unencrypted')
    restored = tmp_path / 'restored-briefing'
    verify(result['package'], '--into', str(restored))
    assert recovery.main(['mark-http-restored', str(restored / 'http.sqlite'),
                          str(restored / 'telemetry.sqlite'), str(result['package'])]) == 0
    saved = HttpStore(restored / 'http.sqlite')
    restored_console = TelemetryStore(restored / 'telemetry.sqlite')
    with saved.connection() as db:
        assert http_incidents.meta(db, 'briefing_work') == checkpoint
    for _ in range(100):
        if not http_briefings.advance(saved, report_now, batch_size=3):
            break
    else:
        pytest.fail('restored briefing did not finish')
    for _ in range(2):
        publish(saved, restored_console, report_now)
        restored_console.run_notifications([], now=report_now)
    reports = [n['payload'] for n in restored_console.list_notifications(kind='briefing')['items']
               if n['payload'].get('report_type') == 'http_daily']
    assert len(reports) == 1
    assert reports[0]['counts']['requests'] == 20
    assert reports[0]['counts']['cases'] == reports[0]['counts']['attention'] == 1
    assert reports[0]['cutoff'] == report_now
    with saved.connection() as db, restored_console._connection() as destination:
        assert recovery.check_http_pair(db, destination)['notification_checkpoints'] == 'compatible'


@pytest.fixture
def marker_restore(deployment, tmp_path, capsys):
    seed(deployment)
    result = build(deployment, '--allow-unencrypted')
    restored = tmp_path / 'marker-restored'
    verify(result['package'], '--into', str(restored))
    capsys.readouterr()
    return {**result, 'http_path': restored / 'http.sqlite', 'console_path': restored / 'telemetry.sqlite'}


def mark_http(fixture):
    return recovery.main(['mark-http-restored', str(fixture['http_path']),
                          str(fixture['console_path']), str(fixture['package'])])


def http_rows(path):
    with closing(sqlite3.connect(path.as_uri()+'?mode=ro', uri=True)) as db:
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        result = {table: list(db.execute('SELECT * FROM '+table+' ORDER BY rowid')) for table in tables}
    result['http_analysis_meta'] = [r for r in result['http_analysis_meta'] if not r[0].startswith('restore:')]
    return result


def marker_rows(path):
    with closing(sqlite3.connect(path.as_uri()+'?mode=ro', uri=True)) as db:
        return [json.loads(r[0]) for r in db.execute("SELECT value FROM http_analysis_meta WHERE name LIKE 'restore:%'")]


def rewrite_marker_manifest(fixture, edit):
    package = fixture['package']
    manifest = json.loads((package / 'manifest.json').read_text())
    edit(manifest)
    (package / 'manifest.json').write_text(json.dumps(manifest))
    recovery.write_checksums(package, ['manifest.json', manifest['stored_object']])


def test_http_restore_marker_changes_only_history_and_is_idempotent_after_new_writes(marker_restore, capsys):
    before = http_rows(marker_restore['http_path'])
    console_before = recovery.digest_file(marker_restore['console_path'])
    assert mark_http(marker_restore) == 0
    first = json.loads(capsys.readouterr().out)
    record = first['record']
    assert first['recorded'] is True
    assert record['snapshot_at'] == marker_restore['manifest']['consistency']['http_recovery']['pinned_at']
    assert record['restore_id'] == recovery.digest_file(marker_restore['package'] / 'manifest.json')[0]
    assert record['verification_scope'] == 'paired_database_snapshots'
    assert record['signature'] == 'absent' and record['stream_count'] == 1
    assert http_rows(marker_restore['http_path']) == before
    assert recovery.digest_file(marker_restore['console_path']) == console_before
    # Opening the service and allowing normal ingest/analysis/delivery afterward
    # must not prevent a harmless retry, nor make it claim a fresh verification.
    http = HttpStore(marker_restore['http_path'])
    console = TelemetryStore(marker_restore['console_path'])
    ingest(http, [record_for_marker('after-marker')], 'after-marker')
    drain(http)
    publish(http, console, NOW+5)
    advanced = http_rows(marker_restore['http_path'])
    assert mark_http(marker_restore) == 0
    retry = json.loads(capsys.readouterr().out)
    assert retry['recorded'] is False and retry['record'] == record
    assert 'not reauthenticated' in retry['note']
    assert marker_rows(marker_restore['http_path']) == [record]
    assert http_rows(marker_restore['http_path']) == advanced


def record_for_marker(identity):
    return record(identity, path='/.env')


@pytest.mark.parametrize('changed', ['http', 'console'])
def test_http_marker_rejects_new_writes_before_first_mark(marker_restore, capsys, changed):
    if changed == 'http':
        http = HttpStore(marker_restore['http_path'])
        ingest(http, [record_for_marker('too-late')], 'too-late')
    else:
        with closing(sqlite3.connect(marker_restore['console_path'])) as console:
            console.execute("INSERT INTO notification_meta VALUES('test_new_write','true')")
            console.commit()
    before = http_rows(marker_restore['http_path'])
    assert mark_http(marker_restore) == 2
    assert 'before starting' in capsys.readouterr().err
    assert marker_rows(marker_restore['http_path']) == []
    assert http_rows(marker_restore['http_path']) == before


@pytest.mark.parametrize('role', ['http_path', 'console_path'])
def test_http_marker_rejects_wrong_missing_linked_and_aliased_databases(marker_restore, tmp_path, role):
    original = marker_restore[role]
    marker_restore[role] = tmp_path / 'missing.sqlite'
    assert mark_http(marker_restore) == 2
    assert not marker_restore[role].exists()
    marker_restore[role].symlink_to(original)
    assert mark_http(marker_restore) == 2
    marker_restore[role].unlink()
    marker_restore[role].hardlink_to(marker_restore['console_path' if role == 'http_path' else 'http_path'])
    assert mark_http(marker_restore) == 2
    marker_restore[role].unlink()
    with closing(sqlite3.connect(marker_restore[role])) as db:
        db.execute('CREATE TABLE unrelated(value)')
    assert mark_http(marker_restore) == 2
    assert marker_rows(original if role == 'http_path' else marker_restore['http_path']) == []


def test_http_marker_rejects_populated_wal_without_checkpointing_it(marker_restore, capsys):
    path = marker_restore['http_path']
    with closing(sqlite3.connect(path)) as writer:
        writer.execute('PRAGMA wal_autocheckpoint=0')
        writer.execute("INSERT INTO http_analysis_meta VALUES('test_new_write','true')")
        writer.commit()
        assert Path(str(path)+'-wal').stat().st_size > 0
        before = recovery.digest_file(path)
        assert mark_http(marker_restore) == 2
        assert 'empty WAL/journal' in capsys.readouterr().err
        assert recovery.digest_file(path) == before
        assert marker_rows(path) == []


def test_http_marker_busy_pair_releases_first_reservation(marker_restore, capsys):
    ordered = sorted([marker_restore['http_path'], marker_restore['console_path']])
    with closing(sqlite3.connect(ordered[1], isolation_level=None)) as locked:
        locked.execute('BEGIN IMMEDIATE')
        started = time.monotonic()
        assert mark_http(marker_restore) == 2
        assert time.monotonic()-started < 7
        assert 'busy' in capsys.readouterr().err
        with closing(sqlite3.connect(ordered[0], timeout=0.1, isolation_level=None)) as released:
            released.execute('BEGIN IMMEDIATE')
    assert marker_rows(marker_restore['http_path']) == []


@pytest.mark.parametrize('change', [
    lambda m: m.update(backup_id='../escape'),
    lambda m: m.update(backup_id='a'*129),
    lambda m: m['consistency']['http_recovery'].update(http_database='telemetry'),
    lambda m: m['consistency']['http_recovery'].update(pinned_at='invalid'),
    lambda m: m['consistency']['http_recovery'].update(pinned_at='2026-01-01T00:00:00+01:00'),
    lambda m: m['consistency']['http_recovery'].update(collector_states=[]),
    lambda m: m['components'].append(m['components'][0]),
    lambda m: m['consistency']['http_recovery'].update(producer_id='0'*32),
])
def test_http_marker_rejects_invalid_cohort_metadata(marker_restore, change):
    rewrite_marker_manifest(marker_restore, change)
    assert mark_http(marker_restore) == 2
    assert marker_rows(marker_restore['http_path']) == []


def test_http_marker_checks_package_before_writing_and_rejects_path_traversal(marker_restore):
    package = marker_restore['package']
    sums = package / 'SHA256SUMS'
    original = sums.read_text()
    sums.write_text(original+'0'*64+'  ../outside\n')
    assert mark_http(marker_restore) == 2
    sums.write_text(original)
    stored = package / marker_restore['manifest']['stored_object']
    with stored.open('ab') as output:
        output.write(b'damage')
    assert mark_http(marker_restore) == 2
    assert marker_rows(marker_restore['http_path']) == []


def test_http_marker_same_backup_id_with_changed_manifest_cannot_replace_history(marker_restore, capsys):
    assert mark_http(marker_restore) == 0
    original = json.loads(capsys.readouterr().out)['record']
    rewrite_marker_manifest(marker_restore, lambda m: m.update(label='changed manifest'))
    assert mark_http(marker_restore) == 2
    assert 'conflicts' in capsys.readouterr().err
    assert marker_rows(marker_restore['http_path']) == [original]


def test_http_marker_rolls_back_when_pair_or_identity_changes(marker_restore, monkeypatch, capsys):
    original = recovery.check_http_pair

    def reject(http, console):
        raise recovery.PackageError('synthetic pair incompatibility')

    monkeypatch.setattr(recovery, 'check_http_pair', reject)
    assert mark_http(marker_restore) == 2
    assert marker_rows(marker_restore['http_path']) == []
    monkeypatch.setattr(recovery, 'check_http_pair', original)
    check_file = recovery._marker_file
    calls = 0

    def changing(path):
        nonlocal calls
        result = check_file(path)
        if path == marker_restore['http_path']:
            calls += 1
            if calls > 1:
                return (*result[:2], result[2]+1, *result[3:])
        return result

    monkeypatch.setattr(recovery, '_marker_file', changing)
    assert mark_http(marker_restore) == 2
    assert 'changed' in capsys.readouterr().err
    assert marker_rows(marker_restore['http_path']) == []


def test_subsequent_package_preserves_http_restore_history_and_accepts_another_marker(marker_restore, deployment, tmp_path, capsys):
    assert mark_http(marker_restore) == 0
    first = json.loads(capsys.readouterr().out)['record']
    new_inventory = {**deployment, 'store': tmp_path / 'later-packages'}
    change_config(deployment, lambda c: [item.update(path=str(marker_restore['http_path' if item['name'] == 'http' else 'console_path']))
                                       for item in c['components'] if item['kind'] == 'sqlite'])
    later = build(new_inventory, '--allow-unencrypted', '--census')
    restored = tmp_path / 'later-restore'
    verify(later['package'], '--into', str(restored))
    capsys.readouterr()
    later.update(http_path=restored / 'http.sqlite', console_path=restored / 'telemetry.sqlite')
    assert marker_rows(later['http_path']) == [first]
    assert mark_http(later) == 0
    second = json.loads(capsys.readouterr().out)['record']
    assert second['backup_id'] != first['backup_id']
    assert marker_rows(later['http_path']) == [first, second]
    with closing(sqlite3.connect(later['http_path'])) as http, closing(sqlite3.connect(later['console_path'])) as console:
        assert recovery.check_http_pair(http, console)['notification_checkpoints'] == 'compatible'


@needs_gpg
def test_http_marker_validates_present_signature_before_recording(deployment, signing_key, tmp_path, capsys):
    seed(deployment)
    result = build(deployment, '--recipient', signing_key, '--sign-key', signing_key)
    restored = tmp_path / 'signed-marker-restore'
    verify(result['package'], '--into', str(restored))
    capsys.readouterr()
    result.update(http_path=restored / 'http.sqlite', console_path=restored / 'telemetry.sqlite')
    assert mark_http(result) == 0
    assert json.loads(capsys.readouterr().out)['record']['signature'] == 'valid'


def test_http_marker_commit_failure_leaves_no_partial_history(marker_restore, monkeypatch):
    connect = recovery.sqlite3.connect

    def deny_commit(*args, **kwargs):
        database = connect(*args, **kwargs)
        if '?mode=rw' in str(args[0]):
            database.set_authorizer(lambda action, value, *rest: sqlite3.SQLITE_DENY
                                    if action == sqlite3.SQLITE_TRANSACTION and value == 'COMMIT' else sqlite3.SQLITE_OK)
        return database

    monkeypatch.setattr(recovery.sqlite3, 'connect', deny_commit)
    before = http_rows(marker_restore['http_path'])
    assert mark_http(marker_restore) == 2
    assert marker_rows(marker_restore['http_path']) == []
    assert http_rows(marker_restore['http_path']) == before
    monkeypatch.setattr(recovery.sqlite3, 'connect', connect)
    assert mark_http(marker_restore) == 0


@pytest.mark.parametrize('suffix', ['-wal', '-journal', '-shm'])
def test_http_marker_refuses_symlink_sidecars_without_touching_their_target(marker_restore, tmp_path, suffix):
    sentinel = tmp_path / 'sentinel'
    sentinel.write_text('unchanged')
    sidecar = Path(str(marker_restore['http_path'])+suffix)
    sidecar.symlink_to(sentinel)
    assert mark_http(marker_restore) == 2
    assert sentinel.read_text() == 'unchanged'
    sidecar.unlink()
    assert marker_rows(marker_restore['http_path']) == []


@needs_gpg
def test_http_marker_refuses_an_invalid_present_signature(marker_restore):
    package = marker_restore['package']
    (package / recovery.SIGNATURE_NAME).write_text('not a signature')
    recovery.write_checksums(package, [recovery.MANIFEST_NAME, recovery.SIGNATURE_NAME,
                                      marker_restore['manifest']['stored_object']])
    assert mark_http(marker_restore) == 2
    assert marker_rows(marker_restore['http_path']) == []


def test_restoring_the_same_package_again_records_a_new_marking_time(marker_restore, tmp_path, capsys):
    assert mark_http(marker_restore) == 0
    first = json.loads(capsys.readouterr().out)['record']
    restored = tmp_path / 'actual-second-restore'
    verify(marker_restore['package'], '--into', str(restored))
    capsys.readouterr()
    again = {**marker_restore, 'http_path': restored / 'http.sqlite', 'console_path': restored / 'telemetry.sqlite'}
    assert marker_rows(again['http_path']) == []
    assert mark_http(again) == 0
    second = json.loads(capsys.readouterr().out)
    assert second['recorded'] is True
    assert second['record']['restore_id'] == first['restore_id']
    assert second['record']['marked_at'] > first['marked_at']
