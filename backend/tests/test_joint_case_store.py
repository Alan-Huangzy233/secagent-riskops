"""Derived storage tests use only temporary real source schemas and authored data."""
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import json
import os
from pathlib import Path
import sqlite3
import threading

import pytest

from app.telemetry import joint_case_store as module
from app.telemetry.joint_case_contract import (
    AnchorRequest, CaseScope, CaseStoreError, StoreLimits, validate_read,
)
from app.telemetry.joint_case_store import JointCaseStore
from app.telemetry.joint_reader import JointRead
import test_joint_reader as reader_fixtures
from test_joint_reader import read as read_sources


@pytest.fixture
def retained(tmp_path, monkeypatch):
    sources = reader_fixtures.sources.__wrapped__(tmp_path, monkeypatch)
    result = read_sources(sources)
    metadata = result.to_dict()['read']
    scope = CaseScope((sources[2],), metadata['network_observation']['producer_id'])
    request = AnchorRequest(sources[3]['incident_id'], sources[3]['revision'])
    store = JointCaseStore.create(tmp_path/'derived'/'cases.sqlite', scope)
    value = validate_read(scope, request, result, limits=store.limits)
    return store, request, value, result, sources


def start(retained):
    store, request, *_ = retained
    store.register((request,))
    store.begin_cycle()
    return store.next_item()


def observe_next(store, value):
    store.begin_cycle()
    item = store.next_item()
    assert item is not None
    return store.publish(item, value)


def changed(retained):
    store, request, _, _, sources = retained
    _, ssh, _, case, at = sources
    ssh.ingest('auth-a', 'example.invalid', 'derived-late', [
        dict(event_id='derived-late-success', timestamp=(at+timedelta(seconds=24)).isoformat(),
             identifier='sshd', message=f"Accepted publickey for exampleuser from {case['src_ip']} port 42000 ssh2")])
    return validate_read(store.scope, request, read_sources(sources), limits=store.limits)


def digest(path):
    with closing(sqlite3.connect(path)) as db:
        return tuple(db.iterdump())


def test_explicit_private_creation_identity_scope_limits_and_no_implicit_open(retained, tmp_path):
    store, _, _, _, _ = retained
    assert Path(store.path).stat().st_mode & 0o777 == 0o600
    assert Path(store.path).parent.stat().st_mode & 0o777 == 0o700
    opened = JointCaseStore.open(store.path)
    assert opened.scope == store.scope and opened.limits == store.limits
    assert opened.get_cycle() is None and opened.next_item() is None
    with closing(sqlite3.connect(store.path)) as db:
        assert db.execute('PRAGMA application_id').fetchone()[0] == module.APPLICATION_ID
        assert db.execute('PRAGMA user_version').fetchone()[0] == module.SCHEMA_VERSION
        assert db.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0] == 9
    missing = tmp_path/'missing.sqlite'
    with pytest.raises(CaseStoreError, match='joint_store_unavailable'):
        JointCaseStore.open(missing)
    assert not missing.exists()
    with pytest.raises(CaseStoreError, match='joint_store_exists'):
        JointCaseStore.create(store.path, store.scope)


def test_source_databases_existing_empty_and_alias_files_never_initialized(retained, tmp_path):
    store, _, _, _, source = retained
    empty = tmp_path/'existing-empty'
    empty.touch(mode=0o600)
    for path in (source[0].path, source[1].path, empty):
        before = Path(path).read_bytes()
        with pytest.raises(CaseStoreError):
            JointCaseStore.create(path, store.scope)
        with pytest.raises(CaseStoreError):
            JointCaseStore.open(path)
        assert Path(path).read_bytes() == before
    link = tmp_path/'link.sqlite'
    link.symlink_to(store.path)
    with pytest.raises(CaseStoreError):
        JointCaseStore.open(link)
    hard = tmp_path/'hard.sqlite'
    os.link(store.path, hard)
    with pytest.raises(CaseStoreError):
        JointCaseStore.open(hard)
    hard.unlink()
    assert JointCaseStore.open(store.path).scope == store.scope


def test_no_mode_changes_to_existing_parent(retained, tmp_path):
    store, *_ = retained
    directory = tmp_path/'existing-parent'
    directory.mkdir(mode=0o750)
    directory.chmod(0o750)  # Establish the fixture independently of process umask.
    JointCaseStore.create(directory/'new.sqlite', store.scope)
    assert directory.stat().st_mode & 0o777 == 0o750


def test_metadata_only_updates_latest_read_without_new_revision(retained):
    store, request, value, result, _ = retained
    item = start(retained)
    assert store.publish(item, value) == 'published'
    first = store.get_case(value.case_id)
    metadata = result.to_dict()['read']
    metadata['projected_input_bytes'] += 1
    second = validate_read(store.scope, request, JointRead(result.projection,
        json.dumps(metadata, sort_keys=True, separators=(',', ':'), ensure_ascii=True)), limits=store.limits)
    assert observe_next(store, second) == 'unchanged'
    current = store.get_case(value.case_id)
    assert current['revision'] == current['publish_generation'] == 1
    assert current['projection'] == first['projection']
    assert current['first_read_metadata'] == first['first_read_metadata']
    assert store.get_registration(request.incident_id)['latest_read_metadata'] == metadata
    assert store.get_cycle()['counts']['unchanged'] == 1


def test_current_hash_dedup_preserves_a_b_a_history(retained):
    store, _, a, *_ = retained
    assert store.publish(start(retained), a) == 'published'
    b = changed(retained)
    assert b.case_id == a.case_id and b.projection_sha256 != a.projection_sha256
    assert observe_next(store, b) == 'published'
    assert observe_next(store, a) == 'published'
    values = [store.get_case(a.case_id, revision=i) for i in (1, 2, 3)]
    assert [v['projection_sha256'] for v in values] == [a.projection_sha256, b.projection_sha256, a.projection_sha256]
    assert [v['publish_generation'] for v in values] == [1, 2, 3]
    assert [v['is_current'] for v in values] == [False, False, True]
    assert store.get_case(a.case_id, revision=4) is None
    assert store.get_case(a.case_id)['revision'] == 3
    assert observe_next(store, a) == 'unchanged'


def test_history_and_scope_have_database_level_immutability(retained):
    store, _, value, *_ = retained
    store.publish(start(retained), value)
    for sql in ("UPDATE joint_case_revisions SET projection_json='{}'", 'DELETE FROM joint_case_revisions',
                "UPDATE joint_meta SET scope_json='{}'", "UPDATE joint_meta SET limits_json='{}'", 'DELETE FROM joint_meta'):
        with closing(sqlite3.connect(store.path)) as db:
            with pytest.raises(sqlite3.IntegrityError):
                db.execute(sql)
            db.rollback()
    assert JointCaseStore.open(store.path).get_case(value.case_id)['revision'] == 1


def test_registration_monotonic_generation_and_atomic_batch(retained):
    store, request, *_ = retained
    assert store.register((request,))['registered'] == 1
    assert store.register((request,))['unchanged'] == 1
    newer = AnchorRequest(request.incident_id, request.revision+1)
    assert store.register((newer,))['updated'] == 1
    assert store.get_registration(request.incident_id)['request_generation'] == 2
    other = AnchorRequest('NET-'+'b'*32, 1)
    with pytest.raises(CaseStoreError, match='joint_revision_regression'):
        store.register((other, request))
    assert store.get_registration(other.incident_id) is None
    with pytest.raises(CaseStoreError, match='joint_invalid_request'):
        store.register((newer, newer))
    assert store.get_registration(request.incident_id)['request_generation'] == 2


def test_cycle_freezes_all_registrations_and_retries_failures_without_starvation(retained):
    store, request, value, *_ = retained
    other = AnchorRequest('NET-'+'b'*32, 1)
    store.register((request, other))
    first = store.begin_cycle()
    assert store.begin_cycle() == first
    third = AnchorRequest('NET-'+'c'*32, 1)
    store.register((third,))
    assert store.get_cycle()['item_count'] == 2
    item = store.next_item()
    assert store.fail(item, 'source_busy') == 'failed'
    assert store.next_item().incident_id == other.incident_id
    assert JointCaseStore.open(store.path).next_item() == store.next_item()
    assert store.fail(store.next_item(), 'source_unavailable') == 'failed'
    completed = store.get_cycle()
    assert completed['attempted_complete'] and not completed['all_items_refreshed']
    assert completed['counts']['failed'] == 2 and completed['cursor_seq'] == 2
    assert store.next_item() is None
    next_cycle = store.begin_cycle()
    assert next_cycle['cycle_id'] != first['cycle_id'] and next_cycle['item_count'] == 3
    assert store.next_item().incident_id == request.incident_id
    assert store.publish(store.next_item(), value) == 'published'


def test_generation_cas_cannot_publish_or_fail_new_request(retained):
    store, request, value, *_ = retained
    old = start(retained)
    store.register((AnchorRequest(request.incident_id, 2),))
    assert store.publish(old, value) == 'superseded'
    assert store.fail(old, 'source_busy') == 'already_processed'
    registration = store.get_registration(request.incident_id)
    assert registration['request_generation'] == 2 and registration['case_id'] is None
    assert registration['refresh_state'] == 'pending'
    assert store.get_cycle()['counts']['superseded'] == 1
    store.begin_cycle()
    assert store.next_item().network_revision == 2
    assert store.publish(old, value) == 'already_processed'


def test_duplicate_workers_and_restart_only_publish_once(retained):
    store, _, value, *_ = retained
    first = start(retained)
    reopened = JointCaseStore.open(store.path)
    duplicate = reopened.next_item()
    assert duplicate == first
    assert store.publish(first, value) == 'published'
    assert reopened.publish(duplicate, value) == 'already_processed'
    assert reopened.get_case(value.case_id)['publish_generation'] == 1
    reopened.begin_cycle()
    pending = reopened.next_item()
    assert JointCaseStore.open(store.path).next_item() == pending
    assert store.publish(pending, value) == 'unchanged'


@pytest.mark.parametrize('code', ['source_unavailable', 'source_busy', 'source_schema_unavailable',
    'network_revision_missing', 'evidence_invalid', 'adapter_limit_exceeded', 'query_deadline_exceeded',
    'joint_capacity_exceeded', 'joint_result_invalid', 'joint_anchor_mismatch'])
def test_fixed_failures_preserve_successful_history_and_advance_attempt(retained, code):
    store, request, value, *_ = retained
    store.publish(start(retained), value)
    previous = store.get_case(value.case_id)
    store.begin_cycle()
    assert store.fail(store.next_item(), code) == 'failed'
    current = store.get_case(value.case_id)
    assert current['projection_sha256'] == previous['projection_sha256'] and current['revision'] == 1
    assert current['first_read_metadata'] == previous['first_read_metadata']
    registration = store.get_registration(request.incident_id)
    assert registration['case_id'] == value.case_id and registration['fixed_error_code'] == code
    assert store.get_cycle()['attempted_complete'] and not store.get_cycle()['all_items_refreshed']


def test_unknown_error_text_never_persisted(retained):
    store, request, *_ = retained
    item = start(retained)
    with pytest.raises(CaseStoreError):
        store.fail(item, '/private/path raw log secret')
    assert store.next_item() == item
    assert store.get_registration(request.incident_id)['fixed_error_code'] is None


@pytest.mark.parametrize('kind', ['registrations', 'revisions', 'bytes'])
def test_logical_capacity_is_atomic_and_never_deletes_history(retained, tmp_path, kind):
    old, request, a, *_ = retained
    size = len(a.projection_json.encode('ascii'))
    limits = StoreLimits(registration_limit=1) if kind == 'registrations' else (
        StoreLimits(revision_limit=1) if kind == 'revisions' else StoreLimits(payload_byte_limit=size))
    store = JointCaseStore.create(tmp_path/f'{kind}.sqlite', old.scope, limits=limits)
    store.register((request,))
    store.begin_cycle()
    assert store.publish(store.next_item(), a) == 'published'
    if kind == 'registrations':
        with pytest.raises(CaseStoreError, match='joint_capacity_exceeded'):
            store.register((AnchorRequest('NET-'+'b'*32, 1),))
    else:
        b = changed(retained)
        store.begin_cycle()
        item = store.next_item()
        before = digest(store.path)
        with pytest.raises(CaseStoreError, match='joint_capacity_exceeded'):
            store.publish(item, b)
        assert digest(store.path) == before
        assert store.fail(item, 'joint_capacity_exceeded') == 'failed'
    assert store.get_case(a.case_id)['revision'] == 1
    assert JointCaseStore.open(store.path).limits == limits


@pytest.mark.parametrize('stage', ['revision', 'pointer', 'item', 'commit'])
def test_transaction_failures_rollback_revision_pointer_item_and_counters(retained, monkeypatch, stage):
    store, _, a, *_ = retained
    store.publish(start(retained), a)
    b = changed(retained)
    store.begin_cycle()
    item = store.next_item()
    trigger = {'revision': ('INSERT', 'joint_case_revisions'), 'pointer': ('UPDATE', 'joint_cases'),
               'item': ('UPDATE', 'joint_cycle_items')}.get(stage)
    if trigger:
        with closing(sqlite3.connect(store.path)) as db:
            db.execute(f"CREATE TRIGGER inject_failure BEFORE {trigger[0]} ON {trigger[1]} BEGIN SELECT RAISE(ABORT,'synthetic'); END")
            db.commit()
    original = module._commit
    if stage == 'commit':
        def fail_commit(db):
            raise sqlite3.OperationalError('synthetic commit failure')
        monkeypatch.setattr(module, '_commit', fail_commit)
    before = digest(store.path)
    with pytest.raises(CaseStoreError, match='joint_store_unavailable'):
        store.publish(item, b)
    assert digest(store.path) == before and store.next_item() == item
    assert store.get_case(a.case_id)['revision'] == 1
    monkeypatch.setattr(module, '_commit', original)
    if trigger:
        with closing(sqlite3.connect(store.path)) as db:
            db.execute('DROP TRIGGER inject_failure')
            db.commit()
    assert store.publish(item, b) == 'published'
    assert JointCaseStore.open(store.path).get_case(a.case_id)['revision'] == 2


def test_busy_failure_leaves_work_pending_and_full_failure_rolls_back(retained, monkeypatch):
    store, _, value, *_ = retained
    item = start(retained)
    with closing(sqlite3.connect(store.path, isolation_level=None)) as other:
        other.execute('BEGIN IMMEDIATE')
        with pytest.raises(CaseStoreError, match='joint_store_busy'):
            store.publish(item, value)
        other.rollback()
    assert store.next_item() == item
    original = module._commit
    def full(db):
        error = sqlite3.OperationalError('synthetic full')
        error.sqlite_errorcode = sqlite3.SQLITE_FULL
        raise error
    monkeypatch.setattr(module, '_commit', full)
    with pytest.raises(CaseStoreError, match='joint_capacity_exceeded'):
        store.publish(item, value)
    monkeypatch.setattr(module, '_commit', original)
    assert store.next_item() == item and store.get_case(value.case_id) is None
    assert store.publish(item, value) == 'published'


def test_empty_cycle_is_finite_and_invalid_calls_do_not_create_rows(retained):
    store, *_ = retained
    empty = store.begin_cycle()
    assert empty['item_count'] == 0 and empty['attempted_complete'] and empty['all_items_refreshed']
    assert empty['scope'] == 'explicit_registered_anchors_only'
    for requests in ((), [], ('not an anchor',)):
        with pytest.raises(CaseStoreError, match='joint_invalid_request'):
            store.register(requests)
    with pytest.raises(CaseStoreError, match='joint_invalid_request'):
        store.get_case('wrong')
    assert store.get_registration('NET-'+'d'*32) is None


def test_two_simultaneous_connections_cas_one_publication(retained):
    store, _, value, *_ = retained
    start(retained)
    ready = threading.Barrier(2)
    def worker():
        opened = JointCaseStore.open(store.path)
        item = opened.next_item()
        ready.wait(timeout=5)
        return opened.publish(item, value)
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: worker(), range(2)))
    assert sorted(outcomes) == ['already_processed', 'published']
    assert store.get_case(value.case_id)['revision'] == 1
    assert store.get_cycle()['counts']['published'] == 1


def test_crash_after_commit_is_resumable_without_duplicate_revision(retained, monkeypatch):
    store, _, value, *_ = retained
    item = start(retained)
    original = module._commit
    def committed_then_exit(db):
        original(db)
        raise SystemExit('synthetic post-commit crash')
    monkeypatch.setattr(module, '_commit', committed_then_exit)
    with pytest.raises(SystemExit):
        store.publish(item, value)
    monkeypatch.setattr(module, '_commit', original)
    reopened = JointCaseStore.open(store.path)
    assert reopened.next_item() is None
    assert reopened.publish(item, value) == 'already_processed'
    assert reopened.get_case(value.case_id)['revision'] == 1


def test_rejected_reads_do_not_create_or_erase_published_cases(retained, tmp_path):
    store, request, original, _, sources = retained
    store.publish(start(retained), original)
    net = sources[0]
    # Authored malformed eligibility fixture: same immutable anchor, unsupported
    # protocol. The formal reader emits rejected and deliberately skips SSH.
    with closing(sqlite3.connect(net.path)) as db:
        event_id, raw = db.execute('SELECT event_id,event_json FROM network_evidence LIMIT 1').fetchone()
        event = json.loads(raw)
        event['protocol'] = 'UDP'
        db.execute('UPDATE network_evidence SET event_json=? WHERE event_id=?', (json.dumps(event), event_id))
        db.commit()
    rejected = validate_read(store.scope, request, read_sources(sources), limits=store.limits)
    assert rejected.state == 'rejected' and rejected.case_id is None
    assert observe_next(store, rejected) == 'not_eligible'
    registration = store.get_registration(request.incident_id)
    assert registration['case_id'] == original.case_id and registration['refresh_state'] == 'needs_review'
    assert store.get_case(original.case_id)['projection_sha256'] == original.projection_sha256
    assert store.get_case(original.case_id)['revision'] == 1
    assert not store.get_cycle()['all_items_refreshed']
    first = JointCaseStore.create(tmp_path/'first-rejected.sqlite', store.scope)
    first.register((request,))
    first.begin_cycle()
    assert first.publish(first.next_item(), rejected) == 'not_eligible'
    registration = first.get_registration(request.incident_id)
    assert registration['case_id'] is None and registration['refresh_state'] == 'not_eligible'
    assert registration['anchor_fingerprint'] == rejected.anchor_fingerprint
    with closing(sqlite3.connect(first.path)) as db:
        assert db.execute('SELECT count(*) FROM joint_cases').fetchone()[0] == 0
    assert observe_next(first, original) == 'published'


def test_same_network_id_cannot_change_immutable_anchor_and_overwrite_case(retained):
    store, request, original, _, sources = retained
    store.publish(start(retained), original)
    net = sources[0]
    with closing(sqlite3.connect(net.path)) as db:
        raw = db.execute('SELECT payload_json FROM network_incident_revisions WHERE incident_id=? AND revision=?',
                         (request.incident_id, request.revision)).fetchone()[0]
        payload = json.loads(raw)
        payload['boot_id'] = 'f'*32
        db.execute('UPDATE network_incident_revisions SET payload_json=? WHERE incident_id=? AND revision=?',
                   (json.dumps(payload), request.incident_id, request.revision))
        for event_id, raw in db.execute('SELECT event_id,event_json FROM network_evidence').fetchall():
            event = json.loads(raw)
            event['boot_id'] = 'f'*32
            db.execute('UPDATE network_evidence SET event_json=? WHERE event_id=?', (json.dumps(event), event_id))
        db.commit()
    changed_anchor = validate_read(store.scope, request, read_sources(sources), limits=store.limits)
    assert changed_anchor.anchor_fingerprint != original.anchor_fingerprint
    store.begin_cycle()
    item = store.next_item()
    before = digest(store.path)
    with pytest.raises(CaseStoreError, match='joint_anchor_mismatch'):
        store.publish(item, changed_anchor)
    assert digest(store.path) == before
    assert store.fail(item, 'joint_anchor_mismatch') == 'failed'
    assert store.get_case(original.case_id)['revision'] == 1
    assert store.get_registration(request.incident_id)['refresh_state'] == 'needs_review'


def test_default_registration_barrier_is_bounded_at_one_thousand(retained):
    store, *_ = retained
    for chunk in range(20):
        requests = tuple(AnchorRequest('NET-'+format(chunk*50+offset, '032x'), 1) for offset in range(50))
        store.register(requests)
    cycle = store.begin_cycle()
    assert cycle['item_count'] == cycle['target_registration_seq'] == 1000
    with pytest.raises(CaseStoreError, match='joint_capacity_exceeded'):
        store.register((AnchorRequest('NET-'+format(1000, '032x'), 1),))
    with pytest.raises(CaseStoreError, match='joint_invalid_request'):
        store.register(tuple(AnchorRequest('NET-'+format(n, '032x'), 1) for n in range(51)))
    assert store.get_cycle() == cycle
