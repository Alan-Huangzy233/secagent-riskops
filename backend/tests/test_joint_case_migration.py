"""Offline copies preserve source bytes and make recovery verification explicit."""
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from app.telemetry import joint_case_migration as migration
from app.telemetry.joint_case_contract import AnchorRequest, CaseStoreError
from app.telemetry.joint_case_store import JointCaseStore, _SCHEMA_V1
from test_joint_case_query import populated as populated, query, change_saved


def dump(path):
    with sqlite3.connect(path) as db:
        return tuple(db.iterdump())


def downgrade_fixture(store):
    """Only isolated fixture creation; production has no downgrade operation."""
    with sqlite3.connect(store.path) as db:
        db.execute('DROP TRIGGER joint_scope_no_update')
        db.execute('DROP TRIGGER joint_summary_no_update')
        db.execute('DROP TRIGGER joint_summary_no_delete')
        for table in ('joint_revision_summaries','joint_discovery','joint_runtime'):
            db.execute('DROP TABLE '+table)
        db.execute('UPDATE joint_meta SET schema_version=1')
        db.execute('PRAGMA user_version=1')
        db.execute(next(sql for sql in _SCHEMA_V1 if 'CREATE TRIGGER joint_scope_no_update' in sql))


def complete_discovery(store,values):
    cycle = store.begin_discovery(len(values),store.scope.producer_id)
    requests = tuple(AnchorRequest(identity,1) for identity in values)
    page = SimpleNamespace(producer_id=store.scope.producer_id,after_seq=cycle['cursor_seq'],
        target_seq=cycle['target_seq'],next_seq=cycle['target_seq'],scanned_count=len(requests),
        eligible_requests=requests,skipped_counts={},complete=True)
    assert store.apply_discovery_page(cycle['cycle_id'],cycle['cursor_seq'],page)=='applied'


def refresh(store,values):
    store.begin_cycle()
    while item:=store.next_item():
        store.publish(item,values[item.incident_id])


def test_explicit_v1_upgrade_preserves_every_revision_and_source(populated,tmp_path):
    store,values = populated
    history = {value.case_id:store.get_case(value.case_id) for value in values.values()}
    downgrade_fixture(store)
    before = dump(store.path)
    with pytest.raises(CaseStoreError,match='joint_store_schema_mismatch'):
        JointCaseStore.open(store.path)
    output = tmp_path/'upgraded.sqlite'
    upgraded = migration.migrate_v1(store.path,output,expected_scope=store.scope,expected_limits=store.limits)
    assert dump(store.path)==before
    assert query(upgraded).list_cases()['total']==4
    for identity,saved in history.items():
        current = upgraded.get_case(identity)
        assert current['projection']==saved['projection']
        assert current['projection_sha256']==saved['projection_sha256']
        assert current['first_read_metadata']==saved['first_read_metadata']
    with sqlite3.connect(store.path) as source,sqlite3.connect(output) as target:
        assert source.execute('SELECT store_id FROM joint_meta').fetchone()!=target.execute('SELECT store_id FROM joint_meta').fetchone()
    assert output.stat().st_mode&0o777==0o600


def test_migration_scope_rejection_and_existing_outputs_preserve_every_input(populated,tmp_path):
    store,_ = populated
    downgrade_fixture(store)
    before = dump(store.path)
    output = tmp_path/'wrong-scope.sqlite'
    with pytest.raises(CaseStoreError,match='joint_scope_mismatch'):
        migration.migrate_v1(store.path,output,expected_scope=replace(store.scope,producer_id='different'))
    assert not output.exists() and dump(store.path)==before
    existing = tmp_path/'existing.sqlite'
    existing.write_bytes(b'untouched')
    with pytest.raises(CaseStoreError,match='joint_store_exists'):
        migration.migrate_v1(store.path,existing)
    assert existing.read_bytes()==b'untouched' and dump(store.path)==before
    assert not list(tmp_path.glob('.joint-*'))


def test_corrupt_revision_upgrade_never_publishes_partial_output(populated,tmp_path):
    store,_ = populated
    change_saved(store,'joint_case_revisions',"UPDATE joint_case_revisions SET projection_sha256=?",('0'*64,))
    downgrade_fixture(store)
    before = dump(store.path)
    output = tmp_path/'invalid.sqlite'
    with pytest.raises(CaseStoreError,match='joint_store_corrupt'):
        migration.migrate_v1(store.path,output)
    assert not output.exists() and dump(store.path)==before and not list(tmp_path.glob('.joint-*'))


def test_wal_snapshot_manifest_restore_new_epoch_and_revalidation(populated,tmp_path):
    store,values = populated
    baseline = query(store).list_cases()
    before = dump(store.path)
    snapshot = tmp_path/'snapshot.sqlite'
    with sqlite3.connect(store.path) as keeper:
        assert keeper.execute('PRAGMA journal_mode').fetchone()[0]=='wal'
        manifest = migration.snapshot_store(store.path,snapshot)
    assert manifest['cross_store_atomic'] is False and manifest['schema_version']==2
    assert manifest['generation']==4 and dump(store.path)==before
    manifest_path = Path(str(snapshot)+'.manifest.json')
    assert manifest_path.stat().st_mode&0o777==0o600
    restored = migration.restore_store(snapshot,tmp_path/'restored.sqlite',expected_scope=store.scope,
                                      expected_limits=store.limits)
    q = query(restored)
    assert q.status()['state']=='revalidation_pending'
    assert q.list_cases()['total']==4
    with pytest.raises(CaseStoreError,match='joint_refresh_required'):
        q.list_cases(snapshot=baseline['snapshot'])
    refresh(restored,values)
    assert q.status()['revalidation_pending']  # Refresh alone cannot validate the catalog.
    complete_discovery(restored,values)
    refresh(restored,values)
    assert not q.status()['revalidation_pending']
    assert q.status()['state']=='ready'
    assert all(item['revision']==1 for item in q.list_cases()['items'])
    assert dump(store.path)==before


def test_new_discovery_failure_invalidates_old_success_and_pending_gate(populated):
    store,values = populated
    complete_discovery(store,values)
    refresh(store,values)
    store.record_discovery_failure('source_unavailable')
    assert query(store).status()['error']=='source_unavailable'
    refresh(store,values)
    assert query(store).status()['revalidation_pending']
    complete_discovery(store,values)
    store.begin_cycle()
    item = store.next_item()
    store.fail(item,'source_unavailable')
    while item:=store.next_item():
        store.publish(item,values[item.incident_id])
    assert query(store).status()['revalidation_pending']
    refresh(store,values)
    assert not query(store).status()['revalidation_pending']


def test_current_request_changes_cannot_be_cleared_by_old_cycle(populated):
    store,values = populated
    store.record_discovery_failure('source_unavailable')
    complete_discovery(store,values)
    store.begin_cycle()
    item = store.next_item()
    store.register((AnchorRequest(item.incident_id,2),))
    assert store.publish(item,values[item.incident_id])=='superseded'
    while item:=store.next_item():
        store.publish(item,values[item.incident_id])
    assert query(store).status()['revalidation_pending']


def test_snapshot_rejects_summary_drift_without_silently_repairing(populated,tmp_path):
    store,_ = populated
    change_saved(store,'joint_revision_summaries',"UPDATE joint_revision_summaries SET peer_ip='198.51.100.99'")
    before = dump(store.path)
    output = tmp_path/'bad-snapshot.sqlite'
    with pytest.raises(CaseStoreError,match='joint_store_corrupt'):
        migration.snapshot_store(store.path,output)
    assert not output.exists() and not Path(str(output)+'.manifest.json').exists()
    assert dump(store.path)==before


@pytest.mark.parametrize('mutation',['extra','checksum','bytes','scope','bool_type'])
def test_manifest_tampering_fails_without_output(populated,tmp_path,mutation):
    store,_ = populated
    snapshot = tmp_path/'snapshot.sqlite'
    migration.snapshot_store(store.path,snapshot)
    path = Path(str(snapshot)+'.manifest.json')
    manifest = json.loads(path.read_text())
    if mutation=='extra':
        manifest['private_path'] = '/private'
    elif mutation=='checksum':
        manifest['sha256'] = '0'*64
    elif mutation=='bytes':
        manifest['bytes'] += 1
    elif mutation=='scope':
        manifest['scope_sha256'] = '0'*64
    else:
        manifest['cross_store_atomic'] = 0
    path.write_text(json.dumps(manifest,sort_keys=True,separators=(',',':'),ensure_ascii=True))
    output = tmp_path/'invalid-restore.sqlite'
    with pytest.raises(CaseStoreError,match='joint_store_corrupt'):
        migration.restore_store(snapshot,output,expected_scope=store.scope,expected_limits=store.limits)
    assert not output.exists() and not list(tmp_path.glob('.joint-*'))


def test_offline_deadline_and_disk_failure_cleanup(populated,tmp_path,monkeypatch):
    store,_ = populated
    before = dump(store.path)
    output = tmp_path/'timeout.sqlite'
    monkeypatch.setattr(migration,'OFFLINE_SECONDS',0)
    with pytest.raises(CaseStoreError,match='joint_store_busy'):
        migration.snapshot_store(store.path,output)
    assert not output.exists() and dump(store.path)==before
    monkeypatch.setattr(migration,'OFFLINE_SECONDS',60)
    monkeypatch.setattr(migration.shutil,'disk_usage',lambda *_:SimpleNamespace(free=0))
    with pytest.raises(CaseStoreError,match='joint_capacity_exceeded'):
        migration.snapshot_store(store.path,output)
    assert not output.exists() and dump(store.path)==before


def test_resuming_failed_discovery_tail_requires_a_new_complete_scan(populated):
    store,values = populated
    store.record_discovery_failure('source_unavailable')
    cycle = store.begin_discovery(4,store.scope.producer_id)
    requests = tuple(AnchorRequest(identity,1) for identity in values)
    first = SimpleNamespace(producer_id=store.scope.producer_id,after_seq=0,target_seq=4,next_seq=2,
        scanned_count=2,eligible_requests=requests[:2],skipped_counts={},complete=False)
    assert store.apply_discovery_page(cycle['cycle_id'],0,first)=='applied'
    store.fail_discovery(cycle['cycle_id'],2,'source_unavailable')
    tail = SimpleNamespace(producer_id=store.scope.producer_id,after_seq=2,target_seq=4,next_seq=4,
        scanned_count=2,eligible_requests=requests[2:],skipped_counts={},complete=True)
    assert store.apply_discovery_page(cycle['cycle_id'],2,tail)=='applied'
    refresh(store,values)
    status = query(store).status()
    assert status['revalidation_pending'] and status['error']=='source_unavailable'
    complete_discovery(store,values)
    refresh(store,values)
    assert not query(store).status()['revalidation_pending']


def test_slow_discovery_failure_cannot_override_a_new_success(populated):
    store,values = populated
    assert store.get_discovery() is None
    complete_discovery(store,values)
    assert store.record_discovery_failure('source_unavailable',expected_cycle_id=None,expected_cursor=None)=='superseded'
    old = store.get_discovery()
    complete_discovery(store,values)
    assert store.record_discovery_failure('source_unavailable',expected_cycle_id=old['cycle_id'],
                                          expected_cursor=old['cursor_seq'])=='superseded'
    assert query(store).status()['error'] is None and not query(store).status()['revalidation_pending']


def test_late_preflight_failure_cannot_override_new_refresh_success(populated):
    store,values = populated
    store.record_discovery_failure('source_unavailable')
    complete_discovery(store,values)
    observed = query(store).status()
    discovery = observed['discovery']
    assert observed['revalidation_pending']
    refresh(store,values)
    assert store.record_discovery_failure('source_busy',expected_cycle_id=discovery['cycle_id'],
        expected_cursor=discovery['cursor_seq'],expected_revalidation_pending=True,
        expected_refresh_cycle_id=observed['cycle']['cycle_id'])=='superseded'
    assert query(store).status()['state']=='ready' and query(store).status()['error'] is None
