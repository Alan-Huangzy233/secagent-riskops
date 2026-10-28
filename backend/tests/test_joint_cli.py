"""Explicit commands, source immutability and safe failures over synthetic stores."""
from contextlib import closing
from datetime import timedelta
import json
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from app.telemetry import joint_cli as cli
from app.telemetry.joint_case_contract import CaseStoreError
from app.telemetry.joint_case_query import open_query
from app.telemetry.joint_case_store import JointCaseStore
from app.telemetry.joint_reader_io import EvidenceReadError
from test_joint_catalog import configured as configured, clone_heads
from test_joint_reader import sources as sources, store_digest
from test_network_detection import REMOTE


def test_explicit_init_discover_refresh_query_sources_unchanged(configured,sources):
    config,spec=configured
    before=[store_digest(path) for path in (sources[0].path,sources[1].path)]
    assert cli.run(config,'check')['store']=='not_initialized'
    assert not Path(spec.database_path).exists()
    assert cli.run(config,'init')['state']=='initialized'
    assert cli.run(config,'discover')['discovery']['complete']
    refreshed=cli.run(config,'refresh')
    assert refreshed['attempted']==1 and refreshed['outcomes']['published']==1
    query=open_query(spec.database_path,spec.scope,spec.limits,catalog_min_seq=spec.catalog_min_seq)
    result=query.list_cases()
    assert result['total']==1
    row=result['items'][0]
    detail=query.case_detail(row['case_id'],row['revision'])
    assert detail['projection']['state']=='linked'
    assert [store_digest(path) for path in (sources[0].path,sources[1].path)]==before
    assert cli.run(config,'refresh')['outcomes']['unchanged']==1


def test_refresh_revisits_unchanged_network_after_ssh_only_late(configured,sources):
    config,spec=configured
    cli.run(config,'init')
    cli.run(config,'discover')
    cli.run(config,'refresh')
    _,ssh,_,_,at=sources
    ssh.ingest('auth-a','synthetic.invalid','late',[
        {'event_id':'late-cli-success','timestamp':(at+timedelta(seconds=23)).isoformat(),
         'identifier':'sshd','message':f'Accepted publickey for fixture from {REMOTE} port 42000 ssh2'}])
    assert cli.run(config,'refresh')['outcomes']['published']==1
    result=open_query(spec.database_path,spec.scope,spec.limits).list_cases()
    assert result['items'][0]['revision']==2


def test_disabled_commands_do_not_access_files_or_source(configured,monkeypatch):
    config,_=configured
    config.joint_cases=None
    monkeypatch.setattr(cli,'_separate',lambda *a,**k:pytest.fail('disabled I/O'))
    for command in ('check','init','discover','refresh','tick','migrate-v1','snapshot','restore'):
        assert cli.run(config,command)=={'enabled':False,'state':'disabled'}
    assert cli.run(SimpleNamespace(joint_cases=None),'check')['enabled'] is False


@pytest.mark.parametrize('kind',['symlink','hardlink'])
def test_source_alias_is_rejected_before_any_derived_write(configured,sources,kind):
    config,spec=configured
    target=Path(spec.database_path)
    if kind=='symlink':
        target.symlink_to(sources[0].path)
    else:
        os.link(sources[0].path,target)
    before=store_digest(sources[0].path)
    with pytest.raises(CaseStoreError,match='joint_source_alias'):
        cli.run(config,'init')
    assert store_digest(sources[0].path)==before


def test_one_page_per_call_and_fixed_target_survive_reopen(configured,sources):
    config,spec=configured
    clone_heads(sources[0].path,52)
    cli.run(config,'init')
    first=cli.run(config,'discover')['discovery']
    assert first['scanned_count']==50 and not first['complete']
    clone_heads(sources[0].path,1,start=300)
    second=cli.run(config,'discover')['discovery']
    assert second['complete'] and second['target_seq']==first['target_seq']
    assert second['scanned_count']==53
    third=cli.run(config,'discover')['discovery']
    assert third['target_seq']>first['target_seq'] and third['scanned_count']==50
    # Missing cloned revision payloads produce bounded failures, never hang the page.
    assert cli.run(config,'refresh')['attempted']==5


def test_capacity_failure_keeps_cursor_and_old_cases(configured,sources):
    config,spec=configured
    config.joint_cases=config.joint_cases.model_copy(update={'store_limits':{'registration_limit':1}})
    cli.run(config,'init')
    cli.run(config,'discover')
    cli.run(config,'refresh')
    store=JointCaseStore.open(spec.database_path)
    old=store.get_registration(sources[3]['incident_id'])
    clone_heads(sources[0].path,1)
    with pytest.raises(CaseStoreError,match='joint_capacity_exceeded'):
        cli.run(config,'discover')
    state=store.get_discovery()
    assert state['cursor_seq']==0 and state['error']=='joint_capacity_exceeded'
    assert store.get_registration(sources[3]['incident_id'])==old


def test_discovery_failure_does_not_prevent_explicit_refresh_of_old_anchor(configured,sources):
    config,spec=configured
    cli.run(config,'init')
    cli.run(config,'discover')
    cli.run(config,'refresh')
    clone_heads(sources[0].path,1)
    with closing(sqlite3.connect(sources[0].path)) as db:
        db.execute("UPDATE network_incidents SET payload_json='{' WHERE seq=2")
        db.commit()
    with pytest.raises(EvidenceReadError,match='evidence_invalid'):
        cli.run(config,'discover')
    assert cli.run(config,'refresh')['outcomes']['unchanged']==1
    assert not JointCaseStore.open(spec.database_path).get_discovery()['complete']


def test_bad_scope_or_catalog_floor_cannot_write_existing_store(configured):
    config,spec=configured
    cli.run(config,'init')
    old=store_digest(spec.database_path)
    config.joint_cases=config.joint_cases.model_copy(update={'catalog_min_seq':2})
    with pytest.raises(CaseStoreError,match='joint_scope_mismatch'):
        cli.run(config,'refresh')
    assert store_digest(spec.database_path)==old


def test_main_errors_never_print_private_config_or_path(configured,monkeypatch,capsys):
    config,spec=configured
    monkeypatch.setattr('app.telemetry.config.load_config',lambda path:config)
    assert cli.main(['--config','/private/secret.json','refresh'])==2
    output=capsys.readouterr().out
    assert json.loads(output)=={'ok':False,'error':'joint_store_unavailable'}
    assert spec.database_path not in output and 'secret' not in output


def test_snapshot_cli_returns_safe_summary_only(configured,tmp_path):
    config,_=configured
    cli.run(config,'init')
    cli.run(config,'discover')
    cli.run(config,'refresh')
    target=tmp_path/'snapshot.sqlite'
    result=cli.run(config,'snapshot',output=str(target))
    assert result['state']=='completed'
    assert target.is_file() and Path(str(target)+'.manifest.json').is_file()
    encoded=json.dumps(result)
    assert str(target) not in encoded and 'asset-example' not in encoded and REMOTE not in encoded


@pytest.mark.parametrize('before_first_page',[False,True])
def test_discovery_start_failure_is_persisted_even_without_active_cycle(configured,sources,before_first_page):
    config,spec=configured
    cli.run(config,'init')
    if not before_first_page:
        cli.run(config,'discover')
        cli.run(config,'refresh')
    with closing(sqlite3.connect(sources[0].path)) as db:
        db.execute("UPDATE network_analysis_meta SET value=? WHERE name='producer_id'",(json.dumps('changed-producer'),))
        db.commit()
    with pytest.raises(CaseStoreError,match='joint_anchor_mismatch'):
        cli.run(config,'discover')
    status=open_query(spec.database_path,spec.scope,spec.limits).status()
    assert status['state']=='revalidation_pending' and status['error']=='joint_anchor_mismatch'
    if not before_first_page:
        assert open_query(spec.database_path,spec.scope,spec.limits).list_cases()['total']==1


def test_migration_config_mismatch_fails_before_publishing_output(configured,tmp_path):
    from test_joint_case_migration import downgrade_fixture
    config,spec=configured
    cli.run(config,'init')
    cli.run(config,'discover')
    cli.run(config,'refresh')
    downgrade_fixture(JointCaseStore.open(spec.database_path))
    before=store_digest(spec.database_path)
    config.joint_cases=config.joint_cases.model_copy(update={'store_limits':{'registration_limit':10}})
    output=tmp_path/'upgraded.sqlite'
    with pytest.raises(CaseStoreError,match='joint_scope_mismatch'):
        cli.run(config,'migrate-v1',output=str(output))
    assert not output.exists() and store_digest(spec.database_path)==before


def test_restored_observations_require_new_discovery_and_full_refresh(configured,tmp_path):
    config,spec=configured
    cli.run(config,'init')
    cli.run(config,'discover')
    cli.run(config,'refresh')
    snapshot=tmp_path/'snapshot.sqlite'
    restored=tmp_path/'restored.sqlite'
    cli.run(config,'snapshot',output=str(snapshot))
    cli.run(config,'restore',input_path=str(snapshot),output=str(restored))
    config.joint_cases=config.joint_cases.model_copy(update={'database_path':str(restored)})
    query=open_query(restored,spec.scope,spec.limits)
    assert query.status()['revalidation_pending']
    assert cli.run(config,'refresh')['outcomes']['unchanged']==1
    assert query.status()['revalidation_pending']
    assert cli.run(config,'discover')['discovery']['complete']
    assert query.status()['revalidation_pending']
    assert cli.run(config,'refresh')['outcomes']['unchanged']==1
    assert not query.status()['revalidation_pending']


def test_empty_restored_store_cannot_revalidate_with_missing_ssh_schema(configured,sources,tmp_path):
    config,spec=configured
    cli.run(config,'init')
    snapshot=tmp_path/'snapshot-empty.sqlite'
    restored=tmp_path/'restored-empty.sqlite'
    cli.run(config,'snapshot',output=str(snapshot))
    cli.run(config,'restore',input_path=str(snapshot),output=str(restored))
    config.joint_cases=config.joint_cases.model_copy(update={'database_path':str(restored)})
    with closing(sqlite3.connect(sources[0].path)) as db:
        db.execute('DELETE FROM network_incidents')
        db.commit()
    assert cli.run(config,'discover')['discovery']['complete']
    with closing(sqlite3.connect(sources[1].path)) as db:
        db.execute('DROP TABLE incident_evidence')
        db.commit()
    with pytest.raises(EvidenceReadError,match='source_schema_unavailable'):
        cli.run(config,'refresh')
    assert open_query(restored,spec.scope,spec.limits).status()['revalidation_pending']


def test_slow_discovery_start_failure_cannot_overwrite_new_round_success(configured,monkeypatch):
    config,spec=configured
    cli.run(config,'init')
    cli.run(config,'discover')
    cli.run(config,'refresh')
    original=cli.catalog_target
    def slow_failure(*args,**kwargs):
        monkeypatch.setattr(cli,'catalog_target',original)
        # Simulate an older/uncoordinated low-level writer. Current CLI
        # commands are serialized; storage CAS must still reject a stale result.
        assert cli.discover(spec)['discovery']['complete']
        assert cli.refresh(spec)['outcomes']['unchanged']==1
        raise EvidenceReadError('source_unavailable')
    monkeypatch.setattr(cli,'catalog_target',slow_failure)
    with pytest.raises(EvidenceReadError,match='source_unavailable'):
        cli.run(config,'discover')
    status=open_query(spec.database_path,spec.scope,spec.limits).status()
    assert status['state']=='ready' and status['error'] is None


def test_old_heads_are_rediscovered_and_regression_preserves_saved_case(configured,sources):
    from test_network_detection import event
    from test_network_incidents import deliver, drain
    config,spec=configured
    cli.run(config,'init')
    cli.run(config,'discover')
    cli.run(config,'refresh')
    deliver(sources[0],2,[event(20,offset_us=5_500_000)])
    drain(sources[0])
    assert cli.run(config,'discover')['discovery']['complete']
    store=JointCaseStore.open(spec.database_path)
    registration=store.get_registration(sources[3]['incident_id'])
    assert registration['requested_network_revision']==2 and registration['request_generation']==2
    assert cli.run(config,'refresh')['outcomes']['published']==1
    saved=store.get_case(registration['case_id'])
    with closing(sqlite3.connect(sources[0].path)) as db:
        db.execute("UPDATE network_incidents SET revision=1,payload_json=json_set(payload_json,'$.revision',1)")
        db.commit()
    with pytest.raises(CaseStoreError,match='joint_revision_regression'):
        cli.run(config,'discover')
    assert store.get_discovery()['cursor_seq']==0
    assert store.get_case(registration['case_id'])['projection']==saved['projection']


def test_init_checks_source_identity_before_creating_any_derived_file(configured):
    config,spec=configured
    changed=json.loads(spec.scope.to_json())
    changed['producer_id']='wrong-producer'
    config.joint_cases=config.joint_cases.model_copy(update={'scope':changed})
    with pytest.raises(CaseStoreError,match='joint_anchor_mismatch'):
        cli.run(config,'init')
    assert not Path(spec.database_path).exists()


def test_slow_recovery_preflight_cannot_overwrite_completed_refresh(configured,monkeypatch):
    config,spec=configured
    cli.run(config,'init')
    cli.run(config,'discover')
    cli.run(config,'refresh')
    store=JointCaseStore.open(spec.database_path)
    store.record_discovery_failure('source_unavailable')
    cli.run(config,'discover')
    original=cli.preflight_sources
    def slow_failure(*args,**kwargs):
        monkeypatch.setattr(cli,'preflight_sources',original)
        # Bypass admission only to exercise the storage-level stale-write guard.
        assert cli.refresh(spec)['outcomes']['unchanged']==1
        assert not open_query(spec.database_path,spec.scope,spec.limits).status()['revalidation_pending']
        raise EvidenceReadError('source_busy')
    monkeypatch.setattr(cli,'preflight_sources',slow_failure)
    with pytest.raises(EvidenceReadError,match='source_busy'):
        cli.run(config,'refresh')
    status=open_query(spec.database_path,spec.scope,spec.limits).status()
    assert status['state']=='ready' and status['error'] is None


@pytest.mark.parametrize('settings', [None, {}])
def test_tick_default_off_does_not_touch_files(configured, monkeypatch, settings):
    from app.telemetry.joint_config import JointRefreshConfig
    config, _ = configured
    config.joint_cases = config.joint_cases.model_copy(update={
        'refresh': None if settings is None else JointRefreshConfig(**settings)})
    monkeypatch.setattr(Path, 'stat', lambda *a, **k: pytest.fail('disabled tick stat'))
    monkeypatch.setattr(Path, 'resolve', lambda *a, **k: pytest.fail('disabled tick resolve'))
    monkeypatch.setattr(JointCaseStore, 'open', lambda *a, **k: pytest.fail('disabled tick open'))
    assert cli.run(config, 'tick') == {'enabled': False, 'state': 'disabled'}


def test_enabled_tick_does_not_initialize_missing_store(configured, tmp_path):
    from app.telemetry.joint_config import JointRefreshConfig
    config, _ = configured
    missing = tmp_path/'not-initialized'/'cases.sqlite'
    config.joint_cases = config.joint_cases.model_copy(update={
        'database_path': str(missing), 'refresh': JointRefreshConfig(enabled=True)})
    with pytest.raises(CaseStoreError, match='joint_store_unavailable'):
        cli.run(config, 'tick')
    assert not missing.parent.exists()


@pytest.mark.parametrize('command', ['init', 'discover', 'refresh', 'snapshot', 'restore', 'migrate-v1'])
def test_manual_writes_share_nonblocking_worker_lock(configured, tmp_path, command):
    from app.telemetry.joint_refresh_state import writer_lock
    config, spec = configured
    cli.run(config, 'init')
    before = store_digest(spec.database_path)
    output = tmp_path/'output.sqlite'
    with writer_lock(spec):
        with pytest.raises(CaseStoreError, match='joint_store_busy'):
            cli.run(config, command, output=str(output), input_path=str(tmp_path/'input.sqlite'))
        assert cli.run(config, 'check')['store'] == 'available'
    assert not output.exists() and store_digest(spec.database_path) == before
    assert cli.run(config, 'discover')['discovery']['complete']


@pytest.mark.parametrize('kind', ['lock', 'state', 'lock_hardlink', 'state_symlink'])
def test_snapshot_cannot_overwrite_reserved_refresh_paths(configured, tmp_path, kind):
    from app.telemetry.joint_refresh_state import reserved_paths
    config, spec = configured
    cli.run(config, 'init')
    lock, state = reserved_paths(spec)
    state.write_text('{}')
    state.chmod(0o600)
    target = lock if kind.startswith('lock') else state
    before = {path: path.read_bytes() for path in (lock, state)}
    if kind.endswith('hardlink'):
        output = tmp_path/'output.sqlite'
        os.link(target, output)
    elif kind.endswith('symlink'):
        output = tmp_path/'output.sqlite'
        output.symlink_to(target)
    else:
        output = target
    with pytest.raises(CaseStoreError, match='joint_source_alias'):
        cli.run(config, 'snapshot', output=str(output))
    assert {path: path.read_bytes() for path in (lock, state)} == before
    assert not Path(str(output)+'.manifest.json').exists()


@pytest.mark.parametrize('output', [123, '', '/bad\x00name', '/bad\ud800name'])
def test_invalid_output_is_rejected_before_path_access(configured, monkeypatch, output):
    config, _ = configured
    monkeypatch.setattr(Path, 'resolve', lambda *a, **k: pytest.fail('invalid output path accessed'))
    with pytest.raises(CaseStoreError, match='joint_invalid_request'):
        cli.run(config, 'snapshot', output=output)


def test_explicit_restore_can_recover_after_original_store_directory_was_lost(configured, tmp_path):
    config, spec = configured
    cli.run(config, 'init')
    cli.run(config, 'discover')
    cli.run(config, 'refresh')
    snapshot = tmp_path/'snapshot.sqlite'
    cli.run(config, 'snapshot', output=str(snapshot))
    lost = tmp_path/'lost-parent'/'old.sqlite'
    config.joint_cases = config.joint_cases.model_copy(update={'database_path': str(lost)})
    restored = tmp_path/'restored.sqlite'
    assert cli.run(config, 'restore', input_path=str(snapshot), output=str(restored))['state'] == 'completed'
    assert not lost.exists()
    assert open_query(restored, spec.scope, spec.limits).status()['revalidation_pending']


def test_manual_v1_upgrade_still_works_with_shared_writer_lock(configured, tmp_path):
    from test_joint_case_migration import downgrade_fixture
    config, spec = configured
    cli.run(config, 'init')
    cli.run(config, 'discover')
    cli.run(config, 'refresh')
    downgrade_fixture(JointCaseStore.open(spec.database_path))
    output = tmp_path/'v2.sqlite'
    assert cli.run(config, 'migrate-v1', output=str(output))['state'] == 'completed'
    assert open_query(output, spec.scope, spec.limits).list_cases()['total'] == 1
