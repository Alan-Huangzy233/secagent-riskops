"""Temporary real-source acceptance for explicit durable joint refresh."""
from contextlib import contextmanager
from datetime import timedelta

import pytest

from app.telemetry import joint_reconcile as reconcile
from app.telemetry.joint_case_contract import AnchorRequest, CaseScope, CaseStoreError, StoreLimits
from app.telemetry.joint_case_store import JointCaseStore
from app.telemetry.joint_reader import read_joint_evidence
from app.telemetry.joint_reader_io import EvidenceReadError, ReadLimits
from app.telemetry.store import TelemetryStore
from test_joint_reader import sources as sources, store_digest
from test_network_detection import event, REMOTE
from test_network_incidents import deliver, drain


@pytest.fixture
def derived(sources, tmp_path):
    net, ssh, mapping, case, _ = sources
    first = read_joint_evidence(net.path, ssh.path, (mapping,), case['incident_id'], case['revision'])
    scope = CaseScope((mapping,), first.projection.to_dict()['anchor']['producer_id'])
    store = JointCaseStore.create(tmp_path/'joint.sqlite', scope)
    store.register((AnchorRequest(case['incident_id'], 1),))
    return store


def cycle(store, sources, **options):
    store.begin_cycle()
    return reconcile.reconcile_step(store, sources[0].path, sources[1].path, **options)


def stored(store, sources, revision=None):
    registration = store.get_registration(sources[3]['incident_id'])
    return store.get_case(registration['case_id'], revision=revision)


def late_success(sources):
    _, ssh, _, _, at = sources
    ssh.ingest('auth-a', 'synthetic.invalid', 'late', [
        {'event_id':'joint-late-success', 'timestamp':(at+timedelta(seconds=24)).isoformat(),
         'identifier':'sshd', 'message':f'Accepted publickey for exampleuser from {REMOTE} port 42000 ssh2'}])


def test_history_survives_restart_late_ssh_only_and_a_b_a(derived, sources):
    before = [store_digest(path) for path in (sources[0].path, sources[1].path)]
    assert cycle(derived, sources)['outcomes']['published'] == 1
    original = stored(derived, sources)
    assert original['revision'] == 1 and original['projection']['state'] == 'linked'
    assert [store_digest(path) for path in (sources[0].path, sources[1].path)] == before
    reopened = JointCaseStore.open(derived.path)
    assert cycle(reopened, sources)['outcomes']['unchanged'] == 1
    assert stored(reopened, sources)['revision'] == 1
    late_success(sources)
    assert cycle(reopened, sources)['outcomes']['published'] == 1
    second = stored(reopened, sources)
    assert second['revision'] == 2 and second['projection']['anchor']['revision'] == 1
    assert second['projection']['counts']['ssh']['auth-a']['auth_success'] == 1
    assert second['projection_sha256'] != original['projection_sha256']
    with sources[1]._connection(write=True) as db:
        db.execute("DELETE FROM incident_evidence WHERE event_id='joint-late-success'")
    assert cycle(reopened, sources)['outcomes']['published'] == 1
    assert stored(reopened, sources)['revision'] == 3
    assert stored(reopened, sources)['projection_sha256'] == original['projection_sha256']
    assert stored(reopened, sources, 1)['projection'] == original['projection']
    assert stored(reopened, sources, 2)['projection'] == second['projection']


def test_unmatched_is_rechecked_when_only_ssh_arrives(derived, sources, tmp_path):
    net, _, _, _, at = sources
    empty = TelemetryStore(tmp_path/'new-ssh.sqlite')
    derived.begin_cycle()
    reconcile.reconcile_step(derived, net.path, empty.path)
    assert stored(derived, sources)['projection']['state'] == 'unmatched'
    empty.ingest('auth-a', 'synthetic.invalid', 'late-only', [
        {'event_id':f'late-{i}', 'timestamp':(at+timedelta(seconds=20+i)).isoformat(),
         'identifier':'sshd', 'message':f'Failed password for exampleuser from {REMOTE} port 42000 ssh2'}
        for i in range(3)])
    derived.begin_cycle()
    result = reconcile.reconcile_step(derived, net.path, empty.path)
    assert result['outcomes']['published'] == 1
    assert stored(derived, sources)['revision'] == 2
    assert stored(derived, sources)['projection']['state'] == 'linked'


@pytest.mark.parametrize('code', ['source_busy', 'source_unavailable', 'source_schema_unavailable',
    'network_revision_missing', 'evidence_invalid', 'adapter_limit_exceeded', 'query_deadline_exceeded'])
def test_source_failure_retains_old_semantics_and_retries_next_cycle(derived, sources, monkeypatch, code):
    cycle(derived, sources)
    old = stored(derived, sources)
    reader = reconcile.read_joint_evidence
    def unavailable(*args, **kwargs):
        raise EvidenceReadError(code)
    monkeypatch.setattr(reconcile, 'read_joint_evidence', unavailable)
    result = cycle(derived, sources)
    assert result['outcomes']['failed'] == 1
    assert result['current_cycle']['attempted_complete'] and not result['current_cycle']['all_items_refreshed']
    assert stored(derived, sources)['projection_sha256'] == old['projection_sha256']
    assert stored(derived, sources)['revision'] == old['revision']
    monkeypatch.setattr(reconcile, 'read_joint_evidence', reader)
    assert cycle(derived, sources)['outcomes']['unchanged'] == 1


def test_failed_first_anchor_does_not_starve_later_or_create_empty_case(derived, sources, tmp_path):
    another = JointCaseStore.create(tmp_path/'another.sqlite', derived.scope)
    bad = 'NET-'+'f'*32
    another.register((AnchorRequest(bad, 1), AnchorRequest(sources[3]['incident_id'], 1)))
    result = cycle(another, sources)
    assert result['attempted'] == 2
    assert result['outcomes']['failed'] == result['outcomes']['published'] == 1
    assert another.get_registration(bad)['case_id'] is None
    assert not result['current_cycle']['all_items_refreshed']


def test_cycle_is_finite_and_new_registrations_wait(derived, sources):
    derived.begin_cycle()
    derived.register((AnchorRequest('NET-'+'e'*32, 1),))
    first = reconcile.reconcile_step(derived, sources[0].path, sources[1].path)
    assert first['attempted'] == 1 and first['current_cycle']['attempted_complete']
    following = cycle(derived, sources)
    assert following['attempted'] == 2
    assert following['outcomes']['unchanged'] == following['outcomes']['failed'] == 1


def test_new_requested_revision_supersedes_inflight_read(derived, sources, monkeypatch):
    net, _, _, case, _ = sources
    reader = reconcile.read_joint_evidence
    def advance_request(*args, **kwargs):
        result = reader(*args, **kwargs)
        derived.register((AnchorRequest(case['incident_id'], 2),))
        return result
    monkeypatch.setattr(reconcile, 'read_joint_evidence', advance_request)
    assert cycle(derived, sources)['outcomes']['superseded'] == 1
    assert derived.get_registration(case['incident_id'])['case_id'] is None
    deliver(net, 2, [event(20, offset_us=5_500_000)])
    drain(net)
    monkeypatch.setattr(reconcile, 'read_joint_evidence', reader)
    assert cycle(derived, sources)['outcomes']['published'] == 1
    assert stored(derived, sources)['projection']['anchor']['revision'] == 2


def test_concurrent_completion_does_not_republish_or_enter_new_cycle(derived, sources, monkeypatch):
    reader = reconcile.read_joint_evidence
    def race(*args, **kwargs):
        result = reader(*args, **kwargs)
        monkeypatch.setattr(reconcile, 'read_joint_evidence', reader)
        nested = reconcile.reconcile_step(derived, sources[0].path, sources[1].path)
        assert nested['outcomes']['published'] == 1
        derived.begin_cycle()
        return result
    monkeypatch.setattr(reconcile, 'read_joint_evidence', race)
    result = cycle(derived, sources)
    assert result['attempted'] == 1 and result['outcomes']['already_processed'] == 1
    assert stored(derived, sources)['revision'] == 1
    assert not result['current_cycle']['attempted_complete']


@pytest.mark.parametrize('alias_kind', ['same', 'symlink', 'hardlink'])
def test_derived_source_alias_is_rejected_before_reader_or_write(derived, sources, tmp_path, monkeypatch, alias_kind):
    derived.begin_cycle()
    before = store_digest(derived.path)
    alias = tmp_path/'source-alias.sqlite'
    if alias_kind == 'same':
        alias = derived.path
    elif alias_kind == 'symlink':
        alias.symlink_to(derived.path)
    else:
        alias.hardlink_to(derived.path)
    monkeypatch.setattr(reconcile, 'read_joint_evidence', lambda *a, **k: pytest.fail('aliased source read'))
    with pytest.raises(CaseStoreError, match='^joint_source_alias$'):
        reconcile.reconcile_step(derived, alias, sources[1].path)
    assert store_digest(derived.path) == before


def test_store_capacity_failure_keeps_current_and_records_failed_attempt(derived, sources, tmp_path):
    limited = JointCaseStore.create(tmp_path/'limited.sqlite', derived.scope, limits=StoreLimits(revision_limit=1))
    limited.register((AnchorRequest(sources[3]['incident_id'], 1),))
    cycle(limited, sources)
    late_success(sources)
    outcome = cycle(limited, sources)
    assert outcome['outcomes']['failed'] == 1
    assert stored(limited, sources)['revision'] == 1
    assert not outcome['current_cycle']['all_items_refreshed']


@pytest.mark.parametrize('options', [{'max_items':True}, {'max_items':6}, {'deadline_seconds':float('nan')},
    {'deadline_seconds':11}, {'deadline_seconds':0}, {'read_limits':{}}, {'max_items':0}])
def test_invalid_execution_limits_fail_before_source_access(derived, sources, monkeypatch, options):
    monkeypatch.setattr(reconcile, 'read_joint_evidence', lambda *a, **k: pytest.fail('invalid execution read'))
    with pytest.raises(CaseStoreError, match='^joint_invalid_request$'):
        reconcile.reconcile_step(derived, sources[0].path, sources[1].path, **options)


def test_read_deadline_shares_step_budget_and_stops_admitting_items(derived, sources, monkeypatch):
    now = [0.0]
    monkeypatch.setattr(reconcile.time, 'monotonic', lambda: now[0])
    def timed_out(*args, **kwargs):
        assert kwargs['limits'].deadline_seconds == .1
        now[0] = .2
        raise EvidenceReadError('query_deadline_exceeded')
    monkeypatch.setattr(reconcile, 'read_joint_evidence', timed_out)
    result = cycle(derived, sources, deadline_seconds=.1, read_limits=ReadLimits())
    assert result['attempted'] == 1 and result['outcomes']['failed'] == 1
    assert result['stopped_by_budget']


def test_sources_closed_before_derived_write_and_no_source_writes(derived, sources, monkeypatch):
    from app.telemetry import joint_network_reader, joint_ssh_reader
    net, ssh = sources[:2]
    active = []
    calls = []
    for module in (joint_network_reader, joint_ssh_reader):
        original = module.snapshot
        def wrapper(original):
            @contextmanager
            def observed(path, budget):
                assert not active
                with original(path, budget) as db:
                    active.append(path)
                    calls.append(path)
                    try:
                        yield db
                    finally:
                        active.pop()
            return observed
        monkeypatch.setattr(module, 'snapshot', wrapper(original))
    original_publish = JointCaseStore.publish
    def inspect(self, item, result):
        assert not active and len(calls) == 2
        return original_publish(self, item, result)
    monkeypatch.setattr(JointCaseStore, 'publish', inspect)
    before = [store_digest(path) for path in (net.path, ssh.path)]
    assert cycle(derived, sources)['outcomes']['published'] == 1
    assert [store_digest(path) for path in (net.path, ssh.path)] == before


def test_step_requires_explicit_cycle_and_never_creates_missing_source(derived, sources, tmp_path):
    missing = tmp_path/'missing.sqlite'
    result = reconcile.reconcile_step(derived, sources[0].path, missing)
    assert result['attempted'] == 0 and result['current_cycle'] is None
    derived.begin_cycle()
    result = reconcile.reconcile_step(derived, sources[0].path, missing)
    assert result['outcomes']['failed'] == 1 and not missing.exists()
    assert derived.get_registration(sources[3]['incident_id'])['case_id'] is None


@pytest.mark.parametrize('code', ['joint_scope_mismatch', 'joint_anchor_mismatch', 'joint_result_invalid'])
def test_invalid_observation_is_failed_refresh_and_keeps_old_case(derived, sources, monkeypatch, code):
    cycle(derived, sources)
    old = stored(derived, sources)
    def invalid(*args, **kwargs):
        raise CaseStoreError(code)
    monkeypatch.setattr(reconcile, 'validate_read', invalid)
    outcome = cycle(derived, sources)
    assert outcome['outcomes']['failed'] == 1
    assert stored(derived, sources)['revision'] == old['revision']
    assert stored(derived, sources)['projection'] == old['projection']
