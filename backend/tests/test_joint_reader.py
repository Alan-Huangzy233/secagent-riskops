"""Joint reads over real source schemas; all stores are temporary synthetic data."""
from contextlib import contextmanager, closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
import sqlite3

import pytest

from app.telemetry import joint_reader as reader
from app.telemetry import joint_network_reader, joint_ssh_reader
from app.telemetry import network_store, store as ssh_module
from app.telemetry.joint_evidence import AssetMapping, NetworkBinding
from app.telemetry.joint_reader_io import EvidenceReadError, ReadLimits
from app.telemetry.network_store import NetworkStore
from app.telemetry.store import TelemetryStore
from test_network_detection import event, profile, REALTIME_US, REMOTE, DESTINATION
from test_network_incidents import deliver, drain, NOW


@pytest.fixture
def sources(tmp_path, monkeypatch):
    at = datetime.fromtimestamp(REALTIME_US/1_000_000, timezone.utc)
    monkeypatch.setattr(ssh_module, '_now', lambda: at+timedelta(seconds=100))
    monkeypatch.setattr(network_store, '_now_us', lambda: int(NOW*1_000_000))
    net = NetworkStore(tmp_path/'network.sqlite')
    deliver(net, 1, [event(index) for index in range(10)])
    drain(net)
    case, = net.incidents()['items']
    ssh = TelemetryStore(tmp_path/'ssh.sqlite')
    # Shared incident across two hosts. Only mapped source A should participate.
    for source in ('auth-a', 'auth-b'):
        rows = [{'event_id':f'same-id-{index}', 'timestamp':(at+timedelta(seconds=20+index)).isoformat(),
                 'identifier':'sshd',
                 'message':f'Failed password for exampleuser from {REMOTE} port 42000 ssh2'}
                for index in range(3)]
        ssh.ingest(source, 'example.invalid', 'initial-'+source, rows)
    mapping = AssetMapping('asset-example', ('auth-a',),
        (NetworkBinding(profile().source_id, (DESTINATION,), (profile().revision,)),))
    return net, ssh, mapping, case, at


def read(sources, **options):
    net, ssh, mapping, case, _ = sources
    return reader.read_joint_evidence(net.path, ssh.path, (mapping,),
                                     case['incident_id'], case['revision'], **options)


def store_digest(path):
    with closing(sqlite3.connect(path)) as db:
        schema = db.execute("SELECT name,sql FROM sqlite_master ORDER BY name").fetchall()
        tables = db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
        rows = {name: sorted(db.execute('SELECT * FROM "'+name+'"').fetchall(),key=repr) for name, in tables}
    return hashlib.sha256(repr((schema,rows)).encode()).hexdigest()


def test_real_source_read_is_scoped_retained_and_does_not_write(sources, monkeypatch):
    net, ssh, _, _, _ = sources
    before = [store_digest(path) for path in (net.path, ssh.path)]
    def forbidden(*args, **kwargs):
        pytest.fail('reader invoked store constructor, model or subprocess')
    monkeypatch.setattr(TelemetryStore, '__init__', forbidden)
    monkeypatch.setattr(NetworkStore, '__init__', forbidden)
    monkeypatch.setattr('subprocess.run', forbidden)
    result = read(sources)
    payload = result.to_dict()
    assert payload['projection']['state'] == 'linked'
    assert payload['projection']['counts']['ssh']['auth-a']['evidence'] == 3
    assert set(payload['projection']['counts']['ssh']) == {'auth-a'}
    assert payload['read']['cross_store_atomic'] is False
    assert payload['read']['ssh_durable_revision'] is None
    assert payload['read']['source_transaction_order'] == ['network','ssh']
    assert payload['read']['ssh_evidence_scope'] == 'retained_incident_evidence_only'
    assert 'ssh:incident_evidence_only' in payload['projection']['uncertainties']
    serialized = json.dumps(payload)
    for forbidden_text in ('message', 'journal_cursor', str(net.path), str(ssh.path), 'Failed password'):
        assert forbidden_text not in serialized
    assert [store_digest(path) for path in (net.path, ssh.path)] == before
    payload['read']['ssh_records_read'] = 999
    assert result.to_dict()['read']['ssh_records_read'] == 3


def test_retained_evidence_survives_raw_expiry_and_raw_only_login_is_out_of_scope(sources):
    _, ssh, _, _, at = sources
    baseline = read(sources).projection
    # This success is outside the incident correlation gap but within joint margin.
    ssh.ingest('auth-a','example.invalid','raw-only',[
        {'event_id':'raw-only-login', 'timestamp':(at-timedelta(minutes=20)).isoformat(),
         'identifier':'sshd', 'message':f'Accepted publickey for exampleuser from {REMOTE} port 42000 ssh2'}])
    with ssh._connection(write=True) as db:
        assert db.execute("SELECT incident_id FROM events WHERE event_id='raw-only-login'").fetchone()[0] is None
        db.execute('DELETE FROM events')
    assert read(sources).projection.sha256 == baseline.sha256
    assert read(sources).to_dict()['projection']['counts']['ssh']['auth-a']['auth_success'] == 0


def test_fixed_network_revision_and_ssh_late_arrival_have_different_snapshot_semantics(sources):
    net, ssh, _, _, at = sources
    original = read(sources)
    deliver(net, 2, [event(20, offset_us=5_500_000)])
    drain(net)
    assert read(sources).projection.sha256 == original.projection.sha256
    ssh.ingest('auth-a','example.invalid','late',[
        {'event_id':'late-success','timestamp':(at+timedelta(seconds=24)).isoformat(),
         'identifier':'sshd', 'message':f'Accepted publickey for exampleuser from {REMOTE} port 42000 ssh2'}])
    late = read(sources)
    assert late.projection.case_id == original.projection.case_id
    assert late.projection.sha256 != original.projection.sha256
    assert late.to_dict()['read']['network_observation']['revision'] == 1
    assert late.to_dict()['read']['ssh_projection_sha256'] != original.to_dict()['read']['ssh_projection_sha256']
    assert late.to_dict()['projection']['counts']['ssh']['auth-a']['auth_success'] == 1


def test_sources_are_never_read_in_overlapping_transactions(sources, monkeypatch):
    net, _, _, _, _ = sources
    original_network = joint_network_reader.snapshot
    original_ssh = joint_ssh_reader.snapshot
    active = []
    calls = []
    @contextmanager
    def observed(path, budget):
        assert not active
        original = original_network if str(path)==str(net.path) else original_ssh
        active.append(str(path))
        calls.append(str(path))
        try:
            with original(path,budget) as db:
                yield db
        finally:
            active.pop()
    monkeypatch.setattr(joint_network_reader,'snapshot',observed)
    monkeypatch.setattr(joint_ssh_reader,'snapshot',observed)
    result = read(sources)
    assert result.projection.state == 'linked'
    assert calls == [str(sources[0].path),str(sources[1].path)] and not active


def test_known_ssh_clock_problem_skips_ssh_database_not_reports_no_activity(sources):
    net, _, mapping, case, _ = sources
    result = reader.read_joint_evidence(net.path, '/does-not-exist/private.sqlite', (mapping,),
        case['incident_id'], 1, ssh_coverage=('journal_clock_discontinuity',)).to_dict()
    assert result['projection']['state'] == 'partial'
    assert result['read']['ssh_observation']['state'] == 'skipped'
    assert 'ssh_association_not_evaluated' in result['projection']['reasons']
    assert result['read']['source_transaction_order'] == ['network']


def test_rejected_mapping_skips_ssh_and_missing_source_never_becomes_unmatched(sources):
    net, ssh, _, case, _ = sources
    wrong = AssetMapping('different', ('auth-a',),
        (NetworkBinding('different-source',(DESTINATION,),(profile().revision,)),))
    result = reader.read_joint_evidence(net.path,'/missing.sqlite',(wrong,),case['incident_id'],1)
    assert result.projection.state == 'rejected'
    assert result.to_dict()['read']['ssh_observation']['state'] == 'skipped'
    with pytest.raises(EvidenceReadError, match='source_unavailable'):
        reader.read_joint_evidence(net.path,str(ssh.path)+'.missing',(sources[2],),case['incident_id'],1)


def test_caps_raise_unavailable_instead_of_complete_negative(sources):
    with pytest.raises(EvidenceReadError, match='adapter_limit_exceeded'):
        read(sources, limits=ReadLimits(record_limit=2))
    with pytest.raises(EvidenceReadError, match='adapter_limit_exceeded'):
        read(sources, limits=ReadLimits(byte_limit=50))


@pytest.mark.parametrize('options', [{'window_seconds':True},{'max_timeline_records':0},
                                   {'ssh_coverage':['untrusted']},{'limits':{}}])
def test_invalid_requests_fail_before_database_access(sources, options, monkeypatch):
    monkeypatch.setattr(reader,'read_network_case',lambda *a,**k:pytest.fail('invalid request read a source'))
    with pytest.raises(EvidenceReadError, match='adapter_invalid_request'):
        read(sources, **options)


def test_handled_and_zero_score_incidents_keep_evidence_without_changing_disposition(sources):
    _, ssh, _, _, _ = sources
    before = read(sources).projection
    identities = [item['incident_id'] for item in ssh.list_incidents()]
    assert ssh.set_triage(identities, 'resolved', actor='fixture-operator')['changed'] == len(identities)
    with ssh._connection(write=True) as db:
        db.execute("UPDATE incidents SET status='resolved'")
        db.execute('UPDATE incident_scores SET score=0,surfaced=0,priority=NULL')
    protected = store_digest(ssh.path)
    after = read(sources)
    assert after.projection.sha256 == before.sha256
    assert store_digest(ssh.path) == protected
    assert not {'score','risk_score','disposition','ai_verdict'}.intersection(after.projection.to_dict())


@pytest.mark.parametrize('limit_name', ['MAX_INPUT_BYTES', 'MAX_OUTPUT_BYTES'])
def test_pure_serialization_limits_are_resource_errors_not_bad_evidence(sources, monkeypatch, limit_name):
    from app.telemetry import joint_evidence
    monkeypatch.setattr(joint_evidence, limit_name, 100)
    with pytest.raises(EvidenceReadError, match='^adapter_limit_exceeded$'):
        read(sources)
