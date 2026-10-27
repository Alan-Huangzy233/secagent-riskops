"""Strict derived contracts using authored evidence and real retained reader results."""
from dataclasses import FrozenInstanceError, asdict, replace
import hashlib
import json
import sqlite3

import pytest

from app.telemetry import joint_reader as reader
from app.telemetry.joint_case_contract import (
    AnchorRequest, CaseScope, CaseStoreError, ERROR_CODES, StoreLimits, ValidatedRead,
    WorkItem, validate_read,
)
from app.telemetry.joint_evidence import AssetMapping, JointProjection, NetworkBinding, NetworkCase, NetworkEvidence, SSHRecord
from app.telemetry.joint_reader import JointRead
import test_joint_reader as retained_fixtures
from test_joint_network_reader import rewrite_payload

NET = 'NET-'+'a'*32
PROFILE = 'b'*64
BASE = 1_767_225_600_000_000


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode('ascii')).hexdigest()


def authored(monkeypatch, *, count=3, cap=500, coverage=(), changes=None, records=None, mappings=None):
    events = tuple(NetworkEvidence('network-a',f'event-{i}','boot-a',PROFILE,'198.51.100.41','192.0.2.10',
                   BASE+i*1_000_000,100_000_000+i*1_000_000,20000+i) for i in range(count))
    network = NetworkCase('fixture-producer',NET,1,'network-a','boot-a',PROFILE,
                          '198.51.100.41','192.0.2.10',events)
    if changes:
        network = replace(network, **changes)
    if records is None:
        records = (SSHRecord('auth-a','ssh-event','SSH-a','198.51.100.41',BASE+60_000_000,
                             'auth_failure',account='fixture-user'),)
    mappings = mappings or (AssetMapping('asset-a',('auth-a',),
        (NetworkBinding('network-a',('192.0.2.10',),(PROFILE,)),)),)
    monkeypatch.setattr(reader,'read_network_case',lambda *a,**k: network)
    monkeypatch.setattr(reader,'read_ssh_evidence',lambda *a,**k: records)
    result = reader.read_joint_evidence('synthetic-network','synthetic-ssh',mappings,network.incident_id,
                                       network.revision,max_timeline_records=cap,ssh_coverage=coverage)
    scope = CaseScope(mappings,network.producer_id,max_timeline_records=cap,ssh_coverage=coverage)
    return scope, AnchorRequest(network.incident_id,network.revision), result


def altered(result, *, payload=None, metadata=None):
    payload = result.projection.to_dict() if payload is None else payload
    encoded = canonical(payload)
    return JointRead(JointProjection(payload.get('case_id'),payload.get('state'),
        hashlib.sha256(encoded.encode('ascii')).hexdigest(),encoded),
        result.metadata_json if metadata is None else canonical(metadata))


@pytest.fixture
def valid(monkeypatch):
    return authored(monkeypatch)


def rejected_error(scope, request, result, code='joint_result_invalid', **kwargs):
    with pytest.raises(CaseStoreError, match='^'+code+'$') as error:
        validate_read(scope, request, result, **kwargs)
    assert error.value.code == code


def test_canonical_scope_roundtrip_order_versions_and_detached_data(valid):
    scope, *_ = valid
    other = AssetMapping('asset-b',('auth-c','auth-b'),
        (NetworkBinding('network-b',('2001:db8::1','192.0.2.11'),('c'*64,PROFILE)),))
    left = CaseScope((other,*scope.mappings),scope.producer_id,ssh_coverage=('packet_loss','collector_gap'))
    right = CaseScope((*scope.mappings,other),scope.producer_id,ssh_coverage=('collector_gap','packet_loss'))
    assert left == right and left.to_json() == right.to_json() and left.sha256 == right.sha256
    assert left.sha256 == hashlib.sha256(left.to_json().encode()).hexdigest()
    assert CaseScope.from_json(left.to_json()) == left
    data = left.to_dict()
    assert data['scope'] == 'explicit_registered_anchors_only'
    assert data['ssh_evidence_scope'] == 'retained_incident_evidence_only'
    data['producer_id'] = 'modified'
    assert left.producer_id == scope.producer_id


@pytest.mark.parametrize('field,value', [('version','future'),('policy_version','future'),
    ('transformation_version','future'),('projection_version','future'),('reader_version','future'),
    ('scope','all_anchors'),('ssh_evidence_scope','all_logs'),('extra','/private/path'),
    ('window_seconds',True),('max_timeline_records',1001),('ssh_coverage',[[]]),('mappings',{})])
def test_scope_disk_shape_is_fixed(valid, field, value):
    scope, *_ = valid
    payload = json.loads(scope.to_json())
    payload[field] = value
    with pytest.raises(CaseStoreError, match='^joint_invalid_request$'):
        CaseScope.from_json(canonical(payload))


@pytest.mark.parametrize('raw', ['{}','[]','null','{"registration_limit":1,"registration_limit":2}',
    '{"registration_limit":NaN}', '[['*1200+'0'+']]'*1200])
def test_limits_reject_invalid_disk_shape(raw):
    with pytest.raises(CaseStoreError, match='^joint_invalid_request$'):
        StoreLimits.from_json(raw)


def test_lowerable_limits_roundtrip_and_strict_types():
    defaults = StoreLimits()
    lowered = StoreLimits(1,2,1024,512,128)
    assert StoreLimits.from_json(lowered.to_json()) == lowered
    for key, upper in asdict(defaults).items():
        for invalid in (0,upper+1,True,1.0,'1'):
            with pytest.raises(CaseStoreError, match='^joint_invalid_request$'):
                replace(defaults, **{key:invalid})
    payload = asdict(lowered)
    payload['future'] = 1
    with pytest.raises(CaseStoreError, match='^joint_invalid_request$'):
        StoreLimits.from_json(canonical(payload))


@pytest.mark.parametrize('identity,revision', [('NET-bad',1),(NET,True),(NET,0),(NET,2**31),([],1)])
def test_anchor_requires_exact_net_identity_and_revision(identity, revision):
    with pytest.raises(CaseStoreError, match='^joint_invalid_request$'):
        AnchorRequest(identity, revision)


def test_work_items_and_errors_have_fixed_safe_shape():
    assert WorkItem('a'*32,1,1,1,NET).network_revision == 1
    for changes in ({'registration_seq':True},{'request_generation':0},{'cycle_id':'/private/path'},
                    {'network_revision':0},{'incident_id':'anything'}):
        with pytest.raises(CaseStoreError, match='^joint_invalid_request$'):
            WorkItem(**({'cycle_id':'a'*32,'registration_seq':1,'request_generation':1,
                         'network_revision':1,'incident_id':NET}|changes))
    for code in ERROR_CODES:
        assert str(CaseStoreError(code)) == code
    for code in ('/private/path',[],{}):
        with pytest.raises(ValueError, match='^invalid_joint_case_error_code$'):
            CaseStoreError(code)


@pytest.mark.parametrize('mode', ['linked','unmatched','capped','stale','retracted','empty_retracted',
                                  'network_clock','ssh_clock','rejected'])
def test_actual_retained_reader_results_accept_every_state(tmp_path, monkeypatch, mode):
    sources = retained_fixtures.sources.__wrapped__(tmp_path,monkeypatch)
    net, ssh, mapping, case, _ = sources
    options = {}
    if mode == 'unmatched':
        with ssh._connection(write=True) as db:
            db.execute('DELETE FROM incident_evidence')
    if mode == 'capped':
        options['max_timeline_records'] = 2
    if mode in ('stale','retracted','empty_retracted','network_clock'):
        change = {'stale':True} if mode=='stale' else {'active':False}
        if mode == 'network_clock':
            change = {'coverage':['journal_clock_discontinuity']}
        if mode == 'empty_retracted':
            change['evidence_count'] = 0
            with sqlite3.connect(net.path) as db:
                db.execute('DELETE FROM network_evidence_membership')
        rewrite_payload((net,case),change)
    if mode == 'ssh_clock':
        options['ssh_coverage'] = ('journal_clock_discontinuity',)
    if mode == 'rejected':
        mapping = replace(mapping,network_bindings=(replace(mapping.network_bindings[0],source_id='unmapped'),))
    result = reader.read_joint_evidence(net.path,ssh.path,(mapping,),case['incident_id'],case['revision'],**options)
    scope = CaseScope((mapping,),result.to_dict()['projection']['anchor']['producer_id'],**options)
    checked = validate_read(scope,AnchorRequest(case['incident_id'],case['revision']),result)
    assert checked.state == {'capped':'partial','network_clock':'partial','ssh_clock':'partial',
                              'empty_retracted':'retracted'}.get(mode,mode)
    assert checked.projection_json == result.projection.canonical_json
    assert checked.to_joint_read() == result
    assert validate_read(scope,AnchorRequest(case['incident_id'],case['revision']),checked.to_joint_read()) == checked
    if checked.state == 'rejected':
        assert checked.case_id is None and checked.rejection_code == 'network_source_unmapped'
    if mode == 'capped':
        body = result.projection.to_dict()
        assert len(body['timeline']) == 2 and body['observed_evidence_count'] == 13
        assert body['evidence_sha256'] != digest(body['timeline'])


def test_validated_is_frozen_roundtrip_and_validation_performs_no_io(valid, monkeypatch):
    scope, request, result = valid
    def forbidden(*a,**k):
        pytest.fail('pure contract attempted I/O')
    for target in ('builtins.open','sqlite3.connect','socket.socket','subprocess.run'):
        monkeypatch.setattr(target,forbidden)
    value = validate_read(scope,request,result)
    assert isinstance(value,ValidatedRead) and value.to_joint_read() == result
    with pytest.raises(FrozenInstanceError):
        value.state = 'unmatched'


@pytest.mark.parametrize('bad', [None,[],{},True,1,'unknown'])
def test_invalid_state_always_fixed_error(valid, bad):
    scope, request, result = valid
    payload = result.projection.to_dict()
    payload['state'] = bad
    rejected_error(scope,request,altered(result,payload=payload))


@pytest.mark.parametrize('field,value', [('version','future'),('policy_version','future'),('case_id','JOINT-'+'0'*32),
    ('mapping_sha256','broken'),('asset_id',[]),('input_complete',1),('coverage_complete',True),
    ('temporal_association_available',1),('timeline_complete',1),('timeline_limit',True),
    ('observed_evidence_count',True),('declared_network_evidence_total',4),
    ('supplied_ssh_candidate_count',2),('declared_ssh_candidate_total',2),('evidence_sha256','0'*64),
    ('reasons',[]),('uncertainties',[[]]),('counts',[]),('window',{}),('raw_message','private raw text')])
def test_projection_tampering_is_rejected_even_with_recomputed_hash(valid, field, value):
    scope, request, result = valid
    payload = result.projection.to_dict()
    payload[field] = value
    rejected_error(scope,request,altered(result,payload=payload))


@pytest.mark.parametrize('field,value', [('version','future'),('cross_store_atomic',True),
    ('ssh_durable_revision',1),('ssh_evidence_scope','all_logs'),('ssh_records_read',True),
    ('ssh_projection_sha256','0'*64),('source_transaction_order',['ssh','network']),
    ('no_match_meaning','no_attack'),('deadline_kind','hard_deadline'),('projected_input_bytes',2**40),
    ('limits',{}),('network_observation',{}),('ssh_observation',{}),('path','/private/database')])
def test_metadata_is_fixed_bounded_and_matched_to_projection(valid, field, value):
    scope, request, result = valid
    metadata = json.loads(result.metadata_json)
    metadata[field] = value
    rejected_error(scope,request,altered(result,metadata=metadata))


def test_metadata_timestamps_are_separate_from_evidence_identity(valid):
    scope, request, result = valid
    original = validate_read(scope,request,result)
    metadata = json.loads(result.metadata_json)
    metadata['network_observation']['started_at'] = '2026-10-24T01:00:00Z'
    metadata['network_observation']['finished_at'] = '2026-10-24T00:00:00Z'
    changed = validate_read(scope,request,altered(result,metadata=metadata))
    assert changed.projection_sha256 == original.projection_sha256
    assert changed.anchor_fingerprint == original.anchor_fingerprint
    assert changed.metadata_json != original.metadata_json
    metadata['network_observation']['started_at'] = '2026-99-99T00:00:00Z'
    rejected_error(scope,request,altered(result,metadata=metadata))


@pytest.mark.parametrize('mode', ['hash','case','state','noncanonical','duplicate','nan','deep'])
def test_canonical_json_and_projection_property_parity(valid, mode):
    scope, request, result = valid
    projection = result.projection
    if mode in ('hash','case','state'):
        projection = replace(projection,**{{'hash':'sha256','case':'case_id','state':'state'}[mode]:'wrong'})
    else:
        raw = {'noncanonical':json.dumps(projection.to_dict()),
               'duplicate':'{"state":"linked","state":"linked"}',
               'nan':'{"state":NaN}','deep':'['*1200+'0'+']'*1200}[mode]
        projection = replace(projection,canonical_json=raw,sha256=hashlib.sha256(raw.encode()).hexdigest())
    rejected_error(scope,request,JointRead(projection,result.metadata_json))


def test_lowered_byte_limits_apply_before_parsing(valid):
    scope, request, result = valid
    for limits in (StoreLimits(projection_byte_limit=1),StoreLimits(metadata_byte_limit=1)):
        rejected_error(scope,request,result,'joint_capacity_exceeded',limits=limits)
    rejected_error(scope,request,result,'joint_invalid_request',limits={})


@pytest.mark.parametrize('mode', ['producer','incident','revision'])
def test_expected_anchor_must_match_explicit_request(valid, mode):
    scope, request, result = valid
    if mode == 'producer':
        scope = replace(scope,producer_id='different-producer')
    else:
        request = replace(request,**({'incident_id':'NET-'+'c'*32} if mode=='incident' else {'revision':2}))
    rejected_error(scope,request,result,'joint_anchor_mismatch')


@pytest.mark.parametrize('mode', ['asset','source','destination','profile','window','cap','coverage'])
def test_scope_cannot_change_silently(valid, mode):
    scope, request, result = valid
    mapping = scope.mappings[0]
    if mode == 'asset':
        scope = replace(scope,mappings=(replace(mapping,asset_id='different'),))
    elif mode == 'source':
        scope = replace(scope,mappings=(replace(mapping,ssh_source_ids=('other-auth',)),))
    elif mode in ('destination','profile'):
        change = {'destination_ips':('192.0.2.111',)} if mode=='destination' else {'profile_revisions':('c'*64,)}
        scope = replace(scope,mappings=(replace(mapping,network_bindings=(replace(mapping.network_bindings[0],**change),)),))
    else:
        scope = replace(scope,**{'window':{'window_seconds':0},'cap':{'max_timeline_records':2},
                                 'coverage':{'ssh_coverage':('packet_loss',)}}[mode])
    rejected_error(scope,request,result,'joint_scope_mismatch')


@pytest.mark.parametrize('mode', ['network_peer','ssh_source','ssh_time','ssh_reference','raw_message','duplicate','ordering'])
def test_visible_evidence_corruption_rejected_under_timeline_cap(monkeypatch, mode):
    scope, request, result = authored(monkeypatch,cap=3,records=(
        SSHRecord('auth-a','ssh-early','SSH-a','198.51.100.41',BASE,'auth_failure'),))
    payload = result.projection.to_dict()
    net = next(row for row in payload['timeline'] if row['kind']=='network')
    ssh = next(row for row in payload['timeline'] if row['kind']=='ssh')
    if mode=='network_peer':
        net['src_ip'] = '198.51.100.99'
    elif mode=='ssh_source':
        ssh['source_id'] = 'auth-other'
    elif mode=='ssh_time':
        ssh['event_ts_us'] = BASE+10_000_000_000
    elif mode=='ssh_reference':
        ssh['incident_refs'].append(dict(ssh['incident_refs'][0]))
    elif mode=='raw_message':
        net['message'] = 'raw message must never persist'
    elif mode=='duplicate':
        payload['timeline'][1] = payload['timeline'][0]
    else:
        payload['timeline'].reverse()
    rejected_error(scope,request,altered(result,payload=payload))


def test_canonical_merged_reference_and_sha_parity(monkeypatch):
    record = SSHRecord('auth-a','ssh-event','SSH-old','198.51.100.41',BASE,'auth_success',
                       canonical_incident_id='SSH-canonical')
    scope, request, result = authored(monkeypatch,records=(record,))
    checked = validate_read(scope,request,result)
    row = next(row for row in result.projection.to_dict()['timeline'] if row['kind']=='ssh')
    assert row['incident_refs'] == [{'incident_id':'SSH-old','canonical_incident_id':'SSH-canonical'}]
    assert json.loads(checked.metadata_json)['ssh_projection_sha256'] == digest([asdict(record)])


def test_anchor_fingerprint_stable_across_revision_but_not_identity(monkeypatch):
    scope, request, result = authored(monkeypatch)
    baseline = validate_read(scope,request,result)
    scope2, request2, result2 = authored(monkeypatch,changes={'revision':2})
    newer = validate_read(scope2,request2,result2)
    assert newer.case_id == baseline.case_id and newer.anchor_fingerprint == baseline.anchor_fingerprint
    assert newer.projection_sha256 != baseline.projection_sha256
    scope3, request3, result3 = authored(monkeypatch,changes={'producer_id':'other-producer'})
    other = validate_read(scope3,request3,result3)
    assert other.case_id != baseline.case_id and other.anchor_fingerprint != baseline.anchor_fingerprint


@pytest.mark.parametrize('cap',[2,500])
def test_visible_network_clock_jump_cannot_be_hidden_behind_ssh_flag(monkeypatch,cap):
    events = tuple(NetworkEvidence('network-a',f'e-{i}','boot-a',PROFILE,'198.51.100.41','192.0.2.10',
                    BASE+i*3_000_000,100_000_000+i*1_000_000,20000+i) for i in range(3))
    scope, request, result = authored(monkeypatch,changes={'evidence':events},cap=cap,
                                     coverage=('journal_clock_discontinuity',))
    validate_read(scope,request,result)
    payload = result.projection.to_dict()
    payload['uncertainties'].remove('network:journal_clock_discontinuity')
    rejected_error(scope,request,altered(result,payload=payload))


def test_rejected_reason_malformed_and_mapping_mismatch(monkeypatch):
    mapping = AssetMapping('asset-a',('auth-a',),(NetworkBinding('other',('192.0.2.10',),(PROFILE,)),))
    scope, request, result = authored(monkeypatch,mappings=(mapping,))
    assert validate_read(scope,request,result).rejection_code == 'network_source_unmapped'
    payload = result.projection.to_dict()
    payload['reasons'] = [[]]
    rejected_error(scope,request,altered(result,payload=payload))
    payload['reasons'] = ['network_profile_unmapped']
    rejected_error(scope,request,altered(result,payload=payload),'joint_scope_mismatch')


def test_nested_malformed_shapes_never_escape_as_python_errors(valid):
    scope, request, result = valid
    def locations(value, path=()):
        yield path
        if isinstance(value, dict):
            for key, item in value.items():
                yield from locations(item, (*path,key))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                yield from locations(item, (*path,index))
    for name, original in (('payload', result.projection.to_dict()), ('metadata', json.loads(result.metadata_json))):
        for path in locations(original):
            if not path:
                continue
            for replacement in ([], {}, None, True):
                changed = json.loads(canonical(original))
                parent = changed
                for key in path[:-1]:
                    parent = parent[key]
                parent[path[-1]] = replacement
                try:
                    validate_read(scope,request,altered(result,**{name:changed}))
                except CaseStoreError as error:
                    assert error.code in ERROR_CODES
                except Exception as error:
                    pytest.fail(f'untyped exception at {name}.{path}: {type(error).__name__}')
