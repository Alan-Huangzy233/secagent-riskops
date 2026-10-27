"""Strict bounded contracts for a separate derived joint-case store.

Canonical hashes describe observations, not authenticity. Capped timelines are
validated only for the evidence actually present; missing evidence is never
reconstructed or silently promoted to a complete historical snapshot.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from datetime import datetime
import hashlib
import json
import re

from .joint_evidence import (
    MAX_ANCHOR_SPAN_US, MAX_TIME_US, POLICY_VERSION, SSH_KINDS, VERSION as PROJECTION_VERSION,
    AssetMapping, JointProjection, NetworkBinding, NetworkCase, NetworkEvidence, SSHRecord,
    validate_mappings,
)
from .joint_reader import JointRead, VERSION as READER_VERSION
from .joint_reader_io import ERROR_CODES as READER_ERROR_CODES, ReadLimits

SCOPE_VERSION = 'joint-case-scope-v1'
TRANSFORMATION_VERSION = 'joint-case-retained-observation-v1'
SCOPE_BYTES = 4 * 1024 * 1024
ERROR_CODES = READER_ERROR_CODES | frozenset({
    'joint_store_exists', 'joint_store_unavailable', 'joint_store_busy',
    'joint_store_schema_mismatch', 'joint_revision_regression', 'joint_invalid_request',
    'joint_scope_mismatch', 'joint_capacity_exceeded', 'joint_result_invalid',
    'joint_anchor_mismatch', 'joint_source_alias', 'joint_store_corrupt',
})
_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')
_NET_ID = re.compile(r'NET-[0-9a-f]{32}\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_CODE = re.compile(r'[a-z][a-z0-9_]{0,63}\Z')
_STAMP = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z')
_REJECTIONS = frozenset({'network_source_unmapped', 'network_destination_unmapped',
                         'network_profile_unmapped', 'network_observation_not_local_tcp'})
_STATES = frozenset({'linked', 'unmatched', 'partial', 'stale', 'retracted', 'rejected'})
_BASE_UNCERTAINTIES = {'shared_ip_does_not_establish_identity', 'cross_source_clock_alignment_unknown',
                       'observations_are_lower_bounds'}
_EXTRA_UNCERTAINTIES = {'network_anchor_time_span_exceeded', 'single_network_observation_clock_unverifiable',
    'network_evidence_unavailable', 'temporal_association_unavailable', 'timeline_truncated',
    'network_anchor_retracted', 'network_anchor_stale'}
_ANCHOR_KEYS = {'producer_id', 'incident_id', 'revision', 'source_id', 'boot_id',
                'profile_revision', 'src_ip', 'dst_ip'}
_REJECTED_KEYS = {'version', 'policy_version', 'case_id', 'state', 'anchor', 'reasons', 'timeline',
                  'input_complete', 'coverage_complete', 'timeline_complete', 'uncertainties'}
_PROJECTION_KEYS = _REJECTED_KEYS | {'asset_id', 'mapping_sha256', 'window',
    'temporal_association_available', 'evidence_sha256', 'observed_evidence_count',
    'declared_network_evidence_total', 'supplied_ssh_candidate_count', 'declared_ssh_candidate_total',
    'counts', 'timeline_limit', 'scope', 'completeness_scope', 'assessment'}
_METADATA_KEYS = {'version', 'cross_store_atomic', 'network_observation', 'ssh_observation',
    'ssh_evidence_scope', 'ssh_projection_sha256', 'ssh_records_read', 'ssh_durable_revision',
    'source_transaction_order', 'no_match_meaning', 'limits', 'projected_input_bytes', 'deadline_kind'}


class CaseStoreError(RuntimeError):
    def __init__(self, code: str):
        if type(code) is not str or code not in ERROR_CODES:
            raise ValueError('invalid_joint_case_error_code')
        self.code = code
        super().__init__(code)


def _fail(code='joint_result_invalid'):
    raise CaseStoreError(code)


def _integer(value, low, high, code='joint_result_invalid'):
    if type(value) is not int or not low <= value <= high:
        _fail(code)
    return value


def _identifier(value, code='joint_result_invalid'):
    if type(value) is not str or not _ID.fullmatch(value):
        _fail(code)
    return value


def _digest(value):
    if type(value) is not str or not _DIGEST.fullmatch(value):
        _fail()
    return value


def _keys(value, expected):
    if type(value) is not dict or set(value) != set(expected):
        _fail()


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def _hash(value):
    return hashlib.sha256(_json(value).encode('ascii')).hexdigest()


def _decode(raw, maximum, *, code='joint_result_invalid', capacity='joint_capacity_exceeded'):
    if type(raw) is not str or not raw:
        _fail(code)
    if len(raw) > maximum:
        _fail(capacity)
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                _fail(code)
            result[key] = value
        return result
    try:
        raw.encode('ascii')
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: _fail(code))
        if _json(value) != raw:
            _fail(code)
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        _fail(code)


def _string_list(value, maximum, *, codes=False):
    if type(value) is not list or len(value) > maximum or any(type(x) is not str for x in value):
        _fail()
    if value != sorted(set(value)) or (codes and any(not _CODE.fullmatch(x) for x in value)):
        _fail()
    return value


@dataclass(frozen=True)
class StoreLimits:
    registration_limit: int = 1000
    revision_limit: int = 10000
    payload_byte_limit: int = 256 * 1024 * 1024
    projection_byte_limit: int = 4 * 1024 * 1024
    metadata_byte_limit: int = 32 * 1024

    def __post_init__(self):
        for name, maximum in (('registration_limit', 1000), ('revision_limit', 10000),
            ('payload_byte_limit', 256*1024*1024), ('projection_byte_limit', 4*1024*1024),
            ('metadata_byte_limit', 32*1024)):
            _integer(getattr(self, name), 1, maximum, 'joint_invalid_request')

    def to_json(self):
        return _json(asdict(self))

    @classmethod
    def from_json(cls, raw):
        value = _decode(raw, 1024, code='joint_invalid_request', capacity='joint_invalid_request')
        if type(value) is not dict or set(value) != {field.name for field in fields(cls)}:
            _fail('joint_invalid_request')
        return cls(**value)


@dataclass(frozen=True)
class CaseScope:
    mappings: tuple[AssetMapping, ...]
    producer_id: str
    window_seconds: int = 1800
    max_timeline_records: int = 500
    ssh_coverage: tuple[str, ...] = ()

    def __post_init__(self):
        try:
            mappings = validate_mappings(self.mappings)
        except (ValueError, TypeError):
            _fail('joint_invalid_request')
        _identifier(self.producer_id, 'joint_invalid_request')
        _integer(self.window_seconds, 0, 3600, 'joint_invalid_request')
        _integer(self.max_timeline_records, 1, 1000, 'joint_invalid_request')
        if (type(self.ssh_coverage) is not tuple or len(self.ssh_coverage) > 60
                or any(type(x) is not str or not _CODE.fullmatch(x) for x in self.ssh_coverage)):
            _fail('joint_invalid_request')
        object.__setattr__(self, 'mappings', mappings)
        object.__setattr__(self, 'ssh_coverage', tuple(sorted(set(self.ssh_coverage))))
        if len(self.to_json()) > SCOPE_BYTES:
            _fail('joint_invalid_request')

    def to_dict(self):
        return {'version':SCOPE_VERSION, 'transformation_version':TRANSFORMATION_VERSION,
            'projection_version':PROJECTION_VERSION, 'policy_version':POLICY_VERSION,
            'reader_version':READER_VERSION, 'scope':'explicit_registered_anchors_only',
            'ssh_evidence_scope':'retained_incident_evidence_only', 'producer_id':self.producer_id,
            'mappings':[asdict(item) for item in self.mappings], 'window_seconds':self.window_seconds,
            'max_timeline_records':self.max_timeline_records, 'ssh_coverage':list(self.ssh_coverage)}

    def to_json(self):
        return _json(self.to_dict())

    @property
    def sha256(self):
        return hashlib.sha256(self.to_json().encode('ascii')).hexdigest()

    @classmethod
    def from_json(cls, raw):
        value = _decode(raw, SCOPE_BYTES, code='joint_invalid_request', capacity='joint_invalid_request')
        try:
            if type(value) is not dict or type(value.get('mappings')) is not list:
                _fail('joint_invalid_request')
            mappings = []
            for item in value['mappings']:
                _keys(item, {'asset_id','ssh_source_ids','network_bindings'})
                if type(item['ssh_source_ids']) is not list or type(item['network_bindings']) is not list:
                    _fail('joint_invalid_request')
                bindings = []
                for binding in item['network_bindings']:
                    _keys(binding, {'source_id','destination_ips','profile_revisions'})
                    if type(binding['destination_ips']) is not list or type(binding['profile_revisions']) is not list:
                        _fail('joint_invalid_request')
                    bindings.append(NetworkBinding(binding['source_id'], tuple(binding['destination_ips']),
                                                   tuple(binding['profile_revisions'])))
                mappings.append(AssetMapping(item['asset_id'], tuple(item['ssh_source_ids']), tuple(bindings)))
            if type(value['ssh_coverage']) is not list:
                _fail('joint_invalid_request')
            scope = cls(tuple(mappings), value['producer_id'], value['window_seconds'],
                        value['max_timeline_records'], tuple(value['ssh_coverage']))
            if scope.to_json() != raw:
                _fail('joint_invalid_request')
            return scope
        except (ValueError, TypeError, KeyError, CaseStoreError):
            _fail('joint_invalid_request')


@dataclass(frozen=True)
class AnchorRequest:
    incident_id: str
    revision: int

    def __post_init__(self):
        if type(self.incident_id) is not str or not _NET_ID.fullmatch(self.incident_id):
            _fail('joint_invalid_request')
        _integer(self.revision, 1, 2**31-1, 'joint_invalid_request')


@dataclass(frozen=True)
class WorkItem:
    cycle_id: str
    registration_seq: int
    request_generation: int
    network_revision: int
    incident_id: str

    def __post_init__(self):
        _identifier(self.cycle_id, 'joint_invalid_request')
        _integer(self.registration_seq, 1, 2**63-1, 'joint_invalid_request')
        _integer(self.request_generation, 1, 2**63-1, 'joint_invalid_request')
        AnchorRequest(self.incident_id, self.network_revision)


def _anchor(value):
    _keys(value, _ANCHOR_KEYS)
    try:
        AnchorRequest(value['incident_id'], value['revision'])
        case = NetworkCase(**value, evidence=())
        if any(getattr(case, key) != value[key] for key in _ANCHOR_KEYS):
            _fail()
    except (ValueError, TypeError, CaseStoreError):
        _fail()
    return _hash({'version':'joint-anchor-v1', **{k:v for k,v in value.items() if k != 'revision'}})


def _stamp(value):
    if type(value) is not str or not _STAMP.fullmatch(value):
        _fail()
    try:
        datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        _fail()


def _metadata(value, payload):
    _keys(value, _METADATA_KEYS)
    if (value['version'] != READER_VERSION or value['cross_store_atomic'] is not False
            or value['ssh_durable_revision'] is not None
            or value['ssh_evidence_scope'] != 'retained_incident_evidence_only'
            or value['no_match_meaning'] != 'no_matching_retained_incident_evidence_in_this_read'
            or value['deadline_kind'] != 'cooperative_sql_and_python_not_os_io'):
        _fail()
    observation = value['network_observation']
    _keys(observation, {'state','started_at','finished_at','producer_id','incident_id','revision'})
    if observation['state'] != 'read':
        _fail()
    for key in ('producer_id','incident_id','revision'):
        if type(observation[key]) is not type(payload['anchor'][key]) or observation[key] != payload['anchor'][key]:
            _fail()
    _stamp(observation['started_at'])
    _stamp(observation['finished_at'])
    _keys(value['limits'], {field.name for field in fields(ReadLimits)})
    try:
        limits = ReadLimits(**value['limits'])
    except (ValueError, TypeError, RuntimeError):
        _fail()
    _integer(value['projected_input_bytes'], 0, limits.byte_limit)
    _integer(value['ssh_records_read'], 0, limits.record_limit)
    _digest(value['ssh_projection_sha256'])
    if value['ssh_records_read'] == 0 and value['ssh_projection_sha256'] != _hash([]):
        _fail()
    ssh = value['ssh_observation']
    if payload['state'] == 'rejected' or not payload['temporal_association_available']:
        _keys(ssh, {'state','reason'})
        reason = 'network_rejected' if payload['state']=='rejected' else 'temporal_association_unavailable'
        if (ssh != {'state':'skipped','reason':reason} or value['ssh_records_read'] != 0
                or value['source_transaction_order'] != ['network']):
            _fail()
    else:
        _keys(ssh, {'state','started_at','finished_at'})
        if ssh['state'] != 'read' or value['source_transaction_order'] != ['network','ssh']:
            _fail()
        _stamp(ssh['started_at'])
        _stamp(ssh['finished_at'])
    return limits


def _timeline(payload, anchor, sources):
    timeline = payload['timeline']
    if type(timeline) is not list or len(timeline) > 1000:
        _fail()
    networks, ssh_records, seen = [], [], set()
    for row in timeline:
        if type(row) is not dict:
            _fail()
        kind = row.get('kind')
        try:
            if kind == 'network':
                names = {field.name for field in fields(NetworkEvidence)}
                _keys(row, names | {'kind','incident_refs'})
                event = NetworkEvidence(**{key:row[key] for key in names})
                if any(asdict(event)[key] != row[key] for key in names):
                    _fail()
                if any(getattr(event, key) != anchor[key] for key in
                       ('source_id','boot_id','profile_revision','src_ip','dst_ip')):
                    _fail()
                refs = row['incident_refs']
                if type(refs) is not list or len(refs) != 1:
                    _fail()
                _keys(refs[0], {'incident_id','revision'})
                _integer(refs[0]['revision'], 1, 2**31-1)
                if refs != [{'incident_id':anchor['incident_id'], 'revision':anchor['revision']}]:
                    _fail()
                if event.protocol != 'TCP' or event.direction != 'local_input':
                    _fail()
                networks.append(event)
            elif kind == 'ssh':
                names = {field.name for field in fields(SSHRecord)}-{'incident_id','canonical_incident_id'}
                _keys(row, names | {'kind','incident_refs'})
                refs = row['incident_refs']
                # The retained adapter reads one actual owner per unique event.
                if type(refs) is not list or len(refs) != 1:
                    _fail()
                _keys(refs[0], {'incident_id','canonical_incident_id'})
                original, canonical = refs[0]['incident_id'], refs[0]['canonical_incident_id']
                _identifier(original)
                _identifier(canonical)
                record = SSHRecord(**{key:row[key] for key in names}, incident_id=original,
                                   canonical_incident_id=canonical if original != canonical else None)
                if any(asdict(record)[key] != row[key] for key in names):
                    _fail()
                window = payload['window']
                if (record.source_id not in sources or record.src_ip != anchor['src_ip']
                        or not payload['temporal_association_available']
                        or not window['start_us'] <= record.event_ts_us <= window['end_us']):
                    _fail()
                ssh_records.append(record)
            else:
                _fail()
        except (ValueError, TypeError):
            _fail()
        key = (kind, row['source_id'], row['event_id'])
        if key in seen:
            _fail()
        seen.add(key)
    if timeline != sorted(timeline, key=lambda row:(row['event_ts_us'],row['kind'],row['source_id'],row['event_id'])):
        _fail()
    return networks, ssh_records


def _projection(payload, metadata, scope=None):
    if (type(payload) is not dict or type(payload.get('state')) is not str
            or payload['state'] not in _STATES):
        _fail()
    rejected = payload['state']=='rejected'
    _keys(payload, _REJECTED_KEYS if rejected else _PROJECTION_KEYS)
    if payload['version'] != PROJECTION_VERSION or payload['policy_version'] != POLICY_VERSION:
        _fail()
    fingerprint = _anchor(payload['anchor'])
    anchor = payload['anchor']
    if rejected:
        if (payload['case_id'] is not None or payload['timeline'] != []
                or payload['input_complete'] is not None or payload['coverage_complete'] is not None
                or payload['timeline_complete'] is not False or payload['uncertainties'] != ['association_not_evaluated']
                or type(payload['reasons']) is not list or len(payload['reasons']) != 1
                or type(payload['reasons'][0]) is not str or payload['reasons'][0] not in _REJECTIONS):
            _fail()
        _metadata(metadata, payload)
        return fingerprint
    _identifier(payload['asset_id'])
    _digest(payload['mapping_sha256'])
    identity = {key:value for key,value in anchor.items() if key != 'revision'}
    expected_id = 'JOINT-'+_hash([POLICY_VERSION,payload['mapping_sha256'],identity,payload['asset_id']])[:32]
    if (payload['case_id'] != expected_id or payload['scope'] != 'retained_typed_evidence_only'
            or payload['completeness_scope'] != 'supplied_projection_only'
            or payload['assessment'] != 'association_only_no_joint_risk_score'
            or payload['input_complete'] is not True or payload['coverage_complete'] is not None
            or type(payload['temporal_association_available']) is not bool
            or type(payload['timeline_complete']) is not bool):
        _fail()
    limits = _metadata(metadata, payload)
    _keys(payload['counts'], {'network','ssh'})
    _keys(payload['counts']['network'], {anchor['source_id']})
    net_total = _integer(payload['counts']['network'][anchor['source_id']], 0, limits.record_limit)
    if type(payload['counts']['ssh']) is not dict or len(payload['counts']['ssh']) > 16:
        _fail()
    ssh_total = 0
    for source, counts in payload['counts']['ssh'].items():
        _identifier(source)
        _keys(counts, {'evidence', *SSH_KINDS})
        for count in counts.values():
            _integer(count, 0, limits.record_limit)
        if counts['evidence'] < 1 or counts['evidence'] != sum(counts[kind] for kind in SSH_KINDS):
            _fail()
        ssh_total += counts['evidence']
    _integer(ssh_total, 0, limits.record_limit)
    for name, expected in (('declared_network_evidence_total', net_total),
            ('declared_ssh_candidate_total', ssh_total), ('supplied_ssh_candidate_count', ssh_total),
            ('observed_evidence_count', net_total+ssh_total)):
        if type(payload[name]) is not int or payload[name] != expected:
            _fail()
    if metadata['ssh_records_read'] != ssh_total:
        _fail()
    cap = _integer(payload['timeline_limit'], 1, 1000)
    observed = net_total+ssh_total
    if (type(payload['timeline']) is not list or len(payload['timeline']) != min(observed, cap)
            or payload['timeline_complete'] is not (observed <= cap)):
        _fail()
    _digest(payload['evidence_sha256'])
    uncertainties = set(_string_list(payload['uncertainties'], 200))
    if not _BASE_UNCERTAINTIES <= uncertainties:
        _fail()
    plain = {value for value in uncertainties if ':' not in value}
    if plain - (_BASE_UNCERTAINTIES | _EXTRA_UNCERTAINTIES):
        _fail()
    for value in uncertainties-plain:
        prefix, code = value.split(':', 1)
        if prefix not in ('ssh','network') or not _CODE.fullmatch(code):
            _fail()
    ssh_codes = {value[4:] for value in uncertainties if value.startswith('ssh:')}
    if not {'incident_evidence_only','collection_coverage_unknown'} <= ssh_codes:
        _fail()
    if scope is not None and ssh_codes != {'incident_evidence_only','collection_coverage_unknown',*scope.ssh_coverage}:
        _fail('joint_scope_mismatch')
    for code, expected in (('timeline_truncated', observed>cap), ('network_evidence_unavailable', net_total==0),
            ('single_network_observation_clock_unverifiable', net_total==1),
            ('temporal_association_unavailable', not payload['temporal_association_available']),
            ('network_anchor_retracted', payload['state']=='retracted'), ('network_anchor_stale', payload['state']=='stale')):
        if (code in uncertainties) != expected:
            _fail()
    window = payload['window']
    _keys(window, {'start_us','end_us','margin_seconds'})
    margin = _integer(window['margin_seconds'], 0, 3600)
    available = payload['temporal_association_available']
    clock_bad = bool({'network:journal_clock_discontinuity','ssh:journal_clock_discontinuity'} & uncertainties)
    span_bad = 'network_anchor_time_span_exceeded' in uncertainties
    if available != bool(net_total and not clock_bad and not span_bad):
        _fail()
    if available:
        start = _integer(window['start_us'], 0, MAX_TIME_US)
        end = _integer(window['end_us'], start, MAX_TIME_US)
        if end-start > MAX_ANCHOR_SPAN_US+2*margin*1_000_000:
            _fail()
    elif window['start_us'] is not None or window['end_us'] is not None or ssh_total:
        _fail()
    expected_state = 'partial' if observed>cap or not available else 'linked' if ssh_total else 'unmatched'
    if payload['state'] not in ('stale','retracted') and payload['state'] != expected_state:
        _fail()
    reasons = {'explicit_asset_mapping','network_anchor_retained'}
    if ssh_total:
        reasons.update(('same_observed_peer','mapped_ssh_evidence_in_window'))
        kinds = {kind for counts in payload['counts']['ssh'].values() for kind in SSH_KINDS if counts[kind]}
        if kinds & {'auth_failure','ssh_failure','invalid_user'}:
            reasons.add('ssh_authentication_failure_observed')
        if kinds & {'auth_success','ssh_success'}:
            reasons.add('ssh_authentication_success_observed')
        if 'preauth_abort' in kinds:
            reasons.add('ssh_preauth_abort_observed')
    else:
        reasons.add('no_matching_retained_ssh_evidence' if available else 'ssh_association_not_evaluated')
    if payload['reasons'] != sorted(reasons):
        _fail()
    networks, records = _timeline(payload, anchor, set(payload['counts']['ssh']))
    if len(networks) > net_total or len(records) > ssh_total:
        _fail()
    for source, counts in payload['counts']['ssh'].items():
        selected = [record for record in records if record.source_id==source]
        if len(selected) > counts['evidence']:
            _fail()
        if any(sum(record.event_type==kind for record in selected) > counts[kind] for kind in SSH_KINDS):
            _fail()
    if payload['timeline_complete']:
        if len(networks) != net_total or len(records) != ssh_total or _hash(payload['timeline']) != payload['evidence_sha256']:
            _fail()
    if len(records)==ssh_total:
        values = sorted((asdict(record) for record in records), key=lambda row:(row['source_id'],row['event_id']))
        if _hash(values) != metadata['ssh_projection_sha256']:
            _fail()
    if networks:
        times = [event.event_ts_us for event in networks]
        monotonic = [event.monotonic_us for event in networks]
        offsets = [event.event_ts_us-event.monotonic_us for event in networks]
        actual_span = max(times)-min(times)>MAX_ANCHOR_SPAN_US or max(monotonic)-min(monotonic)>MAX_ANCHOR_SPAN_US
        if ((actual_span and not span_bad) or (len(networks)==net_total and actual_span != span_bad)
                or (max(offsets)-min(offsets)>1_000_000
                    and 'network:journal_clock_discontinuity' not in uncertainties)):
            _fail()
        if available and len(networks)==net_total and (window['start_us'] != max(0,min(times)-margin*1_000_000)
                          or window['end_us'] != min(MAX_TIME_US,max(times)+margin*1_000_000)):
            _fail()
    return fingerprint


@dataclass(frozen=True)
class ValidatedRead:
    case_id: str | None
    projection_sha256: str
    projection_json: str
    metadata_json: str
    anchor_fingerprint: str
    state: str
    rejection_code: str | None = None

    def __post_init__(self):
        defaults = StoreLimits()
        payload = _decode(self.projection_json, defaults.projection_byte_limit)
        metadata = _decode(self.metadata_json, defaults.metadata_byte_limit)
        _digest(self.projection_sha256)
        _digest(self.anchor_fingerprint)
        if (type(payload) is not dict or self.case_id != payload.get('case_id')
                or self.state != payload.get('state')
                or self.projection_sha256 != hashlib.sha256(self.projection_json.encode('ascii')).hexdigest()):
            _fail()
        if self.anchor_fingerprint != _projection(payload, metadata):
            _fail()
        expected_rejection = payload['reasons'][0] if self.state=='rejected' else None
        if self.rejection_code != expected_rejection:
            _fail()

    def to_joint_read(self):
        return JointRead(JointProjection(self.case_id,self.state,self.projection_sha256,self.projection_json),
                         self.metadata_json)


def validate_read(scope: CaseScope, request: AnchorRequest, result: JointRead, *,
                  limits: StoreLimits | None = None) -> ValidatedRead:
    limits = StoreLimits() if limits is None else limits
    if type(scope) is not CaseScope or type(request) is not AnchorRequest or type(limits) is not StoreLimits:
        _fail('joint_invalid_request')
    if type(result) is not JointRead or type(result.projection) is not JointProjection:
        _fail()
    payload = _decode(result.projection.canonical_json, limits.projection_byte_limit)
    metadata = _decode(result.metadata_json, limits.metadata_byte_limit)
    if (type(payload) is not dict or result.projection.case_id != payload.get('case_id')
            or result.projection.state != payload.get('state')
            or result.projection.sha256 != hashlib.sha256(result.projection.canonical_json.encode('ascii')).hexdigest()):
        _fail()
    fingerprint = _projection(payload, metadata, scope)
    anchor = payload['anchor']
    if (anchor['producer_id'] != scope.producer_id or anchor['incident_id'] != request.incident_id
            or anchor['revision'] != request.revision):
        _fail('joint_anchor_mismatch')
    asset = binding = None
    for candidate in scope.mappings:
        for entry in candidate.network_bindings:
            if entry.source_id == anchor['source_id']:
                asset, binding = candidate, entry
    rejection = ('network_source_unmapped' if asset is None else
                 'network_destination_unmapped' if anchor['dst_ip'] not in binding.destination_ips else
                 'network_profile_unmapped' if anchor['profile_revision'] not in binding.profile_revisions else None)
    if payload['state']=='rejected':
        if payload['reasons'] != [rejection or 'network_observation_not_local_tcp']:
            _fail('joint_scope_mismatch')
    else:
        if (rejection or payload['asset_id'] != asset.asset_id or payload['mapping_sha256'] != _hash(asdict(asset))
                or set(payload['counts']['ssh'])-set(asset.ssh_source_ids)
                or payload['timeline_limit'] != scope.max_timeline_records
                or payload['window']['margin_seconds'] != scope.window_seconds):
            _fail('joint_scope_mismatch')
    return ValidatedRead(result.projection.case_id, result.projection.sha256,
        result.projection.canonical_json, result.metadata_json, fingerprint, result.projection.state,
        payload['reasons'][0] if payload['state']=='rejected' else None)
