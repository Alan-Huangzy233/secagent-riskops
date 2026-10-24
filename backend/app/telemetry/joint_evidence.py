"""Pure, bounded SSH/network association contracts; no live integration.

Inputs are typed projections of retained source evidence, never raw log prompts.
A matching IP/time is an investigation relationship, not identity or compromise.
This module does not open stores, call models, change scores or execute actions.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import ipaddress
import json
import re

VERSION = 'joint-evidence-v1'
POLICY_VERSION = 'explicit-asset-peer-window-v1'
MAX_RECORDS = 5000
# One network monotonic-hour case may include five minutes on either side.
MAX_ANCHOR_SPAN_US = 4200 * 1_000_000
MAX_TIME_US = 253402300799999999
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')
_CODE = re.compile(r'[a-z][a-z0-9_]{0,63}\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
SSH_KINDS = frozenset({'auth_failure', 'invalid_user', 'preauth_abort',
                       'auth_success', 'ssh_failure', 'ssh_success', 'disconnect'})


def _fail(code):
    raise ValueError(code)


def _integer(value, low, high, code):
    if type(value) is not int or not low <= value <= high:
        _fail(code)
    return value


def _text(value, maximum, code):
    if (type(value) is not str or not value or len(value) > maximum
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        _fail(code)
    return value


def _identifier(value):
    if type(value) is not str or not _ID.fullmatch(value):
        _fail('invalid_joint_identity')
    return value


def _ip(value):
    if type(value) is not str or not 1 <= len(value) <= 64 or '%' in value:
        _fail('invalid_joint_ip')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        _fail('invalid_joint_ip')


def _profile(value):
    if type(value) is not str or not _DIGEST.fullmatch(value):
        _fail('invalid_joint_profile')
    return value


def _tuple(value, low, high, code):
    if type(value) is not tuple or not low <= len(value) <= high:
        _fail(code)
    return value


def _codes(values):
    _tuple(values, 0, 64, 'invalid_joint_coverage')
    if any(type(value) is not str or not _CODE.fullmatch(value) for value in values):
        _fail('invalid_joint_coverage')
    return tuple(sorted(set(values)))


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False)


def _hash(value):
    return hashlib.sha256(_json(value).encode('ascii')).hexdigest()


@dataclass(frozen=True)
class NetworkBinding:
    source_id: str
    destination_ips: tuple[str, ...]
    profile_revisions: tuple[str, ...]

    def __post_init__(self):
        _identifier(self.source_id)
        destinations = tuple(_ip(x) for x in _tuple(self.destination_ips, 1, 32, 'invalid_joint_destinations'))
        profiles = tuple(_profile(x) for x in _tuple(self.profile_revisions, 1, 32, 'invalid_joint_profiles'))
        if len(set(destinations)) != len(destinations) or len(set(profiles)) != len(profiles):
            _fail('duplicate_joint_binding')
        object.__setattr__(self, 'destination_ips', tuple(sorted(destinations)))
        object.__setattr__(self, 'profile_revisions', tuple(sorted(profiles)))


@dataclass(frozen=True)
class AssetMapping:
    asset_id: str
    ssh_source_ids: tuple[str, ...]
    network_bindings: tuple[NetworkBinding, ...]

    def __post_init__(self):
        _identifier(self.asset_id)
        sources = tuple(_identifier(x) for x in _tuple(self.ssh_source_ids, 1, 16, 'invalid_joint_ssh_sources'))
        bindings = _tuple(self.network_bindings, 1, 16, 'invalid_joint_network_bindings')
        if any(type(x) is not NetworkBinding for x in bindings):
            _fail('invalid_joint_network_bindings')
        if len(set(sources)) != len(sources) or len({x.source_id for x in bindings}) != len(bindings):
            _fail('duplicate_joint_source')
        object.__setattr__(self, 'ssh_source_ids', tuple(sorted(sources)))
        object.__setattr__(self, 'network_bindings', tuple(sorted(bindings, key=lambda x: x.source_id)))


def validate_mappings(mappings: tuple[AssetMapping, ...]) -> tuple[AssetMapping, ...]:
    """Validate explicit ownership; source names themselves never establish it."""
    _tuple(mappings, 1, 64, 'invalid_joint_mappings')
    if any(type(item) is not AssetMapping for item in mappings):
        _fail('invalid_joint_mappings')
    assets, ssh, network = set(), set(), set()
    for item in mappings:
        own_network = {x.source_id for x in item.network_bindings}
        if item.asset_id in assets or ssh.intersection(item.ssh_source_ids) or network.intersection(own_network):
            _fail('ambiguous_joint_mapping')
        assets.add(item.asset_id)
        ssh.update(item.ssh_source_ids)
        network.update(own_network)
    return tuple(sorted(mappings, key=lambda x: x.asset_id))


@dataclass(frozen=True)
class NetworkEvidence:
    source_id: str
    event_id: str
    boot_id: str
    profile_revision: str
    src_ip: str
    dst_ip: str
    event_ts_us: int
    monotonic_us: int
    dst_port: int
    protocol: str = 'TCP'
    direction: str = 'local_input'

    def __post_init__(self):
        _identifier(self.source_id)
        _text(self.event_id, 2048, 'invalid_joint_event_id')
        _identifier(self.boot_id)
        _profile(self.profile_revision)
        object.__setattr__(self, 'src_ip', _ip(self.src_ip))
        object.__setattr__(self, 'dst_ip', _ip(self.dst_ip))
        _integer(self.event_ts_us, 0, MAX_TIME_US, 'invalid_joint_time')
        _integer(self.monotonic_us, 0, 2**63-1, 'invalid_joint_monotonic_time')
        _integer(self.dst_port, 1, 65535, 'invalid_joint_port')
        if (type(self.protocol) is not str or type(self.direction) is not str
                or self.protocol not in ('TCP', 'UDP') or self.direction not in ('local_input', 'unknown')):
            _fail('invalid_joint_network_shape')


@dataclass(frozen=True)
class NetworkCase:
    producer_id: str
    incident_id: str
    revision: int
    source_id: str
    boot_id: str
    profile_revision: str
    src_ip: str
    dst_ip: str
    evidence: tuple[NetworkEvidence, ...]
    evidence_total: int | None = None
    active: bool = True
    stale: bool = False
    coverage: tuple[str, ...] = ()

    def __post_init__(self):
        for value in (self.producer_id, self.incident_id, self.source_id, self.boot_id):
            _identifier(value)
        _integer(self.revision, 1, 2**31-1, 'invalid_joint_revision')
        _profile(self.profile_revision)
        object.__setattr__(self, 'src_ip', _ip(self.src_ip))
        object.__setattr__(self, 'dst_ip', _ip(self.dst_ip))
        _tuple(self.evidence, 0, MAX_RECORDS, 'invalid_joint_network_evidence')
        if any(type(x) is not NetworkEvidence for x in self.evidence):
            _fail('invalid_joint_network_evidence')
        if self.evidence_total is not None:
            _integer(self.evidence_total, 0, 1_000_000, 'invalid_joint_evidence_total')
        if type(self.active) is not bool or type(self.stale) is not bool:
            _fail('invalid_joint_network_state')
        object.__setattr__(self, 'coverage', _codes(self.coverage))


@dataclass(frozen=True)
class SSHRecord:
    source_id: str
    event_id: str
    incident_id: str
    src_ip: str
    event_ts_us: int
    event_type: str
    canonical_incident_id: str | None = None
    account: str | None = None

    def __post_init__(self):
        _identifier(self.source_id)
        _text(self.event_id, 2048, 'invalid_joint_event_id')
        _identifier(self.incident_id)
        if self.canonical_incident_id is not None:
            _identifier(self.canonical_incident_id)
        object.__setattr__(self, 'src_ip', _ip(self.src_ip))
        _integer(self.event_ts_us, 0, MAX_TIME_US, 'invalid_joint_time')
        if type(self.event_type) is not str or self.event_type not in SSH_KINDS:
            _fail('invalid_joint_ssh_kind')
        if self.account is not None:
            _text(self.account, 256, 'invalid_joint_account')


@dataclass(frozen=True)
class JointProjection:
    """An immutable serialized revision; to_dict returns an independent copy."""
    case_id: str | None
    state: str
    sha256: str
    canonical_json: str

    def to_dict(self):
        return json.loads(self.canonical_json)


def _projection(payload):
    encoded = _json(payload)
    if len(encoded) > MAX_OUTPUT_BYTES:
        _fail('joint_projection_byte_limit')
    return JointProjection(payload['case_id'], payload['state'],
                           hashlib.sha256(encoded.encode('ascii')).hexdigest(), encoded)


def _unique_network(network):
    unique = {}
    for record in network.evidence:
        if (record.source_id, record.boot_id, record.profile_revision, record.src_ip, record.dst_ip) != (
                network.source_id, network.boot_id, network.profile_revision, network.src_ip, network.dst_ip):
            _fail('joint_network_provenance_mismatch')
        key = (record.source_id, record.event_id)
        if key in unique and unique[key] != record:
            _fail('conflicting_joint_network_evidence')
        unique[key] = record
    if network.evidence_total is not None and network.evidence_total < len(unique):
        _fail('invalid_joint_evidence_total')
    return unique


def _unique_ssh(records):
    unique, references, aliases = {}, {}, {}
    for record in records:
        canonical = record.canonical_incident_id or record.incident_id
        if record.incident_id in aliases and aliases[record.incident_id] != canonical:
            _fail('conflicting_joint_ssh_alias')
        aliases[record.incident_id] = canonical
        key = (record.source_id, record.event_id)
        facts = {k: v for k, v in asdict(record).items() if k not in ('incident_id', 'canonical_incident_id')}
        if key in unique and unique[key] != facts:
            _fail('conflicting_joint_ssh_evidence')
        unique[key] = facts
        references.setdefault(key, set()).add((record.incident_id, canonical))
    if any(len({canonical for _, canonical in refs}) != 1 for refs in references.values()):
        _fail('ambiguous_joint_ssh_ownership')
    # Alias inputs describe one resolved snapshot, not an arbitrary merge graph.
    if any(target in aliases and aliases[target] != target for target in aliases.values()):
        _fail('unresolved_joint_ssh_alias')
    return unique, references


def correlate(mappings: tuple[AssetMapping, ...], network: NetworkCase,
              ssh_records: tuple[SSHRecord, ...], *, ssh_records_total: int | None = None,
              ssh_coverage: tuple[str, ...] = ('collection_coverage_unknown',),
              window_seconds: int = 1800, max_timeline_records: int = 500) -> JointProjection:
    """Build a local evidence revision; declared totals count distinct identities.

    Input omissions and output caps make the result partial, never a complete
    negative finding. input_complete describes declared/supplied identities only;
    coverage_complete remains unknown. Counts describe observed matches only.
    Coverage codes must describe this mapped source/window, not unrelated hosts.
    No global SSH incident score or interval is accepted as an input.
    """
    mappings = validate_mappings(mappings)
    if type(network) is not NetworkCase:
        _fail('invalid_joint_network_case')
    _tuple(ssh_records, 0, MAX_RECORDS, 'invalid_joint_ssh_evidence')
    if any(type(x) is not SSHRecord for x in ssh_records):
        _fail('invalid_joint_ssh_evidence')
    _integer(window_seconds, 0, 3600, 'invalid_joint_window')
    _integer(max_timeline_records, 1, 1000, 'invalid_joint_timeline_limit')
    if ssh_records_total is not None:
        _integer(ssh_records_total, 0, 1_000_000, 'invalid_joint_evidence_total')
    coverage = _codes(ssh_coverage)
    # Tuple, field and byte limits bound allocations before deduplication/sorts.
    size = sum(len(_json(asdict(x))) for x in (*network.evidence, *ssh_records))
    if size > MAX_INPUT_BYTES:
        _fail('joint_input_byte_limit')
    network_records = _unique_network(network)
    ssh, references = _unique_ssh(ssh_records)
    if ssh_records_total is not None and ssh_records_total < len(ssh):
        _fail('invalid_joint_evidence_total')
    asset = binding = None
    for candidate in mappings:
        for item in candidate.network_bindings:
            if item.source_id == network.source_id:
                asset, binding = candidate, item
    rejection = ('network_source_unmapped' if asset is None else
                 'network_destination_unmapped' if network.dst_ip not in binding.destination_ips else
                 'network_profile_unmapped' if network.profile_revision not in binding.profile_revisions else
                 'network_observation_not_local_tcp' if any(x.protocol != 'TCP' or x.direction != 'local_input'
                                                             for x in network_records.values()) else None)
    anchor = {k: getattr(network, k) for k in ('producer_id', 'incident_id', 'revision', 'source_id',
                                              'boot_id', 'profile_revision', 'src_ip', 'dst_ip')}
    if rejection:
        return _projection(dict(version=VERSION, policy_version=POLICY_VERSION, case_id=None,
                                state='rejected', anchor=anchor, reasons=[rejection], timeline=[],
                                input_complete=None, coverage_complete=None, timeline_complete=False,
                                uncertainties=['association_not_evaluated']))
    mapping_hash = _hash(asdict(asset))
    # An opaque upstream ID cannot silently transfer ownership to another boot,
    # profile, peer or destination. Source revisions remain within one identity.
    identity = {key: value for key, value in anchor.items() if key != 'revision'}
    case_id = 'JOINT-' + _hash([POLICY_VERSION, mapping_hash, identity, asset.asset_id])[:32]
    times = [x.event_ts_us for x in network_records.values()]
    uncertainties = {'shared_ip_does_not_establish_identity', 'cross_source_clock_alignment_unknown',
                     'observations_are_lower_bounds',
                     *('network:'+code for code in network.coverage), *('ssh:'+code for code in coverage)}
    offsets = [x.event_ts_us-x.monotonic_us for x in network_records.values()]
    monotonic = [x.monotonic_us for x in network_records.values()]
    network_clock_uncertain = 'journal_clock_discontinuity' in network.coverage or (
        offsets and max(offsets)-min(offsets) > 1_000_000)
    if network_clock_uncertain:
        uncertainties.add('network:journal_clock_discontinuity')
    ssh_clock_uncertain = 'journal_clock_discontinuity' in coverage
    span_exceeded = bool(times and (max(times)-min(times) > MAX_ANCHOR_SPAN_US
                                   or max(monotonic)-min(monotonic) > MAX_ANCHOR_SPAN_US))
    if span_exceeded:
        uncertainties.add('network_anchor_time_span_exceeded')
    if len(network_records) == 1:
        uncertainties.add('single_network_observation_clock_unverifiable')
    temporal_available = bool(times) and not network_clock_uncertain and not ssh_clock_uncertain and not span_exceeded
    start = max(0, min(times)-window_seconds*1_000_000) if temporal_available else None
    end = min(MAX_TIME_US, max(times)+window_seconds*1_000_000) if temporal_available else None
    matched = {key: row for key, row in ssh.items() if row['source_id'] in asset.ssh_source_ids
               and row['src_ip'] == network.src_ip and start is not None
               and start <= row['event_ts_us'] <= end}
    net_total = network.evidence_total if network.evidence_total is not None else len(network_records)
    ssh_total = ssh_records_total if ssh_records_total is not None else len(ssh)
    input_complete = net_total == len(network_records) and ssh_total == len(ssh)
    partial = not input_complete or not temporal_available
    if net_total > len(network_records):
        uncertainties.add('network_evidence_incomplete')
    if ssh_total > len(ssh):
        uncertainties.add('ssh_candidate_evidence_incomplete')
    if not times:
        uncertainties.add('network_evidence_unavailable')
    if not temporal_available:
        uncertainties.add('temporal_association_unavailable')
    timeline = []
    for row in network_records.values():
        timeline.append(dict(kind='network', **asdict(row),
                             incident_refs=[{'incident_id': network.incident_id, 'revision': network.revision}]))
    counts = {}
    for key, row in matched.items():
        source_counts = counts.setdefault(row['source_id'], {'evidence': 0, **{kind: 0 for kind in sorted(SSH_KINDS)}})
        source_counts['evidence'] += 1
        source_counts[row['event_type']] += 1
        timeline.append(dict(kind='ssh', **row, incident_refs=[dict(incident_id=original,
            canonical_incident_id=canonical) for original, canonical in sorted(references[key])]))
    timeline.sort(key=lambda x: (x['event_ts_us'], x['kind'], x['source_id'], x['event_id']))
    evidence_hash = _hash(timeline)
    observed = len(timeline)
    if observed > max_timeline_records:
        uncertainties.add('timeline_truncated')
        partial = True
    reasons = ['explicit_asset_mapping', 'network_anchor_retained']
    if matched:
        reasons.extend(['same_observed_peer', 'mapped_ssh_evidence_in_window'])
        kinds = {x['event_type'] for x in matched.values()}
        if kinds.intersection({'auth_failure', 'ssh_failure', 'invalid_user'}):
            reasons.append('ssh_authentication_failure_observed')
        if kinds.intersection({'auth_success', 'ssh_success'}):
            reasons.append('ssh_authentication_success_observed')
        if 'preauth_abort' in kinds:
            reasons.append('ssh_preauth_abort_observed')
    elif temporal_available:
        reasons.append('no_matching_retained_ssh_evidence')
    else:
        reasons.append('ssh_association_not_evaluated')
    if not network.active:
        state = 'retracted'
        uncertainties.add('network_anchor_retracted')
    elif network.stale:
        state = 'stale'
        uncertainties.add('network_anchor_stale')
    elif partial:
        state = 'partial'
    else:
        state = 'linked' if matched else 'unmatched'
    return _projection(dict(version=VERSION, policy_version=POLICY_VERSION, case_id=case_id,
        state=state, asset_id=asset.asset_id, mapping_sha256=mapping_hash, anchor=anchor,
        window=dict(start_us=start, end_us=end, margin_seconds=window_seconds),
        input_complete=input_complete, coverage_complete=None,
        timeline_complete=observed <= max_timeline_records,
        temporal_association_available=temporal_available,
        reasons=sorted(reasons), uncertainties=sorted(uncertainties),
        evidence_sha256=evidence_hash, observed_evidence_count=observed,
        declared_network_evidence_total=net_total, supplied_ssh_candidate_count=len(ssh),
        declared_ssh_candidate_total=ssh_total,
        counts=dict(network={network.source_id: len(network_records)}, ssh=counts),
        timeline=timeline[:max_timeline_records], timeline_limit=max_timeline_records,
        scope='retained_typed_evidence_only', completeness_scope='supplied_projection_only',
        assessment='association_only_no_joint_risk_score'))
