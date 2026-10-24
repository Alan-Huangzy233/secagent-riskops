"""Explicit, bounded joint-evidence reads; no worker, API or activation.

A fixed network revision and a separate SSH read transaction are observations
of two sources, not one atomic snapshot or a durable SSH revision.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

from .joint_evidence import AssetMapping, JointProjection, correlate, validate_mappings
from .joint_network_reader import read_network_case
from .joint_reader_io import EvidenceReadError, ReadBudget, ReadLimits
from .joint_ssh_reader import read_ssh_evidence

VERSION = 'joint-retained-reader-v1'


def _stamp():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


@dataclass(frozen=True)
class JointRead:
    projection: JointProjection
    metadata_json: str

    def to_dict(self):
        return {'projection': self.projection.to_dict(),
                'projection_sha256': self.projection.sha256,
                'read': json.loads(self.metadata_json)}


def read_joint_evidence(network_path: str | Path, ssh_path: str | Path,
                        mappings: tuple[AssetMapping, ...], incident_id: str, revision: int, *,
                        limits: ReadLimits | None = None, window_seconds: int = 1800,
                        max_timeline_records: int = 500,
                        ssh_coverage: tuple[str, ...] = ()) -> JointRead:
    """Read exactly one retained network revision and mapped SSH incident evidence.

    ssh_coverage, when supplied, describes only the mapped sources/window. The
    reader cannot infer historical clock health from a current source heartbeat.
    Missing sources, invalid records and limits raise fixed EvidenceReadError
    codes instead of returning an apparently complete unmatched projection.
    """
    try:
        mappings = validate_mappings(mappings)
    except (ValueError, TypeError):
        raise EvidenceReadError('adapter_invalid_request') from None
    if (type(incident_id) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', incident_id)
            or type(revision) is not int or not 1 <= revision <= 2**31-1
            or type(window_seconds) is not int or not 0 <= window_seconds <= 3600
            or type(max_timeline_records) is not int or not 1 <= max_timeline_records <= 1000
            or type(ssh_coverage) is not tuple or len(ssh_coverage) > 60
            or any(type(code) is not str or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', code)
                   for code in ssh_coverage)):
        raise EvidenceReadError('adapter_invalid_request')
    coverage = tuple(sorted({'incident_evidence_only', 'collection_coverage_unknown', *ssh_coverage}))
    budget = ReadBudget(limits)
    network_start = _stamp()
    network = read_network_case(network_path, incident_id, revision, budget=budget)
    network_end = _stamp()
    try:
        # The pure contract is the single authority for mapping and clock gates.
        probe = correlate(mappings, network, (), ssh_coverage=coverage,
                          window_seconds=window_seconds, max_timeline_records=max_timeline_records)
        preliminary = probe.to_dict()
        records = ()
        if probe.state != 'rejected' and preliminary['temporal_association_available']:
            asset = next(item for item in mappings if item.asset_id == preliminary['asset_id'])
            ssh_start = _stamp()
            records = read_ssh_evidence(ssh_path, asset.ssh_source_ids, network.src_ip,
                preliminary['window']['start_us'], preliminary['window']['end_us'], budget=budget)
            ssh_observation = {'state': 'read', 'started_at': ssh_start, 'finished_at': _stamp()}
            projection = correlate(mappings, network, records, ssh_records_total=len(records),
                ssh_coverage=coverage, window_seconds=window_seconds,
                max_timeline_records=max_timeline_records)
        else:
            ssh_observation = {'state': 'skipped', 'reason': 'network_rejected' if probe.state == 'rejected'
                               else 'temporal_association_unavailable'}
            projection = probe
    except ValueError as error:
        if str(error) in {'joint_input_byte_limit', 'joint_projection_byte_limit'}:
            raise EvidenceReadError('adapter_limit_exceeded') from None
        raise EvidenceReadError('evidence_invalid') from None
    except (TypeError, KeyError):
        raise EvidenceReadError('evidence_invalid') from None
    budget.check()
    record_values = sorted((asdict(row) for row in records),
                           key=lambda row: (row['source_id'], row['event_id']))
    metadata = {'version': VERSION, 'cross_store_atomic': False,
        'network_observation': {'state': 'read', 'started_at': network_start,
                               'finished_at': network_end, 'producer_id': network.producer_id,
                               'incident_id': network.incident_id, 'revision': network.revision},
        'ssh_observation': ssh_observation, 'ssh_evidence_scope': 'retained_incident_evidence_only',
        'ssh_projection_sha256': hashlib.sha256(_json(record_values).encode('ascii')).hexdigest(),
        'ssh_records_read': len(records), 'ssh_durable_revision': None,
        'source_transaction_order': ['network', 'ssh'] if ssh_observation['state']=='read' else ['network'],
        'no_match_meaning': 'no_matching_retained_incident_evidence_in_this_read',
        'limits': asdict(budget.limits), 'projected_input_bytes': budget.bytes_read,
        'deadline_kind': 'cooperative_sql_and_python_not_os_io'}
    result = JointRead(projection, _json(metadata))
    budget.check()
    return result
