"""Finite, read-only catalog pages; no source constructors or full JSON export."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import ipaddress
import json
import re

from .joint_case_contract import AnchorRequest, CaseStoreError
from .joint_config import JointRuntimeSpec
from .joint_network_reader import _text
from .joint_reader_io import EvidenceReadError, ReadBudget, ReadLimits, snapshot
from .joint_ssh_reader import _probe_schema as _probe_ssh_schema
from .network_store import APPLICATION_ID, SCHEMA_VERSION

_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')
_PROFILE = re.compile(r'[0-9a-f]{64}\Z')
SKIP_CODES = ('source_unmapped', 'destination_unmapped', 'profile_unmapped')
MAX_CATALOG_HEADER_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class CatalogPage:
    producer_id: str
    after_seq: int
    target_seq: int
    next_seq: int
    scanned_count: int
    eligible_requests: tuple[AnchorRequest, ...]
    skipped_counts: dict[str, int]
    complete: bool


class _CatalogFailure(Exception):
    pass


@contextmanager
def _catalog_snapshot(path, budget):
    # Preserve domain errors across the generic SQLite adapter boundary.
    try:
        with snapshot(path, budget) as db:
            yield db
    except _CatalogFailure as error:
        raise CaseStoreError(str(error)) from None


def _invalid():
    raise EvidenceReadError('evidence_invalid')


def _scalar(column, maximum):
    return (f"CASE WHEN typeof({column})='text' AND length(CAST({column} AS BLOB)) "
            f"BETWEEN 1 AND {maximum} THEN {column} END")


def _integer(column, minimum=1):
    return (f"CASE WHEN typeof({column})='integer' AND {column}>={minimum} "
            f"THEN {column} END")


def _identity(db, spec, budget):
    budget.check()
    if (db.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID
            or db.execute('PRAGMA user_version').fetchone()[0] != SCHEMA_VERSION):
        raise EvidenceReadError('source_schema_unavailable')
    for query in (
        'SELECT seq,incident_id,source_id,source_profile_revision,src_ip,dst_ip,revision,payload_json FROM network_incidents LIMIT 0',
        'SELECT incident_id,revision,payload_json FROM network_incident_revisions LIMIT 0',
        'SELECT incident_id,event_id,monotonic_us,event_json FROM network_evidence LIMIT 0',
        'SELECT incident_id,event_id,from_revision,to_revision FROM network_evidence_membership LIMIT 0',
    ):
        budget.check()
        db.execute(query).close()
    row = db.execute("SELECT CASE WHEN typeof(value)='text' AND length(CAST(value AS BLOB))<=1024 THEN "+_text('value', '$', 128)+" END"+
                     " FROM network_analysis_meta WHERE name='producer_id'").fetchone()
    if row is None or type(row[0]) is not str or not _ID.fullmatch(row[0]):
        _invalid()
    budget.consume_bytes(len(row[0]))
    if row[0] != spec.scope.producer_id:
        raise _CatalogFailure('joint_anchor_mismatch')
    return row[0]


def _maximum(db):
    value = db.execute('SELECT coalesce(max(seq),0) FROM network_incidents').fetchone()[0]
    if type(value) is not int or not 0 <= value <= 2**63-1:
        _invalid()
    return value


def _spec(spec):
    if type(spec) is not JointRuntimeSpec:
        raise EvidenceReadError('adapter_invalid_request')


def catalog_target(network_path, spec, *, budget=None) -> int:
    """Capture the finite sequence barrier; later pages retain this target."""
    _spec(spec)
    if budget is not None and not isinstance(budget, ReadBudget):
        raise EvidenceReadError('adapter_invalid_request')
    budget = budget or ReadBudget()
    with _catalog_snapshot(network_path, budget) as db:
        _identity(db, spec, budget)
        return _maximum(db)


def preflight_sources(spec, *, limits: ReadLimits | None = None) -> dict:
    """Validate metadata/schema only, sequentially; never read business rows."""
    _spec(spec)
    budget = ReadBudget(limits)
    with _catalog_snapshot(spec.network_database_path, budget) as db:
        _identity(db, spec, budget)
    with snapshot(spec.ssh_database_path, budget) as db:
        _probe_ssh_schema(db, budget)
    return {'network_identity': 'matched', 'network_schema': 'available',
            'ssh_schema': 'available', 'ssh_durable_identity': 'unavailable',
            'cross_store_atomic': False}


def read_catalog_page(network_path, spec, *, after_seq, target_seq, limit=50,
                      budget=None, limits: ReadLimits | None = None) -> CatalogPage:
    """Read at most 50 current heads in a previously captured sequence range.

    All heads are considered, including retracted, unsurfaced and stale cases.
    Unmapped heads are explicitly counted; malformed rows fail the whole page.
    A completed range is a catalog bound, never an assertion of log coverage.
    """
    _spec(spec)
    if (type(after_seq) is not int or not spec.catalog_min_seq-1 <= after_seq <= 2**63-1
            or type(target_seq) is not int or not after_seq <= target_seq <= 2**63-1
            or type(limit) is not int or not 1 <= limit <= 50
            or (budget is not None and (limits is not None or not isinstance(budget, ReadBudget)))):
        raise EvidenceReadError('adapter_invalid_request')
    budget = budget or ReadBudget(limits)
    fields = {name: _scalar(name, maximum) for name, maximum in (
        ('incident_id', 36), ('source_id', 128), ('source_profile_revision', 64),
        ('src_ip', 64), ('dst_ip', 64))}
    select = ','.join(expression+' AS '+name for name, expression in fields.items())
    # Validate bounded header parity without returning payload_json to Python.
    parity = ' AND '.join(_text('payload_json', '$.'+name, maximum)+'='+name
        for name, maximum in (('incident_id',36), ('source_id',128),
            ('source_profile_revision',64), ('src_ip',64), ('dst_ip',64)))
    query = ('SELECT '+_integer('seq')+' AS seq,'+_integer('revision')+' AS revision,'+select+
        ",CASE WHEN typeof(payload_json)='text' AND length(CAST(payload_json AS BLOB))<="+str(MAX_CATALOG_HEADER_BYTES)+
        " THEN CASE WHEN json_valid(payload_json) THEN ("+parity+
        " AND json_type(payload_json,'$.revision')='integer' AND json_extract(payload_json,'$.revision')=revision) ELSE 0 END ELSE 0 END AS valid "
        'FROM network_incidents WHERE seq>? AND seq<=? ORDER BY seq LIMIT ?')
    requests, skipped = [], {}
    bindings = {binding.source_id: binding for mapping in spec.scope.mappings for binding in mapping.network_bindings}
    with _catalog_snapshot(network_path, budget) as db:
        producer = _identity(db, spec, budget)
        if _maximum(db) < target_seq:
            raise _CatalogFailure('joint_revision_regression')
        rows = db.execute(query, (after_seq, target_seq, limit)).fetchall()
        for row in rows:
            budget.consume_bytes(len(json.dumps(list(row), separators=(',', ':'), ensure_ascii=True)))
            if row['valid'] != 1 or any(value is None for value in row):
                _invalid()
            if not _ID.fullmatch(row['source_id']) or not _PROFILE.fullmatch(row['source_profile_revision']):
                _invalid()
            try:
                request = AnchorRequest(row['incident_id'], row['revision'])
                if any('%' in row[key] or str(ipaddress.ip_address(row[key])) != row[key] for key in ('src_ip','dst_ip')):
                    _invalid()
            except (ValueError, CaseStoreError):
                _invalid()
            binding = bindings.get(row['source_id'])
            reason = ('source_unmapped' if binding is None else
                'destination_unmapped' if row['dst_ip'] not in binding.destination_ips else
                'profile_unmapped' if row['source_profile_revision'] not in binding.profile_revisions else None)
            if reason:
                skipped[reason] = skipped.get(reason, 0)+1
            else:
                requests.append(request)
        complete = len(rows) < limit or (bool(rows) and rows[-1]['seq'] == target_seq)
        # When exactly a full page ends before a sparse tail, the next invocation
        # completes that tail; no unbounded extra count or payload scan is used.
        next_seq = target_seq if complete else rows[-1]['seq']
        return CatalogPage(producer, after_seq, target_seq, next_seq, len(rows), tuple(requests), skipped, complete)
