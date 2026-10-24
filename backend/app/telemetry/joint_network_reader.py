"""Read one retained network revision as bounded typed association evidence.

No store initialization, current-version substitution or raw JSON export. The
caller owns a shared read budget and opens the SSH snapshot only after this
function returns and its network read transaction has closed.
"""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import re

from .joint_evidence import MAX_TIME_US, NetworkCase, NetworkEvidence
from .joint_reader_io import EvidenceReadError, ReadBudget, snapshot
from .network_store import APPLICATION_ID, SCHEMA_VERSION

_INCIDENT_ID = re.compile(r'NET-[0-9a-f]{32}\Z')
_MEMBERSHIP = ('m.incident_id=? AND m.from_revision<=? '
               'AND (m.to_revision IS NULL OR m.to_revision>=?)')


def _text(column, path, maximum):
    value = f"json_extract({column},'{path}')"
    return (f"CASE WHEN json_type({column},'{path}')='text' "
            f"AND length(CAST({value} AS BLOB)) BETWEEN 1 AND {maximum} THEN {value} END")


def _integer(column, path, low, high):
    value = f"json_extract({column},'{path}')"
    return (f"CASE WHEN json_type({column},'{path}')='integer' "
            f"AND {value} BETWEEN {low} AND {high} THEN {value} END")


def _boolean(column, path):
    return (f"CASE json_type({column},'{path}') WHEN 'true' THEN 1 "
            "WHEN 'false' THEN 0 END")


# CASE expressions bound each extracted field before it crosses SQLite/Python.
# The source JSON may contain large or sensitive unused fields; never fetch it.
_HEADER_FIELDS = {
    **{key: _text('payload_json', '$.'+key, maximum) for key, maximum in (
        ('incident_id', 128), ('source_id', 128), ('boot_id', 128),
        ('source_profile_revision', 64), ('src_ip', 64), ('dst_ip', 64), ('protocol', 16))},
    'revision': _integer('payload_json', '$.revision', 1, 2**31-1),
    'evidence_count': _integer('payload_json', '$.evidence_count', 0, 1_000_000),
    'active': _boolean('payload_json', '$.active'),
    'stale': _boolean('payload_json', '$.stale'),
    'coverage': ("CASE WHEN json_type(payload_json,'$.coverage')='array' "
                 "AND json_array_length(payload_json,'$.coverage')<=64 "
                 "AND length(CAST(json_extract(payload_json,'$.coverage') AS BLOB))<=8192 "
                 "THEN json_extract(payload_json,'$.coverage') END"),
}
_HEADER_SQL = ('SELECT '+','.join(value+' AS '+key for key, value in _HEADER_FIELDS.items())+
               ' FROM network_incident_revisions WHERE incident_id=? AND revision=?')
_EVENT_FIELDS = {
    **{key: _text('e.event_json', '$.'+key, maximum) for key, maximum in (
        ('source_id', 128), ('event_id', 2048), ('boot_id', 128),
        ('source_profile_revision', 64), ('src_ip', 64), ('dst_ip', 64),
        ('protocol', 16), ('direction', 32))},
    'journal_realtime_us': _integer('e.event_json', '$.journal_realtime_us', 0, MAX_TIME_US),
    'journal_monotonic_us': _integer('e.event_json', '$.journal_monotonic_us', 0, 2**63-1),
    'dst_port': _integer('e.event_json', '$.dst_port', 1, 65535),
}
# Select the bounded revision membership first. Otherwise SQLite can prefer the
# ordering index and walk every historical event of a heavily revised incident.
_EVIDENCE_SQL = (
    "SELECT CASE WHEN typeof(m.event_id)='text' AND length(CAST(m.event_id AS BLOB)) BETWEEN 1 AND 2048 "
    "THEN m.event_id END AS retained_event_id,CASE WHEN typeof(e.monotonic_us)='integer' "
    'THEN e.monotonic_us END AS retained_monotonic_us,'+
    ','.join(value+' AS '+key for key, value in _EVENT_FIELDS.items())+
    ' FROM network_evidence_membership m CROSS JOIN network_evidence e '
    'ON e.incident_id=m.incident_id AND e.event_id=m.event_id WHERE '+_MEMBERSHIP+
    ' ORDER BY e.monotonic_us,e.event_id LIMIT ?')
_COUNT_SQL = (
    'SELECT count(*) AS total,count(DISTINCT m.event_id) AS distinct_total,'
    'count(e.event_id) AS retained_total,'
    "coalesce(sum(CASE WHEN typeof(m.from_revision)!='integer' OR m.from_revision<1 "
    "OR (m.to_revision IS NOT NULL AND (typeof(m.to_revision)!='integer' "
    'OR m.to_revision<m.from_revision)) THEN 1 ELSE 0 END),0) AS invalid_intervals '
    'FROM network_evidence_membership m '
    'LEFT JOIN network_evidence e ON e.incident_id=m.incident_id AND e.event_id=m.event_id '
    'WHERE '+_MEMBERSHIP)


def _consume(row, budget):
    # Only scalar projected fields reach this boundary, never complete JSON.
    try:
        size = len(json.dumps(list(row), ensure_ascii=True, separators=(',', ':'), allow_nan=False))
    except (TypeError, ValueError):
        raise EvidenceReadError('evidence_invalid') from None
    budget.consume_bytes(size)


def _one(db, sql, params, budget):
    budget.check()
    row = db.execute(sql, params).fetchone()
    if row is not None:
        _consume(row, budget)
    return row


def _invalid():
    raise EvidenceReadError('evidence_invalid')


def _header(row, producer, identity, revision):
    if any(row[key] is None for key in _HEADER_FIELDS):
        _invalid()
    if row['incident_id'] != identity or row['revision'] != revision or row['protocol'] != 'network':
        _invalid()
    try:
        coverage = json.loads(row['coverage'])
        if type(coverage) is not list:
            _invalid()
        return NetworkCase(producer_id=producer, incident_id=row['incident_id'],
            revision=row['revision'], source_id=row['source_id'], boot_id=row['boot_id'],
            profile_revision=row['source_profile_revision'], src_ip=row['src_ip'], dst_ip=row['dst_ip'],
            evidence=(), evidence_total=row['evidence_count'], active=bool(row['active']),
            stale=bool(row['stale']), coverage=tuple(coverage))
    except (ValueError, TypeError):
        raise EvidenceReadError('evidence_invalid') from None


def _event(row, case):
    if any(row[key] is None for key in _EVENT_FIELDS):
        _invalid()
    if row['retained_event_id'] != row['event_id'] or row['retained_monotonic_us'] != row['journal_monotonic_us']:
        _invalid()
    try:
        event = NetworkEvidence(source_id=row['source_id'], event_id=row['event_id'], boot_id=row['boot_id'],
            profile_revision=row['source_profile_revision'], src_ip=row['src_ip'], dst_ip=row['dst_ip'],
            event_ts_us=row['journal_realtime_us'], monotonic_us=row['journal_monotonic_us'],
            dst_port=row['dst_port'], protocol=row['protocol'], direction=row['direction'])
    except (ValueError, TypeError):
        raise EvidenceReadError('evidence_invalid') from None
    provenance = ('source_id', 'boot_id', 'profile_revision', 'src_ip', 'dst_ip')
    if any(getattr(event, key) != getattr(case, key) for key in provenance):
        _invalid()
    return event


def read_network_case(path: str | Path, incident_id: str, revision: int, *, budget: ReadBudget) -> NetworkCase:
    """Return exactly one complete retained revision, or a fixed error code.

    Unknown revisions, omissions, malformed provenance and exhausted limits do
    not produce an empty successful case. Source coverage remains declarative;
    typed extraction does not authenticate collector evidence or verify clocks.
    """
    if (type(incident_id) is not str or not _INCIDENT_ID.fullmatch(incident_id)
            or type(revision) is not int or not 1 <= revision <= 2**31-1
            or not isinstance(budget, ReadBudget)):
        raise EvidenceReadError('adapter_invalid_request')
    with snapshot(path, budget) as db:
        if (_one(db, 'PRAGMA application_id', (), budget)[0] != APPLICATION_ID
                or _one(db, 'PRAGMA user_version', (), budget)[0] != SCHEMA_VERSION):
            raise EvidenceReadError('source_schema_unavailable')
        producer = _one(db, 'SELECT '+_text('value', '$', 128)+
                        " AS producer FROM network_analysis_meta WHERE name='producer_id'", (), budget)
        if producer is None or producer['producer'] is None:
            _invalid()
        row = _one(db, _HEADER_SQL, (incident_id, revision), budget)
        if row is None:
            raise EvidenceReadError('network_revision_missing')
        case = _header(row, producer['producer'], incident_id, revision)
        if case.evidence_total > budget.limits.record_limit:
            raise EvidenceReadError('adapter_limit_exceeded')
        params = (incident_id, revision, revision)
        counts = _one(db, _COUNT_SQL, params, budget)
        if counts['total'] > budget.limits.record_limit:
            raise EvidenceReadError('adapter_limit_exceeded')
        if (counts['invalid_intervals'] or counts['total'] != counts['distinct_total']
                or counts['total'] != counts['retained_total'] or counts['total'] != case.evidence_total):
            _invalid()
        budget.check()
        cursor = db.execute(_EVIDENCE_SQL, (*params, budget.limits.record_limit+1))
        records = []
        while True:
            budget.check()
            rows = cursor.fetchmany(budget.limits.batch_size)
            if not rows:
                break
            for record in rows:
                _consume(record, budget)
                records.append(_event(record, case))
                if len(records) > budget.limits.record_limit:
                    raise EvidenceReadError('adapter_limit_exceeded')
        if len(records) != counts['total']:
            _invalid()
        budget.check()
        return replace(case, evidence=tuple(records))
