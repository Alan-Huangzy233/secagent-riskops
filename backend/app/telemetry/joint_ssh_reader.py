"""Bounded, read-only projections of retained SSH incident evidence.

This is not a raw-log search or a historical coverage proof. One short source
transaction freezes this read; merges and late evidence can change a later read.
"""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import math
import re

from .joint_evidence import MAX_ANCHOR_SPAN_US, MAX_TIME_US, SSHRecord
from .joint_reader_io import EvidenceReadError, ReadBudget, snapshot

_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')
_TIMESTAMP = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z')
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
MAX_ALIAS_HOPS = 32


def _invalid():
    raise EvidenceReadError('evidence_invalid')


def _bounded_text_sql(expression, maximum):
    # CASE prevents a malicious text/object field becoming a Python allocation.
    return (f"CASE WHEN typeof({expression})='text' AND length({expression})<={maximum}"
            f" AND length(CAST({expression} AS BLOB))<={maximum*4} THEN {expression} END")


def _json_text_sql(field, maximum):
    expression = f"json_extract(snapshot_json,'$.{field}')"
    return ("CASE WHEN json_valid(snapshot_json) THEN CASE WHEN "
            f"json_type(snapshot_json,'$.{field}')='text' THEN "
            f"{_bounded_text_sql(expression, maximum)} END END")


def _candidate_sql(source_count):
    placeholders = ','.join('?' for _ in range(source_count))
    return f"""SELECT {_bounded_text_sql('incident_id', 128)} AS incident_id,
            CASE WHEN typeof(first_ts) IN ('real','integer') THEN first_ts END AS first_ts,
            CASE WHEN typeof(last_ts) IN ('real','integer') THEN last_ts END AS last_ts
        FROM incidents
        WHERE status!='merged' AND src_ip=? AND last_ts>=? AND first_ts<=?
          AND (source_id IN ({placeholders}) OR EXISTS (
            SELECT 1 FROM incident_sources s
            WHERE s.incident_id=incidents.incident_id AND s.source_id IN ({placeholders})))
        ORDER BY incidents.last_ts DESC,incidents.incident_id LIMIT ?"""


def _evidence_sql(source_count):
    placeholders = ','.join('?' for _ in range(source_count))
    fields = [('source_id', 128), ('event_id', 2048), ('timestamp', 27),
              ('event_type', 32), ('src_ip', 64), ('ssh_user', 256)]
    projected = ','.join(f'{_json_text_sql(field, maximum)} AS json_{field}' for field, maximum in fields)
    return f"""SELECT {_bounded_text_sql('source_id', 128)} AS source_id,
            {_bounded_text_sql('event_id', 2048)} AS event_id,
            {_bounded_text_sql('incident_id', 128)} AS incident_id,
            CASE WHEN typeof(event_ts) IN ('real','integer') THEN event_ts END AS event_ts,
            {projected},
            CASE WHEN json_valid(snapshot_json) THEN
              json_type(snapshot_json,'$.ssh_user') IS NULL OR
              json_type(snapshot_json,'$.ssh_user')='null' OR
              ({_json_text_sql('ssh_user', 256)} IS NOT NULL)
            ELSE 0 END AS account_valid
        FROM incident_evidence
        WHERE incident_id=? AND event_ts>=? AND event_ts<=?
          AND source_id IN ({placeholders})
        ORDER BY incident_evidence.event_ts,incident_evidence.source_id,incident_evidence.event_id LIMIT ?"""


def _probe_schema(db, budget):
    # Compile every required table/column even when the candidate query is empty.
    # LIMIT 0 reads no evidence rows and never turns a damaged source into an
    # apparently successful empty retained-evidence result.
    for query in (
        'SELECT incident_id,source_id,src_ip,status,first_ts,last_ts,merged_into FROM incidents LIMIT 0',
        'SELECT incident_id,source_id FROM incident_sources LIMIT 0',
        'SELECT source_id,event_id,incident_id,event_ts,snapshot_json FROM incident_evidence LIMIT 0',
    ):
        budget.check()
        db.execute(query).close()


def _consume(budget, row):
    budget.consume_bytes(len(json.dumps(list(row), ensure_ascii=True, separators=(',', ':'))))


def _identifier(value):
    if type(value) is not str or not _ID.fullmatch(value):
        _invalid()
    return value


def _peer(value):
    if type(value) is not str or not 1 <= len(value) <= 64 or '%' in value:
        _invalid()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        _invalid()


def _canonical_incident(db, identity, peer, budget, cache):
    """Resolve only actual owner pointers; never invent event-level old aliases."""
    original, seen = identity, set()
    for _ in range(MAX_ALIAS_HOPS):
        budget.check()
        if identity in seen:
            _invalid()
        if identity in cache:
            canonical = cache[identity]
            break
        seen.add(identity)
        row = db.execute(f"""SELECT {_bounded_text_sql('merged_into', 128)} AS target,
                merged_into IS NULL AS no_target,
                {_bounded_text_sql('src_ip', 64)} AS peer,
                {_bounded_text_sql('status', 32)} AS status
            FROM incidents WHERE incident_id=?""", (identity,)).fetchone()
        if row is None:
            _invalid()
        _consume(budget, row)
        if _peer(row['peer']) != peer or type(row['status']) is not str:
            _invalid()
        if row['no_target']:
            if row['status'] == 'merged':
                _invalid()
            canonical = identity
            break
        identity = _identifier(row['target'])
    else:
        _invalid()
    for item in seen:
        cache[item] = canonical
    cache[original] = canonical
    return canonical


def _timestamp(value, event_ts):
    if type(value) is not str or not _TIMESTAMP.fullmatch(value):
        _invalid()
    try:
        at = datetime.fromisoformat(value[:-1]+'+00:00')
    except ValueError:
        _invalid()
    delta = at-_EPOCH
    micros = delta.days*86400_000_000 + delta.seconds*1_000_000 + delta.microseconds
    if (type(event_ts) not in (int, float) or not math.isfinite(event_ts)
            or event_ts != at.timestamp() or not 0 <= micros <= MAX_TIME_US):
        _invalid()
    return micros


def read_ssh_evidence(path, source_ids: tuple[str, ...], peer: str,
                      start_us: int, end_us: int, *, budget: ReadBudget) -> tuple[SSHRecord, ...]:
    """Read exact mapped source/peer/window records from incident_evidence only.

    Candidate intervals only narrow the indexed read. Actual normalized UTC
    timestamps determine membership with integer microseconds. Unknown source
    coverage and raw-only events are deliberately not inferred from this tuple.
    """
    try:
        if (type(source_ids) is not tuple or not 1 <= len(source_ids) <= 16
                or len(set(source_ids)) != len(source_ids)
                or type(budget) is not ReadBudget
                or type(start_us) is not int or type(end_us) is not int
                or not 0 <= start_us <= end_us <= MAX_TIME_US
                or end_us-start_us > MAX_ANCHOR_SPAN_US+7200_000_000):
            raise EvidenceReadError('adapter_invalid_request')
        sources = tuple(sorted(_identifier(item) for item in source_ids))
        peer = _peer(peer)
    except (EvidenceReadError, TypeError):
        raise EvidenceReadError('adapter_invalid_request') from None
    # Stored REAL timestamps come from datetime.timestamp(). Outward rounding
    # includes boundary rows even when the two float conversions differ by an ULP.
    lower = math.nextafter(start_us/1_000_000, -math.inf)
    upper = math.nextafter(end_us/1_000_000, math.inf)
    result, cache, materialized = [], {}, 0
    with snapshot(path, budget) as db:
        _probe_schema(db, budget)
        candidates = db.execute(_candidate_sql(len(sources)),
            (peer, lower, upper, *sources, *sources, budget.limits.candidate_limit+1))
        identities = []
        for row in candidates:
            _consume(budget, row)
            if len(identities) >= budget.limits.candidate_limit:
                raise EvidenceReadError('adapter_limit_exceeded')
            identity = _identifier(row['incident_id'])
            first, last = row['first_ts'], row['last_ts']
            if (any(type(value) not in (int, float) or not math.isfinite(value) for value in (first, last))
                    or first > last):
                _invalid()
            identities.append(identity)
        for identity in identities:
            canonical = _canonical_incident(db, identity, peer, budget, cache)
            budget.check()
            cursor = db.execute(_evidence_sql(len(sources)),
                (identity, lower, upper, *sources, budget.limits.record_limit-materialized+1))
            while True:
                budget.check()
                batch = cursor.fetchmany(budget.limits.batch_size)
                if not batch:
                    break
                for row in batch:
                    _consume(budget, row)
                    materialized += 1
                    if materialized > budget.limits.record_limit:
                        raise EvidenceReadError('adapter_limit_exceeded')
                    if (row['source_id'] not in sources or row['incident_id'] != identity
                            or row['source_id'] != row['json_source_id']
                            or row['event_id'] != row['json_event_id']
                            or _peer(row['json_src_ip']) != peer or not row['account_valid']):
                        _invalid()
                    event_us = _timestamp(row['json_timestamp'], row['event_ts'])
                    try:
                        record = SSHRecord(source_id=row['source_id'], event_id=row['event_id'],
                            incident_id=identity, canonical_incident_id=canonical if canonical != identity else None,
                            src_ip=peer, event_ts_us=event_us, event_type=row['json_event_type'],
                            account=row['json_ssh_user'])
                    except (ValueError, TypeError):
                        raise EvidenceReadError('evidence_invalid') from None
                    if start_us <= event_us <= end_us:
                        result.append(record)
        budget.check()
    return tuple(sorted(result, key=lambda row: (row.event_ts_us, row.source_id, row.event_id)))
