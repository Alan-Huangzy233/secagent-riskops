"""One-revision read adapters against real, isolated network store schemas."""
from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import json
import sqlite3

import pytest

from app.telemetry import joint_network_reader as reader
from app.telemetry import network_incidents as analysis
from app.telemetry.joint_evidence import NetworkCase
from app.telemetry.joint_reader_io import EvidenceReadError, ReadBudget, ReadLimits
from app.telemetry.network_store import NetworkStore
from test_network_detection import event
from test_network_incidents import deliver, drain


@pytest.fixture
def retained(tmp_path):
    store = NetworkStore(tmp_path/'network.sqlite')
    deliver(store, 1, [event(index) for index in range(10)])
    drain(store)
    case, = store.incidents()['items']
    return store, case


def read(retained, *, revision=1, limits=None, budget=None):
    store, case = retained
    return reader.read_network_case(store.path, case['incident_id'], revision,
                                    budget=budget or ReadBudget(limits))


def rewrite_payload(retained, change):
    store, case = retained
    with sqlite3.connect(store.path) as db:
        row = db.execute('SELECT payload_json FROM network_incident_revisions WHERE incident_id=? AND revision=1',
                         (case['incident_id'],)).fetchone()
        value = json.loads(row[0])
        value.update(change)
        db.execute('UPDATE network_incident_revisions SET payload_json=? WHERE incident_id=? AND revision=1',
                   (json.dumps(value), case['incident_id']))


def rewrite_event(retained, change):
    store, _ = retained
    with sqlite3.connect(store.path) as db:
        key, raw = db.execute('SELECT event_id,event_json FROM network_evidence ORDER BY monotonic_us LIMIT 1').fetchone()
        value = json.loads(raw)
        value.update(change)
        db.execute('UPDATE network_evidence SET event_json=? WHERE event_id=?', (json.dumps(value), key))


def state_hash(store):
    with sqlite3.connect(store.path) as db:
        return hashlib.sha256('\n'.join(db.iterdump()).encode()).hexdigest()


def test_real_retained_revision_maps_exact_fields_and_leaves_source_unchanged(retained, monkeypatch):
    store, source = retained
    before = state_hash(store)
    def forbidden(*args, **kwargs):
        raise AssertionError('reader initialized a writable source store')
    monkeypatch.setattr(NetworkStore, '__init__', forbidden)
    budget = ReadBudget()
    case = read(retained, budget=budget)
    assert type(case) is NetworkCase
    assert case.incident_id == source['incident_id'] and case.revision == 1
    assert case.source_id == source['source_id'] and case.boot_id == source['boot_id']
    assert case.profile_revision == source['source_profile_revision']
    assert case.evidence_total == len(case.evidence) == 10
    assert case.active and not case.stale and case.coverage == tuple(source['coverage'])
    with sqlite3.connect(store.path) as db:
        producer = analysis.meta(db, 'producer_id')
    assert case.producer_id == producer
    raw = event(0)
    first = case.evidence[0]
    assert first.event_id == raw.event_id
    assert first.event_ts_us == raw.journal_realtime_us
    assert first.monotonic_us == raw.journal_monotonic_us
    assert first.dst_port == raw.dst_port and first.protocol == 'TCP' and first.direction == 'local_input'
    assert 0 < budget.bytes_read < 20_000
    assert state_hash(store) == before


def test_current_revision_cannot_replace_requested_history(retained):
    store, source = retained
    first = read(retained)
    deliver(store, 2, [event(20, offset_us=5_500_000)])
    drain(store)
    assert store.incident(source['incident_id'])['revision'] == 2
    assert read(retained) == first
    second = read(retained, revision=2)
    assert second.revision == 2 and second.evidence_total == 11
    assert {x.event_id for x in first.evidence} < {x.event_id for x in second.evidence}


def test_closed_membership_and_readded_event_are_resolved_at_requested_revision(retained):
    store, source = retained
    identity = source['incident_id']
    original = read(retained)
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE network_evidence_membership SET to_revision=1 WHERE incident_id=?', (identity,))
        withdrawn = {**source, 'revision':2, 'active':False, 'evidence_count':0}
        restored = {**source, 'revision':3}
        for payload in (withdrawn, restored):
            db.execute('INSERT INTO network_incident_revisions VALUES(?,?,?)',
                       (identity, payload['revision'], json.dumps(payload)))
        db.execute('INSERT INTO network_evidence_membership SELECT incident_id,event_id,3,NULL FROM network_evidence')
    assert read(retained) == original
    empty = read(retained, revision=2)
    assert empty.evidence == () and empty.evidence_total == 0 and not empty.active
    assert read(retained, revision=3).evidence == original.evidence


def test_stale_snapshot_keeps_its_declared_coverage_and_evidence(retained):
    rewrite_payload(retained, {'stale':True, 'coverage':['context_limit', 'journal_clock_discontinuity']})
    case = read(retained)
    assert case.stale and len(case.evidence) == 10
    assert case.coverage == ('context_limit', 'journal_clock_discontinuity')


@pytest.mark.parametrize('revision', [None, 0, -1, True, 1.0, '1', 2**31])
def test_revision_is_required_and_validated_before_io(tmp_path, revision):
    with pytest.raises(EvidenceReadError, match='^adapter_invalid_request$'):
        reader.read_network_case(tmp_path/'missing.sqlite', 'NET-'+'a'*32, revision, budget=ReadBudget())
    assert not (tmp_path/'missing.sqlite').exists()


@pytest.mark.parametrize('identity', ['', None, 'NET-wrong', 'NET-'+'A'*32, "NET-'; DROP TABLE x;--"])
def test_network_identity_shape_is_validated_before_io(tmp_path, identity):
    with pytest.raises(EvidenceReadError, match='^adapter_invalid_request$'):
        reader.read_network_case(tmp_path/'missing.sqlite', identity, 1, budget=ReadBudget())


def test_unknown_revision_is_not_an_empty_success(retained):
    with pytest.raises(EvidenceReadError, match='^network_revision_missing$'):
        read(retained, revision=200)


@pytest.mark.parametrize('pragma,value', [('application_id', 0), ('user_version', 1), ('user_version', 99)])
def test_unsupported_schema_is_rejected_without_migration(retained, pragma, value):
    store, _ = retained
    with sqlite3.connect(store.path) as db:
        db.execute(f'PRAGMA {pragma}={value}')
    before = state_hash(store)
    with pytest.raises(EvidenceReadError, match='^source_schema_unavailable$'):
        read(retained)
    assert state_hash(store) == before


def test_missing_required_table_has_a_fixed_schema_error(retained):
    store, _ = retained
    with sqlite3.connect(store.path) as db:
        db.execute('DROP TABLE network_evidence_membership')
    with pytest.raises(EvidenceReadError, match='^source_schema_unavailable$'):
        read(retained)


@pytest.mark.parametrize('change', [
    {'incident_id':'NET-'+'b'*32}, {'revision':2}, {'revision':True}, {'revision':'1'},
    {'protocol':'TCP'}, {'active':1}, {'stale':'false'}, {'evidence_count':True},
    {'evidence_count':9}, {'coverage':None}, {'coverage':['bad-code']},
    {'coverage':['x']*65}, {'source_id':'invalid source'}, {'source_profile_revision':'bad'},
])
def test_invalid_header_types_counts_and_identity_are_not_coerced(retained, change):
    rewrite_payload(retained, change)
    with pytest.raises(EvidenceReadError, match='^evidence_invalid$'):
        read(retained)


@pytest.mark.parametrize('change', [
    {'source_id':'another-source'}, {'boot_id':'2'*32}, {'source_profile_revision':'b'*64},
    {'src_ip':'198.51.100.43'}, {'dst_ip':'192.0.2.11'}, {'event_id':'b'*64},
    {'journal_monotonic_us':True}, {'journal_monotonic_us':2},
    {'journal_realtime_us':True}, {'dst_port':'22'}, {'dst_port':False}, {'protocol':None},
])
def test_invalid_event_provenance_and_numeric_json_types_are_rejected(retained, change):
    rewrite_event(retained, change)
    with pytest.raises(EvidenceReadError, match='^evidence_invalid$'):
        read(retained)


@pytest.mark.parametrize('mode', ['missing_evidence', 'missing_membership', 'overlapping_membership', 'bad_monotonic'])
def test_retained_membership_inconsistency_cannot_become_partial_success(retained, mode):
    store, _ = retained
    with sqlite3.connect(store.path) as db:
        identity, event_id = db.execute('SELECT incident_id,event_id FROM network_evidence LIMIT 1').fetchone()
        if mode == 'missing_evidence':
            db.execute('DELETE FROM network_evidence WHERE incident_id=? AND event_id=?', (identity,event_id))
        elif mode == 'missing_membership':
            db.execute('DELETE FROM network_evidence_membership WHERE incident_id=? AND event_id=?', (identity,event_id))
        elif mode == 'overlapping_membership':
            db.execute('UPDATE network_evidence_membership SET to_revision=2 WHERE incident_id=? AND event_id=?',
                       (identity,event_id))
            db.execute('INSERT INTO network_evidence_membership VALUES(?,?,0,2)', (identity,event_id))
        else:
            db.execute('UPDATE network_evidence SET monotonic_us=123 WHERE incident_id=? AND event_id=?',
                       (identity,event_id))
    with pytest.raises(EvidenceReadError, match='^evidence_invalid$'):
        read(retained)


@pytest.mark.parametrize('table,column', [('network_incident_revisions','payload_json'),('network_evidence','event_json')])
def test_malformed_json_errors_do_not_echo_raw_evidence(retained, table, column):
    store, _ = retained
    marker = 'PRIVATE_SYNTHETIC_MALFORMED'
    with sqlite3.connect(store.path) as db:
        db.execute(f'UPDATE {table} SET {column}=?', (marker,))
    with pytest.raises(EvidenceReadError, match='^evidence_invalid$') as failure:
        read(retained)
    assert marker not in str(failure.value) and store.path not in str(failure.value)


def test_unused_large_raw_fields_are_never_materialized_or_counted(retained, monkeypatch):
    marker = 'RAW_PAYLOAD_MUST_NOT_CROSS_SQL'
    rewrite_event(retained, {'message':marker*100_000, 'journal_cursor':marker*100_000})
    captured = []
    original = reader._consume
    def consume(row, budget):
        captured.append(list(row))
        original(row, budget)
    monkeypatch.setattr(reader, '_consume', consume)
    budget = ReadBudget(ReadLimits(byte_limit=20_000))
    case = read(retained, budget=budget)
    assert len(case.evidence) == 10 and budget.bytes_read < 20_000
    assert marker not in json.dumps(captured)
    assert 'message' not in json.dumps(asdict(case)) and 'journal_cursor' not in json.dumps(asdict(case))


def test_oversized_required_json_field_is_rejected_before_materialization(retained, monkeypatch):
    marker = 'OVERSIZED_EVENT_ID'
    rewrite_event(retained, {'event_id':marker*100_000})
    captured = []
    original = reader._consume
    def consume(row, budget):
        captured.append(list(row))
        original(row, budget)
    monkeypatch.setattr(reader, '_consume', consume)
    with pytest.raises(EvidenceReadError, match='^evidence_invalid$'):
        read(retained)
    assert marker not in json.dumps(captured)


@pytest.mark.parametrize('limits', [ReadLimits(record_limit=9), ReadLimits(byte_limit=100)])
def test_record_and_byte_caps_fail_explicitly_and_connection_is_released(retained, limits):
    store, _ = retained
    before = state_hash(store)
    with pytest.raises(EvidenceReadError, match='^adapter_limit_exceeded$'):
        read(retained, limits=limits)
    assert state_hash(store) == before
    assert read(retained).evidence_total == 10
    with sqlite3.connect(store.path, timeout=.1) as db:
        db.execute('BEGIN IMMEDIATE')
        db.execute("UPDATE network_analysis_meta SET value=value WHERE name='producer_id'")


def test_expired_budget_performs_no_partial_success_and_releases_source(retained):
    now = [0.0]
    budget = ReadBudget(clock=lambda:now[0])
    now[0] = 6.0
    with pytest.raises(EvidenceReadError, match='^query_deadline_exceeded$'):
        read(retained, budget=budget)
    assert read(retained).evidence_total == 10


def test_all_fields_belong_to_one_source_transaction_during_concurrent_mutation(retained, monkeypatch):
    store, _ = retained
    original_case = read(retained)
    original_snapshot = reader.snapshot
    mutated = []
    @contextmanager
    def snapshot(path, budget):
        with original_snapshot(path,budget) as db:
            class Proxy:
                def execute(self, sql, params=()):
                    cursor = db.execute(sql, params)
                    if 'network_analysis_meta' in sql and not mutated:
                        # An independent writer changes the source after the
                        # reader has pinned its producer snapshot. Neither part
                        # may leak into this already-open source transaction.
                        with sqlite3.connect(store.path) as writer:
                            writer.execute("UPDATE network_analysis_meta SET value=? WHERE name='producer_id'",
                                           (json.dumps('b'*32),))
                            writer.execute("UPDATE network_incident_revisions SET payload_json=json_set(payload_json,'$.source_id','changed-source')")
                        mutated.append(True)
                    return cursor
            yield Proxy()
    monkeypatch.setattr(reader, 'snapshot', snapshot)
    assert read(retained) == original_case and mutated
    monkeypatch.setattr(reader, 'snapshot', original_snapshot)
    with pytest.raises(EvidenceReadError, match='^evidence_invalid$'):
        read(retained)


def test_selected_revision_queries_seek_existing_incident_indexes(retained):
    store, case = retained
    params = (case['incident_id'],1,1)
    with sqlite3.connect(store.path) as db:
        counts = [row[3] for row in db.execute('EXPLAIN QUERY PLAN '+reader._COUNT_SQL, params)]
        items = [row[3] for row in db.execute('EXPLAIN QUERY PLAN '+reader._EVIDENCE_SQL, (*params,5001))]
    for plan in (counts,items):
        assert any('SEARCH m USING' in row and 'incident_id=?' in row for row in plan)
        assert any('SEARCH e USING' in row and 'incident_id=? AND event_id=?' in row for row in plan)
        assert not any('SCAN m' in row or 'SCAN e' in row for row in plan)


@pytest.mark.parametrize('field', ['event_id', 'source_id', 'protocol'])
def test_nul_cannot_hide_a_huge_required_text_field_from_sql_byte_bounds(retained, monkeypatch, field):
    marker = 'HIDDEN_AFTER_NUL'
    rewrite_event(retained, {field:'x\x00'+marker*100_000})
    captured = []
    original = reader._consume
    def consume(row, budget):
        captured.append(list(row))
        original(row, budget)
    monkeypatch.setattr(reader, '_consume', consume)
    with pytest.raises(EvidenceReadError, match='^evidence_invalid$'):
        read(retained)
    assert marker not in json.dumps(captured)


@pytest.mark.parametrize('value', ['INVALID_NUMBER'*100_000, b'INVALID_NUMBER'*100_000])
def test_invalid_retained_numeric_column_never_materializes_bad_text_or_blob(retained, monkeypatch, value):
    store, _ = retained
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE network_evidence SET monotonic_us=? WHERE rowid=(SELECT min(rowid) FROM network_evidence)',
                   (value,))
    captured = []
    original = reader._consume
    def consume(row, budget):
        captured.append(list(row))
        original(row, budget)
    monkeypatch.setattr(reader, '_consume', consume)
    with pytest.raises(EvidenceReadError, match='^evidence_invalid$'):
        read(retained)
    assert 'INVALID_NUMBER' not in json.dumps(captured)


def test_deadline_expiring_during_evidence_iteration_releases_the_reader(retained, monkeypatch):
    now = [0.0]
    budget = ReadBudget(clock=lambda:now[0])
    original = reader._consume
    def consume(row, current):
        if 'retained_event_id' in row.keys():
            now[0] = 6.0
        original(row, current)
    monkeypatch.setattr(reader, '_consume', consume)
    with pytest.raises(EvidenceReadError, match='^query_deadline_exceeded$'):
        read(retained, budget=budget)
    monkeypatch.setattr(reader, '_consume', original)
    store, _ = retained
    with sqlite3.connect(store.path, timeout=.1) as db:
        db.execute('BEGIN EXCLUSIVE')
    assert read(retained).evidence_total == 10


def test_invalid_membership_start_revision_is_not_silently_accepted(retained):
    store, _ = retained
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE network_evidence_membership SET from_revision=0')
    with pytest.raises(EvidenceReadError, match='^evidence_invalid$'):
        read(retained)


def test_large_unrelated_retained_history_does_not_expand_selected_query_work(retained):
    store, _ = retained
    baseline_budget = ReadBudget()
    expected = read(retained, budget=baseline_budget)
    with sqlite3.connect(store.path) as db:
        # These deliberately unreadable unrelated payloads must never be parsed.
        db.executemany('INSERT INTO network_evidence VALUES(?,?,?,?)',
            ((f'NET-{index:032x}',f'unrelated-{index}',0,'not-json') for index in range(20_000)))
        db.executemany('INSERT INTO network_evidence_membership VALUES(?,?,1,NULL)',
            ((f'NET-{index:032x}',f'unrelated-{index}') for index in range(20_000)))
    budget = ReadBudget()
    assert read(retained, budget=budget) == expected
    assert budget.bytes_read == baseline_budget.bytes_read
    assert budget.progress_calls <= baseline_budget.progress_calls+4
