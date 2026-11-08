"""Exact indexed HTTP peer search, bounded failure and snapshot consistency."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import time

import pytest

from app.telemetry import http_incident_search as search
from app.telemetry import http_incidents as analysis
from app.telemetry.http_store import HttpIncidentSearchUnavailable, HttpStore
from test_http_incidents import HOUR, NOW, drain, ingest, record, scan

PEER = '198.51.100.23'


@pytest.fixture
def store(tmp_path):
    result = HttpStore(tmp_path / 'http.sqlite')
    ingest(result, scan())
    drain(result)
    return result


def add_case(store, identity, *, peer=PEER, source='web', service='public', hour=HOUR,
             active=True, surfaced=True):
    """Add another synthetic analyzed case while preserving payload/index agreement."""
    payload = store.incidents()['items'][0].copy()
    payload.update(incident_id=identity, source_id=source, service_id=service, client_ip=peer,
                   window_start=analysis.stamp(hour), window_end=analysis.stamp(hour + 3600), active=active)
    payload['assessment'] = {**payload['assessment'], 'surfaced': surfaced,
                             'score': 30 if active and surfaced else 25 if active else 0}
    with store.connection(write=True) as db:
        db.execute('INSERT INTO http_incidents(incident_id,source_id,service_id,client_ip,hour,revision,'
                   'score,surfaced,active,coverage,updated_at,payload_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                   (identity, source, service, peer, hour, payload['revision'], payload['assessment']['score'],
                    int(surfaced), int(active), payload['coverage'], NOW, analysis.canonical(payload)))
    return payload


def test_exact_peer_filters_before_count_and_pagination(store):
    first = store.incidents()['items'][0]
    other = add_case(store, 'other', peer='198.51.100.230')
    second = add_case(store, 'second', hour=HOUR + 3600)
    third = add_case(store, 'third', hour=HOUR + 3600)
    page = store.incidents(ip=PEER, limit=2)
    assert page['items'] == [third, second]
    assert page['total'] == 3 and page['total_pages'] == 2 and page['page'] == 1
    assert page['query'] == dict(ip=PEER, source_id=None, service_id=None, focus='all')
    assert page['limitations'] == ['retained_cases_only', 'connection_peer_only',
                                   'analysis_coverage_limited', 'pages_may_change']
    assert store.incidents(ip=PEER, page=2, limit=2)['items'] == [first]
    assert store.incidents(ip=PEER, page=1_000_000, limit=2)['page'] == 2
    assert other not in page['items']
    assert store.incidents()['total'] == 4
    assert set(store.incidents()) == {'items', 'total', 'page', 'total_pages'}


def test_source_service_and_focus_are_intersected_before_count(store):
    low = add_case(store, 'low', service='private', surfaced=False)
    retracted = add_case(store, 'retracted', source='other', active=False, surfaced=False)
    for focus, expected in [('attention', 1), ('low', 1), ('retracted', 1), ('all', 3)]:
        assert store.incidents(ip=PEER, focus=focus)['total'] == expected
    assert store.incidents(ip=PEER, service_id='private')['items'] == [low]
    assert store.incidents(ip=PEER, source_id='other', focus='retracted')['items'] == [retracted]
    empty = store.incidents(ip=PEER, source_id='other', service_id='private', page=99)
    assert empty['items'] == [] and empty['total'] == 0 and empty['page'] == empty['total_pages'] == 1


@pytest.mark.parametrize('query, canonical', [('2001:0DB8:0000::1', '2001:db8::1'),
                                               ('::ffff:198.51.100.23', PEER),
                                               ('::ffff:c633:6417', PEER)])
def test_canonical_ipv6_and_mapped_ipv4_match_ingestion(store, query, canonical):
    if canonical != PEER:
        ingest(store, [record('v6', path='/../etc/passwd', peer=query)], 'v6')
        drain(store)
    result = store.incidents(ip=query)
    assert result['query']['ip'] == canonical
    assert result['total'] == 1 and result['items'][0]['client_ip'] == canonical


@pytest.mark.parametrize('value', ['', ' ', ' 198.51.100.23', '198.51.100.23 ', '198.51.100.0/24',
                                   'fe80::1%eth0', 'not-ip', True, 123, b'198.51.100.23', [], {},
                                   '198.051.100.23', '1' * 10000])
def test_invalid_ip_is_generic_and_does_not_open_database(store, monkeypatch, value):
    def unexpected(*args, **kwargs):
        pytest.fail('invalid query reached sqlite')
    monkeypatch.setattr(search.sqlite3, 'connect', unexpected)
    with pytest.raises(ValueError, match='^invalid_http_incident_search$'):
        store.incidents(ip=value)


@pytest.mark.parametrize('kwargs', [dict(source_id=''), dict(source_id='x OR 1=1'), dict(service_id=0),
                                    dict(focus='unknown'), dict(page=True), dict(page=0), dict(page=1.5),
                                    dict(page=1_000_001), dict(limit=True), dict(limit=201), dict(limit='1')])
def test_invalid_filtered_scope_is_generic(store, kwargs):
    with pytest.raises(ValueError, match='^invalid_http_incident_search$'):
        store.incidents(ip=PEER, **kwargs)


def test_search_plan_uses_peer_index_and_does_not_sort_entire_history(store):
    with store.connection() as db:
        plan = [r[3] for r in db.execute('EXPLAIN QUERY PLAN SELECT payload_json FROM http_incidents '
                                         'INDEXED BY http_incidents_peer WHERE client_ip=? AND source_id=? '
                                         'ORDER BY hour DESC,seq DESC LIMIT ? OFFSET ?', (PEER, 'web', 20, 0))]
    assert any('SEARCH' in row and 'http_incidents_peer' in row and 'client_ip=?' in row for row in plan)
    assert not any('TEMP B-TREE' in row for row in plan)


def test_unrelated_corrupt_payload_is_not_read(store):
    add_case(store, 'unrelated', peer='192.0.2.4')
    with store.connection(write=True) as db:
        db.execute("UPDATE http_incidents SET payload_json='not json' WHERE incident_id='unrelated'")
    assert store.incidents(ip=PEER)['total'] == 1


@pytest.mark.parametrize('field,value', [('client_ip', '192.0.2.99'), ('source_id', 'other'),
                                        ('service_id', 'other'), ('incident_id', 'wrong'),
                                        ('window_start', '2000-01-01T00:00:00Z'), ('revision', True),
                                        ('active', 1), ('coverage', 'wrong'), ('protocol', 'ssh'),
                                        ('updated_at', '2000-01-01T00:00:00Z')])
def test_selected_payload_mismatch_fails_whole_page(store, field, value):
    add_case(store, 'second')
    with store.connection(write=True) as db:
        row = db.execute("SELECT payload_json FROM http_incidents WHERE incident_id='second'").fetchone()
        payload = json.loads(row[0])
        payload[field] = value
        db.execute("UPDATE http_incidents SET payload_json=? WHERE incident_id='second'", (json.dumps(payload),))
    with pytest.raises(HttpIncidentSearchUnavailable, match='^http_incident_search_unavailable$'):
        store.incidents(ip=PEER)


@pytest.mark.parametrize('raw', ['{', '[]', 'null', json.dumps({'assessment': []}), b'private data'])
def test_malformed_payload_is_safe_failure(store, raw):
    with store.connection(write=True) as db:
        db.execute('UPDATE http_incidents SET payload_json=?', (raw,))
    with pytest.raises(HttpIncidentSearchUnavailable, match='^http_incident_search_unavailable$'):
        store.incidents(ip=PEER)


@pytest.mark.parametrize('constant', ['NaN', 'Infinity', '-Infinity', '1e9999', '-1e9999', r'"\ud800"'])
@pytest.mark.parametrize('location', ['title', 'rules'])
def test_unserializable_json_in_unindexed_fields_is_safe_failure(store, constant, location):
    with store.connection(write=True) as db:
        raw = db.execute('SELECT payload_json FROM http_incidents').fetchone()[0]
        payload = json.loads(raw)
        payload[location] = '__nonfinite__' if location == 'title' else [{'extra': '__nonfinite__'}]
        damaged = json.dumps(payload).replace('"__nonfinite__"', constant)
        db.execute('UPDATE http_incidents SET payload_json=?', (damaged,))
    with pytest.raises(HttpIncidentSearchUnavailable, match='^http_incident_search_unavailable$'):
        store.incidents(ip=PEER)


@pytest.mark.parametrize('bound', ['peer', 'bytes', 'record', 'vm', 'time'])
def test_search_budget_exhaustion_never_returns_partial_result(store, monkeypatch, bound):
    add_case(store, 'second')
    if bound == 'peer':
        monkeypatch.setattr(search, 'MAX_PEER_CASES', 1)
    elif bound == 'bytes':
        monkeypatch.setattr(search, 'MAX_SELECTED_BYTES', 1)
    elif bound == 'record':
        monkeypatch.setattr(search, 'MAX_RECORD_BYTES', 1)
    elif bound == 'vm':
        monkeypatch.setattr(search, 'PROGRESS_INTERVAL', 1)
        monkeypatch.setattr(search, 'MAX_VM_STEPS', 0)
    else:
        monkeypatch.setattr(search, 'MAX_SECONDS', -1)
    with pytest.raises(HttpIncidentSearchUnavailable, match='^http_incident_search_unavailable$'):
        store.incidents(ip=PEER)


def test_hot_peer_remains_bounded_even_for_selective_scope_and_deep_page(store, monkeypatch):
    add_case(store, 'second', source='other')
    monkeypatch.setattr(search, 'MAX_PEER_CASES', 1)
    with pytest.raises(HttpIncidentSearchUnavailable):
        store.incidents(ip=PEER, source_id='web', page=1_000_000, limit=1)


def test_oversized_payload_cannot_allocate_unbounded_result(store):
    with store.connection(write=True) as db:
        db.execute('UPDATE http_incidents SET payload_json=?', ('x' * (search.MAX_RECORD_BYTES * 2),))
    with pytest.raises(HttpIncidentSearchUnavailable):
        store.incidents(ip=PEER)


def test_missing_store_and_missing_index_fail_without_initialization(store):
    with store.connection(write=True) as db:
        db.execute('DROP INDEX http_incidents_peer')
    with pytest.raises(HttpIncidentSearchUnavailable):
        store.incidents(ip=PEER)
    with store.connection() as db:
        assert db.execute("SELECT 1 FROM sqlite_master WHERE name='http_incidents_peer'").fetchone() is None
    Path(store.path).unlink()
    with pytest.raises(HttpIncidentSearchUnavailable):
        store.incidents(ip=PEER)
    assert not Path(store.path).exists()


def test_exclusive_lock_obeys_short_busy_bound(store):
    with closing(sqlite3.connect(store.path, isolation_level=None)) as writer:
        writer.execute('PRAGMA journal_mode=DELETE')
        writer.execute('BEGIN EXCLUSIVE')
        started = time.monotonic()
        with pytest.raises(HttpIncidentSearchUnavailable):
            store.incidents(ip=PEER)
        assert time.monotonic() - started < 2
        writer.rollback()


def test_count_and_page_share_snapshot_while_subsequent_page_can_change(store, monkeypatch):
    original = store.incidents(ip=PEER)
    connect = sqlite3.connect
    changed = []
    def open_read(*args, **kwargs):
        db = connect(*args, **kwargs)
        def trace(statement):
            if statement.startswith('SELECT count(*) FROM http_incidents ') and not changed:
                with closing(connect(store.path, isolation_level=None)) as writer:
                    writer.execute('DELETE FROM http_incidents')
                changed.append(True)
        db.set_trace_callback(trace)
        return db
    monkeypatch.setattr(search.sqlite3, 'connect', open_read)
    assert store.incidents(ip=PEER) == original
    assert changed and store.incidents(ip=PEER)['total'] == 0


def test_filtered_read_is_query_only_and_does_not_touch_receipts_or_evidence(store, monkeypatch):
    with store.connection() as db:
        before = list(db.iterdump())
    connect, statements = sqlite3.connect, []
    def open_read(*args, **kwargs):
        assert kwargs['uri'] and args[0].endswith('?mode=ro')
        db = connect(*args, **kwargs)
        db.set_trace_callback(statements.append)
        return db
    monkeypatch.setattr(search.sqlite3, 'connect', open_read)
    assert store.incidents(ip=PEER)['total'] == 1
    monkeypatch.setattr(search.sqlite3, 'connect', connect)
    with store.connection() as db:
        assert list(db.iterdump()) == before
    assert 'PRAGMA query_only=ON' in statements
    assert all(not value.startswith(('INSERT', 'UPDATE', 'DELETE', 'CREATE', 'ALTER')) for value in statements)
