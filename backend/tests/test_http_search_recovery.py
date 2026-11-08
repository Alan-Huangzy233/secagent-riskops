"""Additive peer indexing preserves legacy HTTP data and paired recovery."""
from contextlib import closing
import sqlite3

from app.telemetry.http_store import HttpStore
from app.telemetry.http_worker import publish
from test_http_incident_search import PEER, add_case
from test_http_incidents import HOUR, NOW, drain, ingest, scan
from test_http_recovery import deployment as deployment
from test_recovery_package import build, recovery, verify


def database_contents(store):
    with store.connection() as db:
        names = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        return {name: [tuple(row) for row in db.execute('SELECT * FROM ' + name + ' ORDER BY rowid')]
                for name in names}


def test_pre_index_database_initializes_idempotently_without_data_changes(tmp_path):
    store = HttpStore(tmp_path / 'legacy.sqlite')
    ack = ingest(store, scan())
    drain(store)
    case = store.incidents()['items'][0]
    evidence = store.evidence(case['incident_id'])
    with store.connection(write=True) as db:
        db.execute('DROP INDEX http_incidents_peer')
    before = database_contents(store)
    for _ in range(2):
        store = HttpStore(store.path)
        assert database_contents(store) == before
        with store.connection() as db:
            rows = db.execute("PRAGMA index_xinfo('http_incidents_peer')").fetchall()
            assert [(row['name'], row['desc']) for row in rows if row['key']] == [
                ('client_ip', 0), ('hour', 1), ('seq', 1)]
        assert store.incidents(ip=PEER)['items'] == [case]
        assert store.evidence(case['incident_id']) == evidence
    assert ingest(store, scan()) == ack


def test_paired_snapshot_restore_preserves_exact_order_and_original_evidence(deployment, tmp_path):
    store, console = deployment['http'], deployment['console']
    ack = ingest(store, scan())
    drain(store)
    original = store.incidents()['items'][0]
    add_case(store, 'same-hour')
    add_case(store, 'newest', hour=HOUR + 3600)
    add_case(store, 'other-peer', peer='192.0.2.4')
    publish(store, console, NOW)
    expected = [store.incidents(ip=PEER, page=page, limit=1) for page in (1, 2, 3)]
    evidence = store.evidence(original['incident_id'])
    with store.connection(write=True) as db:
        # A legacy package has the same rows but no optional search index.
        db.execute('DROP INDEX http_incidents_peer')
    before = database_contents(store)
    package = build(deployment, '--allow-unencrypted')
    restored = tmp_path / 'restored'
    verify(package['package'], '--into', str(restored))
    saved = HttpStore(restored / 'http.sqlite')
    assert database_contents(saved) == before
    assert [saved.incidents(ip=PEER, page=page, limit=1) for page in (1, 2, 3)] == expected
    assert saved.evidence(original['incident_id']) == evidence
    assert saved.incident(original['incident_id'], 1) == original
    assert ingest(saved, scan()) == ack
    with saved.connection() as http, closing(sqlite3.connect(restored / 'telemetry.sqlite')) as shared:
        assert recovery.check_http_pair(http, shared)['imported_topics'] == 1
