"""Persistent HTTP correlation: late data, retention, bounded work and crash recovery."""
import time

import pytest
from fastapi.testclient import TestClient

from app.live_api import create_app
from app.telemetry import http_incidents as analysis
from app.telemetry.http_store import HttpBatch, HttpStore
from app.telemetry.http_worker import publish
from app.telemetry.store import TelemetryStore
from test_http_ingest import config as config, password_hash as password_hash, post, read

NOW = time.time()
HOUR = int(NOW // 3600) * 3600 - 7200
BASE = HOUR + 600


def record(index, *, path=None, offset=0, status=404, peer='198.51.100.23'):
    return dict(event_id=str(index), timestamp=analysis.stamp(BASE + offset), client_ip=peer,
                method='GET', path=path or '/probe/' + str(index), status=status)


def scan(count=20, **kwargs):
    return [record(i, offset=i, **kwargs) for i in range(count)]


def ingest(store, rows, batch='b1', source='web', service='public'):
    body = HttpBatch(source_id=source, service_id=service, batch_id=batch, records=rows,
                     caught_up=True, collected_at=analysis.stamp(NOW))
    return store.ingest(body)


def drain(store, now=NOW, **kwargs):
    for _ in range(100):
        result = analysis.process(store, now, **kwargs)
        if result['caught_up']:
            return
    pytest.fail('HTTP analysis did not drain within its bounded ticks')


@pytest.fixture
def store(tmp_path):
    return HttpStore(tmp_path / 'http.sqlite')


def test_multi_batch_scan_restart_and_retries_are_idempotent(store):
    ingest(store, scan(19))
    drain(store)
    assert store.incidents()['total'] == 0
    ack = ingest(store, [record(19, offset=19)], 'last')
    drain(store)
    case = store.incidents()['items'][0]
    assert case['assessment']['score'] == 30 and case['evidence_count'] == 20
    restarted = HttpStore(store.path)
    assert ingest(restarted, [record(19, offset=19)], 'last') == ack
    assert ingest(restarted, scan(), 'redelivered')['duplicates'] == 20
    drain(restarted)
    assert restarted.incident(case['incident_id']) == case
    assert restarted.analysis_status()['analyzed_input_records'] == 20
    assert restarted.evidence(case['incident_id'])['total'] == 20


def test_late_benign_context_retracts_scan_but_preserves_historical_evidence(store):
    ingest(store, scan())
    drain(store)
    original = store.incidents()['items'][0]
    # These arrive later but occurred interspersed with the original requests.
    ingest(store, [record('benign'+str(i), offset=i+0.5, status=200, path='/home') for i in range(10)], 'late')
    drain(store)
    current = store.incident(original['incident_id'])
    assert current['revision'] == 2 and not current['active']
    assert current['assessment']['score'] == 0 and current['evidence_count'] == 0
    assert store.incident(original['incident_id'], 1) == original
    assert store.evidence(original['incident_id'], revision=1, limit=7)['total'] == 20
    assert store.evidence(original['incident_id'], revision=2)['items'] == []
    assert store.incidents(focus='attention')['total'] == 0
    assert store.incidents(focus='retracted')['total'] == 1


def test_arrival_order_has_same_final_detection_and_evidence(tmp_path):
    rows = scan() + [record('benign', offset=9.5, status=200)]
    cases = []
    for index, ordered in enumerate([rows, list(reversed(rows))]):
        store = HttpStore(tmp_path / f'{index}.sqlite')
        for chunk in range(0, len(ordered), 7):
            ingest(store, ordered[chunk:chunk+7], str(chunk))
            drain(store)
        case = store.incidents()['items'][0]
        cases.append((case['incident_id'], case['assessment'], case['evidence_sha256']))
    assert cases[0] == cases[1]


def test_stream_and_peer_isolation_with_shared_event_ids(store):
    ingest(store, scan(10), 'a')
    ingest(store, scan(10), 'b', service='private')
    ingest(store, scan(10), 'c', source='other')
    ingest(store, [record('other'+str(i), offset=i, peer='192.0.2.4') for i in range(10)], 'd')
    drain(store)
    assert store.incidents()['total'] == 0
    ingest(store, [record(i, offset=i) for i in range(10, 20)], 'e')
    drain(store)
    assert store.incidents()['total'] == 1
    case = store.incidents()['items'][0]
    assert (case['source_id'], case['service_id'], case['client_ip']) == ('web', 'public', '198.51.100.23')


def test_cross_hour_scan_uses_context_and_documents_shared_evidence(store):
    ingest(store, [record(i, offset=2990+i) for i in range(20)])
    drain(store)
    cases = store.incidents()['items']
    assert len(cases) == 2
    assert len({case['window_start'] for case in cases}) == 2
    assert all(case['evidence_count'] == 20 and case['assessment']['score'] == 30 for case in cases)
    assert len({case['evidence_sha256'] for case in cases}) == 1


def test_rules_count_once_and_status_200_never_proves_compromise(store):
    ingest(store, scan() + [record('sensitive', path='/.env', status=200),
                           record('traversal', path='/../etc/passwd', status=200)])
    drain(store)
    case = store.incidents()['items'][0]
    assert case['assessment']['score'] == 90 and case['assessment']['priority'] == 'P2'
    assert len(case['assessment']['reasons']) == 3
    assert '不能证明' in case['assessment']['note']
    ingest(store, [record('another', path='/.env', status=200)], 'more')
    drain(store)
    assert store.incidents()['items'][0]['assessment']['score'] == 90


@pytest.mark.parametrize('bound', ['records', 'bytes'])
def test_incomplete_context_keeps_previous_verifiable_result(store, monkeypatch, bound):
    ingest(store, scan())
    drain(store)
    old = store.incidents()['items'][0]
    monkeypatch.setattr(analysis, 'MAX_CONTEXT_RECORDS' if bound == 'records' else 'MAX_CONTEXT_BYTES', 10)
    ingest(store, [record('later', path='/home', status=200)], 'late')
    drain(store)
    case = store.incident(old['incident_id'])
    assert case['stale'] and case['coverage'] == 'context_limit'
    assert case['assessment'] == old['assessment'] and case['evidence_sha256'] == old['evidence_sha256']
    assert store.evidence(old['incident_id'])['total'] == 20
    assert store.analysis_status()['coverage_issues'][0]['coverage'] == 'context_limit'
    with store.connection() as db:
        assert db.execute('SELECT cancelled FROM http_notice_outbox').fetchone()[0] == 1


def test_truncated_context_is_never_scored_as_a_complete_sample(store, monkeypatch):
    monkeypatch.setattr(analysis, 'MAX_CONTEXT_RECORDS', 20)
    ingest(store, scan() + [record('benign', path='/home', status=200)])
    drain(store)
    assert store.incidents()['total'] == 0
    assert store.analysis_status()['coverage_issues']


def test_retention_preserves_evidence_and_replay_receipt(store):
    rows = scan()
    ack = ingest(store, rows)
    drain(store)
    original = store.incidents()['items'][0]
    future = NOW + 15*86400
    drain(store, now=future)
    with store.connection(write=True) as db:
        db.execute('DELETE FROM http_events')
    assert ingest(store, rows) == ack
    ingest(store, [record('late')], 'late')
    drain(store, now=future)
    case = store.incident(original['incident_id'])
    assert case['coverage'] == 'expired_context' and case['stale']
    assert store.evidence(case['incident_id'], revision=1)['total'] == 20
    assert store.evidence(case['incident_id'])['total'] == 20


def test_intake_is_bounded_and_raw_expiry_is_visible(store):
    ingest(store, scan())
    with store.connection(write=True) as db:
        db.execute('DELETE FROM http_events WHERE seq<=2')
    result = analysis.process(store, NOW, intake_limit=3, window_limit=1)
    assert not result['caught_up']
    status = store.analysis_status()
    assert status['analyzed_input_records'] == 3 and status['missing_raw_records'] == 2 and status['pending']
    drain(store, intake_limit=3, window_limit=1)
    assert not store.analysis_status()['pending']


def test_window_commit_failure_rolls_back_revision_evidence_and_outbox(store, monkeypatch):
    ingest(store, scan())
    save = analysis._save_case
    def crash(*args):
        save(*args)
        raise RuntimeError('simulated process loss')
    monkeypatch.setattr(analysis, '_save_case', crash)
    with pytest.raises(RuntimeError):
        analysis.process(store, NOW)
    assert store.incidents()['total'] == 0 and store.analysis_status()['pending']
    with store.connection() as db:
        for table in ('http_incident_revisions', 'http_evidence', 'http_notice_outbox'):
            assert db.execute('SELECT count(*) FROM '+table).fetchone()[0] == 0
    monkeypatch.setattr(analysis, '_save_case', save)
    drain(HttpStore(store.path))
    assert store.incidents()['items'][0]['revision'] == 1


def test_notification_bridge_retries_after_destination_commit_without_duplicates(store, tmp_path):
    console = TelemetryStore(tmp_path / 'console.sqlite')
    ingest(store, scan())
    drain(store)
    def crash():
        raise RuntimeError('simulated crash after console commit')
    with pytest.raises(RuntimeError):
        publish(store, console, NOW, after_import=crash)
    assert publish(store, console, NOW) == 1
    assert publish(store, console, NOW) == 0
    console.run_notifications([], now=NOW)
    console.run_notifications([], now=NOW+1)
    inbox = console.list_notifications(kind='http_incident')
    assert inbox['total'] == 1 and inbox['items'][0]['payload']['revision'] == 1
    assert console.list_events() == []


def test_bridge_revision_race_and_cancellation_leave_delivered_history(store, tmp_path):
    console = TelemetryStore(tmp_path / 'console.sqlite')
    ingest(store, scan())
    drain(store)
    def new_revision():
        ingest(store, [record('sensitive', path='/.env')], 'new')
        drain(store)
    publish(store, console, NOW, after_import=new_revision)
    # ACK of revision 1 must not erase revision 2 created concurrently.
    assert publish(store, console, NOW) == 1
    console.run_notifications([], now=NOW)
    inbox = console.list_notifications(kind='http_incident')
    assert inbox['total'] == 1 and inbox['items'][0]['payload']['revision'] == 2
    ingest(store, [record('benign'+str(i), offset=i+0.5, status=200, path='/home') for i in range(10)], 'late')
    drain(store)
    publish(store, console, NOW+1)
    console.run_notifications([], now=NOW+4000)
    assert console.list_notifications(kind='http_incident')['total'] == 1
    assert store.incidents()['items'][0]['assessment']['score'] == 25


def test_cancel_before_delivery_removes_pending_only(store, tmp_path):
    console = TelemetryStore(tmp_path / 'console.sqlite')
    ingest(store, scan())
    drain(store)
    publish(store, console, NOW)
    ingest(store, [record('benign'+str(i), offset=i+0.5, status=200) for i in range(10)], 'late')
    drain(store)
    publish(store, console, NOW+1)
    console.run_notifications([], now=NOW+2)
    assert console.list_notifications(kind='http_incident')['total'] == 0


def test_api_auth_pagination_and_historical_revision(config):
    with TestClient(create_app(config)) as client:
        client.app.state.http_worker.close()
        assert client.get('/api/http/status').status_code == 401
        assert read(client, 'status').json()['enabled']
        body = dict(source_id='web', service_id='public', batch_id='scan', records=scan(), caught_up=True,
                    collected_at=analysis.stamp(NOW))
        assert post(client, body).json()['durable']
        client.app.state.http_worker.tick(NOW)
        case = read(client, 'incidents').json()['items'][0]
        identity = case['incident_id']
        assert read(client, 'incidents', focus='low').json()['total'] == 0
        assert read(client, 'incidents', page=100, limit=1).json()['page'] == 1
        assert read(client, 'incidents', source_id='unknown').status_code == 404
        assert read(client, 'incidents/'+identity, revision=1).json() == case
        page = read(client, 'incidents/'+identity+'/evidence', revision=1, limit=7, page=2).json()
        assert page['total_pages'] == 3 and len(page['items']) == 7 and page['revision'] == 1
        assert read(client, 'incidents/'+identity, revision=2).status_code == 404
        assert read(client, 'incidents/'+identity, revision=2**64).status_code == 422
        assert read(client, 'incidents/'+identity+'/evidence', limit=201).status_code == 422
        assert client.app.state.store.list_events() == []
        assert not client.app.state.ai.enabled and not client.app.state.control.enabled
    disabled = config.model_copy(update={'http_ingest': None})
    with TestClient(create_app(disabled)) as client:
        assert read(client, 'status').json() == {'enabled': False}
        assert read(client, 'incidents').status_code == 404
