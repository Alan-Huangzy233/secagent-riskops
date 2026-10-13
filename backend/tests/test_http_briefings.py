"""UTC boundaries, immutable reports, crash windows and bounded HTTP summaries."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json

import pytest

from app.telemetry import http_briefings as briefing, http_incidents as analysis, http_store
from app.telemetry.http_store import HttpBatch, HttpStore
from app.telemetry.http_worker import HttpWorker, publish
from app.telemetry.store import TelemetryStore

DAY = datetime(2026, 1, 2, tzinfo=timezone.utc).timestamp()
NOW = DAY + 86400 + 3600


class Clock(datetime):
    at = DAY + 86399

    @classmethod
    def now(cls, tz=None):
        return datetime.fromtimestamp(cls.at, timezone.utc)


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(http_store, 'datetime', Clock)
    Clock.at = DAY + 86399
    return HttpStore(tmp_path / 'http.sqlite')


def ingest(store, count=20, *, name='first', peer='192.0.2.8', path=None, at=DAY+600, status=404, **kwargs):
    return store.ingest(HttpBatch(source_id='web', service_id='public', batch_id=name,
        collected_at=analysis.stamp(Clock.at), caught_up=kwargs.pop('caught_up', True),
        records=[dict(event_id=f'{name}-{i}', timestamp=analysis.stamp(at+i), client_ip=peer,
                      method='GET', path=path or '/probe/'+str(i), status=status) for i in range(count)], **kwargs))


def analyze(store, at=NOW-1):
    for _ in range(100):
        if analysis.process(store, at)['caught_up']:
            return
    pytest.fail('analysis did not finish')


def finish(store, *, now=NOW, batch_size=1000):
    for _ in range(200):
        if not briefing.advance(store, now, batch_size=batch_size):
            return reports(store)
    pytest.fail('briefing did not finish')


def reports(store):
    with store.connection() as db:
        return [json.loads(r[0]) for r in db.execute("SELECT payload_json FROM http_notice_outbox WHERE topic LIKE '%:briefing:%' ORDER BY topic")]


def test_utc_counts_replay_statuses_and_reported_batches(store):
    ingest(store, reports=['rotation_gap'], caught_up=False)
    ingest(store, reports=['rotation_gap'], caught_up=False)  # same durable batch
    ingest(store, 1, name='low', peer='192.0.2.9', path='/.env', status=200)
    ingest(store, 1, name='before', at=DAY-1)
    Clock.at = NOW
    ingest(store, 1, name='after', at=DAY+86400)
    analyze(store)
    report, = finish(store, batch_size=7)
    c = report['counts']
    assert c['requests'] == 21 and c['status_classes'] == {'2xx': 1, '4xx': 20}
    assert (c['cases'], c['attention'], c['low'], c['stale'], c['retracted']) == (2, 1, 1, 0, 0)
    assert c['rules'] == {'http_multi_path_scan': 1, 'http_sensitive_resource': 1}
    assert (c['batches'], c['reported_batches'], c['backlog_batches']) == (3, 1, 1)
    assert c['reports'] == {'rotation_gap': 1}
    assert '192.0.2.8' not in json.dumps(report) and '/probe/' not in json.dumps(report)
    assert not report['analysis_pending']


def test_restart_excludes_late_requests_cases_and_later_retraction(store):
    ingest(store)
    analyze(store)
    assert briefing.advance(store, NOW, batch_size=3)
    Clock.at = NOW+10
    ingest(store, 10, name='late-benign', path='/home', status=200)
    ingest(store, 1, name='late-case', peer='192.0.2.10', path='/.env')
    analyze(store, NOW+11)
    restarted = HttpStore(store.path)
    report, = finish(restarted, now=NOW+12, batch_size=3)
    assert report['counts']['requests'] == 20
    assert report['counts']['cases'] == report['counts']['attention'] == 1
    assert report['counts']['retracted'] == 0
    assert report['cutoff'] == NOW
    assert report == finish(restarted, now=NOW+30)[0]


def test_retracted_and_incomplete_cases_are_not_presented_as_low_risk(store, monkeypatch):
    ingest(store)
    analyze(store)
    ingest(store, 10, name='benign', path='/home', status=200)
    analyze(store)
    ingest(store, 20, name='stale', peer='192.0.2.9')
    analyze(store)
    monkeypatch.setattr(analysis, 'MAX_CONTEXT_RECORDS', 10)
    ingest(store, 1, name='overflow', peer='192.0.2.9')
    analyze(store)
    report, = finish(store)
    assert report['counts']['retracted'] == 1
    assert report['counts']['stale'] == 1
    assert report['counts']['attention'] == report['counts']['low'] == 0


def test_analysis_backlog_is_disclosed_even_when_no_case_exists(store):
    ingest(store)
    report, = finish(store)
    assert report['analysis_pending'] and report['counts']['cases'] == 0
    assert report['counts']['requests'] == 20


def test_retention_loss_and_skipped_days_are_disclosed(store):
    with store.connection(write=True) as db:
        analysis.set_meta(db, 'briefing_date', '2025-01-01')
        analysis.set_meta(db, 'missing_raw_records', 17)
    store.retention_days = 2
    report, = finish(store)
    assert report['skipped_days'] > 300
    assert report['missing_raw_records_total'] == 17
    assert '保留清理' in report['note']


def test_disabled_worker_does_not_generate_or_import_briefings(store, tmp_path):
    console = TelemetryStore(tmp_path/'ssh.sqlite')
    worker = HttpWorker(store, console, notify=False)
    worker.tick(NOW)
    assert reports(store) == []
    assert store.analysis_status()['briefing_in_progress'] is None


def test_failed_briefing_does_not_block_urgent_delivery_and_recovers(store, tmp_path, monkeypatch):
    ingest(store)
    console = TelemetryStore(tmp_path/'ssh.sqlite')
    worker = HttpWorker(store, console)
    real = briefing.advance
    def fail(*args, **kwargs):
        raise RuntimeError('private failure details')
    monkeypatch.setattr(briefing, 'advance', fail)
    worker.tick(NOW)
    with console._connection() as db:
        assert db.execute("SELECT count(*) FROM notification_outbox WHERE kind='http_incident'").fetchone()[0] == 1
    assert store.analysis_status()['briefing_error'] == 'HTTP 简报汇总暂时失败，将自动重试'
    monkeypatch.setattr(briefing, 'advance', real)
    for _ in range(5):
        worker.tick(NOW)
    assert store.analysis_status()['briefing_error'] is None
    assert len(reports(store)) == 1


def test_crash_after_console_commit_and_multiple_workers_deliver_one_report(store, tmp_path):
    ingest(store, 1, path='/home', status=200)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: finish(HttpStore(store.path), batch_size=1), range(2)))
    assert len(reports(store)) == 1
    console = TelemetryStore(tmp_path/'ssh.sqlite')
    def crash():
        raise RuntimeError('simulated restart')
    with pytest.raises(RuntimeError):
        publish(store, console, NOW, after_import=crash)
    publish(HttpStore(store.path), console, NOW+1)
    console.run_notifications([], now=NOW+1)
    publish(store, console, NOW+2)
    console.run_notifications([], now=NOW+2)
    rows = [r for r in console.list_notifications(kind='briefing')['items'] if r['payload'].get('protocol') == 'http']
    assert len(rows) == 1 and rows[0]['payload'] == reports(store)[0]


def test_empty_day_and_multi_day_catchup_are_separate_immutable_reports(store):
    assert finish(store)[0]['counts']['requests'] == 0
    result = finish(store, now=NOW+2*86400)
    assert [r['date'] for r in result] == ['2026-01-02', '2026-01-03', '2026-01-04']
    assert result[0]['generated_at'] == NOW


def test_failed_page_never_advances_or_publishes_partial_report(store, monkeypatch):
    ingest(store)
    assert briefing.advance(store, NOW, batch_size=2)
    with store.connection() as db:
        before = analysis.meta(db, 'briefing_work')
    def fail(db, work, limit):
        work['counts']['requests'] += 12345
        raise RuntimeError('read failed')
    monkeypatch.setattr(briefing, '_page', fail)
    with pytest.raises(RuntimeError):
        briefing.advance(store, NOW)
    with store.connection() as db:
        assert analysis.meta(db, 'briefing_work') == before
    assert reports(store) == []


def test_sql_queries_use_time_and_receipt_indexes(store):
    with store.connection() as db:
        cases = [
            ('SELECT seq FROM http_events WHERE event_ts>=? AND event_ts<? AND (event_ts,seq)>(?,?) AND seq<=? ORDER BY event_ts,seq LIMIT ?', (DAY, DAY+86400, DAY, 0, 100, 10), 'http_events_expiry'),
            ("SELECT seq FROM http_batches WHERE substr(received_at,1,10)=? AND seq>? AND seq<=? ORDER BY seq LIMIT ?", ('2026-01-02', 0, 100, 10), 'http_batches_day'),
            ('SELECT seq FROM http_incidents WHERE hour>=? AND hour<? AND (hour,seq)>(?,?) AND seq<=? ORDER BY hour,seq LIMIT ?', (DAY, DAY+86400, DAY, 0, 100, 10), 'http_incidents_page')]
        for sql, args, index in cases:
            plan = ' '.join(r[3] for r in db.execute('EXPLAIN QUERY PLAN '+sql, args))
            assert index in plan and 'TEMP B-TREE' not in plan


def test_context_limit_without_a_case_remains_visible_in_briefing(store, monkeypatch):
    monkeypatch.setattr(analysis, 'MAX_CONTEXT_RECORDS', 10)
    ingest(store)
    analyze(store)
    report, = finish(store)
    assert report['counts']['cases'] == 0
    assert report['incomplete_windows'] == 1
    assert not report['incomplete_windows_capped']


def test_rejected_records_are_counted_once_from_receipts(store):
    kwargs = {'rejected': [{'event_id': 'bad-record', 'code': 'invalid_record'}]}
    ingest(store, 0, **kwargs)
    ingest(store, 0, **kwargs)
    ingest(store, 0, name='duplicate-event', **kwargs)
    report, = finish(store)
    assert report['counts']['rejected'] == 1
    assert report['counts']['batches'] == 2


def test_long_aggregation_does_not_hold_a_write_lock(store, monkeypatch):
    ingest(store)
    page = briefing._page
    def read_with_concurrent_ingest(db, work, limit):
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert pool.submit(ingest, store, 1, name='concurrent').result(timeout=3)['accepted'] == 1
        page(db, work, limit)
    monkeypatch.setattr(briefing, '_page', read_with_concurrent_ingest)
    assert briefing.advance(store, NOW, batch_size=3)
    with store.connection() as db:
        assert analysis.meta(db, 'briefing_work')['counts']['requests'] == 3
