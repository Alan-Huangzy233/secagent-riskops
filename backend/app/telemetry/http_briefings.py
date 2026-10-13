"""Restartable UTC HTTP reports, delivered through the durable console bridge.

Raw records use an ingestion sequence fence; cases use preserved revisions at
that cutoff. No request paths, peers or external/model calls enter a report.
"""
from datetime import datetime, timedelta, timezone
import json
import time

from . import http_incidents as analysis

STAGES = ('requests', 'cases', 'batches')


def initialize(db):
    # Receipt time is generated locally in UTC, independent of the log clock.
    db.execute('CREATE INDEX IF NOT EXISTS http_batches_day ON http_batches(substr(received_at,1,10),seq)')


def status(db):
    work = analysis.meta(db, 'briefing_work')
    return {'briefing_in_progress': work['date'] if work else None,
            'briefing_last_date': analysis.meta(db, 'briefing_date'),
            'briefing_error': analysis.meta(db, 'briefing_error')}


def _start(db, store, now, last):
    today = datetime.fromtimestamp(now, timezone.utc).date()
    day = datetime.fromisoformat(last).date() + timedelta(days=1) if last else today - timedelta(days=1)
    earliest = today - timedelta(days=max(1, store.retention_days - 1))
    skipped = max(0, (earliest - day).days)
    day = max(day, earliest)
    if day >= today:
        return None
    fences = {key: db.execute(f'SELECT coalesce(max(seq),0) FROM {table}').fetchone()[0]
              for key, table in [('requests', 'http_events'), ('cases', 'http_incidents'), ('batches', 'http_batches')]}
    pending = (analysis.meta(db, 'cursor', 0) < fences['requests'] or
               db.execute('SELECT 1 FROM http_windows WHERE dirty=1 LIMIT 1').fetchone() is not None)
    incomplete = db.execute("SELECT 1 FROM http_windows WHERE coverage IN ('context_limit','expired_context') LIMIT 51").fetchall()
    return {'incomplete_windows': min(50, len(incomplete)), 'incomplete_windows_capped': len(incomplete) > 50,
            'date': day.isoformat(), 'cutoff': now, 'fences': fences, 'stage': 'requests', 'cursor': None,
            'skipped_days': skipped, 'analysis_pending': pending,
            'missing_raw_records_total': analysis.meta(db, 'missing_raw_records', 0),
            'counts': {'requests': 0, 'status_classes': {}, 'cases': 0, 'attention': 0, 'low': 0,
                       'retracted': 0, 'stale': 0, 'rules': {}, 'batches': 0, 'rejected': 0,
                       'reported_batches': 0, 'backlog_batches': 0, 'reports': {}}}


def _increment(counts, key):
    counts[key] = counts.get(key, 0) + 1


def _page(db, work, batch_size):
    start = datetime.fromisoformat(work['date']).replace(tzinfo=timezone.utc).timestamp()
    end = start + 86400
    stage, cursor, counts = work['stage'], work['cursor'], work['counts']
    fence = work['fences'][stage]
    if stage == 'requests':
        after = cursor or [start, 0]
        rows = db.execute('SELECT event_ts,seq,record_json FROM http_events WHERE event_ts>=? AND event_ts<? '
                          'AND (event_ts,seq)>(?,?) AND seq<=? ORDER BY event_ts,seq LIMIT ?',
                          (start, end, *after, fence, batch_size)).fetchall()
        for row in rows:
            counts['requests'] += 1
            _increment(counts['status_classes'], str(json.loads(row['record_json'])['status'] // 100) + 'xx')
        if rows:
            work['cursor'] = list(rows[-1][:2])
    elif stage == 'cases':
        batch_size = min(batch_size, 100)
        after = cursor or [int(start), 0]
        rows = db.execute('SELECT hour,seq,incident_id FROM http_incidents WHERE hour>=? AND hour<? '
                          'AND (hour,seq)>(?,?) AND seq<=? ORDER BY hour,seq LIMIT ?',
                          (start, end, *after, fence, batch_size)).fetchall()
        cutoff = datetime.fromtimestamp(work['cutoff'], timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')
        for row in rows:
            # Normalize whole-second ISO values before comparison; all revisions
            # are generated locally in UTC. The PK visits latest versions first.
            revision = db.execute("""SELECT payload_json FROM http_incident_revisions WHERE incident_id=?
                AND (CASE WHEN length(json_extract(payload_json,'$.updated_at'))=20
                    THEN substr(json_extract(payload_json,'$.updated_at'),1,19)||'.000000Z'
                    ELSE json_extract(payload_json,'$.updated_at') END)<=?
                ORDER BY revision DESC LIMIT 1""", (row['incident_id'], cutoff)).fetchone()
            if revision is None:
                continue
            case = json.loads(revision[0])
            counts['cases'] += 1
            bucket = ('stale' if case['stale'] else 'retracted' if not case['active'] else
                      'attention' if case['assessment']['surfaced'] else 'low')
            counts[bucket] += 1
            if bucket in ('attention', 'low'):
                for rule in case['rules']:
                    _increment(counts['rules'], rule['rule_id'])
        if rows:
            work['cursor'] = list(rows[-1][:2])
    else:
        rows = db.execute('SELECT seq,response_json FROM http_batches WHERE substr(received_at,1,10)=? '
                          'AND seq>? AND seq<=? ORDER BY seq LIMIT ?',
                          (work['date'], cursor or 0, fence, batch_size)).fetchall()
        for row in rows:
            batch = json.loads(row['response_json'])
            counts['batches'] += 1
            counts['rejected'] += batch['rejected']
            counts['reported_batches'] += bool(batch['reports'])
            counts['backlog_batches'] += not batch['caught_up']
            for code in set(batch['reports']):
                _increment(counts['reports'], code)
        if rows:
            work['cursor'] = rows[-1]['seq']
    if len(rows) < batch_size:
        index = STAGES.index(stage) + 1
        work['stage'] = STAGES[index] if index < len(STAGES) else 'complete'
        work['cursor'] = None


def advance(store, now, *, batch_size=1000):
    """One bounded page per tick, no write lock during aggregation.

    COMMIT of the checkpoint and final outbox entry is atomic. Concurrent
    workers compare the old checkpoint before applying their page once.
    """
    if type(batch_size) is not int or not 1 <= batch_size <= 1000:
        raise ValueError('Invalid HTTP briefing page size')
    with store.connection() as db:
        db.execute('BEGIN')
        old = analysis.meta(db, 'briefing_work')
        last = analysis.meta(db, 'briefing_date')
        work = json.loads(json.dumps(old)) if old else _start(db, store, now, last)
        if work is None:
            return False
        deadline = time.monotonic() + 5
        db.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
        _page(db, work, batch_size)
    with store.connection(write=True) as db:
        if analysis.meta(db, 'briefing_work') != old or analysis.meta(db, 'briefing_date') != last:
            return True
        analysis.set_meta(db, 'briefing_error', None)
        if work['stage'] != 'complete':
            analysis.set_meta(db, 'briefing_work', work)
            return True
        payload = {k: work[k] for k in ('date', 'cutoff', 'skipped_days', 'analysis_pending', 'missing_raw_records_total',
                                               'incomplete_windows', 'incomplete_windows_capped', 'counts')}
        payload.update(protocol='http', report_type='http_daily',
                       title=work['date'] + ' HTTP 每日简报（UTC）', generated_at=now,
                       note='请求按发生时间、事件按 UTC 小时窗口、采集批次按接收日统计。仅含汇总开始前已入库的数据和当时的事件版本；迟到数据、保留清理及检测积压可能影响完整性。批次报告次数不代表独立缺口；规则命中与响应码不代表入侵成功。')
        topic = 'http:' + analysis.meta(db, 'producer_id') + ':briefing:' + work['date']
        db.execute('INSERT OR IGNORE INTO http_notice_outbox VALUES(?,1,0,?,1)', (topic, analysis.canonical(payload)))
        analysis.set_meta(db, 'briefing_date', work['date'])
        analysis.set_meta(db, 'briefing_work', None)
    # Catch up another completed day without delaying urgent analysis/delivery.
    return datetime.fromisoformat(work['date']).date() + timedelta(days=1) < datetime.fromtimestamp(now, timezone.utc).date()
