"""Crashes, retry, rejected lines, resource bounds and log rotation."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import time

import pytest

MODULE = Path(__file__).resolve().parents[2] / 'scripts' / 'http_collector.py'
sys.path.insert(0, str(MODULE.parent))
SPEC = importlib.util.spec_from_file_location('http_collector', MODULE)
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)
sys.path.pop(0)


def line(path='/.env', **updates):
    return json.dumps(dict(timestamp='2026-01-05T00:00:00Z', client_ip='198.51.100.23',
                           method='GET', path=path, status=404) | updates).encode()+b'\n'


@pytest.fixture
def config(tmp_path):
    path = tmp_path / 'access.jsonl'
    path.write_bytes(line())
    config = dict(endpoint='http://127.0.0.1:8088/api/http/batches', state_dir=str(tmp_path / 'state'),
                  streams=[dict(source_id='web', service_id='public', path=str(path), rotated_path=str(path)+'.1',
                                token='synthetic-http-test-token-12345678901234567890')])
    config_path = tmp_path / 'config.json'
    config_path.write_text(json.dumps(config))
    return collector.load_config(config_path)


def ack(endpoint, token, body, timeout):
    return {k: body[k] for k in ('source_id', 'service_id', 'batch_id')} | {'durable': True}


def capture(sent):
    def send(endpoint, token, body, timeout):
        sent.append(body)
        return ack(endpoint, token, body, timeout)
    return send


def files(config, pattern):
    return list(Path(config['state_dir']).glob(pattern))


def test_retry_and_crash_after_ack_preserve_identical_batch(config, monkeypatch):
    sent = []
    original = collector.atomic_write
    def fail_commit(path, value):
        if path.name.endswith('.state.json'):
            raise OSError('simulated failure')
        original(path, value)
    monkeypatch.setattr(collector, 'atomic_write', fail_commit)
    assert collector.run_once(config, capture(sent))[0]['code'] == 'local_storage_failed'
    pending, = files(config, '*.pending.json')
    assert config['streams'][0]['token'] not in pending.read_text()
    assert not files(config, '*.state.json')
    # Retry uses the saved data even after the input has disappeared.
    Path(config['streams'][0]['path']).unlink()
    monkeypatch.setattr(collector, 'atomic_write', original)
    assert collector.run_once(config, capture(sent))[0]['records'] == 1
    assert sent[0] == sent[1] and not files(config, '*.pending.json')
    assert files(config, '*.state.json')[0].stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('response', [{}, {'durable': True}, {'durable': False}, []])
def test_invalid_ack_never_advances(config, response):
    assert collector.run_once(config, lambda *args: response)[0]['code'] == 'invalid_ack'
    assert not files(config, '*.state.json') and files(config, '*.pending.json')


def test_append_preserves_occurrences_and_strips_query_before_spool(config):
    path = Path(config['streams'][0]['path'])
    path.write_bytes(line('/.env?key=PRIVATE')*2)
    sent = []
    collector.run_once(config, capture(sent))
    first = sent[0]['records']
    assert len(first) == 2 and first[0]['event_id'] != first[1]['event_id']
    with path.open('ab') as out:
        out.write(line('/.git/config'))
    collector.run_once(config, capture(sent))
    assert len(sent[1]['records']) == 1 and sent[1]['records'][0]['event_id'] not in {r['event_id'] for r in first}
    assert 'PRIVATE' not in json.dumps(sent)


def test_rotation_drains_old_before_new_and_keeps_generation(config):
    config['max_pages_per_run'] = 1
    config['rotation_quiet_seconds'] = 1
    path = Path(config['streams'][0]['path'])
    sent = []
    collector.run_once(config, capture(sent))
    with path.open('ab') as out:
        out.write(line('/old-tail'))
    path.rename(config['streams'][0]['rotated_path'])
    old = Path(config['streams'][0]['rotated_path'])
    os.utime(old, (time.time()-10, time.time()-10))
    path.write_bytes(line('/new-file'))
    result = collector.run_once(config, capture(sent))[0]
    assert result['records'] == 1 and not result['caught_up']
    assert sent[1]['records'][0]['path'] == '/old-tail'
    assert sent[0]['records'][0]['event_id'].split(':')[0] == sent[1]['records'][0]['event_id'].split(':')[0]
    collector.run_once(config, capture(sent))
    assert sent[2]['records'][0]['path'] == '/new-file'
    assert sent[2]['records'][0]['event_id'].split(':')[0] != sent[1]['records'][0]['event_id'].split(':')[0]


def test_recent_rotation_waits_for_writer_and_missing_rotation_reports_gap(config):
    path = Path(config['streams'][0]['path'])
    sent = []
    collector.run_once(config, capture(sent))
    path.rename(config['streams'][0]['rotated_path'])
    path.write_bytes(line('/new'))
    result = collector.run_once(config, capture(sent))[0]
    assert 'rotation_wait' in result['reports'] and not result['caught_up']
    Path(config['streams'][0]['rotated_path']).unlink()
    result = collector.run_once(config, capture(sent))[0]
    assert 'rotation_gap' in result['reports'] and sent[-1]['records'][0]['path'] == '/new'


def test_copytruncate_with_regrowth_uses_new_generation_and_reports_gap(config):
    path = Path(config['streams'][0]['path'])
    sent = []
    collector.run_once(config, capture(sent))
    path.write_bytes(line('/regrown-longer-path')*2)
    result = collector.run_once(config, capture(sent))[0]
    assert 'file_truncated' in result['reports'] and result['records'] == 2
    assert sent[0]['records'][0]['event_id'] != sent[1]['records'][0]['event_id']


def test_invalid_lines_are_counted_without_private_bytes_partial_tail_waits(config):
    path = Path(config['streams'][0]['path'])
    path.write_bytes(line() + b'{"PRIVATE":\n' + line('/', x_forwarded_for='PRIVATE') + b'{"partial":')
    sent = []
    result = collector.run_once(config, capture(sent))[0]
    assert result['records'] == 1 and result['rejected'] == 2 and 'partial_line' in result['reports']
    assert 'PRIVATE' not in json.dumps(sent)
    old = json.loads(files(config, '*.state.json')[0].read_text())['cursor']['offset']
    assert path.read_bytes()[old:] == b'{"partial":'
    with path.open('ab') as out:
        out.write(b'42}\n' + line('/next'))
    result = collector.run_once(config, capture(sent))[0]
    assert result['records'] == 1 and result['rejected'] == 1


def test_overlong_line_stalls_without_unbounded_read_or_silent_skip(config, monkeypatch):
    path = Path(config['streams'][0]['path'])
    path.write_bytes(b'x'*1000+b'\n')
    monkeypatch.setattr(collector, 'MAX_LINE_BYTES', 100)
    result = collector.run_once(config, ack)[0]
    assert result['reports'] == ['line_too_long'] and result['records'] == 0
    assert json.loads(files(config, '*.state.json')[0].read_text())['cursor']['offset'] == 0


def test_page_and_spool_limits_keep_unread_input(config, monkeypatch):
    monkeypatch.setattr(collector, 'MAX_RECORDS', 2)
    config['max_pages_per_run'] = 2
    path = Path(config['streams'][0]['path'])
    path.write_bytes(line()*5)
    result = collector.run_once(config, ack)[0]
    assert result['records'] == 4 and result['pages'] == 2 and not result['caught_up']
    assert collector.run_once(config, ack)[0]['records'] == 1
    config['max_spool_bytes'] = 1
    before = files(config, '*.state.json')[0].read_bytes()
    assert collector.run_once(config, ack)[0]['code'] == 'spool_capacity_reached'
    assert files(config, '*.state.json')[0].read_bytes() == before


def test_corrupt_spool_config_change_and_locks_do_not_advance(config):
    collector.run_once(config, lambda *args: {})
    spool, = files(config, '*.pending.json')
    data = json.loads(spool.read_text())
    data['next_cursor']['offset'] += 1
    spool.write_text(json.dumps(data))
    assert collector.run_once(config, ack)[0]['code'] == 'invalid_spool'
    assert not files(config, '*.state.json')
    with collector.collector_lock(Path(config['state_dir'])):
        with pytest.raises(collector.CollectorError, match='collector_locked'):
            collector.run_once(config, ack)


@pytest.mark.parametrize('change', ['plaintext', 'id', 'rotation', 'path', 'token'])
def test_bad_config_is_rejected_without_values(config, tmp_path, change):
    if change == 'plaintext':
        config['endpoint'] = 'http://example.invalid/api/http/batches'
    if change == 'id':
        config['streams'][0]['service_id'] = '../PRIVATE'
    if change == 'rotation':
        config['streams'][0]['rotated_path'] = '/different/PRIVATE'
    if change == 'path':
        config['streams'][0]['path'] = 'PRIVATE'
    if change == 'token':
        config['streams'][0]['token'] = 'PRIVATE\n'
    path = tmp_path / 'config.json'
    path.write_text(json.dumps(config))
    with pytest.raises(collector.CollectorError, match='^invalid_config$'):
        collector.load_config(path)


def test_crash_after_cursor_commit_before_spool_unlink_is_idempotent(config, monkeypatch):
    original = Path.unlink
    sent = []
    def fail_unlink(path, *args, **kwargs):
        if path.name.endswith('.pending.json'):
            raise OSError('simulated crash')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'unlink', fail_unlink)
    assert collector.run_once(config, capture(sent))[0]['code'] == 'local_storage_failed'
    assert files(config, '*.state.json') and files(config, '*.pending.json')
    monkeypatch.setattr(Path, 'unlink', original)
    assert collector.run_once(config, capture(sent))[0]['status'] == 'acknowledged'
    assert sent[0] == sent[1]


def test_source_error_is_visible_and_other_services_continue(config, tmp_path):
    stream = config['streams'][0]
    Path(stream['path']).unlink()
    other = tmp_path / 'other.jsonl'
    other.write_bytes(line())
    config['streams'].append(stream | dict(service_id='other', path=str(other), rotated_path=str(other)+'.1'))
    sent = []
    results = collector.run_once(config, capture(sent))
    assert results[0]['reports'] == ['file_unavailable']
    assert results[1]['records'] == 1 and results[1]['status'] == 'acknowledged'
    assert len(files(config, '*.state.json')) == 2
    assert sent[0]['records'] == [] and sent[1]['service_id'] == 'other'


def test_changed_endpoint_cannot_retarget_existing_spool(config):
    collector.run_once(config, lambda *args: {})
    config['endpoint'] = 'https://elsewhere.example.invalid/api/http/batches'
    result = collector.run_once(config, lambda *args: pytest.fail('must not send'))[0]
    assert result['code'] == 'invalid_spool'
    assert not files(config, '*.state.json')


def test_nonregular_file_cannot_block_collector(config):
    path = Path(config['streams'][0]['path'])
    path.unlink()
    os.mkfifo(path)
    assert collector.run_once(config, ack)[0]['reports'] == ['file_unavailable']


@pytest.mark.parametrize('limit', ['MAX_READ_BYTES', 'MAX_BATCH_BYTES'])
def test_byte_limits_leave_next_unread_record_for_later(config, monkeypatch, limit):
    path = Path(config['streams'][0]['path'])
    path.write_bytes(line('/'+500*'a')*10)
    config['max_pages_per_run'] = 1
    monkeypatch.setattr(collector, limit, 2000)
    sent = []
    result = collector.run_once(config, capture(sent))[0]
    assert 0 < result['records'] < 10 and not result['caught_up']
    first_ids = {r['event_id'] for r in sent[0]['records']}
    collector.run_once(config, capture(sent))
    assert not first_ids & {r['event_id'] for r in sent[1]['records']}
    if limit == 'MAX_BATCH_BYTES':
        assert len(collector.encode(sent[0])) < 2000


def test_rewrite_during_read_discards_uncommitted_page(config, monkeypatch):
    path = Path(config['streams'][0]['path'])
    original = collector.open_log
    class RewritingReader:
        def __init__(self, handle):
            self.handle, self.changed = handle, False
        def __getattr__(self, key):
            return getattr(self.handle, key)
        def readline(self, size):
            raw = self.handle.readline(size)
            if not self.changed:
                self.changed = True
                path.write_bytes(line('/rewritten-longer-path'))
            return raw
    monkeypatch.setattr(collector, 'open_log', lambda p: RewritingReader(original(p)))
    sent = []
    result = collector.run_once(config, capture(sent))[0]
    assert result['reports'] == ['file_unavailable'] and sent[0]['records'] == []
    assert json.loads(files(config, '*.state.json')[0].read_text())['cursor'] is None
