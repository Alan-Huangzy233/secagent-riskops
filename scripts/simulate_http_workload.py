#!/usr/bin/env python3
"""Measure bounded HTTP backlog handling in disposable Linux processes.

Uses the actual collector CLI, API and background analysis over loopback HTTP.
Synthetic inputs only; no production configuration, models or external targets.
"""
from __future__ import annotations

import argparse
from contextlib import closing, contextmanager
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import resource
import runpy
import secrets
import signal
import socket
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
import time

REPO = Path(__file__).resolve().parents[1]
SERVICES = ('benign', 'paged', 'time_limit', 'retry', 'record_limit', 'byte_limit',
            'new_incomplete', 'expired_raw', 'expired_context')
SAMPLE_SECONDS = 0.05


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2)+'\n')
    path.chmod(0o600)


def child(args):
    """Collect each process's own high-water mark, never subtract child maxima."""
    began = time.monotonic()
    try:
        sys.argv = ['http_collector.py', '--once', '--config', str(args.config)]
        runpy.run_path(str(REPO / 'scripts/http_collector.py'), run_name='__main__')
    finally:
        usage = resource.getrusage(resource.RUSAGE_SELF)
        write_json(args.metrics, dict(wall_seconds=round(time.monotonic()-began, 4),
            cpu_seconds=round(usage.ru_utime+usage.ru_stime, 4), peak_rss_bytes=usage.ru_maxrss*1024))


def size(path):
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0


def rss(pid):
    if pid is None:
        return 0
    try:
        for line in Path(f'/proc/{pid}/status').read_text().splitlines():
            if line.startswith('VmRSS:'):
                return int(line.split()[1])*1024
    except (FileNotFoundError, ProcessLookupError):
        pass
    return 0


class Sampler:
    def __init__(self, root):
        self.root, self.pid, self.current = root, None, None
        self.lock, self.stop = threading.Lock(), threading.Event()
        self.failure = None
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def sample(self):
        with self.lock:
            if self.current is None:
                return
            observed = {}
            for name in ('http.sqlite', 'console.sqlite'):
                for suffix in ('', '-wal', '-shm'):
                    observed[name+suffix] = size(self.root/(name+suffix))
            observed['pending_spool'] = sum(size(p) for p in self.root.glob('*/state/*.pending.json'))
            observed['collector_cursors'] = sum(size(p) for p in self.root.glob('*/state/*.state.json'))
            row = self.current
            row['samples'] += 1
            row['source_logs_sampled_peak_bytes'] = max(row.get('source_logs_sampled_peak_bytes', 0),
                sum(size(p) for p in self.root.glob('*/access.jsonl')))
            row['api_sampled_peak_rss_bytes'] = max(row['api_sampled_peak_rss_bytes'], rss(self.pid))
            row['managed_files_simultaneous_peak_bytes'] = max(row['managed_files_simultaneous_peak_bytes'], sum(observed.values()))
            for key, value in observed.items():
                row['file_sampled_peaks_bytes'][key] = max(row['file_sampled_peaks_bytes'].get(key, 0), value)

    def begin(self, name):
        with self.lock:
            self.current = dict(name=name, samples=0, api_rss_at_start_bytes=rss(self.pid),
                api_sampled_peak_rss_bytes=0, managed_files_simultaneous_peak_bytes=0, file_sampled_peaks_bytes={})
        self.sample()
        return self.current

    def run(self):
        try:
            while not self.stop.wait(SAMPLE_SECONDS):
                self.sample()
        except Exception as exc:
            self.failure = exc

    def close(self):
        self.stop.set()
        self.thread.join(timeout=5)
        assert not self.thread.is_alive()
        if self.failure:
            raise RuntimeError('resource sampler failed') from self.failure


class Drill:
    def __init__(self, root):
        from app.telemetry.config import LiveConfig, hash_operator_password
        self.root = root
        self.token = secrets.token_urlsafe(32)
        self.password: str = secrets.token_urlsafe(32)
        self.environment = dict(PATH=os.defpath, LANG='C.UTF-8', PYTHONPATH=str(REPO/'backend'),
                                PYTHONDONTWRITEBYTECODE='1', RISKOPS_CONFIG=str(root/'api.json'))
        config = LiveConfig(database_path=str(root/'console.sqlite'), sources=[
            dict(id='unused-ssh', hostname='unused.invalid', token_sha256=hashlib.sha256(secrets.token_bytes(32)).hexdigest())],
            operator_username='operator', operator_password_pbkdf2=hash_operator_password(self.password),
            notifications_enabled=False, console_cache_enabled=False,
            http_ingest=dict(database_path=str(root/'http.sqlite'), sources=[
                dict(id='workload-web', hostname='workload.invalid', services=list(SERVICES),
                     token_sha256=hashlib.sha256(self.token.encode()).hexdigest())]))
        write_json(root/'api.json', config.model_dump())
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(32)
        self.base = f'http://127.0.0.1:{self.listener.getsockname()[1]}'
        self.api = None
        self.api_runs, self.collector_runs, self.scenarios = [], [], []
        self.sampler = Sampler(root)

    def start(self):
        import httpx
        index = len(self.api_runs)
        started = time.monotonic()
        with (self.root/f'api-{index}.log').open('wb') as log:
            self.api = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'app.live_api:app',
                '--fd', str(self.listener.fileno()), '--log-level', 'error', '--no-access-log'], cwd=REPO,
                env=self.environment, pass_fds=(self.listener.fileno(),), stdout=log, stderr=log)
        self.sampler.pid = self.api.pid
        self.api_runs.append(dict(started=started))
        deadline = time.monotonic()+20
        with httpx.Client(trust_env=False, timeout=0.5) as client:
            while time.monotonic() < deadline:
                assert self.api.poll() is None, 'isolated API exited during startup'
                try:
                    if client.get(self.base+'/health').status_code == 200:
                        return
                except httpx.TransportError:
                    pass
                time.sleep(0.05)
        raise AssertionError('isolated API did not start')

    def stop_api(self):
        if self.api is None:
            return
        process = self.api
        try:
            assert process.returncode is None, 'isolated API exited unexpectedly'
            process.terminate()
            deadline = time.monotonic()+20
            while True:
                pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    process.returncode = os.waitstatus_to_exitcode(status)
                    assert process.returncode in (0, -signal.SIGTERM), 'API exited abnormally during shutdown'
                    break
                if time.monotonic() > deadline:
                    process.kill()
                    _, status, _ = os.wait4(process.pid, 0)
                    process.returncode = os.waitstatus_to_exitcode(status)
                    raise AssertionError('isolated API failed to stop')
                time.sleep(0.05)
            entry = self.api_runs[-1]
            entry.update(wall_seconds=round(time.monotonic()-entry.pop('started'), 4),
                         cpu_seconds=round(usage.ru_utime+usage.ru_stime, 4), peak_rss_bytes=usage.ru_maxrss*1024)
        finally:
            self.sampler.pid = None
            self.api = None

    def close(self):
        try:
            self.stop_api()
        finally:
            self.listener.close()
            self.sampler.close()

    def read(self, route, **params):
        import httpx
        with httpx.Client(base_url=self.base, auth=('operator', self.password), trust_env=False, timeout=15) as client:
            response = client.get('/api/http/'+route, params=params)
            response.raise_for_status()
            return response.json()

    def pages(self, service, batches=False):
        rows, after, snapshot = [], 0, None
        while True:
            params = dict(source_id='workload-web', service_id=service, limit=200, after=after)
            if snapshot is not None:
                params['snapshot'] = snapshot
            page = self.read('batches' if batches else 'events', **params)
            rows.extend(page['items'])
            if not page['has_more']:
                return rows
            assert page['next_after'] > after
            after, snapshot = page['next_after'], page['snapshot']

    def analyzed(self):
        began = time.monotonic()
        while time.monotonic()-began < 100:
            status = self.read('status')
            assert status['last_error'] is None, status
            if not status['pending']:
                return status, round(time.monotonic()-began, 4)
            time.sleep(0.25)
        raise AssertionError('analysis did not catch up within the drill deadline')

    def case(self, name, **updates):
        folder = self.root/name
        folder.mkdir(mode=0o700)
        access = folder/'access.jsonl'
        access.touch()
        config = dict(endpoint=self.base+'/api/http/batches', state_dir=str(folder/'state'),
            http_timeout_seconds=5, max_pages_per_run=5, max_seconds_per_stream=300,
            streams=[dict(source_id='workload-web', service_id=name, path=str(access), rotated_path=str(access)+'.1', token=self.token)])
        config.update(updates)
        write_json(folder/'collector.json', config)
        return dict(name=name, folder=folder, access=access, config=config, runs=[])

    def collect(self, case, error=None):
        path = case['folder']/'collector.json'
        write_json(path, case['config'])
        metrics = case['folder']/f'collector-{len(case["runs"])}.json'
        began = time.monotonic()
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--child', 'collector',
            '--config', str(path), '--metrics', str(metrics)], env=self.environment, cwd=REPO,
            capture_output=True, text=True, timeout=45)
        assert self.token not in result.stdout+result.stderr and not result.stderr
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        assert len(rows) == 1
        row = rows[0]
        if error:
            assert result.returncode == 1 and row.get('code') == error, row
        else:
            assert result.returncode == 0 and row['status'] == 'acknowledged', row
        sample = {**json.loads(metrics.read_text()), 'elapsed_including_startup_seconds': round(time.monotonic()-began, 4),
                  'service': case['name'], 'result': row}
        case['runs'].append(sample)
        self.collector_runs.append(sample)
        self.sampler.sample()
        return row

    def collect_all(self, case):
        for _ in range(40):
            row = self.collect(case)
            assert row['pages'] <= case['config']['max_pages_per_run']
            if row['caught_up']:
                return
        raise AssertionError('collector did not reach EOF within bounded runs')

    def verify(self, case, expected, retained=None):
        retained = expected if retained is None else retained
        rows = self.pages(case['name'])
        assert len(rows) == len({row['event_id'] for row in rows}) == retained
        stream = next(s for s in self.read('streams')['items'] if s['service_id'] == case['name'])
        assert stream['accepted_total'] == expected and stream['rejected_total'] == 0
        batches = self.pages(case['name'], batches=True)
        assert len(batches) == len({row['batch_id'] for row in batches})
        assert all(b['durable'] and b['duplicates'] == 0 for b in batches)
        assert sum(b['accepted'] for b in batches) == expected  # Unique persisted receipts, never retry stdout.
        cursor, = (case['folder']/'state').glob('*.state.json')
        assert json.loads(cursor.read_text())['cursor']['offset'] == size(case['access'])
        assert not list((case['folder']/'state').glob('*.pending.json'))
        return batches

    @contextmanager
    def phase(self, name):
        self.analyzed()  # Do not charge earlier scenarios' pending work to this phase.
        observation = self.sampler.begin(name)
        began = time.monotonic()
        row = dict(name=name, resources=observation)
        self.scenarios.append(row)
        try:
            yield row
        finally:
            self.sampler.sample()
            with self.sampler.lock:
                self.sampler.current = None
            row['total_seconds'] = round(time.monotonic()-began, 4)


def append(case, records):
    with case['access'].open('a') as output:
        for row in records:
            output.write(json.dumps(row, separators=(',', ':'))+'\n')


def records(count, timestamp, *, scan=False, long=False, peer='198.51.100.20'):
    for i in range(count):
        path = f'/probe/{i}' if scan else '/health'
        if long:
            path = '/'+('a'*7990)+f'{i:04}'
        yield dict(timestamp=datetime.fromtimestamp(timestamp, timezone.utc).isoformat(), client_ip=peer,
                   method='GET', path=path, status=404 if scan else 200)


@contextmanager
def delayed_gateway(endpoint):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            import httpx
            body = self.rfile.read(int(self.headers['Content-Length']))
            time.sleep(1.2)  # Real slow response; no patched collector clock or bounds.
            with httpx.Client(trust_env=False, timeout=10) as client:
                response = client.post(endpoint, content=body, headers={
                    'Content-Type': 'application/json', 'Authorization': self.headers['Authorization']})
            self.send_response(response.status_code)
            self.send_header('Content-Length', str(len(response.content)))
            self.end_headers()
            self.wfile.write(response.content)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}/api/http/batches'
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def simulate():
    import httpx
    from app.telemetry.http_incidents import MAX_CONTEXT_RECORDS, MAX_CONTEXT_BYTES
    assert (MAX_CONTEXT_RECORDS, MAX_CONTEXT_BYTES) == (5000, 4*1024*1024)
    # Middle of a previous UTC hour avoids accidental adjacent review windows.
    moment = int(time.time()//3600)*3600 - 7200 + 600
    with TemporaryDirectory(prefix='riskops-http-workload-') as directory:
        drill = Drill(Path(directory))
        try:
            drill.start()
            with drill.phase('benign') as result:
                case = drill.case('benign')
                append(case, records(24, moment))
                began = time.monotonic()
                drill.collect_all(case)
                result['collection_seconds'] = round(time.monotonic()-began, 4)
                status, result['analysis_after_collection_seconds'] = drill.analyzed()
                drill.verify(case, 24)
                assert drill.read('incidents', service_id='benign')['total'] == 0
                result.update(records=24, analysis_complete=True)

            with drill.phase('paged') as result:
                case = drill.case('paged')
                append(case, records(20, moment, scan=True))
                append(case, records(981, moment+600))
                began = time.monotonic()
                first = drill.collect(case)
                assert first['records'] == 1000 and first['pages'] == 5 and not first['caught_up']
                second = drill.collect(case)
                assert second['records'] == second['pages'] == 1 and second['caught_up']
                result['collection_seconds'] = round(time.monotonic()-began, 4)
                status, result['analysis_after_collection_seconds'] = drill.analyzed()
                drill.verify(case, 1001)
                cases = drill.read('incidents', service_id='paged')['items']
                assert len(cases) == 1 and cases[0]['assessment']['score'] == 30 and not cases[0]['stale']
                before = [(c['incident_id'], c['revision']) for c in cases]
                assert drill.collect(case)['records'] == 0
                drill.analyzed()
                assert [(c['incident_id'], c['revision']) for c in drill.read('incidents', service_id='paged')['items']] == before
                drill.verify(case, 1001)
                result.update(records=1001, first_run_records=1000, later_run_records=1, benign_replay_duplicates=0)

            with drill.phase('time_limit') as result, delayed_gateway(drill.base+'/api/http/batches') as endpoint:
                case = drill.case('time_limit', endpoint=endpoint, max_seconds_per_stream=1)
                append(case, records(401, moment))
                first = drill.collect(case)
                assert first['records'] == 200 and first['pages'] == 1 and not first['caught_up']
                drill.collect_all(case)
                drill.analyzed()
                drill.verify(case, 401)
                result.update(records=401, first_run_records=200, injected_response_delay_seconds=1.2,
                              time_budget_seconds=1, limit_checked_after_page=True)

            with drill.phase('retry') as result:
                case = drill.case('retry', max_spool_bytes=1024)
                append(case, records(401, moment))
                drill.collect(case, 'spool_capacity_reached')
                assert not list((case['folder']/'state').glob('*.json'))
                assert drill.pages('retry', batches=True) == []
                case['config']['max_spool_bytes'] = 16777216
                case['config']['streams'][0]['token'] = secrets.token_urlsafe(32)
                drill.collect(case, 'http_rejected')
                pending, = (case['folder']/'state').glob('*.pending.json')
                saved = pending.read_bytes()
                drill.collect(case, 'http_rejected')
                assert pending.read_bytes() == saved
                assert not list((case['folder']/'state').glob('*.state.json'))
                # Commit the real pending batch but intentionally discard its ACK
                # from the collector's perspective, then restart the real API.
                with httpx.Client(trust_env=False, timeout=10) as client:
                    response = client.post(drill.base+'/api/http/batches', json=json.loads(saved)['body'],
                                           headers={'Authorization': 'Bearer '+drill.token})
                    response.raise_for_status()
                    original = response.json()
                drill.stop_api()
                drill.start()
                assert pending.read_bytes() == saved
                case['config']['streams'][0]['token'] = drill.token
                drill.collect_all(case)
                drill.analyzed()
                batches = drill.verify(case, 401)
                persisted = next(b for b in batches if b['batch_id'] == original['batch_id'])
                assert {k: v for k, v in persisted.items() if k != 'seq'} == original
                result.update(records=401, capacity_failure_preserved_cursor=True,
                    failed_spool_preserved=True, restart_replayed_original_receipt=True)

            for name, more, long in [('record_limit', 4981, False), ('byte_limit', 300, True)]:
                with drill.phase(name) as result:
                    case = drill.case(name)
                    append(case, records(20, moment, scan=True))
                    drill.collect_all(case)
                    drill.analyzed()
                    original, = drill.read('incidents', service_id=name)['items']
                    assert original['assessment']['score'] == 30
                    run_index = len(case['runs'])
                    append(case, records(more if long else more-1, moment+600, long=long))
                    drill.collect_all(case)
                    if not long:
                        _, result['at_limit_analysis_wait_seconds'] = drill.analyzed()
                        at_limit, = drill.read('incidents', service_id=name)['items']
                        assert at_limit['coverage'] == 'complete' and not at_limit['stale']
                        assert at_limit['assessment'] == original['assessment']
                        drill.verify(case, MAX_CONTEXT_RECORDS)
                        append(case, records(1, moment+600))
                        drill.collect_all(case)
                    result['collection_seconds_after_seed'] = round(sum(
                        r['elapsed_including_startup_seconds'] for r in case['runs'][run_index:]), 4)
                    status, result['analysis_after_collection_seconds'] = drill.analyzed()
                    drill.verify(case, more+20)
                    current, = drill.read('incidents', service_id=name)['items']
                    assert current['stale'] and current['coverage'] == 'context_limit'
                    assert current['assessment'] == original['assessment']
                    assert current['evidence_sha256'] == original['evidence_sha256']
                    assert drill.read('incidents/'+current['incident_id']+'/evidence')['total'] == 20
                    with closing(sqlite3.connect(drill.root/'http.sqlite')) as db:
                        count, byte_count = db.execute('SELECT count(*),sum(length(CAST(record_json AS BLOB))) FROM http_context WHERE service_id=?', (name,)).fetchone()
                    if long:
                        assert count < MAX_CONTEXT_RECORDS and byte_count > MAX_CONTEXT_BYTES
                    else:
                        assert count == MAX_CONTEXT_RECORDS+1 and byte_count < MAX_CONTEXT_BYTES
                    result.update(records=more+20, normalized_context_bytes=byte_count, previous_score=30,
                                  previous_evidence_preserved=True, coverage='context_limit')

            with drill.phase('new_incomplete') as result:
                case = drill.case('new_incomplete')
                append(case, records(300, moment+600, long=True))
                drill.collect_all(case)
                drill.analyzed()
                append(case, records(20, moment, scan=True))
                drill.collect_all(case)
                status, result['analysis_after_collection_seconds'] = drill.analyzed()
                drill.verify(case, 320)
                assert drill.read('incidents', service_id='new_incomplete')['total'] == 0
                assert any(i['service_id'] == 'new_incomplete' and i['coverage'] == 'context_limit' for i in status['coverage_issues'])
                result.update(records=320, coverage='context_limit', fabricated_cases=0)

            with drill.phase('expired_raw') as result:
                case = drill.case('expired_raw')
                before = drill.read('status')['missing_raw_records']
                append(case, records(201, time.time()-15*86400))
                drill.collect_all(case)
                status, result['analysis_after_collection_seconds'] = drill.analyzed()
                drill.verify(case, 201, retained=0)
                assert status['missing_raw_records'] == before+201 and not status['pending']
                result.update(acknowledged_records=201, retained_raw_records=0, missing_raw_records=201,
                              caught_up_is_not_complete_history=True)

            with drill.phase('expired_context') as result:
                cutoff = time.time()-14*86400
                hour = int(cutoff//3600)*3600
                # Keep records inside raw retention, with a generous run margin,
                # while their hour's required preceding context is already gone.
                event_time = hour+3599 if cutoff-hour <= 3300 else hour+3720
                case = drill.case('expired_context')
                append(case, records(20, event_time, scan=True))
                drill.collect_all(case)
                status, result['analysis_after_collection_seconds'] = drill.analyzed()
                drill.verify(case, 20)
                assert any(i['service_id'] == 'expired_context' and i['coverage'] == 'expired_context' for i in status['coverage_issues'])
                assert drill.read('incidents', service_id='expired_context')['total'] == 0
                result.update(records=20, coverage='expired_context', fabricated_cases=0)
            drill.stop_api()
            return dict(mode='isolated_http_workload_acceptance', python=platform.python_version(), sqlite=sqlite3.sqlite_version,
                sample_interval_seconds=SAMPLE_SECONDS, scenarios=drill.scenarios, collector_runs=drill.collector_runs,
                api_processes=drill.api_runs, production_writes=False, model_calls=0, limitations=[
                    'Synthetic sequential loopback HTTP, not public TLS or a production capacity guarantee.',
                    'Notifications, console cache, SSH traffic and AI disabled in the isolated API.',
                    'Sampled RSS/files can miss short peaks; each process rusage reports its own lifetime RSS peak.',
                    'File peaks include shared store growth from earlier phases; only the simultaneous total is a concurrent footprint.',
                    'ACK completion precedes asynchronous analysis; sustained arrival above intake rate can keep analysis pending.',
                    'Receipts and evidence persist; bounded batches do not imply bounded lifetime disk usage.'])
        finally:
            drill.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--child', choices=('collector',), help=argparse.SUPPRESS)
    parser.add_argument('--metrics', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--config', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if sys.flags.optimize or sys.platform != 'linux' or not Path('/proc/self/status').exists():
        parser.error('requires Linux /proc and enabled Python assertions')
    if args.child:
        child(args)
        return
    report = simulate()
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        write_json(args.out, report)
    print(json.dumps({'mode': report['mode'], 'scenarios_passed': len(report['scenarios']),
        'scenarios': [{k: v for k, v in s.items() if k != 'resources'} for s in report['scenarios']],
        'collector_peak_rss_bytes': max(r['peak_rss_bytes'] for r in report['collector_runs']),
        'api_peak_rss_bytes': max(r['peak_rss_bytes'] for r in report['api_processes']),
        'managed_files_sampled_peak_bytes': max(r['resources']['managed_files_simultaneous_peak_bytes'] for r in report['scenarios']),
        'source_logs_sampled_peak_bytes': max(r['resources']['source_logs_sampled_peak_bytes'] for r in report['scenarios']),
        'production_writes': False, 'model_calls': 0}))


if __name__ == '__main__':
    main()
