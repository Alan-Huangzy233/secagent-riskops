#!/usr/bin/env python3
"""Run real loopback Nginx -> collector -> API -> encrypted backup -> restore.

Requires .[dev], nginx, gpg and zstd. All listeners, logs, keys and databases
belong to a temporary directory; no deployment configuration is loaded.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
import time

import httpx
import uvicorn

from app.live_api import create_app
from app.telemetry.ai_triage import Service
from app.telemetry.config import LiveConfig, hash_operator_password
from app.telemetry.control import ControlService
from app.telemetry.http_worker import publish
from app.telemetry.store import TelemetryStore
from http_collector import CollectorError, load_config, run_once
from telemetry_collector import post_batch

REPO = Path(__file__).resolve().parents[1]


def wait_until(check, message, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.05)
    raise RuntimeError(message)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2)+'\n')
    path.chmod(0o600)


@contextmanager
def serve(config, password, port=0):
    """Use real TCP and the actual API; manually tick its workers for determinism."""
    console = TelemetryStore(config.database_path)
    ai, control = Service(console), ControlService(None, config.sources)
    app = create_app(config, store=console, ai=ai, control=control)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', port))
    listener.listen(32)
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level='error', access_log=False))
    thread = threading.Thread(target=server.run, kwargs={'sockets': [listener]}, daemon=True)
    thread.start()
    try:
        wait_until(lambda: server.started, 'isolated API did not start')
        app.state.http_worker.close()
        with httpx.Client(base_url=f'http://127.0.0.1:{port}', auth=('operator', password),
                          timeout=10, trust_env=False) as client:
            assert client.get('/health').is_success
            assert not ai.enabled and not control.enabled
            yield app, console, client, port
    finally:
        server.should_exit = True
        thread.join(timeout=15)
        listener.close()
        if thread.is_alive():
            raise RuntimeError('isolated API did not stop')


@contextmanager
def nginx_server(binary, root):
    prefix = root / 'nginx'
    prefix.mkdir()
    access = prefix / 'access.jsonl'
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
    config = prefix / 'nginx.conf'
    # One owned process makes USR1 reopen and teardown independent of services.
    # Return fixed responses; never serve files or proxy to another host.
    config.write_text(f'''daemon off;
master_process off;
pid "{prefix / 'nginx.pid'}";
error_log "{prefix / 'error.log'}";
events {{ worker_connections 32; }}
http {{
    client_body_temp_path "{prefix / 'body'}";
    proxy_temp_path "{prefix / 'proxy'}";
    fastcgi_temp_path "{prefix / 'fastcgi'}";
    uwsgi_temp_path "{prefix / 'uwsgi'}";
    scgi_temp_path "{prefix / 'scgi'}";
    include "{REPO / 'deploy/nginx-http-access.example.conf'}";
    access_log "{access}" riskops_http;
    server {{
        listen 127.0.0.1:{port};
        location = /ready {{ access_log off; return 200 'ready'; }}
        location / {{ return 404; }}
    }}
}}
''')
    with (prefix / 'startup.log').open('wb') as errors:
        process = subprocess.Popen([binary, '-p', str(prefix)+'/', '-c', str(config)],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=errors)
    try:
        with httpx.Client(base_url=f'http://127.0.0.1:{port}', timeout=5, trust_env=False) as client:
            def ready():
                if process.poll() is not None:
                    raise RuntimeError('isolated Nginx failed: '+(prefix / 'startup.log').read_text()[-1000:])
                try:
                    return client.get('/ready').status_code == 200
                except httpx.TransportError:
                    return False
            wait_until(ready, 'isolated Nginx did not start')
            yield process, client, access
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


@contextmanager
def drill_key(root):
    directory = root / 'gnupg'
    directory.mkdir(mode=0o700)
    # Only this disposable child environment can see this disposable keyring.
    import os
    environment = dict(os.environ, GNUPGHOME=str(directory))
    try:
        subprocess.run(['gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '', '--quick-gen-key',
                        'HTTP recovery drill <drill@example.invalid>', 'default', 'default', 'never'],
                       env=environment, check=True, capture_output=True, timeout=60)
        listing = subprocess.run(['gpg', '--batch', '--with-colons', '--list-keys'], env=environment,
                                 check=True, capture_output=True, text=True, timeout=10).stdout
        fingerprint = next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
        yield environment, fingerprint
    finally:
        subprocess.run(['gpgconf', '--homedir', str(directory), '--kill', 'gpg-agent'],
                       capture_output=True, timeout=10)


def package_command(environment, *args):
    result = subprocess.run([sys.executable, str(REPO / 'scripts/recovery_package.py'), *map(str, args)],
                            env=environment, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise RuntimeError('isolated recovery command failed: '+result.stderr[-1000:])
    return json.loads(result.stdout)


def drain(app):
    for _ in range(30):
        if app.state.http_worker.tick()['caught_up']:
            return
    raise RuntimeError('HTTP analysis failed to catch up')


def read(client, path, **params):
    response = client.get(path, params=params)
    response.raise_for_status()
    return response.json()


def simulate(binary):
    version = subprocess.run([binary, '-v'], capture_output=True, text=True, check=True, timeout=5).stderr.strip()
    token = secrets.token_urlsafe(32)
    password: str = secrets.token_urlsafe(24)
    with TemporaryDirectory(prefix='riskops-http-recovery-') as directory:
        root = Path(directory)
        configs = root / 'configs'
        configs.mkdir(mode=0o700)
        state = root / 'collector'
        live_config = configs / 'live.json'
        local_config = configs / 'http-collector.json'
        config = LiveConfig(database_path=str(root / 'telemetry.sqlite'), sources=[
            dict(id='ssh-unused', hostname='unused.invalid', token_sha256=hashlib.sha256(b'unused-drill').hexdigest())],
            operator_username='operator', operator_password_pbkdf2=hash_operator_password(password),
            notifications_enabled=False, console_cache_enabled=False,
            http_ingest=dict(database_path=str(root / 'http.sqlite'), sources=[
                dict(id='drill-web', hostname='example.invalid', services=['drill-site'],
                     token_sha256=hashlib.sha256(token.encode()).hexdigest())]))
        write_json(live_config, config.model_dump())
        with nginx_server(binary, root) as (nginx, web, access), drill_key(root) as (environment, fingerprint):
            with serve(config, password) as (app, console, client, port):
                write_json(local_config, dict(endpoint=f'http://127.0.0.1:{port}/api/http/batches', state_dir=str(state),
                    rotation_quiet_seconds=1, streams=[dict(source_id='drill-web', service_id='drill-site',
                        path=str(access), rotated_path=str(access)+'.1', token=token)]))
                collector = load_config(local_config)
                paths = [f'/probe/{i}' for i in range(20)] + ['/.env', '/%252e%252e/etc/passwd']
                for path in paths:
                    assert web.get(path+'?drill_query=must_not_be_retained').status_code == 404
                wait_until(lambda: access.exists() and len(access.read_text().splitlines()) == 22, 'Nginx did not flush requests')
                assert 'drill_query' not in access.read_text()
                acknowledgements = []

                def lose_ack(endpoint, supplied_token, body, timeout):
                    acknowledgements.append(post_batch(endpoint, supplied_token, body, timeout))
                    raise CollectorError('http_timeout')  # Real API committed before the artificial loss.

                assert run_once(collector, lose_ack)[0]['code'] == 'http_timeout'
                pending = next(state.glob('*.pending.json'))
                pending_bytes = pending.read_bytes()
                drain(app)

                def crash_bridge():
                    raise RuntimeError('injected bridge interruption')

                try:
                    publish(app.state.http_store, console, time.time(), after_import=crash_bridge)
                except RuntimeError as error:
                    assert str(error) == 'injected bridge interruption'
                else:
                    raise AssertionError('expected an HTTP notification')
                # Complete any remaining hour-boundary topics, retaining one pending ACK.
                console.run_notifications([], now=time.time())
                original_cases = read(client, '/api/http/incidents')['items']
                assert original_cases and all(c['assessment']['score'] >= 30 for c in original_cases)
                rules = {r['rule_id'] for c in original_cases for r in c['rules']}
                assert rules == {'http_sensitive_resource', 'http_path_traversal', 'http_multi_path_scan'}
                original_evidence = {c['incident_id']: read(client, '/api/http/incidents/'+c['incident_id']+'/evidence',
                    revision=c['revision'], limit=200)['items'] for c in original_cases}
                inbox_before = read(client, '/api/notifications', kind='http_incident')['total']
                assert inbox_before >= 1
                # New real requests straddle a rename/reopen, still unread at backup time.
                assert web.get('/before-rotation').status_code == 404
                rotated = access.with_name(access.name+'.1')
                access.rename(rotated)
                nginx.send_signal(signal.SIGUSR1)
                wait_until(access.exists, 'Nginx did not reopen its access log')
                assert web.get('/after-rotation').status_code == 404
                wait_until(lambda: len(access.read_text().splitlines()) == 1, 'Nginx did not flush new log')
                backup_config = root / 'recovery.json'
                write_json(backup_config, dict(host_id='http-drill', recipients=[fingerprint], components=[
                    dict(name='collector', kind='state_dir', path=str(state), patterns=['*.state.json', '*.pending.json']),
                    dict(name='http', kind='sqlite', path=config.http_ingest.database_path),
                    dict(name='telemetry', kind='sqlite', path=config.database_path),
                    dict(name='configs', kind='state_dir', path=str(configs), patterns=['live.json', 'http-collector.json'])],
                    http_recovery=dict(http_database='http', console_database='telemetry', collector_states=['collector'])))
                built = package_command(environment, 'build', '--config', backup_config,
                    '--output-dir', root / 'packages', '--sign-key', fingerprint, '--census')
                assert built['encrypted']
                restored = root / 'restored'
                verified = package_command(environment, 'verify', built['package'], '--into', restored)
                assert verified['ok'] and verified['http_recovery']['notification_checkpoints'] == 'compatible'
                assert (restored / 'collector' / pending.name).read_bytes() == pending_bytes
                assert not list(Path(built['package']).glob('*.tar.zst'))
                # The original isolated API stops before replacing its own files.
            displaced = root / 'displaced'
            displaced.mkdir()
            for name in ('http.sqlite', 'telemetry.sqlite'):
                for suffix in ('', '-wal', '-shm'):
                    path = root / (name+suffix)
                    if path.exists():
                        path.rename(displaced / path.name)
                shutil.copy2(restored / name, root / name)
            state.rename(displaced / 'collector')
            shutil.copytree(restored / 'collector', state)
            for name in ('live.json', 'http-collector.json'):
                shutil.copy2(restored / 'configs' / name, configs / name)
            recovered_config = LiveConfig.model_validate_json(live_config.read_text())
            collector = load_config(local_config)
            with serve(recovered_config, password, port) as (app, console, client, _):
                for case in original_cases:
                    base = '/api/http/incidents/'+case['incident_id']
                    assert read(client, base, revision=case['revision']) == case
                    assert read(client, base+'/evidence', revision=case['revision'], limit=200)['items'] == original_evidence[case['incident_id']]
                retried = []

                def record_ack(endpoint, supplied_token, body, timeout):
                    ack = post_batch(endpoint, supplied_token, body, timeout)
                    retried.append(ack)
                    return ack

                assert run_once(collector, record_ack)[0]['status'] == 'acknowledged'
                assert retried[0] == acknowledgements[0]
                publish(app.state.http_store, console, time.time())
                console.run_notifications([], now=time.time())
                assert read(client, '/api/notifications', kind='http_incident')['total'] == len(original_cases)
                # Replaying the already imported source revision adds no second delivery.
                assert publish(app.state.http_store, console, time.time()) == 0
                # Drain both retained log inodes after their configured quiet interval.
                time.sleep(1.1)
                collected = run_once(collector)[0]
                assert collected['caught_up'] and collected['status'] == 'acknowledged'
                assert not set(collected['reports']) - {'catching_up'}
                drain(app)
                stream = read(client, '/api/http/streams')['items'][0]
                events = read(client, '/api/http/events', source_id='drill-web', service_id='drill-site', limit=200)['items']
                assert stream['accepted_total'] == len(events) == 24 and stream['rejected_total'] == 0
                assert len({event['event_id'] for event in events}) == 24
                assert {event['client_ip'] for event in events} == {'127.0.0.1'}
                assert all('?' not in event['path'] for event in events)
                for case in original_cases:
                    assert read(client, '/api/http/incidents/'+case['incident_id']+'/evidence',
                                revision=case['revision'], limit=200)['items'] == original_evidence[case['incident_id']]
                publish(app.state.http_store, console, time.time())
                console.run_notifications([], now=time.time()+3700)
                notice_count = read(client, '/api/notifications', kind='http_incident')['total']
                final_cases = read(client, '/api/http/incidents')['items']
                for _ in range(2):
                    assert run_once(collector)[0]['caught_up']
                    drain(app)
                    assert publish(app.state.http_store, console, time.time()+3701) == 0
                    console.run_notifications([], now=time.time()+3702)
                assert read(client, '/api/notifications', kind='http_incident')['total'] == notice_count
                assert read(client, '/api/http/incidents')['items'] == final_cases
                assert not list(state.glob('*.pending.json'))
                assert console.list_events() == []
                return dict(mode='isolated_real_nginx_http_recovery', nginx=version, requests=24, unique_events=24,
                    rules=sorted(rules), incidents=len(final_cases), scores=sorted(c['assessment']['score'] for c in final_cases),
                    notifications=notice_count, encrypted_backup=True, signature=verified['signature'],
                    paired_checkpoints=verified['http_recovery']['notification_checkpoints'],
                    restored_pending_bytes_identical=True, retry_returned_original_receipt=True,
                    historical_evidence_preserved=True, rename_reopen_caught_up=True,
                    query_removed_at_nginx=True, repeated_replay_created_duplicates=False,
                    production_writes=False, model_calls=0,
                    limitations=['Local synthetic requests exercise behavior, not detection accuracy.',
                                 'Loopback HTTP does not validate deployed TLS, remote collectors or a full-host restore.',
                                 'Original log inodes are retained; lost log files require gap handling.',
                                 'UTC-hour boundaries can produce adjacent cases sharing evidence.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nginx', default=shutil.which('nginx'))
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    if not args.nginx or any(shutil.which(tool) is None for tool in ('gpg', 'gpgconf', 'zstd')):
        parser.error('provide --nginx and install gpg/gpgconf/zstd')
    report = simulate(str(Path(args.nginx).resolve()))
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        write_json(args.out, report)
    print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__':
    main()
