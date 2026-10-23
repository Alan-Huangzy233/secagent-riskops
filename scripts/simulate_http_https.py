#!/usr/bin/env python3
"""Exercise the unmodified HTTP collector CLI through disposable Nginx TLS.

Requires development dependencies, Nginx and OpenSSL. Uses synthetic traffic,
loopback listeners, disposable certificates and databases only.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager, ExitStack
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading

import httpx

from app.telemetry.config import LiveConfig, hash_operator_password
from simulate_http_recovery import REPO, nginx_server, serve, wait_until, write_json


def tls_context(ca):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(ca))
    return context


def openssl(*arguments):
    subprocess.run(['openssl', *map(str, arguments)], check=True, capture_output=True, timeout=20)


def certificates(root):
    """Fresh CA; valid, wrong-name and expired leaves with the same private key."""
    root.mkdir(mode=0o700)
    ca, key = root / 'ca.pem', root / 'server.key'
    openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
            '-subj', '/CN=Disposable HTTP HTTPS drill CA',
            '-addext', 'basicConstraints=critical,CA:TRUE',
            '-keyout', root / 'ca.key', '-out', ca)
    openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost',
            '-keyout', key, '-out', root / 'server.csr')
    for serial, (name, san) in enumerate([
        ('valid', 'IP:127.0.0.1,DNS:localhost'),
        ('wrong_hostname', 'DNS:other.invalid'),
        ('expired', 'IP:127.0.0.1,DNS:localhost'),
    ], start=1):
        extension = root / (name+'.ext')
        extension.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
                             'extendedKeyUsage=serverAuth\nsubjectAltName='+san+'\n')
        if name == 'expired':
            # Negative x509 -days is rejected by some OpenSSL releases and
            # otherwise creates notAfter < notBefore. Sign an ordered validity
            # interval entirely in the past, using the portable ca interface.
            (root / 'index.txt').write_text('')
            (root / 'serial').write_text(f'{serial:02X}\n')
            config = root / 'ca.conf'
            config.write_text('[ca]\ndefault_ca=fixture\n[fixture]\n'
                              f'database="{root / "index.txt"}"\n'
                              f'serial="{root / "serial"}"\n'
                              f'new_certs_dir="{root}"\n'
                              'default_md=sha256\npolicy=subject_policy\n'
                              '[subject_policy]\ncommonName=supplied\n')
            now = datetime.now(timezone.utc)
            openssl('ca', '-batch', '-notext', '-config', config, '-cert', ca,
                    '-keyfile', root / 'ca.key', '-in', root / 'server.csr',
                    '-startdate', (now-timedelta(days=2)).strftime('%Y%m%d%H%M%SZ'),
                    '-enddate', (now-timedelta(days=1)).strftime('%Y%m%d%H%M%SZ'),
                    '-extfile', extension, '-out', root / (name+'.pem'))
        else:
            openssl('x509', '-req', '-in', root / 'server.csr', '-CA', ca, '-CAkey', root / 'ca.key',
                    '-set_serial', str(serial), '-days', '2', '-extfile', extension,
                    '-out', root / (name+'.pem'))
    for path in root.iterdir():
        path.chmod(0o600)
    return ca


@contextmanager
def http_server(handler):
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError('isolated HTTP listener did not stop')


@contextmanager
def fault_gateway(api_port):
    """Fault injection is upstream of TLS; collector and API code stay unchanged."""
    state = dict(mode='normal', requests=0, receipts=[])

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers['Content-Length']))
            state['requests'] += 1
            if state['mode'] == 'unavailable':
                self.send_response(503)
                self.end_headers()
                return
            with httpx.Client(trust_env=False, timeout=5) as client:
                response = client.post(f'http://127.0.0.1:{api_port}/api/http/batches', content=body,
                    headers={'Content-Type': 'application/json', 'Authorization': self.headers.get('Authorization', '')})
            payload = response.content
            if response.is_success:
                state['receipts'].append(response.json())
                if state['mode'] == 'drop_ack':
                    # The API's real transaction has committed. Nginx sees an
                    # upstream disconnect, while the collector never gets the ACK.
                    self.close_connection = True
                    return
                if state['mode'] == 'invalid_ack':
                    payload = json.dumps({**response.json(), 'durable': False}).encode()
            self.send_response(response.status_code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    with http_server(Handler) as port:
        yield port, state


@contextmanager
def capture_sink():
    observed = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def capture(self):
            # Never retain supplied credentials, headers or request bodies.
            observed.append(self.command)
            self.send_response(204)
            self.end_headers()

        do_GET = do_POST = do_CONNECT = capture

    with http_server(Handler) as port:
        yield port, observed


@contextmanager
def tls_proxy(binary, root, api_port, gateway_port, sink_port):
    prefix = root / 'tls-nginx'
    prefix.mkdir(mode=0o700)
    names = ['valid', 'wrong_hostname', 'expired', 'tls_sink']
    redirects = [(status, target) for status in (301, 302, 303, 307, 308)
                 for target in ('same_origin', 'cross_origin', 'downgrade')]
    names += [f'redirect_{status}_{target}' for status, target in redirects]
    # Hold reservations together so distinct cases cannot get the same port.
    with ExitStack() as stack:
        reservations = [stack.enter_context(socket.socket()) for _ in names]
        for listener in reservations:
            listener.bind(('127.0.0.1', 0))
        ports = {name: listener.getsockname()[1] for name, listener in zip(names, reservations)}
    blocks = []
    for name, port in ports.items():
        cert = name if name in ('wrong_hostname', 'expired') else 'valid'
        if name.startswith('redirect_'):
            _, status, target = name.split('_', 2)
            destination = {'same_origin': '/redirect-target',
                           'cross_origin': f'https://127.0.0.1:{ports["tls_sink"]}/redirect-target',
                           'downgrade': f'http://127.0.0.1:{sink_port}/redirect-target'}[target]
            route = f'return {status} {destination};'
        elif name == 'tls_sink':
            route = f'access_log "{prefix / "redirect-target.log"}" drill; return 204;'
        else:
            route = f'''proxy_pass http://127.0.0.1:{gateway_port};
                proxy_set_header Authorization $http_authorization;
                proxy_next_upstream off;'''
        blocks.append(f'''server {{
            listen 127.0.0.1:{port} ssl;
            ssl_certificate "{root / 'certs' / (cert+'.pem')}";
            ssl_certificate_key "{root / 'certs/server.key'}";
            ssl_protocols TLSv1.2 TLSv1.3;
            location = /ready {{ access_log off; return 200 'ready'; }}
            location = /api/http/batches {{ {route} }}
            location = /redirect-target {{ access_log "{prefix / 'redirect-target.log'}" drill; return 204; }}
            location / {{ proxy_pass http://127.0.0.1:{api_port}; proxy_set_header Authorization $http_authorization; }}
        }}''')
    config = prefix / 'nginx.conf'
    config.write_text(f'''daemon off;
master_process off;
pid "{prefix / 'nginx.pid'}";
error_log "{prefix / 'error.log'}";
events {{ worker_connections 128; }}
http {{
    client_body_temp_path "{prefix / 'body'}";
    proxy_temp_path "{prefix / 'proxy'}";
    fastcgi_temp_path "{prefix / 'fastcgi'}";
    uwsgi_temp_path "{prefix / 'uwsgi'}";
    scgi_temp_path "{prefix / 'scgi'}";
    client_max_body_size 1m;
    log_format drill '$request_method $status';
    access_log "{prefix / 'access.log'}" drill;
    {''.join(blocks)}
}}
''')
    with (prefix / 'startup.log').open('wb') as errors:
        process = subprocess.Popen([binary, '-p', str(prefix)+'/', '-c', str(config)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=errors)
    try:
        context = tls_context(root / 'certs/ca.pem')
        with httpx.Client(verify=context, trust_env=False, timeout=2) as client:
            def ready():
                if process.poll() is not None:
                    raise RuntimeError('isolated TLS Nginx failed to start')
                try:
                    return client.get(f'https://127.0.0.1:{ports["valid"]}/ready').status_code == 200
                except httpx.TransportError:
                    return False
            wait_until(ready, 'isolated TLS Nginx did not start')
        yield ports, prefix
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def run_collector(path, environment, token, expected_code=None):
    result = subprocess.run([sys.executable, str(REPO / 'scripts/http_collector.py'), '--once', '--config', str(path)],
                            cwd=REPO, env=environment, capture_output=True, text=True, timeout=15)
    assert token not in result.stdout + result.stderr, 'collector exposed its credential'
    assert not result.stderr, 'collector emitted unexpected diagnostics'
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(rows) == 1
    row = rows[0]
    if expected_code:
        assert result.returncode == 1 and row.get('code') == expected_code, row
    else:
        assert result.returncode == 0 and row['status'] == 'acknowledged' and row['caught_up'], row
    return row


def collector_case(root, name, endpoint, access, token):
    case = root / name
    case.mkdir(mode=0o700)
    config = dict(endpoint=endpoint, state_dir=str(case / 'state'), http_timeout_seconds=2,
                  streams=[dict(source_id='drill-web', service_id='drill-site', path=str(access),
                                rotated_path=str(access)+'.1', token=token)])
    path = case / 'collector.json'
    write_json(path, config)
    return path, config, case / 'state'


def snapshot(state):
    return {path.name: path.read_bytes() for path in state.glob('*.json')}


def totals(store):
    rows = store.streams()
    return [(row['source_id'], row['service_id'], row['accepted_total'], row['rejected_total']) for row in rows]


def simulate(binary):
    version = subprocess.run([binary, '-v'], capture_output=True, text=True, check=True, timeout=5).stderr.strip()
    token = secrets.token_urlsafe(32)
    ssh_token = secrets.token_urlsafe(32)
    password: str = secrets.token_urlsafe(32)
    with TemporaryDirectory(prefix='riskops-http-https-') as directory:
        root = Path(directory)
        ca = certificates(root / 'certs')
        empty_ca_dir = root / 'empty-ca'
        empty_ca_dir.mkdir()
        # Only these child processes inherit this CA/proxy test environment.
        # Never install a CA, change the parent environment or use production keys.
        environment = {**os.environ, 'PYTHONPATH': str(REPO / 'backend'), 'PYTHONOPTIMIZE': '',
                       'SSL_CERT_FILE': str(ca), 'SSL_CERT_DIR': str(empty_ca_dir),
                       'SSLKEYLOGFILE': str(root / 'tls-session-keys'), 'NO_PROXY': '', 'no_proxy': ''}
        config = LiveConfig(database_path=str(root / 'telemetry.sqlite'), sources=[
            dict(id='ssh-unused', hostname='unused.invalid', token_sha256=hashlib.sha256(ssh_token.encode()).hexdigest())],
            operator_username='operator', operator_password_pbkdf2=hash_operator_password(password),
            notifications_enabled=False, console_cache_enabled=False,
            http_ingest=dict(database_path=str(root / 'http.sqlite'), sources=[
                dict(id='drill-web', hostname='example.invalid', services=['drill-site'],
                     token_sha256=hashlib.sha256(token.encode()).hexdigest())]))
        with nginx_server(binary, root) as (_, web, access), serve(config, password) as (app, _, _, api_port), \
                capture_sink() as (sink_port, observed), fault_gateway(api_port) as (gateway_port, gateway), \
                tls_proxy(binary, root, api_port, gateway_port, sink_port) as (ports, proxy_root):
            for name in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy'):
                environment[name] = f'http://127.0.0.1:{sink_port}'
            paths = ['/.env', '/%252e%252e/etc/passwd', '/health-check']
            for path in paths:
                assert web.get(path+'?private_drill_query=discard-me', headers={
                    'X-Forwarded-For': '198.51.100.77', 'Forwarded': 'for=198.51.100.77',
                    'X-Real-IP': '198.51.100.77'}).status_code == 404
            wait_until(lambda: access.exists() and len(access.read_text().splitlines()) == len(paths),
                       'source Nginx did not flush logs')
            records = [json.loads(line) for line in access.read_text().splitlines()]
            assert {row['client_ip'] for row in records} == {'127.0.0.1'}
            assert 'private_drill_query' not in access.read_text()
            store = app.state.http_store
            endpoint = f'https://127.0.0.1:{ports["valid"]}/api/http/batches'
            path, _, state = collector_case(root, 'trusted', endpoint, access, token)
            assert run_collector(path, environment, token)['records'] == 3
            assert not list(state.glob('*.pending.json')) and len(list(state.glob('*.state.json'))) == 1
            assert totals(store)[0][2:] == (3, 0)
            checks = ['trusted_certificate', 'forwarded_headers_do_not_replace_log_peer', 'query_removed_at_nginx']

            # TLS rejection must happen before any HTTP request reaches the API.
            for case in ('unknown_ca', 'wrong_hostname', 'expired'):
                port = ports['valid'] if case == 'unknown_ca' else ports[case]
                path, _, state = collector_case(root, case, f'https://127.0.0.1:{port}/api/http/batches', access, token)
                child_env = environment if case != 'unknown_ca' else {**environment, 'SSL_CERT_FILE': str(root / 'no-ca.pem')}
                before, calls = totals(store), gateway['requests']
                run_collector(path, child_env, token, 'http_unavailable')
                pending = snapshot(state)
                assert len(pending) == 1 and next(iter(pending)).endswith('.pending.json')
                run_collector(path, child_env, token, 'http_unavailable')
                assert snapshot(state) == pending and totals(store) == before and gateway['requests'] == calls
                checks.append(case+'_rejected_before_http')
                if case == 'unknown_ca':
                    original_batch = json.loads(next(iter(pending.values())))['body']['batch_id']
                    run_collector(path, environment, token)
                    assert gateway['receipts'][-1]['batch_id'] == original_batch
                    assert not list(state.glob('*.pending.json'))
                    checks.append('corrected_trust_retries_original_spool')

            # Every redirect status is tested against same-origin, another HTTPS
            # origin and a plaintext destination. All targets count requests.
            for name, port in ports.items():
                if not name.startswith('redirect_'):
                    continue
                path, _, state = collector_case(root, name, f'https://127.0.0.1:{port}/api/http/batches', access, token)
                before, calls = totals(store), gateway['requests']
                run_collector(path, environment, token, 'http_rejected')
                pending = snapshot(state)
                run_collector(path, environment, token, 'http_rejected')
                assert len(pending) == 1 and next(iter(pending)).endswith('.pending.json')
                assert snapshot(state) == pending and totals(store) == before and gateway['requests'] == calls
            target_log = proxy_root / 'redirect-target.log'
            assert not target_log.exists() or not target_log.read_bytes()
            checks.append('15_redirect_combinations_rejected')

            # Exercise server credential boundaries through TLS, independently
            # of the collector's own stricter configuration validator.
            context = tls_context(ca)
            body = dict(source_id='drill-web', service_id='drill-site', batch_id='auth-boundary',
                        collected_at=records[0]['timestamp'], records=[], caught_up=True)
            before = totals(store)
            with httpx.Client(base_url=f'https://127.0.0.1:{ports["valid"]}', verify=context,
                              trust_env=False, timeout=5) as client:
                for credential in (None, 'Bearer '+secrets.token_urlsafe(32), 'Bearer '+ssh_token):
                    headers = {} if credential is None else {'Authorization': credential}
                    assert client.post('/api/http/batches', json=body, headers=headers).status_code == 401
                assert client.post('/api/http/batches', json=body, auth=('operator', password)).status_code == 401
                headers = {'Authorization': 'Bearer '+token}
                for field in ('source_id', 'service_id'):
                    assert client.post('/api/http/batches', json={**body, field: 'other'}, headers=headers).status_code == 403
                assert client.get('/api/http/streams', headers=headers).status_code == 401
                assert client.post('/api/telemetry/batches', json={}, headers=headers).status_code == 401
                assert client.get('/api/http/streams', auth=('operator', password)).status_code == 200
            assert totals(store) == before
            checks.append('http_ssh_operator_and_service_auth_isolation')

            # Preserve the spool through an auth failure, then rotate only the
            # token. Destination/stream identity remains unchanged.
            bad_token = secrets.token_urlsafe(32)
            path, collector, state = collector_case(root, 'rotate_token', endpoint, access, bad_token)
            run_collector(path, environment, bad_token, 'http_rejected')
            pending, = state.glob('*.pending.json')
            batch_id = json.loads(pending.read_text())['body']['batch_id']
            collector['streams'][0]['token'] = token
            write_json(path, collector)
            run_collector(path, environment, token)
            assert gateway['receipts'][-1]['batch_id'] == batch_id and not list(state.glob('*.pending.json'))
            checks.append('token_rotation_retries_original_spool')

            # These failures occur with an already committed cursor, so a failed
            # later page must preserve that existing cursor byte for byte.
            for case, code in [('unavailable', 'http_rejected'), ('drop_ack', 'http_rejected'), ('invalid_ack', 'invalid_ack')]:
                sample = root / (case+'.jsonl')
                sample.write_text(json.dumps(records[0])+'\n')
                path, _, state = collector_case(root, case, endpoint, sample, token)
                gateway['mode'] = 'normal'
                run_collector(path, environment, token)
                cursor, = state.glob('*.state.json')
                cursor_before = cursor.read_bytes()
                with sample.open('a') as output:
                    output.write(json.dumps(records[1])+'\n')
                before_count = totals(store)[0][2]
                gateway['mode'] = case
                run_collector(path, environment, token, code)
                assert cursor.read_bytes() == cursor_before
                pending, = state.glob('*.pending.json')
                pending_before = pending.read_bytes()
                batch_id = json.loads(pending_before)['body']['batch_id']
                committed = case != 'unavailable'
                original_receipt = gateway['receipts'][-1] if committed else None
                assert totals(store)[0][2] == before_count + int(committed)
                run_collector(path, environment, token, code)
                assert pending.read_bytes() == pending_before and cursor.read_bytes() == cursor_before
                assert totals(store)[0][2] == before_count + int(committed)
                gateway['mode'] = 'normal'
                run_collector(path, environment, token)
                assert totals(store)[0][2] == before_count + 1
                assert gateway['receipts'][-1]['batch_id'] == batch_id
                if committed:
                    assert gateway['receipts'][-1] == original_receipt
                assert not pending.exists() and cursor.read_bytes() != cursor_before
                checks.append(case+'_retains_cursor_and_replays_same_batch')
            assert not observed, 'redirect or environment proxy received a request'
            assert not (root / 'tls-session-keys').exists(), 'TLS session secrets were written'
            checks += ['environment_proxies_ignored', 'tls_session_key_logging_disabled']
            assert totals(store)[0][2:] == (15, 0)
            events = store.page('drill-web', 'drill-site', limit=200)['items']
            receipts = store.page('drill-web', 'drill-site', limit=200, batches=True)['items']
            assert len(events) == len({row['event_id'] for row in events}) == 15
            assert len(receipts) == len({row['batch_id'] for row in receipts}) == 9
            return dict(mode='isolated_nginx_https_acceptance', nginx=version, checks=checks,
                        checks_passed=len(checks), unique_events=len(events), durable_receipts=len(receipts), redirect_combinations=15,
                        production_writes=False, model_calls=0, limitations=[
                            'Synthetic loopback TLS acceptance; no production HTTP source enrolled.',
                            'Access-log peer tested without realip rewriting; no trusted-proxy client attribution.',
                            'Does not establish public TLS deployment, load capacity or remote/full-host recovery.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nginx', default=shutil.which('nginx'))
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    if sys.flags.optimize:
        parser.error('run without Python optimization: this acceptance script requires assertions')
    if not args.nginx or not shutil.which('openssl'):
        parser.error('provide --nginx and install OpenSSL before running this isolated drill')
    report = simulate(args.nginx)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        write_json(args.out, report)
    print(json.dumps(report))


if __name__ == '__main__':
    main()
