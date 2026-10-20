#!/usr/bin/env python3
"""Synthetic journal -> exporter -> spool -> authenticated API -> durable store.

Uses authored records, injected source I/O and the in-process ASGI transport.
No host journal, firewall, SSH connection, production config or model is used.
Install .[dev]; this is a functional check, not a detection accuracy benchmark.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.live_api import create_app
from app.telemetry.config import LiveConfig, hash_operator_password
from app.telemetry.network_detection import detect_network
from app.telemetry.network_parse import SourceProfile
from app.telemetry.network_protocol import encode, event_from_dict
from network_collector import CollectorError, run_once
from network_export import export_page


def synthetic_records(now_us):
    rows = []
    for index in range(23):
        ipv6 = 10 <= index < 20
        source, destination = (('2001:db8:1::9', '2001:db8:2::20') if ipv6
                               else ('198.51.100.9', '192.0.2.20'))
        protocol = 'UDP' if index in (20, 21) else 'TCP'
        message = (f'[UFW BLOCK] IN=eth0 OUT= SRC={source} DST={destination} '
                   f'LEN=60 PROTO={protocol} SPT=45000 DPT={8000 + index % 10}')
        if protocol == 'TCP':
            message += ' WINDOW=1024 RES=0x00 SYN URGP=0'
        if index == 22:
            message = '[UFW BLOCK] IN=eth0 OUT= SRC=invalid-address DST=192.0.2.20 PROTO=TCP'
        rows.append({'_TRANSPORT': 'kernel', '_BOOT_ID': '1' * 32,
                     '__CURSOR': f'synthetic-cursor-{index}',
                     '__REALTIME_TIMESTAMP': str(now_us - 60_000_000 + index * 1_000_000),
                     '__MONOTONIC_TIMESTAMP': str(1_000_000 + index * 1_000_000),
                     'MESSAGE': message})
    return rows


def simulate():
    now_us = time.time_ns() // 1000
    profile = SourceProfile(source_id='synthetic-network', ruleset_sha256='a' * 64,
        log_labels=('[UFW BLOCK]',), rejection_labels=('[UFW BLOCK]',),
        local_input_labels=('[UFW BLOCK]',), local_input_interfaces=('eth0',),
        logging_limit='rate_limited', retention='bounded')
    rows = synthetic_records(now_us)
    token = secrets.token_urlsafe(32)
    password: str = secrets.token_urlsafe(24)
    with TemporaryDirectory(prefix='riskops-network-simulation-') as directory:
        root = Path(directory)
        ssh_config = root / 'source.conf'
        ssh_config.write_text('Host synthetic-source\n HostName 192.0.2.20\n User network-export\n')
        ssh_config.chmod(0o600)
        collector = {'version': 1, 'endpoint': 'http://127.0.0.1:8088/api/network/batches',
            'state_dir': str(root / 'state'), 'ssh_config': str(ssh_config),
            'ssh_host': 'synthetic-source', 'profile': asdict(profile), 'token': token}
        config = LiveConfig(database_path=str(root / 'ssh.sqlite'), notifications_enabled=False,
            sources=[{'id': 'ssh-unused', 'hostname': 'unused.invalid',
                'token_sha256': hashlib.sha256(b'unused-ssh-simulation-token').hexdigest()}],
            operator_username='operator', operator_password_pbkdf2=hash_operator_password(password),
            network_ingest={'database_path': str(root / 'network.sqlite'), 'sources': [{
                'id': profile.source_id, 'hostname': 'network.example.invalid',
                'profiles': [asdict(profile)], 'token_sha256': hashlib.sha256(token.encode()).hexdigest()}]})
        exporter = {'version': 1, 'profile': asdict(profile), 'profile_valid_from_us': now_us - 120_000_000}
        available = rows[:6]
        attempts, receipts = [], []

        def fetch(_config, cursor, _timeout):
            start = 0 if cursor is None else next(i + 1 for i, row in enumerate(available) if row['__CURSOR'] == cursor)
            body = export_page(exporter, {'source_id': profile.source_id, 'cursor': cursor}, now_us=now_us,
                exists=lambda value: any(row['__CURSOR'] == value for row in available),
                rules=lambda **_: profile.ruleset_sha256,
                read=lambda *_, **__: iter(available[start:]))
            return encode(body)

        def no_fetch(*args):
            raise AssertionError('A pending batch must be replayed before fetching again')

        def make_app():
            return create_app(config, control=SimpleNamespace(block_listener=None), ai=SimpleNamespace())

        def read(client, endpoint, **params):
            response = client.get('/api/network/' + endpoint, params=params, auth=('operator', password))
            assert response.status_code == 200, response.text
            return response.json()

        with TestClient(make_app()) as client:
            def send(_endpoint, supplied_token, body, _timeout):
                response = client.post('/api/network/batches', content=encode(body),
                    headers={'Authorization': 'Bearer ' + supplied_token, 'Content-Type': 'application/json'})
                assert response.status_code == 200, response.text
                attempts.append(body)
                receipts.append(response.json())
                if len(attempts) == 1:
                    raise CollectorError('http_timeout')  # Lose the response after COMMIT.
                return response.json()

            first = run_once(collector, fetch=fetch, send=send)
            assert first['code'] == 'http_timeout'
            state, pending = root / 'state/network.state.json', root / 'state/network.pending.json'
            assert not state.exists() and pending.exists()
            assert token not in pending.read_text() and 'MESSAGE' not in pending.read_text()
            assert len(read(client, 'events', source_id=profile.source_id)['items']) == 6
            retry = run_once(collector, fetch=no_fetch, send=send)
            assert retry['status'] == 'acknowledged'
            assert attempts[0] == attempts[1] and receipts[0] == receipts[1]
            assert not pending.exists() and json.loads(state.read_text())['cursor'] == 'synthetic-cursor-5'
            available.extend(rows[6:])
            second = run_once(collector, fetch=fetch, send=send)
            assert second['status'] == 'degraded' and second['rejected_records'] == 1
            assert second['rejection_codes'] == ['invalid_record']
            assert json.loads(state.read_text())['cursor'] == 'synthetic-cursor-22'
            events, after, snapshot, page_count = [], 0, None, 0
            while True:
                params = {'source_id': profile.source_id, 'after': after, 'limit': 7}
                if snapshot is not None:
                    params['snapshot'] = snapshot
                page = read(client, 'events', **params)
                page_count += 1
                events.extend(event_from_dict({k: v for k, v in row.items()
                    if k not in {'seq', 'collected_at_us', 'received_at_us'}}) for row in page['items'])
                if not page['has_more']:
                    break
                after, snapshot = page['next_after'], page['snapshot']
            source = read(client, 'sources')['items'][0]
            assert (source['accepted_total'], source['rejected_total'], source['status']) == (22, 1, 'degraded')
            assert len(events) == len({event.event_id for event in events}) == 22
            assert len(read(client, 'batches', source_id=profile.source_id)['items']) == 2
            assert read(client, 'status')['analysis_enabled'] is False
            detection = detect_network(events)
            assert detection.eligible_count == 20 and detection.excluded_count == 2
            assert sorted(len(f.evidence_ids) for f in detection.findings) == [10, 10]
            assert len({eid for f in detection.findings for eid in f.evidence_ids}) == 20

        # Restart the actual application/store, then replay the original request.
        with TestClient(make_app()) as client:
            response = client.post('/api/network/batches', content=encode(attempts[0]),
                headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
            assert response.status_code == 200 and response.json() == receipts[0]
            source = read(client, 'sources')['items'][0]
            assert source['accepted_total'] == 22 and source['rejected_total'] == 1
            assert source['checkpoint'] == 'synthetic-cursor-22'
            assert len(read(client, 'batches', source_id=profile.source_id)['items']) == 2
        return {'mode': 'isolated_network_ingest_simulation', 'input_records': len(rows),
                'stored_unique_events': len(events), 'rejected_records': 1, 'durable_batches': 2,
                'event_read_pages': page_count, 'lost_ack_replayed_identically': True,
                'restart_replayed_identically': True, 'cursor_advanced_only_after_ack': True,
                'continuous_analysis_enabled': False, 'offline_findings': [
                    {'rule_id': f.rule_id, 'evidence_count': len(f.evidence_ids),
                     'distinct_ports': len(f.distinct_dst_ports)} for f in detection.findings],
                'coverage': list(detection.coverage), 'production_writes': False, 'model_calls': 0,
                'limitations': ['Authored records are not an accuracy benchmark.',
                    'Injected source I/O does not test deployed SSH permissions, journal retention or firewall provenance.',
                    'In-process ASGI transport does not test a deployed TLS proxy.',
                    'Offline findings are not published to the console or notifications.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    report = simulate()
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
