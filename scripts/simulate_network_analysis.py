#!/usr/bin/env python3
"""Exercise authored records through network ingestion, analysis and console delivery.

Exporter/collector source I/O is injected; API requests use in-process ASGI;
all SQLite/spool files live in a temporary directory. No host journal, firewall
command, SSH connection, production source or model is used. Install .[dev].
This is a functional check, not a detection accuracy benchmark.
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

from fastapi.testclient import TestClient

from app.live_api import create_app
from app.telemetry.ai_triage import Service
from app.telemetry.config import LiveConfig, hash_operator_password
from app.telemetry.control import ControlService
from app.telemetry.network_parse import SourceProfile
from app.telemetry.network_protocol import encode
from app.telemetry.network_worker import publish
from app.telemetry.store import TelemetryStore
from network_collector import CollectorError, run_once
from network_export import export_page


def synthetic_records(now_us):
    """Six TCP ports per family, then four more, then one delayed observation."""
    rows = []

    def add(family, port, protocol='TCP', *, offset=None):
        index = len(rows)
        source, destination = (('2001:db8:1::9', '2001:db8:2::20') if family == 6
                               else ('198.51.100.9', '192.0.2.20'))
        message = (f'[UFW BLOCK] IN=eth0 OUT= SRC={source} DST={destination} '
                   f'LEN=60 PROTO={protocol} SPT=45000 DPT={port}')
        if protocol == 'TCP':
            message += ' WINDOW=1024 RES=0x00 SYN URGP=0'
        seconds = index if offset is None else offset
        rows.append({'_TRANSPORT': 'kernel', '_BOOT_ID': '1' * 32,
                     '__CURSOR': f'synthetic-analysis-{index}',
                     '__REALTIME_TIMESTAMP': str(now_us - 120_000_000 + seconds * 1_000_000),
                     '__MONOTONIC_TIMESTAMP': str(600_000_000 + seconds * 1_000_000),
                     'MESSAGE': message})

    for port in range(8000, 8006):
        for family in (4, 6):
            add(family, port)
    for family in (4, 6):
        add(family, 9999, 'UDP')
    add(4, 9998)
    rows[-1]['MESSAGE'] = '[UFW BLOCK] IN=eth0 OUT= SRC=invalid-address DST=192.0.2.20 PROTO=TCP'
    for port in range(8006, 8010):
        for family in (4, 6):
            add(family, port)
    add(4, 9000, offset=5)  # Arrives last, inside the existing monotonic window.
    return rows


def simulate():
    now_us = time.time_ns() // 1000
    now = now_us / 1_000_000
    profile = SourceProfile(source_id='synthetic-network', ruleset_sha256='a' * 64,
        log_labels=('[UFW BLOCK]',), rejection_labels=('[UFW BLOCK]',),
        local_input_labels=('[UFW BLOCK]',), local_input_interfaces=('eth0',),
        logging_limit='rate_limited', retention='bounded')
    rows = synthetic_records(now_us)
    token = secrets.token_urlsafe(32)
    password: str = secrets.token_urlsafe(24)
    with TemporaryDirectory(prefix='riskops-network-analysis-') as directory:
        root = Path(directory)
        ssh_config = root / 'source.conf'
        ssh_config.write_text('Host synthetic-source\n HostName 192.0.2.20\n User network-export\n')
        ssh_config.chmod(0o600)
        collector = {'version': 1, 'endpoint': 'http://127.0.0.1:8088/api/network/batches',
            'state_dir': str(root / 'state'), 'ssh_config': str(ssh_config),
            'ssh_host': 'synthetic-source', 'profile': asdict(profile), 'token': token}
        config = LiveConfig(database_path=str(root / 'console.sqlite'),
            notifications_enabled=False, console_cache_enabled=False,
            sources=[{'id': 'ssh-unused', 'hostname': 'unused.invalid',
                'token_sha256': hashlib.sha256(b'unused-ssh-simulation-token').hexdigest()}],
            operator_username='operator', operator_password_pbkdf2=hash_operator_password(password),
            network_ingest={'database_path': str(root / 'network.sqlite'), 'sources': [{
                'id': profile.source_id, 'hostname': 'network.example.invalid',
                'profiles': [asdict(profile)], 'token_sha256': hashlib.sha256(token.encode()).hexdigest()}]})
        console = TelemetryStore(config.database_path)
        control, ai = ControlService(None, config.sources), Service(console)
        exporter = {'version': 1, 'profile': asdict(profile), 'profile_valid_from_us': now_us - 180_000_000}
        available = rows[:15]
        attempts, receipts = [], []

        def fetch(_config, cursor, _timeout):
            start = 0 if cursor is None else next(i + 1 for i, row in enumerate(available) if row['__CURSOR'] == cursor)
            return encode(export_page(exporter, {'source_id': profile.source_id, 'cursor': cursor},
                now_us=now_us, exists=lambda value: any(row['__CURSOR'] == value for row in available),
                rules=lambda **_: profile.ruleset_sha256,
                read=lambda *_, **__: iter(available[start:])))

        def no_fetch(*_args):
            raise AssertionError('A pending batch must be replayed before fetching again')

        def make_app():
            return create_app(config, store=console, control=control, ai=ai)

        def read(client, endpoint, **params):
            response = client.get('/api/network/' + endpoint, params=params, auth=('operator', password))
            assert response.status_code == 200, response.text
            return response.json()

        def drain(client):
            for _ in range(20):
                if client.app.state.network_worker.tick(now=now)['caught_up']:
                    return
            raise AssertionError('Network worker failed to drain the authored records')

        def evidence(client, identity, revision):
            result, page = [], 1
            while True:
                response = read(client, f'incidents/{identity}/evidence', revision=revision, page=page, limit=3)
                assert response['revision'] == revision and response['page'] == page
                result.extend(response['items'])
                if page == response['total_pages']:
                    assert len(result) == response['total']
                    return result
                page += 1

        with TestClient(make_app()) as client:
            client.app.state.network_worker.close()  # Drive deterministic ticks after joining the thread.

            def send(_endpoint, supplied_token, body, _timeout):
                response = client.post('/api/network/batches', content=encode(body),
                    headers={'Authorization': 'Bearer ' + supplied_token, 'Content-Type': 'application/json'})
                assert response.status_code == 200, response.text
                attempts.append(body)
                receipts.append(response.json())
                if len(attempts) == 1:
                    raise CollectorError('http_timeout')  # Response lost after durable COMMIT.
                return response.json()

            assert run_once(collector, fetch=fetch, send=send)['code'] == 'http_timeout'
            state, pending = root / 'state/network.state.json', root / 'state/network.pending.json'
            assert not state.exists() and pending.exists()
            assert token not in pending.read_text() and 'MESSAGE' not in pending.read_text()
            drain(client)
            assert read(client, 'incidents')['total'] == 0  # Six ports is below threshold.
            retry = run_once(collector, fetch=no_fetch, send=send)
            assert retry['status'] == 'degraded' and retry['rejected_records'] == 1
            assert attempts[0] == attempts[1] and receipts[0] == receipts[1]
            assert not pending.exists() and json.loads(state.read_text())['cursor'] == rows[14]['__CURSOR']

            available.extend(rows[15:23])
            assert run_once(collector, fetch=fetch, send=send)['status'] == 'acknowledged'
            drain(client)
            first_page = read(client, 'incidents', page=1, limit=1)
            second_page = read(client, 'incidents', page=2, limit=1)
            assert first_page['total'] == second_page['total'] == 2
            assert first_page['total_pages'] == second_page['total_pages'] == 2
            cases = first_page['items'] + second_page['items']
            assert len({case['incident_id'] for case in cases}) == 2
            assert {case['src_ip'] for case in cases} == {'198.51.100.9', '2001:db8:1::9'}
            assert all(case['revision'] == 1 and case['evidence_count'] == 10 for case in cases)
            assert all(case['assessment']['score'] == 35 and case['assessment']['priority'] == 'P3'
                       for case in cases)
            before = {case['src_ip']: case for case in cases}
            retained = {case['incident_id']: evidence(client, case['incident_id'], 1) for case in cases}
            assert all(len(records) == 10 and all(row['protocol'] == 'TCP' for row in records)
                       for records in retained.values())
            assert len({row['event_id'] for records in retained.values() for row in records}) == 20

            available.extend(rows[23:])
            assert run_once(collector, fetch=fetch, send=send)['status'] == 'acknowledged'
            drain(client)
            cases = read(client, 'incidents')['items']
            after = {case['src_ip']: case for case in cases}
            assert after['2001:db8:1::9'] == before['2001:db8:1::9']
            changed = after['198.51.100.9']
            assert changed['incident_id'] == before['198.51.100.9']['incident_id']
            assert changed['revision'] == 2 and changed['evidence_count'] == 11
            assert changed['evidence_sha256'] != before['198.51.100.9']['evidence_sha256']
            assert read(client, 'incidents/' + changed['incident_id'], revision=1) == before['198.51.100.9']
            for case in cases:
                assert evidence(client, case['incident_id'], 1) == retained[case['incident_id']]
                assert len(evidence(client, case['incident_id'], case['revision'])) == case['evidence_count']

            def crash_after_import():
                raise RuntimeError('synthetic crash after console COMMIT')

            try:
                publish(client.app.state.network_store, console, now, after_import=crash_after_import)
            except RuntimeError as exc:
                assert str(exc) == 'synthetic crash after console COMMIT'
            else:
                raise AssertionError('The notification bridge did not reach its crash window')
            assert publish(client.app.state.network_store, console, now) == 2
            assert publish(client.app.state.network_store, console, now) == 0
            console.run_notifications([], now=now)
            console.run_notifications([], now=now + 1)
            notices = console.list_notifications(kind='network_incident')
            assert notices['total'] == 2
            assert {row['payload']['incident_id']: row['payload']['revision'] for row in notices['items']} == {
                case['incident_id']: case['revision'] for case in cases}
            source = read(client, 'sources')['items'][0]
            assert (source['accepted_total'], source['rejected_total']) == (23, 1)
            assert source['checkpoint'] == rows[-1]['__CURSOR']
            assert len(read(client, 'batches', source_id=profile.source_id)['items']) == 3
            assert read(client, 'status')['analysis_enabled'] is True
            stored_events, after_seq, snapshot = [], 0, None
            while True:
                params = {'source_id': profile.source_id, 'after': after_seq, 'limit': 7}
                if snapshot is not None:
                    params['snapshot'] = snapshot
                page = read(client, 'events', **params)
                stored_events.extend(page['items'])
                if not page['has_more']:
                    break
                after_seq, snapshot = page['next_after'], page['snapshot']
            event_ids = {row['event_id'] for row in stored_events}
            assert len(stored_events) == len(event_ids) == 23
            assert sum(row['protocol'] == 'UDP' for row in stored_events) == 2
            assert all('MESSAGE' not in row for row in stored_events)
            assert {row['event_id'] for case in cases
                    for row in evidence(client, case['incident_id'], case['revision'])} <= event_ids
            assert console.list_events() == [] and not ai.enabled and not control.enabled

        with TestClient(make_app()) as client:
            client.app.state.network_worker.close()
            response = client.post('/api/network/batches', content=encode(attempts[0]),
                headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
            assert response.status_code == 200 and response.json() == receipts[0]
            drain(client)
            assert read(client, 'incidents')['items'] == cases
            for case in cases:
                assert evidence(client, case['incident_id'], 1) == retained[case['incident_id']]
            assert publish(client.app.state.network_store, console, now) == 0
            console.run_notifications([], now=now + 2)
            assert console.list_notifications(kind='network_incident')['total'] == 2
            source = read(client, 'sources')['items'][0]
            assert (source['accepted_total'], source['rejected_total']) == (23, 1)
            assert source['checkpoint'] == rows[-1]['__CURSOR']
            assert len(read(client, 'batches', source_id=profile.source_id)['items']) == 3

        return {'mode': 'isolated_network_analysis_simulation', 'input_records': len(rows),
                'stored_unique_events': len(stored_events), 'rejected_records': 1, 'udp_negative_records': 2,
                'durable_batches': 3, 'before_threshold_incidents': 0, 'incidents': len(cases),
                'incident_revisions': sorted(case['revision'] for case in cases),
                'evidence_counts': sorted(case['evidence_count'] for case in cases),
                'console_notifications': notices['total'], 'lost_ack_replayed_identically': True,
                'restart_preserved_incidents_and_original_ack': True, 'historical_evidence_retained': True,
                'late_evidence_revised_existing_incident': True, 'console_commit_retry_idempotent': True,
                'production_writes': False, 'model_calls': 0,
                'limitations': ['Authored records are not an accuracy benchmark.',
                    'Injected source I/O does not test deployed SSH permissions, journal retention or firewall provenance.',
                    'In-process ASGI transport does not test a deployed TLS proxy.',
                    'A TCP probe pattern does not establish exploitation or identify a person.']}


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
