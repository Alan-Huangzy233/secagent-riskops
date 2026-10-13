#!/usr/bin/env python3
"""Exercise synthetic HTTP file -> spool -> authenticated API -> DB -> incidents -> console inbox.

Uses the in-process ASGI test transport and temporary databases. No production
configuration, outbound request, website or model is needed. Install .[dev].
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
import secrets
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from app.live_api import create_app
from app.telemetry import http_briefings
from app.telemetry.ai_triage import Service
from app.telemetry.config import LiveConfig, hash_operator_password
from app.telemetry.control import ControlService
from app.telemetry.http_parse import HttpEvent
from app.telemetry.http_worker import publish
from app.telemetry.store import TelemetryStore
from app.telemetry.web_detection import detect_web
from http_collector import CollectorError, load_config, run_once


def simulate(fixture: Path):
    rows = [json.loads(line) for line in fixture.read_text().splitlines()]
    first = min(datetime.fromisoformat(r['timestamp'].replace('Z', '+00:00')) for r in rows)
    start = (datetime.now(timezone.utc) - timedelta(hours=2)).replace(minute=10, second=0, microsecond=0)
    for row in rows:
        row['timestamp'] = (start + (datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00')) - first)).isoformat()
    token = secrets.token_urlsafe(32)
    password: str = secrets.token_urlsafe(24)
    with TemporaryDirectory(prefix='riskops-http-simulation-') as directory:
        root = Path(directory)
        access = root / 'access.jsonl'
        config = LiveConfig(database_path=str(root / 'ssh.sqlite'), sources=[
            dict(id='ssh-unused', hostname='unused.invalid', token_sha256=hashlib.sha256(b'unused-ssh-simulation-token').hexdigest())],
            operator_username='operator', operator_password_pbkdf2=hash_operator_password(password),
            notifications_enabled=False,
            http_ingest=dict(database_path=str(root / 'http.sqlite'), sources=[
                dict(id='synthetic-web', hostname='example.invalid', services=['example-site'],
                     token_sha256=hashlib.sha256(token.encode()).hexdigest())]))
        local_config = root / 'collector.json'
        local_config.write_text(json.dumps(dict(endpoint='http://127.0.0.1:8088/api/http/batches', state_dir=str(root / 'state'),
            streams=[dict(source_id='synthetic-web', service_id='example-site', path=str(access),
                          rotated_path=str(access)+'.1', token=token)])))
        local_config.chmod(0o600)
        collector = load_config(local_config)
        ssh = TelemetryStore(config.database_path)
        control, ai = ControlService(None, config.sources), Service(ssh)
        attempts, acknowledgements, results = [], [], []
        with TestClient(create_app(config, store=ssh, control=control, ai=ai)) as client:
            client.app.state.http_worker.close()  # Drive actual worker ticks deterministically.
            def send(endpoint, supplied_token, body, timeout):
                attempts.append(body)
                response = client.post('/api/http/batches', json=body, headers={'Authorization': 'Bearer '+supplied_token})
                assert response.status_code == 200
                acknowledgements.append(response.json())
                if len(attempts) == 1:
                    raise CollectorError('http_timeout')  # Simulate a lost response after COMMIT.
                return response.json()
            for at in range(0, len(rows), 13):
                with access.open('a') as out:
                    for row in rows[at:at+13]:
                        out.write(json.dumps(row)+'\n')
                result = run_once(collector, send)[0]
                if at == 0:
                    assert result['code'] == 'http_timeout'
                    result = run_once(collector, send)[0]
                    assert attempts[0] == attempts[1] and acknowledgements[0] == acknowledgements[1]
                assert result['status'] == 'acknowledged' and result['caught_up']
                results.append(result)
                client.app.state.http_worker.tick()
            # Inspect the persistent evidence through the authenticated, paged API.
            events, after, snapshot = [], 0, None
            while True:
                params = dict(source_id='synthetic-web', service_id='example-site', limit=7, after=after)
                if snapshot is not None:
                    params['snapshot'] = snapshot
                response = client.get('/api/http/events', params=params, auth=('operator', password))
                assert response.status_code == 200
                page = response.json()
                events.extend(HttpEvent(**{k: v for k, v in row.items() if k != 'seq'}) for row in page['items'])
                if not page['has_more']:
                    break
                after, snapshot = page['next_after'], page['snapshot']
            stream = client.get('/api/http/streams', auth=('operator', password)).json()['items'][0]
            assert stream['accepted_total'] == len(rows) == len(events) == 42
            assert stream['rejected_total'] == 0 and stream['status'] == 'current'
            assert ssh.list_events() == []
            assert not ai.enabled and not control.enabled
            findings = detect_web(events)
            assert [(f.rule_id, len(f.evidence_ids)) for f in findings] == [
                ('http_sensitive_resource', 2), ('http_path_traversal', 1), ('http_multi_path_scan', 20)]
            for _ in range(20):
                if client.app.state.http_worker.tick()['caught_up']:
                    break
            else:
                raise AssertionError('HTTP worker failed to drain')
            cases = client.get('/api/http/incidents', auth=('operator', password)).json()['items']
            assert sorted(case['assessment']['score'] for case in cases) == [25, 30, 35]
            retained = []
            for case in cases:
                response = client.get('/api/http/incidents/'+case['incident_id']+'/evidence',
                                      params={'revision': case['revision']}, auth=('operator', password))
                assert response.status_code == 200
                retained.extend(response.json()['items'])
            now = datetime.now(timezone.utc).timestamp()
            publish(client.app.state.http_store, ssh, now)
            ssh.run_notifications([], now=now)
            notices = ssh.list_notifications(kind='http_incident')['items']
            assert len(notices) == 2
            assert sorted(n['payload']['assessment']['score'] for n in notices) == [30, 35]
            # A repeat tick and bridge must not produce another incident or notice.
            client.app.state.http_worker.tick()
            assert publish(client.app.state.http_store, ssh, now) == 0
            ssh.run_notifications([], now=now+1)
            assert ssh.list_notifications(kind='http_incident')['total'] == 2
            # Complete this event day's report on the isolated clock, then
            # import/deliver it twice to verify the actual console pipeline.
            report_now = max(now, (start.replace(hour=0, minute=0) + timedelta(days=1, seconds=1)).timestamp())
            for _ in range(100):
                if not http_briefings.advance(client.app.state.http_store, report_now, batch_size=7):
                    break
            else:
                raise AssertionError('HTTP daily report did not finish')
            for _ in range(2):
                publish(client.app.state.http_store, ssh, report_now)
                ssh.run_notifications([], now=report_now)
            briefings = [n['payload'] for n in ssh.list_notifications(kind='briefing')['items']
                         if n['payload'].get('report_type') == 'http_daily']
            assert len(briefings) == 1
            daily = briefings[0]
            assert daily['counts']['requests'] == 42
            assert daily['counts']['cases'] == 3 and daily['counts']['attention'] == 2
            assert daily['counts']['low'] == 1 and not daily['analysis_pending']
            referenced = {eid for f in findings for eid in f.evidence_ids}
            assert referenced == {e['event_id'] for e in retained}
            assert referenced <= {e.event_id for e in events}
            return dict(mode='isolated_http_incident_simulation', records=len(rows), stored_unique_events=len(events),
                        acknowledged_pages=len(results), retry_kept_same_receipt=True,
                        incidents=cases, console_notifications=len(notices), http_daily_briefing=daily,
                        findings=[asdict(f) for f in findings],
                        evidence=[asdict(e) for e in events if e.event_id in referenced],
                        production_writes=False, model_calls=0,
                        limitations=['Authored fixtures are not an accuracy benchmark.',
                                     'The ASGI transport does not test a deployed TLS proxy or real Nginx rotation.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    report = simulate(Path(__file__).resolve().parents[1] / 'examples/http-access/access.jsonl')
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({k: v for k, v in report.items() if k not in ('evidence', 'findings', 'incidents')} |
                     {'incidents': len(report['incidents']), 'findings': [{'rule_id': f['rule_id'], 'evidence_count': len(f['evidence_ids'])} for f in report['findings']]}))


if __name__ == '__main__':
    main()
