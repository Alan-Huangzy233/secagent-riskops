"""A real SQLite reader blocks checkpoint; collector keeps and replays its batch."""
from contextlib import closing
from dataclasses import asdict
import json
from pathlib import Path
import sqlite3
import sys
import time

from fastapi.testclient import TestClient

from test_network_api import NET_TOKEN, app, config, password_hash, payload, profile  # noqa: F401
from app.telemetry.network_protocol import encode, validate_ack

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import network_collector as collector


def test_busy_api_preserves_original_pending_and_cursor_until_durable_retry(config, tmp_path):  # noqa: F811 — shared pytest fixture
    ssh = tmp_path / 'ssh.conf'
    ssh.write_text('Host synthetic\n HostName 192.0.2.1\n')
    ssh.chmod(0o600)
    cc = {'version': 1, 'state_dir': str(tmp_path / 'state'),
          'endpoint': 'http://127.0.0.1:8088/api/network/batches',
          'profile': asdict(profile()), 'ssh_config': str(ssh),
          'ssh_host': 'synthetic', 'token': NET_TOKEN}
    body = payload(0)
    with TestClient(app(config)) as client:
        store = client.app.state.network_store
        # Establish an old WAL snapshot while the actual worker is between
        # ticks. The read lock, rather than a mocked storage error, causes 503.
        with client.app.state.network_worker.lock:
            reader = sqlite3.connect(config.network_ingest.database_path, isolation_level=None)
            reader.execute('BEGIN')
            reader.execute('SELECT count(*) FROM network_meta').fetchone()
            with closing(sqlite3.connect(config.network_ingest.database_path, timeout=5)) as writer:
                writer.execute("INSERT OR REPLACE INTO network_meta VALUES('synthetic-held-reader','1')")
                writer.commit()
        statuses = []

        def send(_endpoint, _token, batch, _timeout):
            response = client.post('/api/network/batches', content=encode(batch),
                headers={'Authorization': 'Bearer '+NET_TOKEN, 'Content-Type': 'application/json'})
            statuses.append(response.status_code)
            if response.status_code != 200:
                assert response.status_code == 503 and response.json()['detail'] == 'network_storage_busy'
                assert 'durable' not in response.json()
                raise collector.CollectorError('http_rejected')
            validate_ack(response.json(), batch)
            return response.json()

        try:
            result = collector.run_once(cc, fetch=lambda *_: encode(body), send=send)
            assert result['status'] == 'error' and statuses == [503]
            pending = tmp_path / 'state/network.pending.json'
            state = tmp_path / 'state/network.state.json'
            original = pending.read_bytes()
            assert not state.exists()
            with store.connection() as db:
                assert db.execute('SELECT count(*) FROM network_receipts').fetchone()[0] == 0
                assert db.execute('SELECT count(*) FROM network_sources').fetchone()[0] == 0
        finally:
            reader.rollback()
            reader.close()

        def no_refetch(*_):
            raise AssertionError('Existing pending batch must be retried without another export')

        for _ in range(4):
            assert pending.read_bytes() == original
            result = collector.run_once(cc, fetch=no_refetch, send=send)
            if result['status'] == 'acknowledged':
                break
            time.sleep(0.05)
        assert result['status'] == 'acknowledged' and statuses[-1] == 200
        assert not pending.exists()
        assert json.loads(state.read_text())['cursor'] == body['cursor_after']
        with store.connection() as db:
            assert db.execute('SELECT count(*) FROM network_receipts').fetchone()[0] == 1
            assert db.execute('SELECT count(*) FROM network_batches').fetchone()[0] == 1
