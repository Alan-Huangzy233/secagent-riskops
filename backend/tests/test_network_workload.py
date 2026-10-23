"""The small authored workload keeps local state separate and durable on replay."""
from pathlib import Path
import socket
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from simulate_network_workload import budget_result, simulate


@pytest.mark.parametrize('records, cases, batches', [(270, 4, 18), (204, 2, 12)])
def test_authored_workload_drains_three_sources_without_external_io(monkeypatch, records, cases, batches):
    def forbidden(*_args, **_kwargs):
        raise AssertionError('The synthetic workload must not access sockets or host commands')

    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    monkeypatch.setattr(socket.socket, 'connect_ex', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    result = simulate(records=records, page_size=17, backlog_pages=4)
    assert result['input_records'] == sum(result['source_records'].values()) == records
    assert result['incidents'] == result['console_incident_notifications'] == cases
    assert result['udp_observation_incidents'] == 0
    assert result['analysis_drained'] and result['reopened_store_replay_identical']
    assert result['replay_added_receipts'] == result['replay_added_batches'] == result['replay_added_notifications'] == 0
    metrics = result['metrics']
    assert metrics['receipt_growth'] == records and metrics['batch_growth'] == batches
    assert metrics['peak_unanalyzed_receipts'] > 0 and metrics['worker_ticks'] > 1
    assert metrics['network_pages_after'] > metrics['network_pages_before']
    assert metrics['file_samples'] > 0 and metrics['process_peak_rss_bytes'] > 0
    assert metrics['network_database_bytes_after'] > metrics['network_database_bytes_before']
    assert not result['production_writes'] and result['model_calls'] == 0


@pytest.mark.parametrize('kwargs', [{'records': 89}, {'records': True}, {'page_size': 201},
    {'backlog_pages': 0}, {'budget_seconds': float('nan')}, {'budget_rss_mib': 0}])
def test_workload_rejects_unbounded_or_unusable_parameters(kwargs):
    with pytest.raises(ValueError):
        simulate(**kwargs)


def test_engineering_budget_checks_time_and_whole_process_rss():
    within = {'elapsed_seconds': 5, 'process_peak_rss_bytes': 20 * 1024 * 1024}
    assert budget_result(within, 60, 512)['passed']
    assert not budget_result(within, 4, 512)['passed']
    assert not budget_result(within, 60, 19)['passed']
