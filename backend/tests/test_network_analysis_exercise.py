"""Run the authored end-to-end exercise without host commands or network I/O."""
from pathlib import Path
import socket
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from simulate_network_analysis import simulate


def test_continuous_network_exercise_is_isolated_and_replayable(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError('The authored network exercise must not use outbound sockets or host commands')

    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    monkeypatch.setattr(socket.socket, 'connect_ex', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    result = simulate()
    assert result['before_threshold_incidents'] == 0
    assert result['incidents'] == result['console_notifications'] == 2
    assert result['incident_revisions'] == [1, 2]
    assert result['evidence_counts'] == [10, 11]
    assert result['stored_unique_events'] + result['rejected_records'] == result['input_records'] == 24
    assert result['restart_preserved_incidents_and_original_ack']
    assert result['historical_evidence_retained'] and result['console_commit_retry_idempotent']
    assert not result['production_writes'] and result['model_calls'] == 0
