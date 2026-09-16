from pathlib import Path
import importlib.util
import io
import json

import pytest

spec = importlib.util.spec_from_file_location('journal_export', Path(__file__).parents[2] / 'scripts/journal_export.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@pytest.mark.parametrize('payload', [
    {'source_id': 'arbitrary-host'},
    {'source_id': ['source-a']},
    {'source_id': '../source-a'},
    {'source_id': 'source-a', 'cursor': 'x\ncommand'},
    {'source_id': 'source-a', 'command': 'id'},
    {'source_id': 'source-a', 'limit': 201},
    {'source_id': 'source-a', 'limit': True},
    {'source_id': 'source-a', 'since_minutes': 10000},
])
def test_export_rejects_unbounded_or_injected_request(payload):
    with pytest.raises(ValueError):
        module.validate_request(payload, {"source-a", "source-b"})


def test_export_cursor_is_an_argv_value_and_never_tails_backlog():
    request = module.validate_request({'source_id': 'source-a', 'cursor': 's=abc;i=123;b=def'}, {"source-a", "source-b"})
    command = module.journal_command(request, True)
    assert '--after-cursor=s=abc;i=123;b=def' in command
    assert '-n' not in command
    assert not any(x.startswith('--lines') for x in command)
    assert not any(x.startswith('--since') for x in command)


def test_export_initial_or_vacuumed_cursor_uses_bounded_time():
    request = module.validate_request({'source_id': 'source-b', 'cursor': 's=abc', 'since_minutes': 10}, {"source-a", "source-b"})
    command = module.journal_command(request, False)
    assert '--since=-10min' in command


def test_export_large_backlog_returns_bounded_prefix(monkeypatch, capsys):
    records = [{'__CURSOR': f's=abc;i={i}', '__REALTIME_TIMESTAMP': '1788870000000000',
                'MESSAGE': 'x' * 60000} for i in range(100)]
    class Process:
        def __init__(self, *args, **kwargs):
            self.stdout = io.BytesIO(b''.join(json.dumps(r).encode() + b'\n' for r in records))
            self.returncode = None
        def poll(self):
            return self.returncode
        def terminate(self):
            self.returncode = -15
        def communicate(self, timeout):
            return b'', b''
    monkeypatch.setattr(module.subprocess, 'Popen', Process)
    module.local_export(module.validate_request({'source_id': 'source-a'}, {"source-a", "source-b"}))
    output = capsys.readouterr().out
    assert len(output.encode()) < module.MAX_OUTPUT_BYTES
    lines = [json.loads(line) for line in output.splitlines()]
    assert 1 < len(lines) - 1 < 100
    assert lines[0]['__CURSOR'] == records[0]['__CURSOR']
    assert lines[-1]['__riskops_checkpoint__'] == lines[-2]['__CURSOR']


def test_main_serves_only_sources_from_root_configuration(tmp_path, monkeypatch):
    config = tmp_path / 'export.json'
    config.write_text(json.dumps({'local_source_id': 'custom-node', 'relays': {}}))
    monkeypatch.setattr(module, 'CONFIG_PATH', config)
    monkeypatch.delenv('SSH_ORIGINAL_COMMAND', raising=False)
    calls = []
    monkeypatch.setattr(module, 'local_export', calls.append)
    monkeypatch.setattr(module.sys, 'stdin', io.TextIOWrapper(io.BytesIO(b'{"source_id":"custom-node"}')))
    assert module.main() == 0
    assert calls[0]['source_id'] == 'custom-node'
    monkeypatch.setattr(module.sys, 'stdin', io.TextIOWrapper(io.BytesIO(b'{"source_id":"source-a"}')))
    with pytest.raises(ValueError, match='unknown source'):
        module.main()
    assert len(calls) == 1


def test_main_relays_only_to_fixed_configured_target(tmp_path, monkeypatch):
    config = tmp_path / 'export.json'
    config.write_text(json.dumps({'local_source_id': 'relay-node', 'relays': {
        'custom-node': {'ssh_config': '/etc/ssh/riskops-example.conf', 'host': 'export-example'}
    }}))
    monkeypatch.setattr(module, 'CONFIG_PATH', config)
    monkeypatch.delenv('SSH_ORIGINAL_COMMAND', raising=False)
    monkeypatch.setattr(module.sys, 'stdin', io.TextIOWrapper(io.BytesIO(b'{"source_id":"custom-node"}')))
    output = io.BytesIO()
    monkeypatch.setattr(module.sys, 'stdout', io.TextIOWrapper(output))
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return module.subprocess.CompletedProcess(command, 0, stdout=b'checkpoint\n')
    monkeypatch.setattr(module.subprocess, 'run', run)
    assert module.main() == 0
    assert calls[0][0] == ['/usr/bin/ssh', '-T', '-F', '/etc/ssh/riskops-example.conf', 'export-example']
    assert json.loads(calls[0][1]['input'])['source_id'] == 'custom-node'
    assert output.getvalue() == b'checkpoint\n'
