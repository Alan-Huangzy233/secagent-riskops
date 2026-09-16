"""Fixed-command gateway rejects commands and unconfigured relay destinations."""
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('gateway', Path(__file__).parents[2] / 'scripts/control_gateway.py')
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)


@pytest.fixture
def config():
    return {'local_source_id': 'relay-a', 'ssh_config': '/etc/riskops-control/ssh_config',
            'relays': {'source-b': 'fixed-peer'}}


def test_local_command_is_fixed_interpreter_and_helper(config):
    command = gateway.command_for(config, {'version': 1, 'source_id': 'relay-a', 'action': 'check'})
    assert command == ['/usr/bin/sudo', '-n', '/usr/bin/python3', '-I', '/usr/local/sbin/riskops-ssh-control']


def test_relay_alias_and_config_only_come_from_configuration(config, monkeypatch):
    paths = []
    monkeypatch.setattr(gateway, 'secure_file', paths.append)
    command = gateway.command_for(config, {'version': 1, 'source_id': 'source-b', 'action': 'status'})
    assert paths == ['/etc/riskops-control/ssh_config']
    assert command[-1] == 'fixed-peer' and command[:4] == ['/usr/bin/ssh', '-T', '-F', paths[0]]


@pytest.mark.parametrize('extra', [{'source_id': 'unknown'}, {'source_id': ';id'}, {'action': 'exec'},
                                  {'command': 'id'}, {'version': True}, {'ssh_config': '/tmp/attacker'}])
def test_untrusted_commands_paths_and_sources_are_rejected(config, extra):
    with pytest.raises(ValueError):
        gateway.command_for(config, {'version': 1, 'source_id': 'relay-a', 'action': 'check', **extra})
