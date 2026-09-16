from copy import deepcopy
import importlib.util
import ipaddress
import json
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace

import pytest

spec = importlib.util.spec_from_file_location('ssh_block_control',
    Path(__file__).parents[2] / 'scripts/ssh_block_control.py')
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)

NOW = 1800000000
CONFIG = control.validate_config({'source_id': 'source-a', 'ssh_ports': [2222],
                                 'protected_networks': ['198.51.100.0/24']})
NETWORKS = ['127.0.0.0/8', '198.51.100.0/24', '::1/128']


def request(action='add', request_id='request-1', **fields):
    value = {'version': 1, 'source_id': 'source-a', 'request_id': request_id,
             'action': action, 'ip': '203.0.113.30', 'channel': 'ssh'}
    if action == 'add':
        value['expires_at'] = NOW + 3600
    return {**value, **fields}


def nft_state(config=CONFIG, networks=NETWORKS, desired=None, now=NOW):
    entries = [next(iter(c.values())) for c in control.create_commands(config)]
    for entry in entries:
        value = entry.get('set')
        if not value:
            continue
        version = int(value['name'][-1])
        value['elem'] = []
        if value['name'].startswith('allow'):
            for n in networks:
                network = ipaddress.ip_network(n)
                if network.version == version:
                    value['elem'].append({'prefix': {'addr': str(network.network_address),
                                                     'len': network.prefixlen}})
        else:
            for (ip, channel), expiry in (desired or {}).items():
                if control.set_name(ip, channel) != value['name']:
                    continue
                if expiry is None:
                    value['elem'].append(ip)
                elif expiry > now:
                    value['elem'].append({'elem': {'val': ip, 'timeout': expiry-now,
                                                  'expires': expiry-now}})
    return {'nftables': [{'metainfo': {'json_schema_version': 1}}, *entries]}


class FakeFirewall(control.Firewall):
    def __init__(self):
        self.state = None
        self.calls = []
        self.fail = None
        self.readback_error = False

    def read(self, config):
        if self.calls and self.readback_error:
            raise control.ControlError('command_timeout')
        if self.state:
            self.validate_schema(self.state, config)
        return deepcopy(self.state)

    def apply(self, config, networks, desired, current, now):
        self.calls.append(deepcopy(desired))
        if self.fail == 'before':
            raise control.ControlError('nft_rejected')
        self.state = nft_state(config, networks, desired, now)
        if self.fail == 'after':
            raise control.ControlError('command_timeout', uncertain=True)
        if self.fail == 'missing':
            self.state = nft_state(config, networks, {}, now)
        if self.fail == 'protection':
            for entry in self.state['nftables']:
                if entry.get('set', {}).get('name') == 'allow4':
                    entry['set']['elem'] = []


@pytest.fixture
def harness(tmp_path):
    store = control.Store(tmp_path / 'control.sqlite')
    firewall = FakeFirewall()
    def run(payload, now=NOW, restore=False):
        return control.execute(payload, CONFIG, store, firewall, NETWORKS,
                               clock=lambda: now, restore=restore)
    yield store, firewall, run
    store.close()


@pytest.mark.parametrize('change', [
    {'ip': '203.0.113.0/24'}, {'ip': '203.0.113.30; reboot'}, {'ip': ['203.0.113.30']},
    {'ip': 'fe80::1%eth0'}, {'channel': 'all'}, {'channel': ['tcp', 'udp']},
    {'action': 'flush'}, {'version': True}, {'source_id': 'another-source'},
    {'request_id': 'bad\ncommand'}, {'request_id': 'x'*129}, {'command': 'id'},
    {'port': 443}, {'expires_at': True}, {'expires_at': -1}, {'expires_at': 'permanent'},
    {'ttl_seconds': True}, {'ttl_seconds': 86401}, {'ttl_seconds': 0},
])
def test_rejects_untyped_or_unbounded_fields(change):
    with pytest.raises(control.ControlError):
        control.validate_request(request(**change), CONFIG)


def test_add_requires_explicit_deadline_and_delete_cannot_take_one():
    value = request()
    del value['expires_at']
    with pytest.raises(control.ControlError, match='missing_deadline'):
        control.validate_request(value, CONFIG)
    with pytest.raises(control.ControlError, match='unexpected_deadline'):
        control.validate_request(request('delete', expires_at=None), CONFIG)


@pytest.mark.parametrize('raw', [
    {'source_id': 'source-a', 'ssh_ports': [22]},
    {'source_id': 'source-a', 'ssh_ports': [22], 'protected_networks': []},
    {'source_id': 'source-a', 'ssh_ports': [True], 'protected_networks': NETWORKS},
    {'source_id': 'source-a', 'ssh_ports': [22], 'protected_networks': ['198.51.100.1/24']},
    {'source_id': 'source-a', 'ssh_ports': [22], 'protected_networks': ['example.org']},
    {'source_id': 'source-a', 'ssh_ports': [22], 'protected_networks': NETWORKS, 'nft_path': '/tmp/nft'},
])
def test_config_requires_fixed_ports_and_valid_management_networks(raw):
    with pytest.raises(control.ControlError):
        control.validate_config(raw)


def test_add_delete_are_verified_and_old_add_retry_never_reblocks(harness):
    store, firewall, run = harness
    added = run(request())
    assert added['status'] == 'ok' and added['blocked'] is True
    assert added['expires_at'] == NOW+3600
    assert run(request('delete', 'delete-1'))['blocked'] is False
    replay = run(request(), now=NOW+300)
    assert replay['status'] == 'ok' and replay['blocked'] is False and replay['replayed']
    assert len(firewall.calls) == 2
    assert store.desired(NOW, NETWORKS) == {}


def test_same_request_id_cannot_change_target_or_deadline(harness):
    _, firewall, run = harness
    run(request())
    assert run(request(expires_at=NOW+7200))['code'] == 'request_id_conflict'
    assert run(request(ip='203.0.113.31'))['code'] == 'request_id_conflict'
    assert len(firewall.calls) == 1


def test_pending_crash_before_apply_reconciles_latest_intent(harness):
    store, firewall, run = harness
    original = request()
    validated = control.validate_request(original, CONFIG)
    desired = {(original['ip'], original['channel']): original['expires_at']}
    store.save(desired, validated, control.reply(validated, 'uncertain', 'pending_verification'))
    result = run(original, now=NOW+60)
    assert result['status'] == 'ok' and result['blocked'] is True
    assert firewall.calls == [desired]
    assert result['expires_at'] == NOW+3600


def test_pending_old_add_after_later_delete_never_resurrects(harness):
    store, firewall, run = harness
    original = request()
    store.save({(original['ip'], 'ssh'): NOW+3600}, original,
               control.reply(original, 'uncertain', 'pending_verification'))
    assert run(request('delete', 'delete-after-pending'))['blocked'] is False
    assert run(original)['blocked'] is False
    assert firewall.calls[-1] == {}


def test_timeout_is_uncertain_then_retry_reconciles_without_extending_ttl(harness):
    _, firewall, run = harness
    firewall.fail = 'after'
    assert run(request())['status'] == 'uncertain'
    firewall.fail = None
    result = run(request(), now=NOW+600)
    assert result['status'] == 'ok' and result['expires_at'] == NOW+3600
    assert result['remaining_seconds'] == 3000


def test_definite_rejection_rolls_back_intent_and_retry_does_not_apply(harness):
    store, firewall, run = harness
    firewall.fail = 'before'
    result = run(request())
    assert result['status'] == 'error'
    assert store.desired(NOW, NETWORKS) == {}
    firewall.fail = None
    assert run(request())['blocked'] is False
    assert len(firewall.calls) == 1


@pytest.mark.parametrize('mode', ['missing', 'protection'])
def test_does_not_report_success_without_complete_readback(harness, mode):
    _, firewall, run = harness
    firewall.fail = mode
    assert run(request())['status'] == 'uncertain'


def test_failed_post_apply_readback_is_uncertain(harness):
    _, firewall, run = harness
    firewall.readback_error = True
    assert run(request())['status'] == 'uncertain'


@pytest.mark.parametrize('ip', ['198.51.100.42', '127.0.0.2', '::1', '0.0.0.0',
                               '224.0.0.1', 'fe80::1', '::ffff:198.51.100.42'])
def test_management_local_and_special_addresses_are_never_blocked(harness, ip):
    _, firewall, run = harness
    result = run(request(ip=ip))
    assert result['code'] == 'protected_address'
    assert not firewall.calls


def test_local_interfaces_and_ssh_connection_are_added_to_protection(monkeypatch):
    monkeypatch.setattr(control, 'run_command', lambda *a, **k: [
        {'addr_info': [{'family': 'inet', 'local': '192.0.2.20'},
                       {'family': 'inet6', 'local': '2001:db8::20'}]}])
    monkeypatch.setenv('SSH_CONNECTION', '192.0.2.40 50000 192.0.2.20 2222')
    networks = control.local_protections(CONFIG)
    for ip in ('192.0.2.20', '192.0.2.40', '2001:db8::20', '198.51.100.42'):
        assert control.protected_ip(ip, networks)
    assert not control.protected_ip('203.0.113.30', networks)
    monkeypatch.setenv('SSH_CONNECTION', 'malformed')
    with pytest.raises(control.ControlError, match='invalid_ssh_connection'):
        control.local_protections(CONFIG)


def test_absent_local_address_inventory_fails_closed(monkeypatch):
    monkeypatch.setattr(control, 'run_command', lambda *a, **k: [])
    with pytest.raises(control.ControlError, match='local_addresses_unavailable'):
        control.local_protections(CONFIG)


def test_check_is_read_only_and_status_returns_all_channels(harness):
    _, firewall, run = harness
    check = {'version': 1, 'source_id': 'source-a', 'action': 'check', 'request_id': 'check-1'}
    assert run(check)['table_present'] is False
    assert not firewall.calls
    run(request(request_id='tcp-1', channel='tcp', expires_at=None))
    run(request(request_id='udp-1', channel='udp', ip='2001:db8::5'))
    status = run({**check, 'action': 'status'})
    assert len(status['blocks']) == 2
    assert {b['channel'] for b in status['blocks']} == {'tcp', 'udp'}
    assert len(firewall.calls) == 2


def test_reboot_restores_permanent_and_remaining_deadline_without_extension(harness):
    store, firewall, run = harness
    run(request(request_id='permanent', channel='tcp', expires_at=None))
    run(request(request_id='timed', channel='udp', expires_at=NOW+900))
    firewall.state = None
    restore = {'version': 1, 'source_id': 'source-a', 'action': 'check', 'request_id': 'restore-1'}
    result = run(restore, now=NOW+600, restore=True)
    assert result['status'] == 'ok'
    assert {b['channel']: b['expires_at'] for b in result['blocks']} == {'tcp': None, 'udp': NOW+900}
    firewall.state = None
    result = run({**restore, 'request_id': 'restore-2'}, now=NOW+1200, restore=True)
    assert result['blocks'] == [{'ip': '203.0.113.30', 'channel': 'tcp', 'expires_at': None}]
    assert store.db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0] == 2


def test_new_protection_on_restore_removes_old_desired_ban(harness):
    store, firewall, run = harness
    run(request())
    original = request('check', 'restore-protected')
    extra = NETWORKS + ['203.0.113.30/32']
    result = control.execute(original, CONFIG, store, firewall, extra,
                             clock=lambda: NOW, restore=True)
    assert result['status'] == 'ok' and result['blocked'] is False
    assert store.desired(NOW, extra) == {}


@pytest.mark.parametrize('expiry', [NOW, NOW-1, NOW+86401])
def test_deadline_outside_policy_never_mutates(harness, expiry):
    _, firewall, run = harness
    assert run(request(expires_at=expiry))['code'] == 'deadline_out_of_range'
    assert not firewall.calls


@pytest.mark.parametrize('mutate', [
    lambda s: s['nftables'][1]['table'].update(comment='foreign-table'),
    lambda s: s['nftables'][1]['table'].update(flags=['dormant']),
    lambda s: s['nftables'][2]['chain'].update(hook='forward'),
    lambda s: s['nftables'][2]['chain'].update(policy='drop'),
    lambda s: s['nftables'][3]['set'].update(timeout=86400),
    lambda s: s['nftables'].pop(),
    lambda s: s['nftables'].append({'rule': {'expr': [{'drop': None}]}}),
])
def test_schema_drift_is_rejected_without_mutation(harness, mutate):
    _, firewall, run = harness
    firewall.state = nft_state()
    mutate(firewall.state)
    with pytest.raises(control.ControlError, match='firewall_schema_mismatch'):
        run(request())
    assert not firewall.calls


def test_changed_ssh_ports_require_explicit_schema_migration(harness):
    _, firewall, _ = harness
    firewall.state = nft_state()
    with pytest.raises(control.ControlError, match='firewall_schema_mismatch'):
        firewall.read({**CONFIG, 'ssh_ports': [22]})


def test_generated_firewall_limits_input_and_uses_atomic_json(monkeypatch):
    calls = []
    monkeypatch.setattr(control, 'run_command', lambda *args, **kw: calls.append((args, kw)))
    firewall = control.Firewall()
    desired = {('203.0.113.30', 'ssh'): NOW+900, ('2001:db8::5', 'udp'): None}
    firewall.apply(CONFIG, NETWORKS, desired, None, NOW+600)
    args, kwargs = calls[-1]
    assert args[0] == ['/usr/sbin/nft', '-j', '-f', '-']
    assert kwargs['mutation'] is True
    commands = args[1]['nftables']
    assert all('flush' not in cmd for cmd in commands)
    chain = next(cmd['add']['chain'] for cmd in commands if 'chain' in cmd.get('add', {}))
    assert chain['hook'] == 'input' and chain['policy'] == 'accept'
    timed = next(cmd['add']['element'] for cmd in commands if cmd.get('add', {}).get('element', {}).get('name') == 'ssh4')
    assert timed['elem'] == [{'elem': {'val': '203.0.113.30', 'timeout': 300}}]
    permanent = next(cmd['add']['element'] for cmd in commands if cmd.get('add', {}).get('element', {}).get('name') == 'udp6')
    assert permanent['elem'] == ['2001:db8::5']
    firewall.apply(CONFIG, NETWORKS, desired, nft_state(), NOW+600)
    for cmd in calls[-1][0][1]['nftables']:
        if 'flush' in cmd:
            assert set(cmd['flush']) == {'set'}
            assert cmd['flush']['set']['table'] == control.TABLE


def test_subprocess_never_uses_shell_or_caller_environment(monkeypatch):
    seen = []
    def fake_run(argv, **kwargs):
        seen.append((argv, kwargs))
        kwargs['stdout'].write(b'{"nftables":[]}')
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(control.subprocess, 'run', fake_run)
    monkeypatch.setenv('LD_PRELOAD', '/tmp/unsafe.so')
    control.run_command(['/usr/sbin/nft', '-j', '-f', '-'], {'nftables': []}, mutation=True)
    _, options = seen[0]
    assert 'shell' not in options and options['timeout'] == 10
    assert 'LD_PRELOAD' not in options['env']
    assert json.loads(options['input']) == {'nftables': []}


def test_subprocess_timeout_mutation_returns_uncertain_without_stderr(monkeypatch):
    def fail(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 10, stderr=b'private-secret')
    monkeypatch.setattr(control.subprocess, 'run', fail)
    with pytest.raises(control.ControlError) as error:
        control.run_command(['/usr/sbin/nft'], mutation=True)
    assert error.value.uncertain
    assert str(error.value) == 'command_timeout'


@pytest.mark.parametrize('mode,uid', [(stat.S_IFREG | 0o666, 0), (stat.S_IFREG | 0o600, 1000),
                                    (stat.S_IFLNK | 0o777, 0)])
def test_config_file_cannot_be_untrusted_or_symlink(mode, uid):
    path = SimpleNamespace(lstat=lambda: SimpleNamespace(st_mode=mode, st_uid=uid), parents=[])
    with pytest.raises(control.ControlError, match='unsafe_permissions'):
        control.secure_path(path, private=True)


def test_config_parent_cannot_be_group_writable():
    parent = SimpleNamespace(lstat=lambda: SimpleNamespace(st_mode=stat.S_IFDIR | 0o775, st_uid=0))
    path = SimpleNamespace(lstat=lambda: SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0),
                           parents=[parent])
    with pytest.raises(control.ControlError, match='unsafe_permissions'):
        control.secure_path(path, private=True)
