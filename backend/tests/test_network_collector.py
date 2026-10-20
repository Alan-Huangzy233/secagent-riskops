"""Synthetic durable retry, receipt binding and finite-work transport checks."""
from dataclasses import asdict
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import network_collector as collector
from app.telemetry.network_parse import SourceProfile
from app.telemetry.network_protocol import encode, fingerprint, journal_entry, profile_from_dict

NOW = 1_790_000_000_000_000


@pytest.fixture
def config(tmp_path):
    ssh = tmp_path / 'network-ssh.conf'
    ssh.write_text('Host source-alias\n HostName 192.0.2.20\n User network-export\n IdentityFile /synthetic/key\n')
    ssh.chmod(0o600)
    return {'version': 1, 'endpoint': 'http://127.0.0.1:8088/api/network/batches',
            'state_dir': str(tmp_path / 'state'), 'ssh_config': str(ssh), 'ssh_host': 'source-alias',
            'token': 'synthetic-secret-never-in-pending-12345',
            'profile': asdict(SourceProfile(source_id='synthetic-network', ruleset_sha256='a' * 64,
                log_labels=('[UFW BLOCK]',), rejection_labels=('[UFW BLOCK]',),
                local_input_labels=('[UFW BLOCK]',), local_input_interfaces=('eth0',)))}


def batch(config, before=None, index=1, reports=None, empty=False):
    profile = profile_from_dict(config['profile'])
    row = {'_TRANSPORT': 'kernel', '_BOOT_ID': 'b' * 32, '__CURSOR': f'cursor-{index}',
           '__REALTIME_TIMESTAMP': str(NOW), '__MONOTONIC_TIMESTAMP': str(index),
           'MESSAGE': '[UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.23 DST=192.0.2.10 '
                      'PROTO=TCP SPT=40000 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0'}
    reports = [] if reports is None else reports
    return {'version': 1, 'source_id': profile.source_id, 'profile_revision': profile.revision,
            'batch_id': f'batch-{index}', 'collected_at_us': NOW, 'cursor_before': before,
            'cursor_after': before if empty else f'cursor-{index}',
            'entries': [] if empty else [journal_entry(row, profile)], 'reports': reports,
            'caught_up': not bool(set(reports) & {'catching_up', 'profile_drift', 'journal_cursor_unavailable'})}


def ack(body, duplicate=False):
    result = {key: value for key, value in body.items() if key != 'entries'}
    results = []
    for entry in body['entries']:
        value = next(iter(entry.values()))
        results.append({'event_id': value['event_id'], 'content_hash': value['content_hash'],
                        'status': 'duplicate' if duplicate else ('accepted' if 'event' in entry else 'rejected'),
                        'code': None if 'event' in entry else value['code']})
    result.update(payload_hash=fingerprint(body), durable=True, received_at_us=NOW + 10,
                  results=results, accepted=sum(r['status'] == 'accepted' for r in results),
                  rejected=sum(r['status'] == 'rejected' for r in results),
                  duplicates=sum(r['status'] == 'duplicate' for r in results))
    return result


def durable(endpoint, token, body, timeout):
    return ack(body)


def fail_send(*args):
    raise collector.CollectorError('http_unavailable')


def state_path(config):
    return Path(config['state_dir']) / 'network.state.json'


def pending_path(config):
    return Path(config['state_dir']) / 'network.pending.json'


def test_pending_is_durable_before_send_and_identical_after_lost_ack(config):
    sent, fetched = [], []
    def fetch(config, cursor, timeout):
        fetched.append(cursor)
        return encode(batch(config))
    def committed_but_lost_ack(endpoint, token, body, timeout):
        assert json.loads(pending_path(config).read_text())['batch'] == body
        sent.append(body)
        raise collector.CollectorError('http_timeout')
    first = collector.run_once(config, fetch, committed_but_lost_ack)
    assert first['code'] == 'http_timeout' and not state_path(config).exists()
    assert config['token'] not in pending_path(config).read_text()
    def retry(endpoint, token, body, timeout):
        sent.append(body)
        return ack(body, duplicate=True)
    second = collector.run_once(config, fetch, retry)
    assert second['status'] == 'acknowledged' and fetched == [None]
    assert sent[0] == sent[1]
    assert json.loads(state_path(config).read_text())['cursor'] == 'cursor-1'
    assert not pending_path(config).exists()


@pytest.mark.parametrize('change', [
    lambda value: value.update(source_id='wrong'), lambda value: value.update(durable=False),
    lambda value: value.update(payload_hash='c' * 64), lambda value: value.update(cursor_after='wrong'),
    lambda value: value.update(profile_revision='c' * 64), lambda value: value.update(results=[]),
    lambda value: value['results'][0].update(content_hash='c' * 64),
    lambda value: value['results'][0].update(status='rejected'), lambda value: value.update(accepted=True),
])
def test_every_ack_binding_is_required_before_cursor_advancement(config, change):
    def send(endpoint, token, body, timeout):
        value = ack(body)
        change(value)
        return value
    result = collector.run_once(config, lambda *a: encode(batch(config)), send)
    assert result['code'] == 'invalid_network_ack'
    assert pending_path(config).exists() and not state_path(config).exists()


def test_crash_after_state_commit_before_pending_unlink_replays_exact_batch(config, monkeypatch):
    original = Path.unlink
    def crash(path, *a, **kwargs):
        if path.name == 'network.pending.json':
            raise OSError('synthetic crash')
        return original(path, *a, **kwargs)
    monkeypatch.setattr(Path, 'unlink', crash)
    first = collector.run_once(config, lambda *a: encode(batch(config)), durable)
    assert first['code'] == 'local_network_storage_failed'
    assert state_path(config).exists() and pending_path(config).exists()
    pending = json.loads(pending_path(config).read_text())['batch']
    monkeypatch.setattr(Path, 'unlink', original)
    sent = []
    def send(endpoint, token, body, timeout):
        sent.append(body)
        return ack(body, duplicate=True)
    second = collector.run_once(config, lambda *a: pytest.fail('must replay'), send)
    assert second['status'] == 'acknowledged' and sent == [pending]


def test_failed_state_fsync_keeps_spooled_retry(config, monkeypatch):
    original = collector.atomic_write
    def fail_state(path, value):
        if path.name == 'network.state.json':
            raise OSError('synthetic storage failure')
        original(path, value)
    monkeypatch.setattr(collector, 'atomic_write', fail_state)
    result = collector.run_once(config, lambda *a: encode(batch(config)), durable)
    assert result['code'] == 'local_network_storage_failed' and pending_path(config).exists()
    assert not state_path(config).exists()
    monkeypatch.setattr(collector, 'atomic_write', original)
    assert collector.run_once(config, lambda *a: pytest.fail('retry expected'), durable)['status'] == 'acknowledged'


@pytest.mark.parametrize('change', [
    lambda value: value['batch'].update(cursor_after='corrupt'),
    lambda value: value.update(payload_hash='c' * 64),
    lambda value: value.update(identity='c' * 64),
    lambda value: value['batch'].update(source_id='wrong'),
    lambda value: value['batch'].update(profile_revision='c' * 64),
])
def test_corrupt_pending_never_fetches_or_advances(config, change):
    collector.run_once(config, lambda *a: encode(batch(config)), fail_send)
    value = json.loads(pending_path(config).read_text())
    change(value)
    collector.atomic_write(pending_path(config), value)
    result = collector.run_once(config, lambda *a: pytest.fail('unsafe fetch'), lambda *a: pytest.fail('unsafe send'))
    assert result['code'] == 'invalid_network_spool' and pending_path(config).exists()
    assert not state_path(config).exists()


def test_profile_endpoint_and_ssh_mapping_change_cannot_retarget_pending(config):
    collector.run_once(config, lambda *a: encode(batch(config)), fail_send)
    changes = [dict(endpoint='https://example.test/api/network/batches'), dict(ssh_host='other-alias'),
               dict(profile={**config['profile'], 'ruleset_sha256': 'c' * 64})]
    for change in changes:
        changed = {**config, **change}
        result = collector.run_once(changed, lambda *a: pytest.fail('no fetch'), lambda *a: pytest.fail('no send'))
        assert result['code'] == 'invalid_network_spool'
    with Path(config['ssh_config']).open('a') as stream:
        stream.write(' HostName 192.0.2.21\n')
    assert collector.run_once(config, lambda *a: b'', durable)['code'] == 'invalid_network_spool'


def test_token_rotation_preserves_mapping_and_retry(config):
    collector.run_once(config, lambda *a: encode(batch(config)), fail_send)
    rotated = {**config, 'token': 'new-synthetic-token-for-retry-123456'}
    result = collector.run_once(rotated, lambda *a: pytest.fail('must retry'), durable)
    assert result['status'] == 'acknowledged'


def test_spool_capacity_stops_before_send_without_checkpoint(config):
    limited = {**config, 'max_spool_bytes': 1024}
    result = collector.run_once(limited, lambda *a: encode(batch(config)), lambda *a: pytest.fail('spool before send'))
    assert result['code'] == 'network_spool_capacity'
    assert not state_path(config).exists() and not pending_path(config).exists()


def test_catchup_is_at_most_five_pages_and_passes_remaining_deadlines(config):
    fetches = []
    def fetch(config, cursor, timeout):
        index = len(fetches) + 1
        fetches.append((cursor, timeout))
        return encode(batch(config, before=cursor, index=index, reports=['catching_up']))
    result = collector.run_once(config, fetch, durable)
    assert result['pages'] == 5 and result['caught_up'] is False
    assert [c for c, _ in fetches] == [None, 'cursor-1', 'cursor-2', 'cursor-3', 'cursor-4']
    assert all(0 < timeout <= 10 for _, timeout in fetches)
    assert json.loads(state_path(config).read_text())['cursor'] == 'cursor-5'


def test_deadline_between_fetch_and_post_retains_pending(config):
    values = iter([0, 0, 21, 21])
    result = collector.run_once(config, lambda *a: encode(batch(config)), lambda *a: pytest.fail('budget exceeded'),
                                clock=lambda: next(values))
    assert result['code'] == 'run_deadline' and pending_path(config).exists()
    assert not state_path(config).exists()


@pytest.mark.parametrize('reports', [['profile_drift'], ['journal_cursor_unavailable'], ['profile_boundary']])
def test_source_health_reports_remain_visible_and_empty_batch_preserves_cursor(config, reports):
    body = batch(config, reports=reports, empty=True)
    result = collector.run_once(config, lambda *a: encode(body), durable)
    assert result['report_codes'] == reports and result['pages'] == 1
    assert json.loads(state_path(config).read_text())['cursor'] is None
    assert result['caught_up'] == (reports == ['profile_boundary'])
    assert result['status'] == ('acknowledged' if reports == ['profile_boundary'] else 'degraded')


@pytest.mark.parametrize('change', [
    {'max_pages_per_run': 6}, {'max_seconds_per_run': 21}, {'max_spool_bytes': 16 * 1024 * 1024 + 1},
    {'ssh_timeout_seconds': True}, {'endpoint': 'http://example.test/api/network/batches'},
    {'endpoint': 'https://example.test/api/telemetry/batches'}, {'ssh_host': '-oProxyCommand=bad'},
    {'ssh_command': ['arbitrary']}, {'state_dir': 'relative'},
])
def test_configuration_cannot_expand_namespace_scope_or_hard_limits(config, change):
    with pytest.raises(collector.CollectorError, match='invalid_network_config'):
        collector.validate_config({**config, **change})


def test_fixed_ssh_argv_and_request_contain_no_remote_command_or_token(config, monkeypatch):
    calls = []
    def chunks(command, **kwargs):
        calls.append((command, kwargs))
        yield encode(batch(config))
    monkeypatch.setattr(collector, 'command_chunks', chunks)
    collector.ssh_export(config, 'opaque/cursor with spaces', 3)
    command, options = calls[0]
    assert command[0] == '/usr/bin/ssh' and command[-1] == 'source-alias'
    assert '-F' in command and '-oStrictHostKeyChecking=yes' in command and '-oClearAllForwardings=yes' in command
    assert json.loads(options['input_data']) == {'source_id': 'synthetic-network', 'cursor': 'opaque/cursor with spaces'}
    assert config['token'] not in repr(calls)
    assert options['maximum'] == 1024 * 1024 + 1


def test_duplicate_json_and_wrong_cursor_export_do_not_create_pending(config):
    for raw in (b'{"version":1,"version":1}', encode(batch(config, before='unrequested'))):
        result = collector.run_once(config, lambda *a: raw, durable)
        assert result['code'] == 'invalid_network_export'
        assert not pending_path(config).exists() and not state_path(config).exists()


def test_lock_and_private_state_permissions(config):
    directory = Path(config['state_dir'])
    directory.mkdir(mode=0o700)
    with collector.collector_lock(directory):
        result = collector.run_once(config, lambda *a: pytest.fail('locked'), durable)
        assert result['code'] == 'collector_locked'
    directory.chmod(0o755)
    with pytest.raises(collector.CollectorError, match='unsafe_network_state_directory'):
        collector.run_once(config, lambda *a: b'', durable)


@pytest.mark.parametrize('directive', ['Include /other/config', 'Match exec "id"', 'ProxyCommand arbitrary', 'RemoteCommand id'])
def test_ssh_mapping_requires_self_contained_nonexecuting_config(config, directive):
    Path(config['ssh_config']).write_text(directive + '\n')
    result = collector.run_once(config, lambda *a: pytest.fail('unsafe mapping'), durable)
    assert result['code'] == 'unsafe_network_ssh_config'


def test_secret_config_rejects_readable_permissions(config, tmp_path):
    path = tmp_path / 'collector.json'
    path.write_bytes(encode(config))
    path.chmod(0o644)
    with pytest.raises(collector.CollectorError, match='invalid_network_config'):
        collector.load_config(path)
    path.chmod(0o600)
    assert collector.load_config(path)['ssh_host'] == 'source-alias'


def test_rejected_metadata_commits_but_summary_is_degraded(config):
    body = batch(config)
    profile = profile_from_dict(config['profile'])
    record = {'_TRANSPORT': 'kernel', '_BOOT_ID': 'b' * 32, '__CURSOR': 'cursor-1',
              '__REALTIME_TIMESTAMP': str(NOW), '__MONOTONIC_TIMESTAMP': '1',
              'MESSAGE': '[UFW BLOCK] malformed synthetic record'}
    body['entries'] = [journal_entry(record, profile)]
    result = collector.run_once(config, lambda *a: encode(body), durable)
    assert result['status'] == 'degraded' and result['code'] == 'network_records_rejected'
    assert result['rejected_records'] == 1 and result['rejection_codes'] == ['invalid_record']
    assert json.loads(state_path(config).read_text())['cursor'] == 'cursor-1'


def test_orphan_atomic_write_temporaries_count_toward_spool_quota(config):
    directory = Path(config['state_dir'])
    directory.mkdir(mode=0o700)
    orphan = directory / ('network.pending.json.' + 'a' * 32 + '.tmp')
    with orphan.open('wb') as stream:
        stream.truncate(16 * 1024 * 1024 + 1)
    orphan.chmod(0o600)
    result = collector.run_once(config, lambda *a: pytest.fail('quota before fetch'), durable)
    assert result['code'] == 'network_spool_capacity' and orphan.exists()
    assert not state_path(config).exists() and not pending_path(config).exists()


def test_spool_reserves_cursor_atomic_write_before_transmission(config):
    body = batch(config)
    mapping = collector.identity(config)
    pending = {'version': 1, 'identity': mapping, 'payload_hash': fingerprint(body), 'batch': body}
    limited = {**config, 'max_spool_bytes': len(encode(pending)) + 50}
    result = collector.run_once(limited, lambda *a: encode(body), lambda *a: pytest.fail('no space for durable state'))
    assert result['code'] == 'network_spool_capacity'
    assert not pending_path(config).exists() and not state_path(config).exists()


@pytest.mark.parametrize('kind', ['foreign', 'symlink'])
def test_untrusted_spool_artifacts_do_not_escape_quota(config, kind):
    directory = Path(config['state_dir'])
    directory.mkdir(mode=0o700)
    if kind == 'foreign':
        (directory / 'foreign.data').write_text('unowned namespace')
    else:
        (directory / ('network.pending.json.' + 'a' * 32 + '.tmp')).symlink_to(config['ssh_config'])
    result = collector.run_once(config, lambda *a: pytest.fail('unsafe spool'), durable)
    assert result['code'] == 'unsafe_network_spool_entry'


def test_symlink_lock_does_not_create_or_touch_an_outside_target(config):
    directory = Path(config['state_dir'])
    directory.mkdir(mode=0o700)
    outside = directory.parent / 'outside-must-not-exist'
    (directory / 'collector.lock').symlink_to(outside)
    result = collector.run_once(config, lambda *a: pytest.fail('unsafe lock'), durable)
    assert result['code'] == 'unsafe_network_lock' and not outside.exists()
