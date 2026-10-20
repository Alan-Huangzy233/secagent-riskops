"""Synthetic journal/export boundary checks; no source host is contacted."""
from dataclasses import asdict
import os
from pathlib import Path
import sys
import time

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import network_export as exporter
from app.telemetry.network_parse import SourceProfile
from app.telemetry.network_protocol import encode

NOW = 1_790_000_000_000_000


def source_profile():
    return SourceProfile(source_id='synthetic-network', ruleset_sha256='a' * 64,
                         log_labels=('[UFW BLOCK]',), rejection_labels=('[UFW BLOCK]',),
                         local_input_labels=('[UFW BLOCK]',), local_input_interfaces=('eth0',),
                         logging_limit='rate_limited')


@pytest.fixture
def config():
    return {'version': 1, 'profile': asdict(source_profile()), 'profile_valid_from_us': NOW - 300_000_000}


def record(index=0, **changes):
    value = {'_TRANSPORT': 'kernel', '_BOOT_ID': 'b' * 32, '__CURSOR': f'opaque-cursor-{index}',
             '__REALTIME_TIMESTAMP': str(NOW - 100_000_000 + index), '__MONOTONIC_TIMESTAMP': str(index),
             'MESSAGE': '[UFW BLOCK] IN=eth0 OUT= MAC=00:00:5e:00:53:01 SRC=198.51.100.23 DST=192.0.2.10 '
                        'LEN=60 PROTO=TCP SPT=40000 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0'}
    value.update(changes)
    return value


def page(config, records=(), cursor=None, **kwargs):
    return exporter.export_page(config, {'source_id': 'synthetic-network', 'cursor': cursor},
                                now_us=NOW, exists=kwargs.pop('exists', lambda _: True),
                                rules=kwargs.pop('rules', lambda **_: 'a' * 64),
                                read=kwargs.pop('read', lambda *a, **k: iter(records)), **kwargs)


def test_first_page_is_normalized_and_explicitly_limited_to_profile_context(config):
    commands = []
    def read(command, **kwargs):
        commands.append(command)
        return iter([record()])
    result = page(config, read=read)
    assert result['reports'] == ['coverage_start', 'profile_boundary']
    assert result['cursor_before'] is None and result['cursor_after'] == 'opaque-cursor-0'
    assert result['caught_up'] is True
    assert result['entries'][0]['event']['direction'] == 'local_input'
    assert b'MESSAGE' not in encode(result) and b'00:00:5e:00:53:01' not in encode(result)
    command = commands[0]
    assert command[0] == '/usr/bin/journalctl' and '_TRANSPORT=kernel' in command and '--all' in command
    assert not any(arg == '-n' or arg.startswith('--lines') for arg in command)
    assert '--since=' in ' '.join(command)
    assert any(arg.startswith('--grep=^') and r'\[UFW\ BLOCK\]' in arg for arg in command)


def test_exact_cursor_resume_and_vacuum_restart_have_distinct_visible_reports(config):
    commands = []
    def read(command, **kwargs):
        commands.append(command)
        return iter([record()])
    resumed = page(config, cursor='old opaque/cursor', read=read)
    assert resumed['reports'] == []
    assert '--after-cursor=old opaque/cursor' in commands[-1]
    reset = page(config, cursor='old opaque/cursor', exists=lambda _: False, read=read)
    assert 'journal_cursor_unavailable' in reset['reports'] and reset['caught_up'] is False
    assert not any(arg.startswith('--after-cursor') for arg in commands[-1])
    assert reset['cursor_before'] == 'old opaque/cursor'
    assert reset['cursor_after'] == 'opaque-cursor-0'
    empty = page(config, cursor='old opaque/cursor', exists=lambda _: False)
    assert empty['cursor_after'] == 'old opaque/cursor'  # No fabricated checkpoint.


def test_profile_context_and_reboot_are_not_conflated_with_missing_history(config):
    old = record(__REALTIME_TIMESTAMP=str(config['profile_valid_from_us'] - 1))
    recent = record(1, _BOOT_ID='c' * 32)
    result = page(config, [old, recent], cursor='previous')
    assert result['entries'][0]['rejection']['code'] == 'profile_context_unavailable'
    assert 'profile_boundary' in result['reports']
    assert 'journal_cursor_unavailable' not in result['reports']
    assert result['entries'][1]['event']['boot_id'] == 'c' * 32
    assert result['caught_up'] is True


@pytest.mark.parametrize('change_before', [True, False])
def test_rules_drift_discards_page_without_advancing(change_before, config):
    calls = []
    def rules(**kwargs):
        calls.append('rules')
        return 'c' * 64 if change_before or len(calls) == 2 else 'a' * 64
    result = page(config, [record()], cursor='previous', rules=rules)
    assert result['entries'] == [] and result['reports'] == ['profile_drift']
    assert result['cursor_before'] == result['cursor_after'] == 'previous'
    assert result['caught_up'] is False
    assert len(calls) == (1 if change_before else 2)


def test_oldest_record_prefix_is_bounded_and_generator_is_closed(config):
    visited = []
    closed = []
    def records():
        try:
            for index in range(300):
                visited.append(index)
                yield record(index)
        finally:
            closed.append(True)
    result = page(config, read=lambda *a, **k: records())
    assert len(result['entries']) == 200 and visited == list(range(200)) and closed == [True]
    assert result['cursor_after'] == 'opaque-cursor-199' and result['caught_up'] is False
    assert 'catching_up' in result['reports'] and len(encode(result)) <= 1024 * 1024


def test_batch_byte_limit_stops_before_next_uncommitted_record(config, monkeypatch):
    monkeypatch.setattr(exporter, 'MAX_BATCH_BYTES', 4096)
    result = page(config, [record(index) for index in range(10)])
    assert 0 < len(result['entries']) < 10 and len(encode(result)) <= 4096
    assert result['cursor_after'] == result['entries'][-1]['event']['journal_cursor']
    assert 'catching_up' in result['reports']


def test_malformed_packet_with_valid_journal_identity_is_a_redacted_rejection(config):
    result = page(config, [record(MESSAGE='[UFW BLOCK] secret malformed packet')])
    assert result['entries'][0]['rejection']['code'] == 'invalid_record'
    assert b'secret' not in encode(result)
    with pytest.raises(ValueError):
        page(config, [record(_BOOT_ID='unusable')])


@pytest.mark.parametrize('value', [
    {'source_id': 'other', 'cursor': None}, {'source_id': 'synthetic-network', 'cursor': None, 'limit': 500},
    {'source_id': 'synthetic-network', 'cursor': None, 'command': 'id'},
    {'source_id': 'synthetic-network', 'cursor': 'x' * 2049},
    {'source_id': 'synthetic-network', 'cursor': 'bad\ncursor'},
])
def test_caller_cannot_change_export_scope(value):
    with pytest.raises(exporter.ExportError, match='invalid_export_request'):
        exporter.validate_request(value, source_profile())


def test_rules_snapshot_excludes_only_generation_comments_and_chain_counters():
    before = b'# generated yesterday\n*filter\n:INPUT DROP [12:340]\n-A INPUT -p tcp --dport 443 -j LOG --log-prefix "[1:2]"\nCOMMIT\n'
    after = before.replace(b'yesterday', b'today').replace(b'[12:340]', b'[999:8888]')
    assert exporter.normalized_rules(before) == exporter.normalized_rules(after)
    for changed in (before.replace(b'--dport 443', b'--dport 444'),
                    before.replace(b'"[1:2]"', b'"[3:4]"'),
                    before.replace(b'"[1:2]"', b'"-c"'),
                    before.replace(b'"[1:2]"', b'"--comment"')):
        assert exporter.normalized_rules(before) != exporter.normalized_rules(changed)
    rule_comment = b'-A INPUT -m comment --comment "note one" -j DROP\n'
    assert exporter.normalized_rules(rule_comment) != exporter.normalized_rules(rule_comment.replace(b'one', b'two'))
    commands = []
    def run(command, **kwargs):
        commands.append(command)
        assert kwargs['maximum'] == 4 * 1024 * 1024
        return before
    assert len(exporter.ruleset_fingerprint(deadline=time.monotonic() + 5, run=run)) == 64
    assert commands == [['/usr/sbin/iptables-save'], ['/usr/sbin/ip6tables-save']]


def test_subprocess_helper_caps_output_and_wall_time():
    with pytest.raises(exporter.ExportError, match='subprocess_output_limit'):
        exporter.run_command([sys.executable, '-c', 'print("x" * 1000)'], deadline=time.monotonic() + 2, maximum=10)
    started = time.monotonic()
    with pytest.raises(exporter.ExportError, match='subprocess_deadline'):
        exporter.run_command([sys.executable, '-c', 'import time; time.sleep(3)'], deadline=time.monotonic() + .05, maximum=1024)
    assert time.monotonic() - started < 2


def test_raw_journal_reader_rejects_duplicates_truncated_and_oversized_lines(monkeypatch):
    for raw in (b'{"MESSAGE":1,"MESSAGE":2}\n', b'{"MESSAGE":1}', b'x' * 65537 + b'\n'):
        monkeypatch.setattr(exporter, 'command_chunks', lambda *a, **k: iter_chunks(raw))
        with pytest.raises(exporter.ExportError):
            list(exporter.journal_records(['unused'], deadline=time.monotonic() + 1))


def iter_chunks(raw):
    yield raw


def test_secure_configuration_rejects_symlinks_and_weak_file_modes(tmp_path):
    path = tmp_path / 'config.json'
    path.write_text('{}')
    path.chmod(0o666)
    with pytest.raises(exporter.ExportError):
        exporter.secure_file(path, root_owned=False)
    path.chmod(0o600)
    linked = tmp_path / 'linked.json'
    linked.symlink_to(path)
    with pytest.raises((OSError, exporter.ExportError)):
        exporter.secure_file(linked, root_owned=False)
    assert exporter.secure_file(path, root_owned=False, secret=True) == b'{}'
    if os.geteuid() != 0:
        with pytest.raises(exporter.ExportError):
            exporter.secure_file(path, root_owned=True)


def test_export_config_is_exact_and_root_owned_reader_is_used(config, monkeypatch):
    reads = []
    def secure(path, **kwargs):
        reads.append(kwargs)
        return encode(config)
    monkeypatch.setattr(exporter, 'secure_file', secure)
    loaded, enrolled = exporter.load_config(Path('/unused/root/config.json'))
    assert loaded['profile_valid_from_us'] == config['profile_valid_from_us']
    assert enrolled.source_id == source_profile().source_id and reads == [{'root_owned': True}]
    config['relays'] = {}
    with pytest.raises(exporter.ExportError, match='invalid_export_config'):
        exporter.load_config(Path('/unused/root/config.json'))


def test_forced_command_rejects_remote_commands_or_cli_arguments(monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['network_export.py'])
    monkeypatch.setenv('SSH_ORIGINAL_COMMAND', 'arbitrary command')
    with pytest.raises(exporter.ExportError, match='remote_commands_disabled'):
        exporter.main()
    monkeypatch.delenv('SSH_ORIGINAL_COMMAND')
    monkeypatch.setattr(sys, 'argv', ['network_export.py', '--some-filter'])
    with pytest.raises(exporter.ExportError, match='remote_commands_disabled'):
        exporter.main()


def test_large_and_byte_array_messages_are_not_lost_to_json_display_defaults(config):
    large = record(MESSAGE=record()['MESSAGE'] + ' ' * 4500)
    assert 4096 < len(large['MESSAGE']) < 8192
    result = page(config, [large])
    assert 'event' in result['entries'][0]
    encoded = record(1, MESSAGE=list(b'[UFW BLOCK] invalid-byte-') + [255])
    result = page(config, [encoded])
    assert result['entries'][0]['rejection']['code'] == 'invalid_record'
    assert 'MESSAGE' not in str(result) and 'invalid-byte-' not in str(result)


def test_vacuum_between_exact_cursor_check_and_read_discards_untrusted_page(config):
    checks = iter([True, False])
    result = page(config, [record()], cursor='previous', exists=lambda _: next(checks))
    assert result['entries'] == [] and result['cursor_after'] == result['cursor_before'] == 'previous'
    assert result['reports'] == ['journal_cursor_unavailable'] and result['caught_up'] is False


def test_exited_parent_cannot_leave_stdout_holding_child_past_deadline():
    command = [sys.executable, '-c',
               'import os,time\npid=os.fork()\nif pid:\n print(pid,flush=True)\n os._exit(0)\ntime.sleep(30)']
    chunks = exporter.command_chunks(command, deadline=time.monotonic() + .2, maximum=1024)
    child_pid = int(next(chunks).strip())
    try:
        with pytest.raises(exporter.ExportError, match='subprocess_deadline'):
            list(chunks)
        for _ in range(50):
            proc = Path(f'/proc/{child_pid}/stat')
            if not proc.exists() or proc.read_text().split()[2] == 'Z':
                break
            time.sleep(.01)
        else:
            pytest.fail('stdout-holding child survived its process group deadline')
    finally:
        try:
            os.kill(child_pid, 9)
        except ProcessLookupError:
            pass
