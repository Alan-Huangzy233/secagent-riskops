#!/usr/bin/env python3
"""Root-only, bounded nftables control for a dedicated SSH forced-command key.

The caller selects one IP, channel and deadline, never a command or filesystem
path. Only this helper's inet table is modified; all state is root-owned.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

CONFIG_PATH = Path('/etc/secagent-riskops/ssh-block-control.json')
STATE_DIR = Path('/var/lib/riskops-control')
NFT_PATH = '/usr/sbin/nft'
IP_PATH = '/usr/sbin/ip'
TABLE = 'riskops_ssh_guard'
CHAIN = 'input_guard'
MARKER = 'secagent-riskops manual control v1'
CHANNELS = ('ssh', 'tcp', 'udp')
MAX_INPUT = 4096
MAX_OUTPUT = 2 * 1024 * 1024
MAX_BLOCKS = 4096
SAFE_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}


class ControlError(Exception):
    def __init__(self, code: str, uncertain: bool = False):
        super().__init__(code)
        self.code, self.uncertain = code, uncertain


def canonical_ip(value: object) -> str:
    if not isinstance(value, str) or len(value) > 45 or '%' in value or '/' in value:
        raise ControlError('invalid_ip')
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ControlError('invalid_ip') from None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def validate_request(raw: object, config: dict) -> dict:
    fields = {'version', 'source_id', 'action', 'request_id', 'ip', 'channel',
              'expires_at', 'ttl_seconds'}
    if not isinstance(raw, dict) or set(raw) - fields:
        raise ControlError('invalid_request')
    if type(raw.get('version')) is not int or raw['version'] != 1:
        raise ControlError('invalid_version')
    if raw.get('source_id') != config['source_id']:
        raise ControlError('wrong_source')
    request_id = raw.get('request_id')
    if not isinstance(request_id, str) or not SAFE_ID.fullmatch(request_id):
        raise ControlError('invalid_request_id')
    action = raw.get('action')
    if not isinstance(action, str) or action not in ('add', 'delete', 'status', 'check'):
        raise ControlError('invalid_action')
    result = {k: raw[k] for k in ('version', 'source_id', 'action', 'request_id')}
    if 'ip' in raw:
        result['ip'] = canonical_ip(raw['ip'])
    if 'channel' in raw:
        if not isinstance(raw['channel'], str) or raw['channel'] not in CHANNELS:
            raise ControlError('invalid_channel')
        result['channel'] = raw['channel']
    if action in ('add', 'delete') and not {'ip', 'channel'} <= result.keys():
        raise ControlError('missing_target')
    if action == 'add':
        if 'expires_at' not in raw:
            raise ControlError('missing_deadline')
        deadline = raw['expires_at']
        if deadline is not None and (type(deadline) is not int or deadline <= 0):
            raise ControlError('invalid_deadline')
        result['expires_at'] = deadline
        if 'ttl_seconds' in raw:
            ttl = raw['ttl_seconds']
            if type(ttl) is not int or not 1 <= ttl <= config['max_ttl_seconds']:
                raise ControlError('invalid_ttl')
            result['ttl_seconds'] = ttl
    elif 'expires_at' in raw or 'ttl_seconds' in raw:
        raise ControlError('unexpected_deadline')
    return result


def validate_config(raw: object) -> dict:
    fields = {'source_id', 'ssh_ports', 'protected_networks', 'max_ttl_seconds'}
    if not isinstance(raw, dict) or set(raw) - fields:
        raise ControlError('invalid_config')
    source = raw.get('source_id')
    ports, protected = raw.get('ssh_ports'), raw.get('protected_networks')
    if not isinstance(source, str) or not SAFE_ID.fullmatch(source):
        raise ControlError('invalid_config')
    if not isinstance(ports, list) or not 1 <= len(ports) <= 16 or any(
            type(p) is not int or not 1 <= p <= 65535 for p in ports):
        raise ControlError('invalid_config')
    if not isinstance(protected, list) or not 1 <= len(protected) <= 256:
        raise ControlError('management_protection_required')
    networks = []
    try:
        for value in protected:
            if not isinstance(value, str) or '%' in value:
                raise ValueError()
            network = ipaddress.ip_network(value, strict=True)
            if isinstance(network, ipaddress.IPv6Network) and network.network_address.ipv4_mapped:
                raise ValueError()
            networks.append(str(network))
    except ValueError:
        raise ControlError('invalid_protected_network') from None
    maximum = raw.get('max_ttl_seconds', 86400)
    if type(maximum) is not int or not 1 <= maximum <= 86400:
        raise ControlError('invalid_config')
    return {'source_id': source, 'ssh_ports': sorted(set(ports)),
            'protected_networks': sorted(set(networks)), 'max_ttl_seconds': maximum}


def secure_path(path: Path, *, directory: bool = False, private: bool = False) -> None:
    """Reject symlinks and any non-root-writable parent before privileged access."""
    for item in (path, *path.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ControlError('unsafe_permissions')
        if item == path:
            if directory and not stat.S_ISDIR(info.st_mode):
                raise ControlError('unsafe_permissions')
            if not directory and not stat.S_ISREG(info.st_mode):
                raise ControlError('unsafe_permissions')
            if private and info.st_mode & 0o077:
                raise ControlError('unsafe_permissions')
        elif not stat.S_ISDIR(info.st_mode):
            raise ControlError('unsafe_permissions')


def read_config() -> dict:
    secure_path(CONFIG_PATH, private=True)
    with CONFIG_PATH.open('rb') as file:
        raw = file.read(32769)
    if len(raw) > 32768:
        raise ControlError('invalid_config')
    return validate_config(json.loads(raw))


def run_command(argv: list[str], payload: dict | None = None, *, mutation=False) -> dict:
    """Time-limit subprocesses and read bounded output, without a shell."""
    data = None if payload is None else json.dumps(payload, separators=(',', ':')).encode()
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.run(argv, input=data, stdout=stdout, stderr=stderr,
                                     timeout=10, env=ENV, check=False)
        except subprocess.TimeoutExpired:
            raise ControlError('command_timeout', uncertain=mutation) from None
        except OSError:
            raise ControlError('command_unavailable') from None
        stdout.seek(0)
        output = stdout.read(MAX_OUTPUT + 1)
        if len(output) > MAX_OUTPUT:
            raise ControlError('output_limit', uncertain=mutation)
        if process.returncode:
            # Do not echo stderr: it may contain host paths or private policy.
            raise ControlError('nft_rejected' if mutation else 'command_failed')
        try:
            return json.loads(output) if output.strip() else {}
        except (ValueError, UnicodeError):
            raise ControlError('invalid_command_output', uncertain=mutation) from None


def local_protections(config: dict) -> list[str]:
    networks = [ipaddress.ip_network(v) for v in config['protected_networks']]
    data = run_command([IP_PATH, '-j', 'address', 'show'])
    if not isinstance(data, list):
        raise ControlError('local_addresses_unavailable')
    found = False
    for interface in data:
        for entry in interface.get('addr_info', []):
            if entry.get('family') not in ('inet', 'inet6'):
                continue
            address = canonical_ip(entry.get('local'))
            networks.append(ipaddress.ip_network(address))
            found = True
    if not found:
        raise ControlError('local_addresses_unavailable')
    connection = os.environ.get('SSH_CONNECTION', '')
    if connection:
        parts = connection.split()
        if len(parts) != 4 or not parts[1].isdigit() or not parts[3].isdigit():
            raise ControlError('invalid_ssh_connection')
        networks += [ipaddress.ip_network(canonical_ip(parts[0])),
                     ipaddress.ip_network(canonical_ip(parts[2]))]
    # Loopback/link-local/multicast/unspecified targets are rejected too.
    networks += [ipaddress.ip_network(v) for v in ('127.0.0.0/8', '::1/128')]
    return [str(n) for version in (4, 6) for n in ipaddress.collapse_addresses(
        [n for n in networks if n.version == version])]


def protected_ip(ip: str, networks: list[str]) -> bool:
    address = ipaddress.ip_address(ip)
    return (address.is_loopback or address.is_link_local or address.is_multicast
            or address.is_unspecified or any(address in ipaddress.ip_network(n) for n in networks))


def obj(name: str) -> dict:
    return {'family': 'inet', 'table': TABLE, 'name': name}


def set_name(ip: str, channel: str) -> str:
    return f'{channel}{ipaddress.ip_address(ip).version}'


def match(left: dict, right: object) -> dict:
    return {'match': {'op': '==', 'left': left, 'right': right}}


def expected_rules(config: dict) -> list[dict]:
    rules = []
    for version, protocol in ((4, 'ip'), (6, 'ip6')):
        expr = [match({'payload': {'protocol': protocol, 'field': 'saddr'}}, f'@allow{version}'),
                {'accept': None}]
        rules.append({'family': 'inet', 'table': TABLE, 'chain': CHAIN,
                      'expr': expr, 'comment': f'riskops protect ipv{version}'})
    for channel in CHANNELS:
        for version, protocol in ((4, 'ip'), (6, 'ip6')):
            # tcp dport already implies TCP. nft removes a redundant meta
            # l4proto predicate on serialization, so generate its canonical form.
            expr = [] if channel == 'ssh' else [match({'meta': {'key': 'l4proto'}}, 'udp' if channel == 'udp' else 'tcp')]
            expr.append(match({'payload': {'protocol': protocol, 'field': 'saddr'}}, f'@{channel}{version}'))
            if channel == 'ssh':
                ports = config['ssh_ports']
                expr.append(match({'payload': {'protocol': 'tcp', 'field': 'dport'}},
                                  ports[0] if len(ports) == 1 else {'set': ports}))
            expr.append({'drop': None})
            rules.append({'family': 'inet', 'table': TABLE, 'chain': CHAIN,
                          'expr': expr, 'comment': f'riskops {channel} ipv{version}'})
    return rules


def create_commands(config: dict) -> list[dict]:
    commands = [{'create': {'table': {'family': 'inet', 'name': TABLE, 'comment': MARKER}}}]
    commands += [{'add': {'chain': {**obj(CHAIN), 'type': 'filter', 'hook': 'input',
                                    'prio': -5, 'policy': 'accept'}}}]
    for version in (4, 6):
        commands.append({'add': {'set': {**obj(f'allow{version}'), 'type': f'ipv{version}_addr',
                                         'flags': ['interval'], 'size': 1024}}})
        for channel in CHANNELS:
            commands.append({'add': {'set': {**obj(f'{channel}{version}'), 'type': f'ipv{version}_addr',
                                             'flags': ['timeout'], 'size': MAX_BLOCKS}}})
    commands += [{'add': {'rule': rule}} for rule in expected_rules(config)]
    return commands


def normalize_expr(value: object) -> object:
    # nft emits numeric protocol identifiers with --numeric and normalized set order.
    if isinstance(value, list):
        return [normalize_expr(x) for x in value]
    if isinstance(value, dict):
        result = {k: normalize_expr(v) for k, v in value.items()}
        if 'match' in result:
            item = result['match']
            if item.get('left') == {'meta': {'key': 'l4proto'}}:
                item['right'] = {6: 'tcp', 17: 'udp'}.get(item.get('right'), item.get('right'))
        return result
    return value


def verify_protections(data: dict, networks: list[str]) -> None:
    actual = []
    try:
        for entry in data['nftables']:
            value = entry.get('set', {})
            if value.get('name') not in ('allow4', 'allow6'):
                continue
            for element in value.get('elem', []):
                if isinstance(element, dict) and 'elem' in element:
                    element = element['elem']['val']
                if isinstance(element, dict):
                    prefix = element['prefix']
                    element = f"{prefix['addr']}/{prefix['len']}"
                actual.append(ipaddress.ip_network(element))
        normalized = {str(n) for v in (4, 6) for n in ipaddress.collapse_addresses(
            [n for n in actual if n.version == v])}
        if normalized != set(networks):
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise ControlError('protection_verification_failed', uncertain=True) from None


class Firewall:
    def read(self, config: dict) -> dict | None:
        listing = run_command([NFT_PATH, '-j', '-n', 'list', 'tables'])
        if not isinstance(listing, dict) or not isinstance(listing.get('nftables'), list):
            raise ControlError('invalid_nft_state')
        if not any(x.get('table', {}).get('family') == 'inet' and
                   x.get('table', {}).get('name') == TABLE for x in listing['nftables']):
            return None
        data = run_command([NFT_PATH, '-j', '-n', 'list', 'table', 'inet', TABLE])
        self.validate_schema(data, config)
        return data

    @staticmethod
    def validate_schema(data: dict, config: dict) -> None:
        try:
            entries = data['nftables']
            tables = [x['table'] for x in entries if 'table' in x]
            chains = [x['chain'] for x in entries if 'chain' in x]
            sets = {x['set']['name']: x['set'] for x in entries if 'set' in x}
            rules = [x['rule'] for x in entries if 'rule' in x]
            if any(set(x) - {'metainfo', 'table', 'chain', 'set', 'rule'} for x in entries):
                raise ValueError()
            if len(tables) != 1 or tables[0].get('comment') != MARKER or tables[0].get('flags'):
                raise ValueError()
            if tables[0]['family'] != 'inet' or tables[0]['name'] != TABLE or len(chains) != 1:
                raise ValueError()
            chain = chains[0]
            if any(chain.get(k) != v for k, v in {**obj(CHAIN), 'type': 'filter',
                    'hook': 'input', 'prio': -5, 'policy': 'accept'}.items()):
                raise ValueError()
            wanted = {f'{channel}{version}' for channel in (*CHANNELS, 'allow') for version in (4, 6)}
            if set(sets) != wanted or len(sets) != sum('set' in x for x in entries):
                raise ValueError()
            for name, value in sets.items():
                flags = ['interval'] if name.startswith('allow') else ['timeout']
                if (value.get('type') != f'ipv{name[-1]}_addr' or value.get('flags') != flags
                        or value.get('timeout', 0) != 0 or value.get('table') != TABLE
                        or value.get('family') != 'inet'):
                    raise ValueError()
            expected = expected_rules(config)
            if len(rules) != len(expected):
                raise ValueError()
            for actual, desired in zip(rules, expected):
                if any(normalize_expr(actual.get(k)) != normalize_expr(v) for k, v in desired.items()):
                    raise ValueError()
        except (KeyError, TypeError, ValueError):
            raise ControlError('firewall_schema_mismatch') from None

    @staticmethod
    def blocks(data: dict | None, now: float) -> dict[tuple[str, str], float | None]:
        result = {}
        if data is None:
            return result
        try:
            for item in data['nftables']:
                value = item.get('set', {})
                name = value.get('name', '')
                if name not in {f'{c}{v}' for c in CHANNELS for v in (4, 6)}:
                    continue
                elements = value.get('elem', [])
                if not isinstance(elements, list):
                    elements = [elements]
                for element in elements:
                    extra = element.get('elem', {}) if isinstance(element, dict) else {}
                    ip = canonical_ip(extra.get('val') if extra else element)
                    if ipaddress.ip_address(ip).version != int(name[-1]):
                        raise ValueError()
                    expiry = None
                    if extra.get('timeout', 0):
                        # libnftables JSON represents these values in seconds.
                        remaining = extra.get('expires')
                        if type(remaining) not in (int, float) or remaining < 0:
                            raise ValueError()
                        expiry = now + remaining
                    key = (ip, name[:-1])
                    if key in result:
                        raise ValueError()
                    result[key] = expiry
            return result
        except (KeyError, TypeError, ValueError):
            raise ControlError('invalid_nft_elements') from None

    def apply(self, config: dict, networks: list[str], desired: dict, current: dict | None,
              now: float) -> None:
        commands = create_commands(config) if current is None else []
        for version in (4, 6):
            name = f'allow{version}'
            if current is not None:
                commands.append({'flush': {'set': obj(name)}})
            elements = []
            for value in networks:
                network = ipaddress.ip_network(value)
                if network.version == version:
                    elements.append(str(network.network_address) if network.prefixlen == network.max_prefixlen
                                    else {'prefix': {'addr': str(network.network_address), 'len': network.prefixlen}})
            if elements:
                commands.append({'add': {'element': {**obj(name), 'elem': elements}}})
            for channel in CHANNELS:
                name = f'{channel}{version}'
                if current is not None:
                    commands.append({'flush': {'set': obj(name)}})
                elements = []
                for (ip, selected), expiry in desired.items():
                    if selected != channel or ipaddress.ip_address(ip).version != version:
                        continue
                    if expiry is None:
                        elements.append(ip)
                    else:
                        remaining = math.floor(expiry - now)
                        if remaining >= 1:
                            elements.append({'elem': {'val': ip, 'timeout': remaining}})
                if elements:
                    commands.append({'add': {'element': {**obj(name), 'elem': elements}}})
        run_command([NFT_PATH, '-j', '-f', '-'], {'nftables': commands}, mutation=True)


class Store:
    def __init__(self, path: Path):
        self.db = sqlite3.connect(path, timeout=5)
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS blocks (ip TEXT NOT NULL, channel TEXT NOT NULL, '
                        'expires_at INTEGER, PRIMARY KEY(ip,channel))')
        self.db.execute('CREATE TABLE IF NOT EXISTS receipts (request_id TEXT PRIMARY KEY, '
                        'fingerprint TEXT NOT NULL, response TEXT NOT NULL)')
        self.db.commit()

    def desired(self, now: float, networks: list[str]) -> dict:
        return {(ip, channel): expiry for ip, channel, expiry in self.db.execute(
            'SELECT ip,channel,expires_at FROM blocks') if (expiry is None or expiry > now)
            and not protected_ip(ip, networks)}

    def receipt(self, request_id: str):
        row = self.db.execute('SELECT fingerprint,response FROM receipts WHERE request_id=?',
                              (request_id,)).fetchone()
        return None if row is None else (row[0], json.loads(row[1]))

    def save(self, desired: dict, request: dict, response: dict) -> None:
        with self.db:
            self.db.execute('DELETE FROM blocks')
            self.db.executemany('INSERT INTO blocks VALUES (?,?,?)',
                                [(ip, channel, expiry) for (ip, channel), expiry in desired.items()])
            if request['action'] in ('add', 'delete'):
                self.db.execute('INSERT OR REPLACE INTO receipts VALUES (?,?,?)',
                                (request['request_id'], fingerprint(request), json.dumps(response)))

    def close(self):
        self.db.close()


def fingerprint(request: dict) -> str:
    return hashlib.sha256(json.dumps(request, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def reply(request: dict, status='ok', code='verified', **fields) -> dict:
    return {**{k: request[k] for k in ('version', 'request_id', 'source_id', 'action', 'ip', 'channel')
               if k in request}, 'status': status, 'code': code, **fields}


def observed_reply(request: dict, blocks: dict, desired: dict, now: float, **fields) -> dict:
    if 'ip' in request and 'channel' in request:
        key = (request['ip'], request['channel'])
        expiry = blocks.get(key)
        if key in blocks and key in desired and expiry is not None and desired[key] is not None:
            expiry = desired[key]
        return reply(request, blocked=key in blocks,
                     expires_at=math.ceil(expiry) if expiry is not None else None,
                     remaining_seconds=max(0, math.floor(expiry-now)) if expiry is not None else None,
                     **fields)
    entries = []
    for (ip, channel), expiry in sorted(blocks.items()):
        if 'ip' in request and request['ip'] != ip or 'channel' in request and request['channel'] != channel:
            continue
        original = desired.get((ip, channel))
        if original is not None and expiry is not None:
            expiry = original
        entries.append({'ip': ip, 'channel': channel,
                        'expires_at': math.ceil(expiry) if expiry is not None else None})
    return reply(request, blocks=entries, **fields)


def execute(raw: object, config: dict, store: Store, firewall: Firewall, networks: list[str],
            *, clock=time.time, restore=False) -> dict:
    request = validate_request(raw, config)
    now = clock()
    desired = store.desired(now, networks)
    existing = store.receipt(request['request_id']) if request['action'] in ('add', 'delete') else None
    if existing and existing[0] != fingerprint(request):
        return reply(request, 'rejected', 'request_id_conflict')
    current = firewall.read(config)
    actual = firewall.blocks(current, now)
    if request['action'] in ('status', 'check') and not restore:
        return observed_reply(request, actual, desired, now, ready=True, table_present=current is not None,
                              channels=list(CHANNELS), max_ttl_seconds=config['max_ttl_seconds'])
    reconcile = restore or bool(existing and existing[1]['status'] == 'uncertain')
    if existing and not reconcile:
        # Never reapply an old operation: a later deletion or change wins.
        return observed_reply(request, actual, desired, now, code='idempotent_replay', replayed=True,
                              previous_status=existing[1]['status'])
    if request['action'] == 'add' and not reconcile:
        if protected_ip(request['ip'], networks):
            return reply(request, 'rejected', 'protected_address', blocked=False, expires_at=None)
        expiry = request['expires_at']
        if expiry is not None and (expiry <= now or expiry - now > config['max_ttl_seconds']):
            return reply(request, 'rejected', 'deadline_out_of_range')
    previous = dict(desired)
    if request['action'] == 'add' and not reconcile:
        desired[(request['ip'], request['channel'])] = request['expires_at']
    elif request['action'] == 'delete' and not reconcile:
        desired.pop((request['ip'], request['channel']), None)
    if len(desired) > MAX_BLOCKS:
        return reply(request, 'rejected', 'capacity_reached')
    pending = reply(request, 'uncertain', 'pending_verification')
    store.save(desired, request, pending)
    try:
        firewall.apply(config, networks, desired, current, clock())
        now = clock()
        readback = firewall.read(config)
        if readback is None:
            raise ControlError('verification_failed', uncertain=True)
        verify_protections(readback, networks)
        actual = firewall.blocks(readback, now)
        expected = {key: expiry for key, expiry in desired.items() if expiry is None or expiry > now+1}
        if set(actual) - desired.keys() or expected.keys() - actual.keys():
            raise ControlError('verification_failed', uncertain=True)
        for key, expiry in actual.items():
            target = desired[key]
            if ((expiry is None) != (target is None) or
                    expiry is not None and (expiry > target+1 or expiry < target-12)):
                raise ControlError('verification_failed', uncertain=True)
        result = observed_reply(request, actual, desired, now)
    except ControlError as error:
        # A definite nft rejection applies none of its atomic batch. A timeout
        # or readback failure leaves desired intent for later reconciliation.
        if error.code == 'nft_rejected' or error.code == 'command_unavailable':
            desired = previous
            result = reply(request, 'error', error.code)
        else:
            result = reply(request, 'uncertain', error.code)
    store.save(desired, request, result)
    return result


@contextmanager
def locked_store():
    import fcntl
    secure_path(STATE_DIR.parent, directory=True)
    STATE_DIR.mkdir(mode=0o700, exist_ok=True)
    secure_path(STATE_DIR, directory=True, private=True)
    lock_path = STATE_DIR / 'control.lock'
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    store = None
    try:
        secure_path(lock_path, private=True)
        deadline = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ControlError('control_busy') from None
                time.sleep(0.05)
        database = STATE_DIR / 'control.sqlite'
        if database.exists() or database.is_symlink():
            secure_path(database, private=True)
        for sidecar in STATE_DIR.glob('control.sqlite-*'):
            secure_path(sidecar, private=True)
        store = Store(database)
        secure_path(database, private=True)
        yield store
    finally:
        if store is not None:
            store.close()
        os.close(descriptor)


def main() -> int:
    request = {'version': 1}
    try:
        if sys.platform != 'linux' or os.geteuid() != 0:
            raise ControlError('root_required')
        os.umask(0o077)
        restore = sys.argv[1:] == ['--restore']
        if sys.argv[1:] and not restore:
            raise ControlError('invalid_arguments')
        if restore and (os.environ.get('SSH_CONNECTION') or os.environ.get('SSH_ORIGINAL_COMMAND')):
            raise ControlError('local_restore_only')
        if not restore and os.environ.get('SSH_ORIGINAL_COMMAND', '') not in ('', 'riskops-ssh-control-v1'):
            raise ControlError('unexpected_command')
        config = read_config()
        if restore:
            request = {'version': 1, 'source_id': config['source_id'], 'action': 'check',
                       'request_id': 'restore-' + str(time.time_ns())}
        else:
            raw = sys.stdin.buffer.read(MAX_INPUT+1)
            if len(raw) > MAX_INPUT:
                raise ControlError('request_too_large')
            request = validate_request(json.loads(raw), config)
        networks = local_protections(config)
        with locked_store() as store:
            response = execute(request, config, store, Firewall(), networks, restore=restore)
    except ControlError as error:
        response = reply(request, 'uncertain' if error.uncertain else 'rejected', error.code)
    except (ValueError, OSError, sqlite3.Error, TypeError, KeyError):
        response = reply(request, 'error', 'control_failed')
    print(json.dumps(response, separators=(',', ':')))
    return 0 if response['status'] == 'ok' else 1


if __name__ == '__main__':
    raise SystemExit(main())
