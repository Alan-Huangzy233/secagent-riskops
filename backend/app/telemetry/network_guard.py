"""Narrow review policy for dynamic terminal-denial address sets.

Input is the bounded normalized nft JSON snapshot, not user-selected commands.
Every rule and definition remains fingerprinted. Only literal members of an
explicitly enrolled, fully checked terminal-denial set can vary. This policy
says nothing about final packet outcomes or complete logging coverage.
"""
from __future__ import annotations

from copy import deepcopy
import ipaddress
import re

TERMINAL_GUARD = 'netfilter-terminal-v2'
_SET_ID = re.compile(r'(?:ip|ip6|inet)/[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}/[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\Z')
_MAX_SETS = 8


class NetworkGuardError(ValueError):
    """Fixed rejection code; never carries a ruleset or supplied identifier."""


def _fail():
    raise NetworkGuardError('unsafe_dynamic_terminal_set')


def validate_terminal_set_ids(identities):
    if (type(identities) is not tuple or not 1 <= len(identities) <= _MAX_SETS
            or any(type(item) is not str or not _SET_ID.fullmatch(item) for item in identities)
            or len(set(identities)) != len(identities)):
        _fail()


def _literal_numbers(value, maximum):
    def number(item):
        return type(item) is int and 0 <= item <= maximum
    if number(value):
        return True
    if type(value) is not dict or len(value) != 1:
        return False
    if 'set' in value:
        items = value['set']
        return (type(items) is list and 1 <= len(items) <= 64
                and all(number(item) for item in items) and len(set(items)) == len(items))
    if 'range' in value:
        items = value['range']
        return (type(items) is list and len(items) == 2
                and all(number(item) for item in items) and items[0] <= items[1])
    return False


def _static_match(expr):
    if type(expr) is not dict or set(expr) != {'match'}:
        return False
    match = expr['match']
    if type(match) is not dict or set(match) != {'left', 'op', 'right'} or match['op'] != '==':
        return False
    left = match['left']
    if left in ({'payload': {'protocol': protocol, 'field': field}}
                for protocol in ('tcp', 'udp') for field in ('sport', 'dport')):
        return _literal_numbers(match['right'], 65535)
    if left == {'meta': {'key': 'l4proto'}}:
        return _literal_numbers(match['right'], 255)
    return False


def _terminal(expr):
    if expr == {'drop': None} or expr == {'reject': None}:
        return True
    if type(expr) is not dict or set(expr) != {'reject'} or type(expr['reject']) is not dict:
        return False
    reject = expr['reject']
    if set(reject) - {'type', 'expr'}:
        return False
    if reject.get('type') == 'tcp reset':
        return reject.get('expr') is None
    return (reject.get('type') in ('icmp', 'icmpv6', 'icmpx')
            and type(reject.get('expr')) is int and 0 <= reject['expr'] <= 255)


def _reference_paths(value, name, path=()):
    """Find even unknown uses, including bare names and suspicious @ prefixes.

    A conservative false positive in a comment or a longer name fails closed.
    Only the exact supported lookup position will be authorized by the caller.
    """
    if type(value) is str:
        if value == name or '@' + name in value:
            yield path
    elif type(value) is dict:
        for key, child in value.items():
            if key == name or '@' + name in key:
                yield path + ('<key>', key)
            yield from _reference_paths(child, name, path + (key,))
    elif type(value) is list:
        for index, child in enumerate(value):
            yield from _reference_paths(child, name, path + (index,))


def _review_rule(rule, reference_paths, name, protocol):
    required = {'family', 'table', 'chain', 'expr'}
    if (not required <= rule.keys() or set(rule) - required - {'comment'}
            or type(rule['chain']) is not str
            or ('comment' in rule and (type(rule['comment']) is not str or len(rule['comment']) > 256))):
        _fail()
    exprs = rule.get('expr')
    if type(exprs) is not list or not 2 <= len(exprs) <= 16 or not _terminal(exprs[-1]):
        _fail()
    lookups = []
    expected = {'match': {'left': {'payload': {'protocol': protocol, 'field': 'saddr'}},
                          'op': '==', 'right': '@' + name}}
    for index, expr in enumerate(exprs[:-1]):
        if expr == expected:
            lookups.append(('rule', 'expr', index, 'match', 'right'))
        elif expr != {'counter': {}} and not _static_match(expr):
            _fail()
    if len(lookups) != 1 or reference_paths != lookups:
        _fail()


def terminal_set_snapshot(items, identities):
    """Return a copy with only verified address memberships made nonbinding.

    Unsupported element objects, timeouts, intervals, concatenations, maps,
    unknown expressions, unused sets or an additional reference all fail closed.
    Names are scoped to their exact family/table, as in nftables. A selected
    set's definition is retained, including its configured maximum size.
    """
    validate_terminal_set_ids(identities)
    if (type(items) is not list or len(items) > 100_000
            or any(type(item) is not dict or len(item) != 1
                   or any(type(key) is not str or type(body) is not dict for key, body in item.items())
                   for item in items)):
        _fail()
    result = deepcopy(items)
    for identity in identities:
        family, table, name = identity.split('/')
        found = []
        for index, wrapper in enumerate(items):
            if 'set' in wrapper:
                obj = wrapper['set']
                if (obj.get('family'), obj.get('table'), obj.get('name')) == (family, table, name):
                    found.append((index, obj))
        if len(found) != 1:
            _fail()
        index, definition = found[0]
        required = {'family', 'table', 'name', 'type'}
        if (not required <= definition.keys() or set(definition) - required - {'elem', 'size', 'comment'}
                or definition['type'] not in ('ipv4_addr', 'ipv6_addr')):
            _fail()
        version = 4 if definition['type'] == 'ipv4_addr' else 6
        if family not in ('inet', 'ip' if version == 4 else 'ip6'):
            _fail()
        if 'size' in definition and (type(definition['size']) is not int or not 1 <= definition['size'] <= 10_000_000):
            _fail()
        if 'comment' in definition and (type(definition['comment']) is not str or len(definition['comment']) > 256):
            _fail()
        members = definition.get('elem', [])
        if type(members) is not list or len(members) > 100_000:
            _fail()
        seen = set()
        for member in members:
            if type(member) is not str or len(member) > 45 or '%' in member:
                _fail()
            try:
                address = ipaddress.ip_address(member)
            except ValueError:
                _fail()
            if (address.version != version or str(address) != member
                    or (isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None)):
                _fail()
            if member in seen:
                _fail()
            seen.add(member)
        referenced = 0
        for obj in items:
            kind, body = next(iter(obj.items()))
            owner_table = body.get('name') if kind == 'table' else body.get('table')
            if body.get('family') != family or owner_table != table:
                continue
            paths = list(_reference_paths(obj, name))
            if kind == 'set' and body is definition:
                paths = [path for path in paths if path != ('set', 'name')]
            if not paths:
                continue
            if kind != 'rule':
                _fail()
            _review_rule(body, paths, name, 'ip' if version == 4 else 'ip6')
            referenced += 1
        if not referenced:
            _fail()
        result[index]['set']['elem'] = {'reviewed_dynamic_terminal_membership': True}
    return result
