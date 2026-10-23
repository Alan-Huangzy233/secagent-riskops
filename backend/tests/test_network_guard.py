"""Authored firewall graphs only; no captured source rules or host addresses."""
from copy import deepcopy

import pytest

from app.telemetry.network_guard import NetworkGuardError, terminal_set_snapshot
from app.telemetry.network_protocol import fingerprint

IDENTITIES = ('inet/synthetic/denied_sources',)


def snapshot(*, ipv6=False):
    return [
        {'table': {'family': 'inet', 'name': 'synthetic'}},
        {'chain': {'family': 'inet', 'table': 'synthetic', 'name': 'entry',
                   'type': 'filter', 'hook': 'input', 'prio': -2, 'policy': 'accept'}},
        {'set': {'family': 'inet', 'table': 'synthetic', 'name': 'denied_sources',
                 'type': 'ipv6_addr' if ipv6 else 'ipv4_addr',
                 'elem': ['2001:db8::8'] if ipv6 else ['192.0.2.8']}},
        {'rule': {'family': 'inet', 'table': 'synthetic', 'chain': 'entry', 'expr': [
            {'match': {'op': '==', 'left': {'payload': {'protocol': 'tcp', 'field': 'dport'}}, 'right': 8443}},
            {'match': {'op': '==', 'left': {'payload': {'protocol': 'ip6' if ipv6 else 'ip', 'field': 'saddr'}}, 'right': '@denied_sources'}},
            {'counter': {}}, {'reject': {'type': 'icmpv6' if ipv6 else 'icmp', 'expr': 3}},
        ]}},
        {'rule': {'family': 'inet', 'table': 'synthetic', 'chain': 'entry',
                  'expr': [{'log': {'prefix': '[SYNTHETIC OBSERVE]'}}]}},
    ]


def digest(items):
    return fingerprint(terminal_set_snapshot(items, IDENTITIES))


@pytest.mark.parametrize('ipv6', [False, True])
def test_only_literal_membership_can_change_and_input_is_immutable(ipv6):
    items = snapshot(ipv6=ipv6)
    original = deepcopy(items)
    baseline = digest(items)
    assert items == original
    for members in ([], ['2001:db8::9', '2001:db8::a'] if ipv6 else ['192.0.2.9', '198.51.100.5']):
        items[2]['set']['elem'] = members
        assert digest(items) == baseline
    del items[2]['set']['elem']
    assert digest(items) == baseline
    assert terminal_set_snapshot(items, IDENTITIES)[2]['set']['type'] == original[2]['set']['type']


@pytest.mark.parametrize('field,value', [('size', 128), ('comment', 'reviewed synthetic limit')])
def test_accepted_definition_fields_are_still_bound(field, value):
    items = snapshot()
    before = digest(items)
    items[2]['set'][field] = value
    assert digest(items) != before


def test_other_members_rules_hooks_and_order_are_still_bound():
    original = snapshot()
    original.append({'set': {'family': 'inet', 'table': 'synthetic', 'name': 'stable_other',
                             'type': 'ipv4_addr', 'elem': ['203.0.113.10']}})
    before = digest(original)
    for target, key, value in [(1, 'hook', 'forward'), (1, 'prio', 3), (3, 'chain', 'other'),
                                (4, 'expr', [{'log': {'prefix': '[OTHER LOG]'}}]),
                                (5, 'elem', ['203.0.113.11'])]:
        items = deepcopy(original)
        next(iter(items[target].values()))[key] = value
        assert digest(items) != before
    items = deepcopy(original)
    items[3], items[4] = items[4], items[3]
    assert digest(items) != before
    items = deepcopy(original)
    items[3]['rule']['expr'][0]['match']['right'] = 8444
    assert digest(items) != before


@pytest.mark.parametrize('identity', [(), [], ('inet/synthetic/missing',), ('inet/synthetic/denied_sources',) * 2,
                                      ('inet/synthetic/../denied_sources',), ('inet/synthetic/denied_sources\n',),
                                      tuple(f'inet/synthetic/name{i}' for i in range(9))])
def test_allowlist_is_nonempty_bounded_exact_and_unique(identity):
    with pytest.raises(NetworkGuardError, match='^unsafe_dynamic_terminal_set$'):
        terminal_set_snapshot(snapshot(), identity)


@pytest.mark.parametrize('changes', [
    {'type': 'inet_service'}, {'type': ['ipv4_addr', 'inet_service']}, {'flags': ['interval']},
    {'flags': []}, {'timeout': 1000}, {'expires': 300}, {'gc-interval': 10}, {'auto-merge': True},
    {'policy': 'memory'}, {'size': True}, {'size': 0}, {'size': 10_000_001}, {'comment': []},
    {'elem': ['192.0.2.0/24']}, {'elem': [{'range': ['192.0.2.1', '192.0.2.2']}]},
    {'elem': [{'elem': {'val': '192.0.2.1', 'timeout': 5000}}]}, {'elem': ['192.0.2.8'] * 2},
    {'elem': ['2001:db8::1']}, {'elem': [['192.0.2.8', 443]]}, {'elem': [True]},
    {'elem': {'set': ['192.0.2.8']}}, {'elem': ['192.000.2.8']},
])
def test_unsupported_set_definitions_or_nonliteral_members_fail_closed(changes):
    items = snapshot()
    items[2]['set'].update(changes)
    with pytest.raises(NetworkGuardError):
        digest(items)


@pytest.mark.parametrize('member', ['2001:0db8::8', '::ffff:192.0.2.8', 'fe80::8%eth0', '192.0.2.8'])
def test_ipv6_members_are_canonical_unmapped_addresses(member):
    items = snapshot(ipv6=True)
    items[2]['set']['elem'] = [member]
    with pytest.raises(NetworkGuardError):
        digest(items)


@pytest.mark.parametrize('expr', [
    {'log': {'prefix': '[SYNTHETIC]'}}, {'jump': {'target': 'next'}}, {'goto': {'target': 'next'}},
    {'dnat': {'addr': '192.0.2.55'}}, {'snat': {'addr': '192.0.2.55'}}, {'counter': 'named'},
    {'counter': {'packets': 0}}, {'limit': {'rate': 1}}, {'accept': None}, {'not_known': None},
    {'mangle': {'key': {'meta': {'key': 'mark'}}, 'value': 1}},
])
def test_any_nontrivial_statement_beside_static_matches_counter_and_terminal_is_refused(expr):
    items = snapshot()
    items[3]['rule']['expr'].insert(1, expr)
    with pytest.raises(NetworkGuardError):
        digest(items)


@pytest.mark.parametrize('terminal', [
    {'drop': True}, {'drop': {}}, {'reject': {'type': 'icmp', 'expr': True}},
    {'reject': {'type': 'icmp', 'expr': 256}}, {'reject': {'type': 'icmp', 'expr': 'port-unreachable'}},
    {'reject': {'type': 'tcp reset', 'expr': 3}}, {'reject': {'type': 'tcp reset', 'extra': None}},
    {'reject': {'type': 'unknown', 'expr': 3}}, {'accept': None}, {'return': None}, {'reject': []},
])
def test_terminal_values_are_not_merely_key_matched(terminal):
    items = snapshot()
    items[3]['rule']['expr'][-1] = terminal
    with pytest.raises(NetworkGuardError):
        digest(items)


@pytest.mark.parametrize('terminal', [{'drop': None}, {'reject': None}, {'reject': {'type': 'tcp reset'}},
                                    {'reject': {'type': 'icmpx', 'expr': 1}}])
def test_supported_exact_terminal_shapes(terminal):
    items = snapshot()
    items[3]['rule']['expr'][-1] = terminal
    assert len(digest(items)) == 64


@pytest.mark.parametrize('change', ['unused', 'double_definition', 'map', 'element', 'bare_name', 'nested',
                                   'wrong_op', 'destination', 'duplicate_lookup', 'two_selected_sets',
                                   'unknown_rule_field', 'unknown_match', 'log_after_terminal'])
def test_every_reference_and_definition_is_reviewed_fail_closed(change):
    items = snapshot()
    rule = items[3]['rule']
    identities = IDENTITIES
    if change == 'unused':
        del items[3]
    elif change == 'double_definition':
        items.append(deepcopy(items[2]))
    elif change in ('map', 'element'):
        items.append({change: {'family': 'inet', 'table': 'synthetic', 'name': 'denied_sources', 'elem': []}})
    elif change == 'bare_name':
        items[4]['rule']['expr'].append({'unknown': 'denied_sources'})
    elif change == 'nested':
        rule['expr'].insert(0, {'vmap': {'key': {'meta': {'key': 'mark'}}, 'data': '@denied_sources'}})
    elif change == 'wrong_op':
        rule['expr'][1]['match']['op'] = '!='
    elif change == 'destination':
        rule['expr'][1]['match']['left']['payload']['field'] = 'daddr'
    elif change == 'duplicate_lookup':
        rule['expr'].insert(0, deepcopy(rule['expr'][1]))
    elif change == 'two_selected_sets':
        items.append({'set': {'family': 'inet', 'table': 'synthetic', 'name': 'second', 'type': 'ipv4_addr'}})
        second = deepcopy(rule['expr'][1])
        second['match']['right'] = '@second'
        rule['expr'].insert(0, second)
        identities += ('inet/synthetic/second',)
    elif change == 'unknown_rule_field':
        rule['unknown'] = 'meaning'
    elif change == 'unknown_match':
        rule['expr'].insert(0, {'match': {'op': '==', 'left': {'unknown': 'state'}, 'right': 1}})
    elif change == 'log_after_terminal':
        rule['expr'].append({'log': {'prefix': '[SYNTHETIC]'}})
    with pytest.raises(NetworkGuardError):
        terminal_set_snapshot(items, identities)


def test_same_spelling_in_another_table_is_not_the_selected_set():
    items = snapshot()
    items.append({'map': {'family': 'inet', 'table': 'other', 'name': 'denied_sources', 'elem': []}})
    baseline = digest(items)
    items[-1]['map']['elem'] = [['192.0.2.8', {'jump': {'target': 'elsewhere'}}]]
    assert digest(items) != baseline


def test_multiple_sets_require_independent_terminal_rules_and_allowlist_order_is_stable():
    items = snapshot()
    second_set = deepcopy(items[2])
    second_set['set'].update(name='second', elem=['198.51.100.9'])
    second_rule = deepcopy(items[3])
    second_rule['rule']['expr'][1]['match']['right'] = '@second'
    items.extend([second_set, second_rule])
    identities = (*IDENTITIES, 'inet/synthetic/second')
    baseline = fingerprint(terminal_set_snapshot(items, identities))
    assert fingerprint(terminal_set_snapshot(items, tuple(reversed(identities)))) == baseline
    second_set['set']['elem'] = []
    items[2]['set']['elem'] = []
    assert fingerprint(terminal_set_snapshot(items, identities)) == baseline
    assert fingerprint(terminal_set_snapshot(items, IDENTITIES)) != baseline
