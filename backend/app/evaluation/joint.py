"""Deterministic synthetic joint-evidence acceptance; no files/stores are ingested.

This exercises the offline contract only. It is neither a production replay nor
an accuracy benchmark. No collector, model, firewall or external service is used.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
import json
from pathlib import Path

from app.telemetry.joint_evidence import (
    AssetMapping, NetworkBinding, NetworkCase, NetworkEvidence, SSHRecord,
    POLICY_VERSION, VERSION, correlate,
)


def fixtures():
    at = 1_790_000_000_000_000
    peer, destination, profile = '198.51.100.9', '192.0.2.20', 'a' * 64
    mapping = AssetMapping('asset-example', ('ssh-example',),
        (NetworkBinding('network-example', (destination,), (profile,)),))
    events = tuple(NetworkEvidence('network-example', f'network-event-{n}', 'boot-example',
        profile, peer, destination, at + n * 1_000_000, 600_000_000 + n * 1_000_000,
        8000 + n) for n in range(10))
    network = NetworkCase('producer-example', 'NET-example', 1, 'network-example',
        'boot-example', profile, peer, destination, events,
        coverage=('dynamic_terminal_filtering',))
    failure = SSHRecord('ssh-example', 'ssh-event-1', 'SSH-example', peer,
        at + 15_000_000, 'auth_failure', account='example-account')
    success = replace(failure, event_id='ssh-event-2', event_type='auth_success',
                      event_ts_us=at + 20_000_000)
    return (mapping,), network, failure, success


def report():
    mappings, network, failure, success = fixtures()
    scenarios = [
        ('probe_and_ssh_failure', network, (failure,), {}, 'linked'),
        ('probe_failure_and_auth_success', network, (failure, success), {}, 'linked'),
        # Same incident label and peer cannot join evidence from another host.
        ('same_incident_other_host', network, (replace(failure, source_id='other-host'),), {}, 'unmatched'),
        ('same_peer_outside_window', network, (replace(failure, event_ts_us=failure.event_ts_us + 86_400_000_000),), {}, 'unmatched'),
        ('other_peer_same_host', network, (replace(failure, src_ip='203.0.113.8'),), {}, 'unmatched'),
        ('duplicate_delivery', network, (failure, failure), {}, 'linked'),
        ('incomplete_candidates', network, (failure,), {'ssh_records_total':2}, 'partial'),
        ('limited_timeline', network, (failure, success), {'max_timeline_records':2}, 'partial'),
        ('stale_network_revision', replace(network, stale=True), (failure,), {}, 'stale'),
        ('retracted_network_revision', replace(network, active=False), (failure,), {}, 'retracted'),
        ('wrong_destination', replace(network, dst_ip='192.0.2.21', evidence=tuple(
            replace(x, dst_ip='192.0.2.21') for x in network.evidence)), (failure,), {}, 'rejected'),
        ('unreviewed_profile', replace(network, profile_revision='b'*64, evidence=tuple(
            replace(x, profile_revision='b'*64) for x in network.evidence)), (failure,), {}, 'rejected'),
    ]
    results = []
    for name, anchor, records, options, expected in scenarios:
        projection = correlate(mappings, anchor, records, **options)
        assert projection.state == expected, name
        payload = projection.to_dict()
        counts = payload.get('counts', {}).get('ssh', {})
        observed = sum(x['evidence'] for x in counts.values())
        if name in ('same_incident_other_host', 'same_peer_outside_window', 'other_peer_same_host'):
            assert observed == 0, name
        if name == 'duplicate_delivery':
            assert observed == 1, name
        assert not any(key in payload for key in ('risk_score', 'block', 'ai_verdict'))
        results.append({'scenario':name, 'state':projection.state,
                        'ssh_evidence':observed, 'projection_sha256':projection.sha256})
    before = correlate(mappings, network, (failure,))
    after = correlate(mappings, network, (failure, success))
    reordered = correlate(mappings, replace(network, evidence=tuple(reversed(network.evidence))), (success, failure))
    assert before.case_id == after.case_id and before.sha256 != after.sha256
    assert after.sha256 == reordered.sha256
    return {'version':VERSION, 'policy_version':POLICY_VERSION,
            'data':'authored synthetic typed evidence', 'production_integration':False,
            'model_calls':0, 'scenarios':results,
            'checks':{'late_ssh_changes_revision_same_case':True,
                      'input_order_does_not_change_projection':True,
                      'duplicate_does_not_increase_evidence_count':True,
                      'cross_host_and_outside_window_not_linked':True}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', type=Path, help='Compare with the published synthetic report')
    args = parser.parse_args()
    result = report()
    if args.check and json.loads(args.check.read_text()) != result:
        parser.error('Published joint-evidence report differs from the current contract')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
