"""Offline network detector contracts, using records authored for these tests."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import random
import runpy

import pytest

from app.telemetry import network_detection
from app.telemetry.network_detection import MaintenanceWindow, detect_network
from app.telemetry.network_parse import SourceProfile, parse_ufw


REALTIME_US = 1_767_225_600_000_000
MONOTONIC_US = 1_000_000
BOOT_ID = "1" * 32
REMOTE = "198.51.100.42"
DESTINATION = "192.0.2.10"


def profile(**changes):
    values = {
        "source_id": "sensor-a", "ruleset_sha256": "a" * 64,
        "log_labels": ("[UFW BLOCK]",), "ip_families": (4, 6),
        "rejection_labels": ("[UFW BLOCK]",),
        "local_input_labels": ("[UFW BLOCK]",), "local_input_interfaces": ("eth0",),
        "logging_limit": "rate_limited", "retention": "unknown",
    }
    values.update(changes)
    return SourceProfile(**values)


def journal(index, *, offset_us=None, realtime_offset_us=None, boot_id=BOOT_ID,
            src_ip=REMOTE, dst_ip=DESTINATION, dst_port=None, src_port=40123,
            protocol="TCP", flags="SYN", complete_flags=True, ingress="eth0",
            egress="", label="[UFW BLOCK]", transport="kernel"):
    offset_us = index * 1_000_000 if offset_us is None else offset_us
    realtime_offset_us = offset_us if realtime_offset_us is None else realtime_offset_us
    dst_port = 20000 + index if dst_port is None else dst_port
    layer3 = "TC=0 HOPLIMIT=64 FLOWLBL=0" if ":" in src_ip else "TOS=0x00 PREC=0x00 TTL=64 ID=7"
    fields = [label, f"IN={ingress}", f"OUT={egress}", f"SRC={src_ip}", f"DST={dst_ip}",
              "LEN=60", layer3, f"PROTO={protocol}"]
    if src_port is not None:
        fields.append(f"SPT={src_port}")
    if dst_port is not None:
        fields.append(f"DPT={dst_port}")
    if protocol == "TCP":
        fields.extend(["WINDOW=64240", "RES=0x00", flags])
        if complete_flags:
            fields.append("URGP=0")
    elif protocol == "UDP":
        # Kernel UDP records legitimately repeat LEN for the transport length.
        fields.append("LEN=40")
    return {
        "_TRANSPORT": transport, "_BOOT_ID": boot_id, "__CURSOR": f"test-cursor-{index}",
        "__REALTIME_TIMESTAMP": str(REALTIME_US + realtime_offset_us),
        "__MONOTONIC_TIMESTAMP": str(MONOTONIC_US + offset_us), "MESSAGE": " ".join(fields),
    }


def event(index, *, source_profile=None, **changes):
    return parse_ufw(journal(index, **changes), profile=source_profile or profile())


def scan(count=10, **changes):
    return [event(index, **changes) for index in range(count)]


def maintenance(**changes):
    values = {
        "authorization_id": "approved-probe", "source_id": "sensor-a",
        "src_ip": REMOTE, "dst_ip": DESTINATION, "protocol": "TCP",
        "dst_ports": frozenset(range(20000, 20010)),
        "starts_at_us": REALTIME_US, "ends_at_us": REALTIME_US + 9_000_000,
        "reason": "Synthetic approved maintenance window",
    }
    values.update(changes)
    return MaintenanceWindow(**values)


def test_empty_context_explicitly_reports_limits_instead_of_claiming_safety():
    report = detect_network([])
    assert report.findings == ()
    assert (report.input_count, report.unique_count, report.duplicate_count,
            report.eligible_count, report.excluded_count) == (0, 0, 0, 0, 0)
    assert {"offline_context_only", "observations_are_lower_bounds",
            "apparent_source_not_identity"} <= set(report.coverage)


def test_threshold_retains_complete_evidence_and_source_provenance():
    rows = scan()
    assert detect_network(rows[:-1]).findings == ()
    report = detect_network(rows)
    finding, = report.findings
    assert (report.input_count, report.unique_count, report.duplicate_count,
            report.eligible_count, report.excluded_count) == (10, 10, 0, 10, 0)
    assert finding.rule_id == "network_tcp_multi_port_probe"
    assert finding.rule_version == 1 and finding.window_seconds == 300
    assert finding.source_id == "sensor-a" and finding.boot_id == BOOT_ID
    assert finding.source_profile_revision == profile().revision
    assert (finding.src_ip, finding.dst_ip) == (REMOTE, DESTINATION)
    assert finding.first_monotonic_us == MONOTONIC_US
    assert finding.last_monotonic_us == MONOTONIC_US + 9_000_000
    assert finding.first_journal_realtime_us == REALTIME_US
    assert finding.last_journal_realtime_us == REALTIME_US + 9_000_000
    assert finding.distinct_dst_ports == tuple(range(20000, 20010))
    assert finding.evidence_ids == tuple(row.event_id for row in rows)
    assert finding.qualifying_windows == 1
    assert finding.maintenance_context == ()


@pytest.mark.parametrize("last_us,expected", [(300_000_000, True), (300_000_001, False)])
def test_five_minute_monotonic_window_boundary_is_inclusive(last_us, expected):
    rows = scan(9) + [event(9, offset_us=last_us)]
    assert bool(detect_network(rows).findings) is expected


def test_many_retries_to_one_port_do_not_supply_port_diversity():
    report = detect_network(scan(50, dst_port=22))
    assert report.eligible_count == 50 and report.findings == ()


@pytest.mark.parametrize("changes", [
    {"protocol": "UDP"}, {"flags": "SYN ACK"}, {"flags": "SYN RST"},
    {"flags": "SYN FIN"}, {"flags": "ACK"}, {"flags": ""},
    {"complete_flags": False}, {"src_port": None}, {"egress": "eth1"},
    {"ingress": "eth2"},
])
def test_non_candidate_packets_do_not_become_probes(changes):
    report = detect_network(scan(**changes))
    assert report.findings == ()
    assert report.eligible_count == 0 and report.excluded_count == 10


def test_log_prefix_from_untrusted_transport_is_rejected():
    # A process writing a convincing prefix cannot create trusted kernel evidence.
    with pytest.raises(ValueError):
        parse_ufw(journal(0, transport="syslog"), profile=profile())


@pytest.mark.parametrize("source_profile", [
    {"local_input_labels": (), "local_input_interfaces": ()},
    {"local_input_interfaces": ("other0",)}, {"rejection_labels": ()},
])
def test_message_shape_alone_does_not_supply_input_or_rejection_provenance(source_profile):
    report = detect_network(scan(source_profile=profile(**source_profile)))
    assert report.findings == () and report.eligible_count == 0
    assert report.excluded_count == 10


@pytest.mark.parametrize("changes", [
    {"source_profile": {"source_id": "sensor-b"}},
    {"source_profile": {"ruleset_sha256": "b" * 64}},
    {"boot_id": "2" * 32}, {"src_ip": "203.0.113.8"}, {"dst_ip": "192.0.2.11"},
])
def test_source_boot_profile_and_endpoint_boundaries_prevent_pooling(changes):
    changes = dict(changes)
    if "source_profile" in changes:
        changes["source_profile"] = profile(**changes["source_profile"])
    report = detect_network(scan(9) + [event(9, **changes)])
    assert report.eligible_count == 10 and report.findings == ()


def test_ipv6_addresses_are_canonicalized_and_detected_without_ipv4_assumptions():
    finding, = detect_network(scan(src_ip="2001:db8::0042", dst_ip="2001:db8::0010")).findings
    assert (finding.src_ip, finding.dst_ip) == ("2001:db8::42", "2001:db8::10")
    assert finding.distinct_dst_ports == tuple(range(20000, 20010))


def test_duplicate_replay_and_shuffling_preserve_evidence_and_expose_counts():
    rows = scan()
    replay = rows + rows[:3]
    reference = detect_network(replay)
    random.Random(29).shuffle(replay)
    assert detect_network(replay) == reference
    assert reference.findings == detect_network(rows).findings
    assert (reference.input_count, reference.unique_count, reference.duplicate_count,
            reference.eligible_count) == (13, 10, 3, 10)
    assert detect_network(scan(9) * 5).findings == ()


@pytest.mark.parametrize("reverse", [False, True])
def test_same_cursor_with_changed_content_is_rejected_in_both_arrival_orders(reverse):
    rows = [event(0), event(0, dst_port=60000)]
    if reverse:
        rows.reverse()
    with pytest.raises(ValueError) as error:
        detect_network(rows)
    assert REMOTE not in str(error.value) and "test-cursor" not in str(error.value)


def test_forged_normalized_event_cannot_bypass_content_validation():
    with pytest.raises(ValueError):
        detect_network([replace(event(0), dst_port=65536)])


def test_dense_windows_coalesce_once_and_keep_every_retained_event():
    rows = [event(index, offset_us=index * 100_000, dst_port=20000 + index % 20)
            for index in range(2000)]
    finding, = detect_network(rows).findings
    assert finding.qualifying_windows == 1991
    assert finding.evidence_ids == tuple(row.event_id for row in rows)
    assert finding.distinct_dst_ports == tuple(range(20000, 20020))


def test_overlapping_qualifying_windows_can_form_an_episode_longer_than_five_minutes():
    rows = [event(index, offset_us=index * 20_000_000) for index in range(40)]
    finding, = detect_network(rows).findings
    assert finding.last_monotonic_us - finding.first_monotonic_us == 780_000_000
    assert finding.qualifying_windows == 31
    assert finding.evidence_ids == tuple(row.event_id for row in rows)


def test_disjoint_episodes_remain_separate():
    first = scan()
    second = [event(100 + index, offset_us=(1000 + index) * 1_000_000)
              for index in range(10)]
    findings = detect_network(second + first).findings
    assert len(findings) == 2
    assert [item.evidence_ids for item in findings] == [
        tuple(row.event_id for row in first), tuple(row.event_id for row in second)]


@pytest.mark.parametrize("jump_us", [-3_600_000_000, 3_600_000_000])
def test_wall_clock_jump_does_not_change_window_but_disables_maintenance_annotation(jump_us):
    rows = [event(index, realtime_offset_us=index * 1_000_000 + (jump_us if index >= 5 else 0))
            for index in range(10)]
    report = detect_network(rows, maintenance=[maintenance(
        starts_at_us=REALTIME_US - 4_000_000_000, ends_at_us=REALTIME_US + 4_000_000_000)])
    finding, = report.findings
    assert "journal_clock_discontinuity" in report.coverage
    assert "journal_clock_discontinuity" in finding.coverage
    assert finding.evidence_ids == tuple(row.event_id for row in rows)
    assert finding.maintenance_context == ()


def test_normal_clock_receipt_jitter_does_not_disable_maintenance():
    rows = [event(index, realtime_offset_us=index * 1_000_000 + (100_000 if index % 2 else 0))
            for index in range(10)]
    report = detect_network(rows, maintenance=[maintenance(ends_at_us=REALTIME_US + 10_000_000)])
    assert "journal_clock_discontinuity" not in report.coverage
    assert len(report.findings[0].maintenance_context) == 1



@pytest.mark.parametrize("jump_us,expected", [(1_000_000, False), (1_000_001, True)])
def test_clock_discontinuity_tolerance_boundary(jump_us, expected):
    rows = [event(index, realtime_offset_us=index * 1_000_000 + (jump_us if index >= 5 else 0))
            for index in range(10)]
    report = detect_network(rows, maintenance=[maintenance(ends_at_us=REALTIME_US + 12_000_000)])
    assert ("journal_clock_discontinuity" in report.coverage) is expected
    assert bool(report.findings[0].maintenance_context) is not expected


def test_clock_discontinuity_on_another_source_does_not_taint_this_finding():
    other_profile = profile(source_id="sensor-b")
    rows = scan() + [event(100, source_profile=other_profile),
                     event(101, source_profile=other_profile, realtime_offset_us=4_000_000_000)]
    report = detect_network(rows, maintenance=[maintenance()])
    finding, = report.findings
    assert "journal_clock_discontinuity" in report.coverage
    assert "journal_clock_discontinuity" not in finding.coverage
    assert len(finding.maintenance_context) == 1


def test_compressed_wall_clock_cannot_turn_an_overlong_monotonic_window_into_a_probe():
    rows = [event(index, offset_us=index * 60_000_000, realtime_offset_us=index * 1_000_000)
            for index in range(10)]
    report = detect_network(rows)
    assert report.findings == ()
    assert "journal_clock_discontinuity" in report.coverage


def test_record_limit_counts_duplicates_and_stops_consuming_lazy_input(monkeypatch):
    monkeypatch.setattr(network_detection, "MAX_INPUT_RECORDS", 3)
    row = event(0)
    consumed = []

    def unbounded_input():
        for index in range(100):
            consumed.append(index)
            if index > 3:
                pytest.fail("detector consumed input beyond its record limit")
            yield row

    with pytest.raises(ValueError, match="^network_context_limit$"):
        detect_network(unbounded_input())
    assert len(consumed) == 4
    assert detect_network([row] * 3).duplicate_count == 2


def test_normalized_byte_limit_rejects_context_without_partial_report(monkeypatch):
    monkeypatch.setattr(network_detection, "MAX_INPUT_BYTES", 1)
    with pytest.raises(ValueError, match="^network_context_limit$"):
        detect_network(scan())


def test_exact_maintenance_scope_annotates_evidence_without_removing_finding():
    rows = scan()
    finding, = detect_network(rows, maintenance=[maintenance()]).findings
    match, = finding.maintenance_context
    assert match.authorization_id == "approved-probe"
    assert match.reason == "Synthetic approved maintenance window"
    assert match.evidence_ids == tuple(row.event_id for row in rows)
    assert finding.evidence_ids == match.evidence_ids


def test_partial_maintenance_marks_only_covered_ports_and_time_inclusively():
    rows = scan()
    finding, = detect_network(rows, maintenance=[maintenance(
        dst_ports=frozenset(range(20000, 20005)), starts_at_us=REALTIME_US + 2_000_000,
        ends_at_us=REALTIME_US + 4_000_000)]).findings
    match, = finding.maintenance_context
    assert match.evidence_ids == tuple(row.event_id for row in rows[2:5])
    assert finding.evidence_ids == tuple(row.event_id for row in rows)


@pytest.mark.parametrize("changes", [
    {"source_id": "sensor-b"}, {"src_ip": "203.0.113.8"}, {"dst_ip": "192.0.2.11"},
    {"dst_ports": frozenset({22, 443})},
    {"starts_at_us": REALTIME_US - 20_000_000, "ends_at_us": REALTIME_US - 1},
    {"starts_at_us": REALTIME_US + 9_000_001, "ends_at_us": REALTIME_US + 20_000_000},
])
def test_maintenance_never_extends_beyond_its_explicit_scope(changes):
    finding, = detect_network(scan(), maintenance=[maintenance(**changes)]).findings
    assert finding.maintenance_context == ()


def test_local_looking_apparent_source_is_still_retained_as_advisory():
    # Address identity alone is not an authorization or remediation decision.
    finding, = detect_network(scan(src_ip=DESTINATION)).findings
    assert finding.src_ip == finding.dst_ip == DESTINATION
    assert finding.maintenance_context == ()


@pytest.mark.parametrize("changes", [
    {"authorization_id": ""}, {"source_id": ""}, {"src_ip": "name.example.invalid"},
    {"dst_ip": "192.0.2.0/24"}, {"dst_ports": frozenset()},
    {"dst_ports": frozenset({-1})}, {"dst_ports": frozenset({65536})},
    {"starts_at_us": True}, {"ends_at_us": REALTIME_US - 1}, {"reason": ""},
    {"protocol": "UDP"}, {"dst_ports": frozenset(range(1025))},
    {"ends_at_us": REALTIME_US + 86_400_000_001},
])
def test_invalid_maintenance_scope_is_rejected(changes):
    with pytest.raises(ValueError):
        detect_network(scan(), maintenance=[maintenance(**changes)])


@pytest.mark.parametrize("reverse", [False, True])
def test_conflicting_authorization_identity_is_rejected_independent_of_arrival_order(reverse):
    windows = [maintenance(), maintenance(reason="A different approval reason")]
    if reverse:
        windows.reverse()
    with pytest.raises(ValueError, match="conflicting_network_maintenance"):
        detect_network(scan(), maintenance=windows)


def test_maintenance_count_bound_includes_duplicate_authorizations(monkeypatch):
    monkeypatch.setattr(network_detection, "MAX_MAINTENANCE_WINDOWS", 2)
    window = maintenance()
    finding, = detect_network(scan(), maintenance=[window, window]).findings
    assert len(finding.maintenance_context) == 1
    with pytest.raises(ValueError, match="network_maintenance_limit"):
        detect_network(scan(), maintenance=[window, window, window])


def test_authored_simulation_has_two_detections_and_reproducible_replay_counts():
    script = Path(__file__).resolve().parents[2] / "scripts" / "simulate_network_detection.py"
    simulate = runpy.run_path(str(script))["simulate"]
    result = simulate()
    assert result == simulate()
    assert result["mode"] == "synthetic_offline_network"
    assert len(result["report"]["findings"]) == 2
    assert result["report"]["unique_count"] == 40
    assert result["report"]["duplicate_count"] == 1
