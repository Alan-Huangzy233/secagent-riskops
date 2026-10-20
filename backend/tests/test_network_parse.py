"""Wholly authored kernel-format scenarios; no captured host/network records."""
from dataclasses import FrozenInstanceError, asdict, replace
import json

import pytest

from app.telemetry.network_parse import (
    MAX_CURSOR_BYTES, MAX_MESSAGE_BYTES, NetworkParseError, SourceProfile,
    parse_ufw, validate_event,
)


def profile(**changes):
    values = dict(
        source_id="synthetic-firewall", ruleset_sha256="a" * 64,
        log_labels=("[UFW BLOCK]", "[UFW ALLOW]"), ip_families=(4, 6),
        rejection_labels=("[UFW BLOCK]",), local_input_labels=("[UFW BLOCK]", "[UFW ALLOW]"),
        local_input_interfaces=("eth0",), logging_limit="rate_limited", retention="unknown",
        logging_limit_context="synthetic per-rule ceiling: three observations/minute, burst ten",
    )
    values.update(changes)
    return SourceProfile(**values)


def record(message=None, **changes):
    values = {
        "_TRANSPORT": "kernel", "_BOOT_ID": "b" * 32, "__CURSOR": "opaque/cursor:one;not-a-parsed-format",
        "__REALTIME_TIMESTAMP": "1790000000000000", "__MONOTONIC_TIMESTAMP": "5000000",
        "MESSAGE": message or (
            "[UFW BLOCK] IN=eth0 OUT= MAC=00:00:5e:00:53:01 "
            "SRC=198.51.100.23 DST=192.0.2.10 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=7 DF "
            "PROTO=TCP SPT=40000 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0"
        ),
    }
    values.update(changes)
    return values


def test_typed_kernel_event_preserves_observation_and_omits_private_input():
    raw = record()
    raw.update({"_HOSTNAME": "ignored-host", "UNRELATED_CONTEXT": "not-exported"})
    event = parse_ufw(raw, profile=profile())
    validate_event(event)
    assert event.source_id == "synthetic-firewall"
    assert event.src_ip == "198.51.100.23"
    assert event.dst_ip == "192.0.2.10"
    assert event.ip_family == 4
    assert event.src_port == 40000 and event.dst_port == 443
    assert event.tcp_flags == frozenset({"SYN"})
    assert event.direction == event.observation_point == "local_input"
    assert event.rejection_related is True
    assert event.final_outcome == "unknown"
    assert event.journal_realtime_us == 1790000000000000
    assert event.journal_monotonic_us == 5000000
    assert event.journal_cursor == raw["__CURSOR"]
    assert set(event.coverage) == {"logging_rate_limited", "journal_retention_unknown"}
    serialized = json.dumps(asdict(event), default=list)
    for excluded in (raw["MESSAGE"], "00:00:5e:00:53:01", "ignored-host", "not-exported"):
        assert excluded not in serialized
    with pytest.raises(FrozenInstanceError):
        event.src_port = 1


def test_profile_revision_binds_stable_context_and_normalizes_set_order():
    enrolled = profile()
    assert enrolled.revision == replace(enrolled, log_labels=tuple(reversed(enrolled.log_labels)), ip_families=(6, 4)).revision
    for change in (
        {"ruleset_sha256": "c" * 64}, {"source_id": "another-synthetic-source"},
        {"local_input_labels": (), "local_input_interfaces": ()},
        {"rejection_labels": ()}, {"logging_limit": "unknown"},
        {"logging_limit_context": "different stable limit"},
        {"retention_context": "different stable retention"},
    ):
        assert replace(enrolled, **change).revision != enrolled.revision


@pytest.mark.parametrize("changes,code", [
    ({"source_id": "sensitive invalid source"}, "invalid_profile_source_id"),
    ({"ruleset_sha256": "no-digest"}, "invalid_ruleset_digest"),
    ({"schema_version": True}, "unsupported_profile_version"),
    ({"schema_version": 2}, "unsupported_profile_version"),
    ({"log_labels": []}, "invalid_profile_labels"),
    ({"log_labels": (["nested"],)}, "invalid_profile_labels"),
    ({"log_labels": ()}, "invalid_profile_labels"),
    ({"log_labels": ("[UFW BLOCK]", "[UFW BLOCK]")}, "invalid_profile_labels"),
    ({"rejection_labels": ("[OTHER BLOCK]",)}, "unenrolled_profile_label"),
    ({"local_input_labels": ("[OTHER BLOCK]",)}, "unenrolled_profile_label"),
    ({"local_input_labels": ()}, "incomplete_local_input_profile"),
    ({"local_input_interfaces": ()}, "incomplete_local_input_profile"),
    ({"local_input_interfaces": ("overlong-interface-name",)}, "invalid_profile_interfaces"),
    ({"ip_families": (True,)}, "invalid_profile_families"),
    ({"ip_families": (4, 4)}, "invalid_profile_families"),
    ({"ip_families": (5,)}, "invalid_profile_families"),
    ({"logging_limit": "guessed"}, "invalid_logging_limit"),
    ({"retention": "forever"}, "invalid_retention"),
    ({"retention_context": "secret\nvalue"}, "invalid_profile_context"),
])
def test_invalid_source_profiles_fail_with_safe_codes(changes, code):
    with pytest.raises(NetworkParseError) as error:
        profile(**changes)
    assert error.value.code == str(error.value) == code


@pytest.mark.parametrize("transport", ["syslog", "stdout", "audit", ["kernel"], None])
def test_kernel_prefix_cannot_replace_trusted_journal_transport(transport):
    with pytest.raises(NetworkParseError, match="^untrusted_transport$"):
        parse_ufw(record(_TRANSPORT=transport), profile=profile())


@pytest.mark.parametrize("field,value,code", [
    ("_BOOT_ID", "bad-sensitive-boot", "invalid_boot_id"),
    ("_BOOT_ID", ["b" * 32], "invalid_boot_id"),
    ("__CURSOR", "", "invalid_journal_cursor"),
    ("__CURSOR", "x" * (MAX_CURSOR_BYTES + 1), "invalid_journal_cursor"),
    ("__CURSOR", "cursor\nsecret", "invalid_journal_cursor"),
    ("__REALTIME_TIMESTAMP", True, "invalid_journal_timestamp"),
    ("__REALTIME_TIMESTAMP", -1, "invalid_journal_timestamp"),
    ("__REALTIME_TIMESTAMP", "1.5", "invalid_journal_timestamp"),
    ("__MONOTONIC_TIMESTAMP", [123], "invalid_journal_timestamp"),
    ("__MONOTONIC_TIMESTAMP", str(1 << 63), "invalid_journal_timestamp"),
    ("MESSAGE", [91, 85, 70, 87], "invalid_message"),
    ("MESSAGE", b"sensitive bytes", "invalid_message"),
    ("MESSAGE", "x" * (MAX_MESSAGE_BYTES + 1), "invalid_message"),
    ("MESSAGE", "[UFW BLOCK]\nsecret", "invalid_message"),
    ("MESSAGE", "[UFW BLOCK] \ud800", "invalid_message"),
])
def test_journal_metadata_bounds_and_unsupported_encodings(field, value, code):
    with pytest.raises(NetworkParseError) as error:
        parse_ufw(record(**{field: value}), profile=profile())
    assert str(error.value) == code



def test_maximum_monotonic_timestamp_has_consistent_json_forms():
    maximum = (1 << 63) - 1
    textual = parse_ufw(record(__MONOTONIC_TIMESTAMP=str(maximum)), profile=profile())
    numeric = parse_ufw(record(__MONOTONIC_TIMESTAMP=maximum), profile=profile())
    assert textual == numeric and textual.journal_monotonic_us == maximum


def test_opaque_cursor_identity_and_separate_content_binding():
    first = parse_ufw(record(), profile=profile())
    same = parse_ufw(record(__REALTIME_TIMESTAMP=1790000000000000), profile=profile())
    assert same == first
    changed = parse_ufw(record(record()["MESSAGE"].replace("DPT=443", "DPT=444")), profile=profile())
    assert changed.key == first.key and changed.content_hash != first.content_hash
    next_profile = parse_ufw(record(), profile=profile(ruleset_sha256="c" * 64))
    assert next_profile.key == first.key and next_profile.content_hash != first.content_hash
    for changed_record, changed_profile in (
        (record(_BOOT_ID="c" * 32), profile()),
        (record(__CURSOR="another opaque cursor"), profile()),
        (record(), profile(source_id="another-synthetic-source")),
    ):
        assert parse_ufw(changed_record, profile=changed_profile).event_id != first.event_id


def test_ipv6_is_canonical_without_collapsing_wire_family():
    line = ("[UFW BLOCK] IN=eth0 OUT= SRC=2001:0DB8:0:1:0:0:0:23 DST=2001:db8:2::10 "
            "LEN=80 TC=0 HOPLIMIT=64 FLOWLBL=0 PROTO=TCP SPT=40000 DPT=443 "
            "WINDOW=64240 RES=0x00 SYN URGP=0")
    event = parse_ufw(record(line), profile=profile())
    assert event.src_ip == "2001:db8:0:1::23" and event.dst_ip == "2001:db8:2::10"
    assert event.ip_family == 6 and event.tcp_flags == frozenset({"SYN"})
    with pytest.raises(NetworkParseError, match="^unenrolled_ip_family$"):
        parse_ufw(record(line), profile=profile(ip_families=(4,)))


@pytest.mark.parametrize("before,after,code", [
    ("SRC=198.51.100.23", "SRC=198.51.100.999", "invalid_ip_address"),
    ("SRC=198.51.100.23", "SRC=2001:db8::23", "mixed_ip_families"),
    ("SRC=198.51.100.23", "SRC=fe80::23%eth0", "invalid_ip_address"),
    ("SRC=198.51.100.23", "SRC=::ffff:198.51.100.23", "unsupported_mapped_address"),
    ("DPT=443", "DPT=65536", "invalid_transport_number"),
    ("DPT=443", "DPT=-1", "invalid_transport_number"),
    ("DPT=443", "DPT=", "invalid_transport_number"),
    ("DPT=443", "DPT=true", "invalid_transport_number"),
    ("IN=eth0", "IN=eth0/secret", "invalid_interface"),
    ("RES=0x00", "RES=oops", "invalid_tcp_reserved_bits"),
    ("SYN URGP=0", "URGP=0 SYN", "invalid_tcp_layout"),
    ("[UFW BLOCK]", "[UNENROLLED BLOCK]", "unenrolled_log_label"),
    ("SRC=198.51.100.23", "", "missing_packet_identity"),
    ("PROTO=TCP", "", "missing_packet_identity"),
    ("PROTO=TCP", "PROTO=UDP", "inconsistent_transport_fields"),
])
def test_malformed_or_ambiguous_values_do_not_echo_input(before, after, code):
    with pytest.raises(NetworkParseError) as error:
        parse_ufw(record(record()["MESSAGE"].replace(before, after)), profile=profile())
    assert str(error.value) == code


@pytest.mark.parametrize("suffix", ["SRC=198.51.100.23", "SRC=203.0.113.23", "DPT=443", "IN=eth0", "PROTO=TCP"])
def test_duplicate_core_fields_are_rejected_even_when_equal(suffix):
    with pytest.raises(NetworkParseError, match="^duplicate_message_field$"):
        parse_ufw(record(record()["MESSAGE"] + " " + suffix), profile=profile())


def test_udp_repeated_len_is_legitimate_but_not_tcp_flags():
    line = ("[UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.23 DST=192.0.2.10 "
            "LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=7 PROTO=UDP SPT=40000 DPT=443 LEN=40")
    event = parse_ufw(record(line), profile=profile())
    assert event.protocol == "UDP" and event.tcp_flags is None
    assert event.src_port == 40000 and event.dst_port == 443
    with pytest.raises(NetworkParseError, match="^duplicate_message_field$"):
        parse_ufw(record(line + " LEN=40"), profile=profile())


def test_label_and_blank_out_do_not_implicitly_prove_input_or_final_verdict():
    line = record()["MESSAGE"]
    for enrolled, message in (
        (profile(local_input_labels=(), local_input_interfaces=()), line),
        (profile(local_input_interfaces=("other0",)), line),
        (profile(), line.replace("OUT= ", "OUT=eth1 ")),
        (profile(), line.replace("IN=eth0 ", "IN= ")),
        (profile(), line.replace("OUT= ", "")),
    ):
        event = parse_ufw(record(message), profile=enrolled)
        assert event.direction == event.observation_point == "unknown"
        assert "unverified_local_input" in event.coverage
        assert event.final_outcome == "unknown"
    allowed = parse_ufw(record(line.replace("[UFW BLOCK]", "[UFW ALLOW]")), profile=profile())
    assert allowed.direction == "local_input" and allowed.rejection_related is False
    assert allowed.final_outcome == "unknown"


def test_flags_distinguish_known_empty_missing_and_truncated_headers():
    line = record()["MESSAGE"]
    empty = parse_ufw(record(line.replace(" SYN ", " ")), profile=profile())
    assert empty.tcp_flags == frozenset()
    assert "tcp_flags_unavailable" not in empty.coverage
    for changed in (
        line.replace(" URGP=0", ""), line.replace("WINDOW=64240 ", ""),
        line.replace("RES=0x00 ", ""), line + " INCOMPLETE [12 bytes]", line + " MF",
    ):
        event = parse_ufw(record(changed), profile=profile())
        assert event.tcp_flags is None
        assert "tcp_flags_unavailable" in event.coverage
    missing = parse_ufw(record(line.replace("SPT=40000 ", "")), profile=profile())
    zero = parse_ufw(record(line.replace("SPT=40000", "SPT=0")), profile=profile())
    assert missing.src_port is None and "missing_transport_ports" in missing.coverage
    assert zero.src_port == 0 and "missing_transport_ports" not in zero.coverage


def test_ipv6_fragment_uncertainty_never_trusts_surviving_flags():
    line = record()["MESSAGE"].replace("SRC=198.51.100.23", "SRC=2001:db8::23").replace("DST=192.0.2.10", "DST=2001:db8::10")
    event = parse_ufw(record(line + " FRAG:0"), profile=profile())
    assert event.tcp_flags is None
    assert {"fragmented_packet", "ipv6_extension_headers", "tcp_flags_unavailable"} <= set(event.coverage)
    with pytest.raises(NetworkParseError, match="^unsupported_ip_options$"):
        parse_ufw(record(line + " OPT ( 0000 )"), profile=profile())


def test_unknown_protocol_remains_an_explicit_unsupported_observation():
    line = "[UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.23 DST=192.0.2.10 LEN=60 PROTO=ICMP TYPE=8 CODE=0"
    event = parse_ufw(record(line), profile=profile())
    assert event.protocol == "OTHER" and event.observed_protocol == "ICMP"
    assert event.src_port is None and event.tcp_flags is None
    assert "unsupported_protocol" in event.coverage
    other = parse_ufw(record(line.replace("PROTO=ICMP", "PROTO=47")), profile=profile())
    assert event.key == other.key and event.content_hash != other.content_hash


def test_unknown_fields_payload_and_excessive_tokens_are_rejected():
    for suffix, code in (
        (" PAYLOAD=private", "unsupported_message_field"),
        (" PRIVATE", "unsupported_message_token"),
        (" " + " ".join("DF" for _ in range(257)), "invalid_message_tokens"),
    ):
        with pytest.raises(NetworkParseError) as error:
            parse_ufw(record(record()["MESSAGE"] + suffix), profile=profile())
        assert str(error.value) == code
    oversized = record()
    oversized.update({f"extra-{i}": "ignored" for i in range(129)})
    with pytest.raises(NetworkParseError, match="^invalid_journal_record$"):
        parse_ufw(oversized, profile=profile())
    missing = record()
    del missing["_BOOT_ID"]
    with pytest.raises(NetworkParseError, match="^missing_journal_metadata$"):
        parse_ufw(missing, profile=profile())


@pytest.mark.parametrize("changes", [
    {"dst_port": 444}, {"journal_realtime_us": 0}, {"source_profile_revision": "c" * 64},
    {"event_id": "c" * 64}, {"content_hash": "c" * 64}, {"rejection_related": False},
    {"tcp_flags": frozenset({"ACK"})}, {"coverage": ()},
    {"ip_family": True}, {"src_port": True}, {"tcp_flags": {"SYN"}},
    {"final_outcome": "blocked"}, {"transport": "syslog"}, {"direction": "forward"},
    {"journal_monotonic_us": -1}, {"schema_version": True},
])
def test_detectors_can_reject_replaced_or_malformed_typed_events(changes):
    with pytest.raises(NetworkParseError):
        validate_event(replace(parse_ufw(record(), profile=profile()), **changes))


def test_hash_binding_ignores_unretained_noise_and_does_not_reinterpret_time():
    initial = parse_ufw(record(), profile=profile())
    # Arrival context is not source content and is deliberately ignored. Kernel
    # MAC/LEN are outside this normalized contract rather than silently stored.
    noisy = record(record()["MESSAGE"].replace("LEN=60", "LEN=61"), collected_at="later", received_at="later")
    assert parse_ufw(noisy, profile=profile()) == initial
    for field in ("__REALTIME_TIMESTAMP", "__MONOTONIC_TIMESTAMP"):
        changed = parse_ufw(record(**{field: "1"}), profile=profile())
        assert changed.key == initial.key and changed.content_hash != initial.content_hash
