"""Network wire contracts using independently authored synthetic journal records."""
from copy import deepcopy
from dataclasses import asdict, replace
import hashlib

import pytest

from app.telemetry import network_protocol as protocol
from app.telemetry.network_parse import (
    MAX_CURSOR_BYTES, MAX_MONOTONIC_US, MAX_REALTIME_US, SourceProfile, parse_ufw,
)
from app.telemetry.network_protocol import (
    MAX_BATCH_BYTES, MAX_ENTRIES, NetworkProtocolError, decode, encode,
    event_from_dict, event_to_dict, fingerprint, journal_entry, profile_from_dict,
    validate_ack, validate_batch,
)


WALL_US = 1_767_225_600_000_000
BOOT_ID = "1" * 32
PRIVATE_SENTINEL = "synthetic-context-not-for-export"
MAC = "00:00:5e:00:53:02"


def profile(**changes):
    values = {
        "source_id": "protocol-synthetic-firewall", "ruleset_sha256": "a" * 64,
        "log_labels": ("[UFW BLOCK]", "[UFW ALLOW]"), "ip_families": (4, 6),
        "rejection_labels": ("[UFW BLOCK]",),
        "local_input_labels": ("[UFW BLOCK]",), "local_input_interfaces": ("eth0",),
        "logging_limit": "rate_limited", "retention": "unknown",
        "logging_limit_context": "authored test limit", "retention_context": "not measured",
    }
    values.update(changes)
    return SourceProfile(**values)


def record(index=1, **changes):
    values = {
        "_TRANSPORT": "kernel", "_BOOT_ID": BOOT_ID,
        "__CURSOR": f"opaque synthetic cursor/{index};never-split",
        "__REALTIME_TIMESTAMP": str(WALL_US + index),
        "__MONOTONIC_TIMESTAMP": str(1_000_000 + index),
        "MESSAGE": (
            f"[UFW BLOCK] IN=eth0 OUT= MAC={MAC} "
            "SRC=198.51.100.42 DST=192.0.2.12 LEN=60 TTL=64 ID=9 "
            f"PROTO=TCP SPT=41001 DPT={3000 + index} WINDOW=64000 RES=0x00 SYN URGP=0"
        ),
        "_HOSTNAME": PRIVATE_SENTINEL, "UNRELATED": PRIVATE_SENTINEL,
    }
    values.update(changes)
    return values


def batch(enrolled=None, *, entries=None, **changes):
    enrolled = enrolled or profile()
    if entries is None:
        entries = [
            journal_entry(record(1), enrolled), journal_entry(record(2), enrolled),
            journal_entry(record(3, MESSAGE=PRIVATE_SENTINEL), enrolled),
        ]
    values = {
        "version": 1, "source_id": enrolled.source_id, "profile_revision": enrolled.revision,
        "batch_id": "synthetic-batch-1", "collected_at_us": WALL_US + 100,
        "cursor_before": None,
        "cursor_after": next(iter(entries[-1].values()))["journal_cursor"] if entries else None,
        "entries": entries, "reports": ["coverage_start"], "caught_up": True,
    }
    values.update(changes)
    return values


def ack(pending, *, duplicate_indexes=()):
    receipt = {key: deepcopy(value) for key, value in pending.items() if key != "entries"}
    receipt.update({
        "payload_hash": fingerprint(pending), "durable": True, "received_at_us": WALL_US + 200,
        "accepted": 0, "rejected": 0, "duplicates": 0, "results": [],
    })
    for index, entry in enumerate(pending["entries"]):
        row = next(iter(entry.values()))
        status = "accepted" if "event" in entry else "rejected"
        if index in duplicate_indexes:
            status = "duplicate"
        receipt["duplicates" if status == "duplicate" else status] += 1
        receipt["results"].append({
            "event_id": row["event_id"], "content_hash": row["content_hash"],
            "status": status, "code": None if "event" in entry else row["code"],
        })
    return receipt


def resign_event(row):
    """An authenticated sender can recompute hashes; profile checks must still hold."""
    row["event_id"] = fingerprint({
        "source_id": row["source_id"], "boot_id": row["boot_id"],
        "journal_cursor": row["journal_cursor"],
    })
    row["content_hash"] = fingerprint({
        key: value for key, value in row.items() if key not in {"event_id", "content_hash"}
    })


def test_canonical_encoding_has_known_bytes_and_fingerprint():
    value = {"b": [True, None], "a": "\u96ea"}
    expected = b'{"a":"\\u96ea","b":[true,null]}'
    assert encode(value) == expected
    assert fingerprint(value) == hashlib.sha256(expected).hexdigest()
    assert fingerprint(value) == fingerprint({"a": "\u96ea", "b": [True, None]})
    assert decode(expected) == value
    assert fingerprint({"a": 1}) != fingerprint({"a": True})
    assert fingerprint({"a": [1, 2]}) != fingerprint({"a": [2, 1]})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), {"x": object()}, {1, 2}])
def test_encoder_rejects_non_json_and_nonfinite_content(value):
    with pytest.raises(NetworkProtocolError):
        encode(value)


@pytest.mark.parametrize("raw", [
    b"", b"{", b'{"x":1,}', b'{} {}', b'"\xff"', b'"\x00"',
    b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}',
    pytest.param(b"[" * 10000 + b"]" * 10000,
                 id="excessive-nesting"),
    b'{"source_id":"one","source_id":"two"}',
    b'{"entries":[{"event":{"event_id":"same","event_id":"same"}}]}',
    b'{"reports":[],"\\u0072eports":[]}',
])
def test_decoder_rejects_malformed_utf8_nested_duplicates_and_constants(raw):
    with pytest.raises(NetworkProtocolError):
        decode(raw)


@pytest.mark.parametrize("raw", ["{}", bytearray(b"{}"), None, 1, True])
def test_decoder_requires_bytes(raw):
    with pytest.raises(NetworkProtocolError):
        decode(raw)


def test_decoder_enforces_exact_wire_byte_limit_before_parsing():
    at_limit = b"{}" + b" " * (MAX_BATCH_BYTES - 2)
    assert decode(at_limit) == {}
    with pytest.raises(NetworkProtocolError, match="^network_batch_limit$"):
        decode(at_limit + b" ")


def test_profile_lists_normalize_without_changing_trust_revision():
    enrolled = profile()
    wire = decode(encode(asdict(enrolled)))
    wire["log_labels"].reverse()
    wire["ip_families"].reverse()
    restored = profile_from_dict(wire)
    assert type(restored.log_labels) is tuple
    assert restored.revision == enrolled.revision
    assert restored.local_input_interfaces == ("eth0",)
    for changes in (
        {"source_id": "different-source"}, {"ruleset_sha256": "b" * 64},
        {"local_input_labels": (), "local_input_interfaces": ()},
        {"rejection_labels": ()}, {"logging_limit": "unlimited"},
        {"retention_context": "changed supported horizon"},
    ):
        assert profile_from_dict(asdict(replace(enrolled, **changes))).revision != enrolled.revision


@pytest.mark.parametrize("changes", [
    {"schema_version": True}, {"schema_version": 2}, {"source_id": "unsafe\nsource"},
    {"ruleset_sha256": "not-a-hash"}, {"log_labels": "[UFW BLOCK]"},
    {"log_labels": []}, {"log_labels": [["nested"]]},
    {"ip_families": [True]}, {"ip_families": [4, 4]}, {"ip_families": [5]},
    {"local_input_labels": []}, {"local_input_interfaces": []},
    {"rejection_labels": ["[UNENROLLED]"]}, {"local_input_interfaces": ["bad/interface"]},
    {"logging_limit": "guessed"}, {"retention_context": "line\nbreak"},
    {"MESSAGE": PRIVATE_SENTINEL},
])
def test_profile_rejects_malformed_types_extra_fields_and_unenrolled_assertions(changes):
    value = asdict(profile()) | changes
    with pytest.raises(NetworkProtocolError, match="^invalid_network_profile$"):
        profile_from_dict(value)


@pytest.mark.parametrize("value", [None, [], True, {}, {"source_id": "incomplete"}])
def test_profile_requires_complete_constructor_identity(value):
    with pytest.raises(NetworkProtocolError):
        profile_from_dict(value)


def test_event_round_trip_keeps_only_typed_observations():
    raw = record()
    event = parse_ufw(raw, profile=profile())
    wire = event_to_dict(event)
    assert wire["tcp_flags"] == ["SYN"] and type(wire["coverage"]) is list
    assert event_from_dict(decode(encode(wire))) == event
    assert event_from_dict(wire).final_outcome == "unknown"
    serialized = encode(wire).decode()
    for forbidden in (raw["MESSAGE"], MAC, PRIVATE_SENTINEL, "MESSAGE", "_HOSTNAME", "UNRELATED"):
        assert forbidden not in serialized


@pytest.mark.parametrize("changes", [
    {"schema_version": True}, {"schema_version": 2}, {"parser_version": "invented"},
    {"event_id": "0" * 64}, {"content_hash": "F" * 64}, {"content_hash": "0" * 64},
    {"source_profile_revision": "invalid"}, {"journal_realtime_us": True},
    {"journal_monotonic_us": MAX_MONOTONIC_US + 1}, {"src_port": True},
    {"dst_port": 65536}, {"rejection_related": 1}, {"final_outcome": "accepted"},
    {"tcp_flags": "SYN"}, {"tcp_flags": ["SYN", "SYN"]},
    {"tcp_flags": ["SYN", "ACK"]}, {"tcp_flags": [True]}, {"tcp_flags": ["UNKNOWN"]},
    {"coverage": "logging_rate_limited"}, {"coverage": [True]},
    {"coverage": ["logging_rate_limited"] * 17}, {"coverage": ["invented"]},
    {"MESSAGE": PRIVATE_SENTINEL}, {"MAC": MAC},
])
def test_event_wire_types_hashes_and_field_allowlist(changes):
    wire = event_to_dict(parse_ufw(record(), profile=profile())) | changes
    with pytest.raises(NetworkProtocolError, match="^invalid_network_event$"):
        event_from_dict(wire)


@pytest.mark.parametrize("value", [None, [], True, {}])
def test_event_requires_complete_typed_object(value):
    with pytest.raises(NetworkProtocolError):
        event_from_dict(value)


def test_event_serialization_validates_in_memory_objects_too():
    event = parse_ufw(record(), profile=profile())
    with pytest.raises(ValueError):
        event_to_dict(replace(event, dst_port=65536))


@pytest.mark.parametrize("message", [PRIVATE_SENTINEL, None, [91, 85, 70, 87], "[UFW BLOCK] IN=eth0"])
def test_bad_record_with_complete_identity_becomes_safe_durable_rejection(message):
    raw = record(MESSAGE=message)
    entry = journal_entry(raw, profile())
    row = entry["rejection"]
    assert row["code"] == "invalid_record"
    assert row["journal_cursor"] == raw["__CURSOR"]
    assert row["journal_realtime_us"] == int(raw["__REALTIME_TIMESTAMP"])
    assert row["boot_id"] == BOOT_ID
    assert set(row) == {"event_id", "content_hash", "boot_id", "journal_cursor",
                        "journal_realtime_us", "journal_monotonic_us", "code"}
    assert row["event_id"] == fingerprint({
        "source_id": profile().source_id, "boot_id": BOOT_ID, "journal_cursor": raw["__CURSOR"],
    })
    validate_batch(batch(entries=[entry]), profile())
    serialized = encode(entry).decode()
    for forbidden in (PRIVATE_SENTINEL, MAC, "MESSAGE", "_HOSTNAME", "UNRELATED"):
        assert forbidden not in serialized


def test_forced_context_rejection_keeps_identity_and_binds_code_and_profile():
    raw = record()
    accepted = journal_entry(raw, profile())["event"]
    rejected = journal_entry(raw, profile(), rejection_code="profile_context_unavailable")["rejection"]
    invalid = journal_entry(raw, profile(), rejection_code="invalid_record")["rejection"]
    changed_profile = journal_entry(raw, profile(ruleset_sha256="c" * 64),
                                    rejection_code="invalid_record")["rejection"]
    assert accepted["event_id"] == rejected["event_id"] == invalid["event_id"] == changed_profile["event_id"]
    assert len({row["content_hash"] for row in (accepted, rejected, invalid, changed_profile)}) == 4
    with pytest.raises(NetworkProtocolError):
        journal_entry(raw, profile(), rejection_code="raw-private-error-detail")


@pytest.mark.parametrize("field,value", [
    ("_TRANSPORT", "syslog"), ("_TRANSPORT", None), ("_BOOT_ID", "invalid"),
    ("_BOOT_ID", [BOOT_ID]), ("__CURSOR", None), ("__CURSOR", ""),
    ("__CURSOR", "cursor\nsecret"), ("__CURSOR", "x" * (MAX_CURSOR_BYTES + 1)),
    ("__REALTIME_TIMESTAMP", True), ("__REALTIME_TIMESTAMP", str(MAX_REALTIME_US + 1)),
    ("__REALTIME_TIMESTAMP", "1.5"), ("__MONOTONIC_TIMESTAMP", None),
    ("__MONOTONIC_TIMESTAMP", str(MAX_MONOTONIC_US + 1)),
])
def test_unusable_journal_identity_aborts_instead_of_acknowledgeable_rejection(field, value):
    with pytest.raises(NetworkProtocolError):
        journal_entry(record(**{field: value}), profile(), rejection_code="invalid_record")


@pytest.mark.parametrize("field", ["_TRANSPORT", "_BOOT_ID", "__CURSOR", "__REALTIME_TIMESTAMP", "__MONOTONIC_TIMESTAMP"])
def test_missing_journal_identity_cannot_be_skipped(field):
    raw = record()
    del raw[field]
    with pytest.raises(NetworkProtocolError):
        journal_entry(raw, profile())


def test_rejection_hashing_has_its_own_record_limit():
    with pytest.raises(NetworkProtocolError, match="^network_journal_record_limit$"):
        journal_entry(record(MESSAGE="x" * 65537), profile())


def test_batch_round_trip_binds_mixed_entries_and_last_cursor():
    pending = batch()
    assert validate_batch(decode(encode(pending)), profile()) == pending
    assert len(pending["entries"]) == 3
    assert pending["entries"][-1]["rejection"]["journal_cursor"] == pending["cursor_after"]
    validate_ack(decode(encode(ack(pending))), pending)


@pytest.mark.parametrize("changes", [
    {"version": True}, {"version": 1.0}, {"version": "1"}, {"version": 2},
    {"source_id": "another-source"}, {"source_id": True}, {"profile_revision": "0" * 64},
    {"batch_id": True}, {"batch_id": ""}, {"batch_id": "spaces forbidden"},
    {"batch_id": "a" * 129}, {"collected_at_us": True}, {"collected_at_us": -1},
    {"collected_at_us": MAX_REALTIME_US + 1}, {"cursor_before": ""},
    {"cursor_before": "\u96ea"}, {"cursor_after": "wrong-last-cursor"}, {"caught_up": 1},
    {"reports": "catching_up"}, {"reports": ["unknown"]},
    {"reports": ["coverage_start", "coverage_start"]}, {"reports": [True]},
    {"entries": {}}, {"entries": None}, {"MESSAGE": PRIVATE_SENTINEL},
])
def test_invalid_batch_types_identity_coverage_and_checkpoint_are_rejected(changes):
    with pytest.raises(NetworkProtocolError):
        validate_batch(batch() | changes, profile())


@pytest.mark.parametrize("field", ["entries", "source_id", "version", "reports", "caught_up", "cursor_before"])
def test_missing_batch_contract_fields_are_rejected(field):
    pending = batch()
    del pending[field]
    with pytest.raises(NetworkProtocolError):
        validate_batch(pending, profile())


@pytest.mark.parametrize("report", ["catching_up", "profile_drift", "journal_cursor_unavailable"])
def test_caught_up_cannot_contradict_loss_or_backlog_report(report):
    with pytest.raises(NetworkProtocolError, match="^inconsistent_network_coverage$"):
        validate_batch(batch(reports=[report]), profile())


def test_empty_health_batch_cannot_advance_checkpoint_and_drift_cannot_carry_events():
    pending = batch(entries=[], cursor_before="last-acknowledged", cursor_after="last-acknowledged",
                    reports=["profile_drift"], caught_up=False)
    validate_batch(pending, profile())
    with pytest.raises(NetworkProtocolError):
        validate_batch(pending | {"cursor_after": "not-read"}, profile())
    with pytest.raises(NetworkProtocolError):
        validate_batch(batch(reports=["profile_drift"], caught_up=False), profile())
    unchanged = pending | {"reports": [], "caught_up": True}
    validate_batch(unchanged, profile())
    with pytest.raises(NetworkProtocolError, match="^network_checkpoint_mismatch$"):
        validate_batch(unchanged | {"cursor_after": "invented"}, profile())


@pytest.mark.parametrize("entry", [None, [], {}, {"event": {}}, {"rejection": {}},
                                    {"event": {}, "rejection": {}}, {"MESSAGE": PRIVATE_SENTINEL}])
def test_entry_envelope_has_exactly_one_supported_record(entry):
    pending = batch()
    pending["entries"][0] = entry
    with pytest.raises(NetworkProtocolError):
        validate_batch(pending, profile())


def test_batch_record_count_and_serialized_byte_budgets(monkeypatch):
    pending = batch(entries=[journal_entry(record(index), profile()) for index in range(MAX_ENTRIES)])
    validate_batch(pending, profile())
    too_many = deepcopy(pending)
    too_many["entries"].append(deepcopy(too_many["entries"][-1]))
    with pytest.raises(NetworkProtocolError, match="^network_batch_limit$"):
        validate_batch(too_many, profile())
    encoded_size = len(encode(pending))
    monkeypatch.setattr(protocol, "MAX_BATCH_BYTES", encoded_size)
    validate_batch(pending, profile())
    monkeypatch.setattr(protocol, "MAX_BATCH_BYTES", encoded_size - 1)
    with pytest.raises(NetworkProtocolError, match="^network_batch_limit$"):
        validate_batch(pending, profile())


@pytest.mark.parametrize("changes", [
    {"source_id": "unenrolled-source"}, {"source_profile_revision": "0" * 64},
    {"log_label": "[OTHER BLOCK]"}, {"rejection_related": False},
    {"direction": "unknown", "observation_point": "unknown",
     "coverage": ["journal_retention_unknown", "logging_rate_limited", "unverified_local_input"]},
])
def test_recomputed_hash_cannot_change_enrolled_source_or_profile_assertions(changes):
    pending = batch()
    row = pending["entries"][0]["event"]
    row.update(changes)
    resign_event(row)
    event_from_dict(row)  # Structurally sound hashes do not grant profile authority.
    with pytest.raises(NetworkProtocolError, match="^network_profile_mismatch$"):
        validate_batch(pending, profile())


def test_recomputed_hash_cannot_claim_unenrolled_ip_family_or_local_input():
    enrolled = profile(ip_families=(4,))
    pending = batch(enrolled)
    row = pending["entries"][0]["event"]
    row.update(ip_family=6, src_ip="2001:db8::42", dst_ip="2001:db8::12")
    resign_event(row)
    with pytest.raises(NetworkProtocolError, match="^network_profile_mismatch$"):
        validate_batch(pending, enrolled)
    unverified = profile(local_input_labels=(), local_input_interfaces=())
    pending = batch(unverified)
    row = pending["entries"][0]["event"]
    row.update(direction="local_input", observation_point="local_input")
    row["coverage"].remove("unverified_local_input")
    resign_event(row)
    with pytest.raises(NetworkProtocolError, match="^network_profile_mismatch$"):
        validate_batch(pending, unverified)


@pytest.mark.parametrize("coverage", [[], ["logging_rate_limited"], ["journal_retention_unknown"],
                                      ["journal_retention_unknown", "logging_limits_unknown"]])
def test_event_cannot_strip_or_relabel_enrolled_limits_even_with_fresh_hash(coverage):
    pending = batch()
    row = pending["entries"][0]["event"]
    row["coverage"] = coverage
    resign_event(row)
    event_from_dict(row)
    with pytest.raises(NetworkProtocolError):
        validate_batch(pending, profile())


@pytest.mark.parametrize("logging_limit,retention", [
    ("rate_limited", "unknown"), ("unknown", "bounded"), ("unlimited", "bounded"),
])
def test_profile_coverage_contract_accepts_each_legitimate_enrollment(logging_limit, retention):
    enrolled = profile(logging_limit=logging_limit, retention=retention)
    pending = batch(enrolled)
    validate_batch(pending, enrolled)
    for entry in pending["entries"][:2]:
        coverage = set(entry["event"]["coverage"])
        assert ("logging_rate_limited" in coverage) == (logging_limit == "rate_limited")
        assert ("logging_limits_unknown" in coverage) == (logging_limit == "unknown")
        assert ("journal_retention_unknown" in coverage) == (retention == "unknown")


@pytest.mark.parametrize("changes,extra_coverage", [
    ({"src_port": None}, ()),
    ({"protocol": "OTHER", "observed_protocol": "ICMP", "tcp_flags": None}, ()),
    ({}, ("fragmented_packet",)),
    ({}, ("truncated_transport_header",)),
])
def test_recomputed_hash_does_not_hide_transport_uncertainty(changes, extra_coverage):
    pending = batch()
    row = pending["entries"][0]["event"]
    row.update(changes)
    row["coverage"] = sorted(set(row["coverage"]) | set(extra_coverage))
    resign_event(row)
    event_from_dict(row)
    with pytest.raises(NetworkProtocolError):
        validate_batch(pending, profile())


@pytest.mark.parametrize("changes", [
    {"event_id": "0" * 64}, {"content_hash": "uppercase"}, {"content_hash": True},
    {"code": "arbitrary-error-detail"}, {"code": None}, {"boot_id": "bad"},
    {"journal_cursor": ""}, {"journal_realtime_us": True},
    {"journal_monotonic_us": -1}, {"MESSAGE": PRIVATE_SENTINEL},
])
def test_rejection_wire_identity_code_types_and_allowlist(changes):
    pending = batch()
    pending["entries"][-1]["rejection"].update(changes)
    with pytest.raises(NetworkProtocolError):
        validate_batch(pending, profile())


@pytest.mark.parametrize("duplicate_indexes", [(), (0,), (2,), (0, 1, 2)])
def test_complete_ack_accepts_exact_commit_or_replay_results(duplicate_indexes):
    pending = batch()
    receipt = ack(pending, duplicate_indexes=duplicate_indexes)
    assert receipt["duplicates"] == len(duplicate_indexes)
    validate_ack(decode(encode(receipt)), pending)


def test_ack_for_empty_health_batch_has_no_invented_results():
    pending = batch(entries=[], cursor_before="last", cursor_after="last", reports=[], caught_up=True)
    receipt = ack(pending)
    assert (receipt["accepted"], receipt["rejected"], receipt["duplicates"]) == (0, 0, 0)
    assert receipt["results"] == []
    validate_ack(receipt, pending)


@pytest.mark.parametrize("changes", [
    {"version": True}, {"version": 1.0}, {"source_id": "other-source"},
    {"profile_revision": "0" * 64}, {"batch_id": "another-batch"},
    {"collected_at_us": True}, {"collected_at_us": WALL_US},
    {"cursor_before": "invented"}, {"cursor_after": "invented"},
    {"reports": []}, {"caught_up": 1}, {"caught_up": False},
    {"payload_hash": "0" * 64}, {"durable": False}, {"durable": 1},
    {"received_at_us": True}, {"received_at_us": -1}, {"received_at_us": MAX_REALTIME_US + 1},
    {"accepted": True}, {"accepted": 2.0}, {"accepted": 3},
    {"rejected": True}, {"rejected": 0}, {"duplicates": False}, {"duplicates": 1},
    {"results": []}, {"results": None}, {"extra": "ignored-is-unsafe"},
])
def test_ack_rejects_wrong_identity_checkpoint_counts_types_and_extra_fields(changes):
    pending = batch()
    with pytest.raises(NetworkProtocolError):
        validate_ack(ack(pending) | changes, pending)


@pytest.mark.parametrize("field", ["durable", "payload_hash", "results", "received_at_us", "cursor_after", "accepted"])
def test_ack_requires_all_commit_receipt_fields(field):
    pending = batch()
    receipt = ack(pending)
    del receipt[field]
    with pytest.raises(NetworkProtocolError):
        validate_ack(receipt, pending)


@pytest.mark.parametrize("index,changes", [
    (0, {"event_id": "0" * 64}), (0, {"content_hash": "0" * 64}),
    (0, {"status": "rejected"}), (0, {"status": "committed"}),
    (0, {"status": True}), (0, {"code": "invalid_record"}),
    (2, {"status": "accepted"}), (2, {"code": "profile_context_unavailable"}),
    (2, {"code": None}), (2, {"content_hash": "0" * 64}),
    (1, {"extra": PRIVATE_SENTINEL}),
])
def test_ack_binds_every_ordered_record_status_code_and_content_hash(index, changes):
    pending = batch()
    receipt = ack(pending)
    receipt["results"][index].update(changes)
    with pytest.raises(NetworkProtocolError):
        validate_ack(receipt, pending)


def test_ack_cannot_reorder_omit_duplicate_or_add_evidence_results():
    pending = batch()
    original = ack(pending)
    results = original["results"]
    for changed_results in (
        [results[1], results[0], results[2]], results[:-1],
        results + [results[0]], [results[0], results[0], results[2]],
    ):
        with pytest.raises(NetworkProtocolError):
            validate_ack(original | {"results": changed_results}, pending)


def test_ack_hash_binds_payload_even_when_all_echoed_fields_stay_equal():
    pending = batch()
    receipt = ack(pending)
    changed = deepcopy(pending)
    changed["entries"][0]["event"]["dst_port"] += 1
    resign_event(changed["entries"][0]["event"])
    validate_batch(changed, profile())
    with pytest.raises(NetworkProtocolError):
        validate_ack(receipt, changed)


def test_full_profile_wire_roundtrip_binds_guard_validity_and_parser_version():
    enrolled = profile(guard_version='netfilter-full-v1', profile_valid_from_us=WALL_US)
    assert profile_from_dict(asdict(enrolled)) == enrolled
    pending = batch(enrolled, entries=[journal_entry(record(1), enrolled)])
    assert validate_batch(decode(encode(pending)), enrolled) == pending
    old = record(0, __REALTIME_TIMESTAMP=str(WALL_US - 1))
    # A correctly hashed event before enrollment must still be refused by API.
    with pytest.raises(NetworkProtocolError, match='network_profile_mismatch'):
        validate_batch(batch(enrolled, entries=[journal_entry(old, enrolled)]), enrolled)
    with pytest.raises(NetworkProtocolError, match='network_profile_mismatch'):
        validate_batch(batch(enrolled, entries=[], collected_at_us=WALL_US - 1), enrolled)
    changed = deepcopy(pending)
    event = changed['entries'][0]['event']
    event['parser_version'] = 'ufw-kernel-v1'
    event['content_hash'] = fingerprint({k: v for k, v in event.items() if k not in {'event_id', 'content_hash'}})
    with pytest.raises(NetworkProtocolError, match='network_profile_mismatch'):
        validate_batch(changed, enrolled)


def test_native_wire_observation_does_not_gain_rejection_or_local_direction():
    enrolled = profile(guard_version='netfilter-full-v1', profile_valid_from_us=WALL_US,
                       log_labels=('sample-observation:',), rejection_labels=(),
                       local_input_labels=(), local_input_interfaces=())
    raw = record(1)
    raw['MESSAGE'] = raw['MESSAGE'].replace('[UFW BLOCK]', 'sample-observation:')
    pending = batch(enrolled, entries=[journal_entry(raw, enrolled)])
    assert validate_batch(pending, enrolled) == pending
    for field, value in [('rejection_related', True), ('direction', 'local_input')]:
        changed = deepcopy(pending)
        event = changed['entries'][0]['event']
        event[field] = value
        event['content_hash'] = fingerprint({k: v for k, v in event.items() if k not in {'event_id', 'content_hash'}})
        with pytest.raises(NetworkProtocolError):
            validate_batch(changed, enrolled)


def test_terminal_profile_roundtrip_rejects_version_coverage_allowlist_and_time_tampering():
    enrolled = profile(guard_version='netfilter-terminal-v2', profile_valid_from_us=WALL_US,
                       dynamic_terminal_sets=('inet/synthetic/denied_sources',))
    assert profile_from_dict(decode(encode(asdict(enrolled)))) == enrolled
    pending = batch(enrolled, entries=[journal_entry(record(1), enrolled)])
    assert validate_batch(decode(encode(pending)), enrolled) == pending
    for parser, remove in [('netfilter-kernel-v3', True), ('netfilter-kernel-v2', False),
                           ('netfilter-kernel-v2', True), ('ufw-kernel-v1', True)]:
        changed = deepcopy(pending)
        event = changed['entries'][0]['event']
        event['parser_version'] = parser
        if remove:
            event['coverage'].remove('dynamic_terminal_filtering')
        resign_event(event)
        with pytest.raises(NetworkProtocolError):
            validate_batch(changed, enrolled)
    different = profile(guard_version='netfilter-terminal-v2', profile_valid_from_us=WALL_US,
                        dynamic_terminal_sets=('inet/synthetic/different',))
    with pytest.raises(NetworkProtocolError, match='network_profile_mismatch'):
        validate_batch(pending, different)
    for old in [batch(enrolled, entries=[], collected_at_us=WALL_US - 1),
                batch(enrolled, entries=[journal_entry(record(0, __REALTIME_TIMESTAMP=str(WALL_US - 1)), enrolled)])]:
        with pytest.raises(NetworkProtocolError, match='network_profile_mismatch'):
            validate_batch(old, enrolled)
