"""Strict versioned network transport; no raw journal messages cross this seam."""
from dataclasses import asdict, fields
import hashlib
import json
import re

from .network_parse import (FULL_GUARD, FULL_PARSER_VERSION, PARSER_VERSION,
                            MAX_CURSOR_BYTES, MAX_MONOTONIC_US, MAX_REALTIME_US,
                            NetworkEvent, SourceProfile, parse_ufw, validate_event)

MAX_BATCH_BYTES = 1024 * 1024
MAX_ENTRIES = 200
REPORT_CODES = frozenset({"coverage_start", "journal_cursor_unavailable", "profile_drift",
                          "catching_up", "profile_boundary"})
REJECTION_CODES = frozenset({"invalid_record", "profile_context_unavailable"})
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_BOOT = re.compile(r"[0-9a-f]{32}\Z")
_BATCH_FIELDS = {"version", "source_id", "profile_revision", "batch_id", "collected_at_us",
                 "cursor_before", "cursor_after", "entries", "reports", "caught_up"}
_REJECTION_FIELDS = {"event_id", "content_hash", "boot_id", "journal_cursor",
                     "journal_realtime_us", "journal_monotonic_us", "code"}


class NetworkProtocolError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _fail(code="invalid_network_payload"):
    raise NetworkProtocolError(code)


def encode(value) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("ascii")
    except (ValueError, TypeError, RecursionError):
        _fail()


def fingerprint(value) -> str:
    return hashlib.sha256(encode(value)).hexdigest()


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate_network_json_field")
        result[key] = value
    return result


def decode(raw: bytes):
    if not isinstance(raw, bytes) or len(raw) > MAX_BATCH_BYTES:
        _fail("network_batch_limit")
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_fields,
                            parse_constant=lambda _: _fail())
        pending = [(result, 0)]
        nodes = 0
        while pending:
            value, depth = pending.pop()
            nodes += 1
            if depth > 16 or nodes > 20_000:
                _fail("network_json_structure_limit")
            if type(value) is dict:
                pending.extend((item, depth + 1) for item in value.values())
            elif type(value) is list:
                pending.extend((item, depth + 1) for item in value)
        return result
    except NetworkProtocolError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        _fail()


def profile_from_dict(value: dict) -> SourceProfile:
    if type(value) is not dict or set(value) - {field.name for field in fields(SourceProfile)}:
        _fail("invalid_network_profile")
    value = dict(value)
    for name in ("log_labels", "ip_families", "rejection_labels", "local_input_labels", "local_input_interfaces"):
        if name in value:
            if type(value[name]) not in (list, tuple):
                _fail("invalid_network_profile")
            value[name] = tuple(value[name])
    try:
        return SourceProfile(**value)
    except (ValueError, TypeError):
        _fail("invalid_network_profile")


def event_to_dict(event: NetworkEvent) -> dict:
    validate_event(event)
    result = asdict(event)
    result["coverage"] = list(event.coverage)
    result["tcp_flags"] = sorted(event.tcp_flags) if event.tcp_flags is not None else None
    return result


def event_from_dict(value: dict) -> NetworkEvent:
    if type(value) is not dict or set(value) != {field.name for field in fields(NetworkEvent)}:
        _fail("invalid_network_event")
    value = dict(value)
    flags = value["tcp_flags"]
    coverage = value["coverage"]
    if (type(coverage) is not list or len(coverage) > 16
            or any(type(code) is not str for code in coverage)):
        _fail("invalid_network_event")
    if flags is not None:
        if (type(flags) is not list or len(flags) > 8
                or any(type(flag) is not str for flag in flags) or flags != sorted(set(flags))):
            _fail("invalid_network_event")
        value["tcp_flags"] = frozenset(flags)
    value["coverage"] = tuple(coverage)
    try:
        event = NetworkEvent(**value)
        validate_event(event)
        return event
    except (ValueError, TypeError):
        _fail("invalid_network_event")


def _cursor(value, *, nullable=False):
    if nullable and value is None:
        return
    if (type(value) is not str or not 1 <= len(value) <= MAX_CURSOR_BYTES
            or any(not 32 <= ord(char) <= 126 for char in value)):
        _fail("invalid_network_cursor")


def _number(value, maximum=MAX_REALTIME_US):
    if type(value) is not int or not 0 <= value <= maximum:
        _fail("invalid_network_timestamp")


def event_identity(source_id, boot_id, cursor):
    return fingerprint({"source_id": source_id, "boot_id": boot_id, "journal_cursor": cursor})


def journal_entry(record: dict, profile: SourceProfile, *, rejection_code=None) -> dict:
    """Rejected messages retain only identity, a content hash and a fixed code.

    Unusable journal identity aborts export: a caller cannot safely advance an
    unknown cursor. The exporter supplies trusted metadata, not client JSON.
    """
    if type(record) is not dict or record.get("_TRANSPORT") != "kernel":
        _fail("invalid_network_journal_identity")
    boot, cursor = record.get("_BOOT_ID"), record.get("__CURSOR")
    if type(boot) is not str or not _BOOT.fullmatch(boot):
        _fail("invalid_network_journal_identity")
    _cursor(cursor)
    times = []
    for name, maximum in (("__REALTIME_TIMESTAMP", MAX_REALTIME_US),
                          ("__MONOTONIC_TIMESTAMP", MAX_MONOTONIC_US)):
        value = record.get(name)
        if type(value) is str and re.fullmatch(r"[0-9]{1,19}", value):
            value = int(value)
        _number(value, maximum)
        times.append(value)
    if rejection_code is not None and rejection_code not in REJECTION_CODES:
        _fail("invalid_network_rejection")
    if rejection_code is None:
        try:
            return {"event": event_to_dict(parse_ufw(record, profile=profile))}
        except ValueError:
            rejection_code = "invalid_record"
    # Limit hashing work even on an invalid journal record. The source reader
    # separately bounds its raw line before JSON decoding.
    selected = {name: record.get(name) for name in ("_TRANSPORT", "_BOOT_ID", "__CURSOR",
                "__REALTIME_TIMESTAMP", "__MONOTONIC_TIMESTAMP", "MESSAGE")}
    raw = encode(selected)
    if len(raw) > 65536:
        _fail("network_journal_record_limit")
    return {"rejection": {
        "event_id": event_identity(profile.source_id, boot, cursor),
        "content_hash": fingerprint({"record_hash": hashlib.sha256(raw).hexdigest(),
                                     "profile_revision": profile.revision, "code": rejection_code}),
        "boot_id": boot, "journal_cursor": cursor, "journal_realtime_us": times[0],
        "journal_monotonic_us": times[1], "code": rejection_code,
    }}


def validate_batch(payload: dict, profile: SourceProfile) -> dict:
    if type(payload) is not dict or set(payload) != _BATCH_FIELDS:
        _fail()
    if type(payload["version"]) is not int or payload["version"] != 1:
        _fail("unsupported_network_version")
    if payload["source_id"] != profile.source_id or payload["profile_revision"] != profile.revision:
        _fail("network_profile_mismatch")
    if type(payload["batch_id"]) is not str or not _ID.fullmatch(payload["batch_id"]):
        _fail("invalid_network_batch_id")
    _number(payload["collected_at_us"])
    if profile.guard_version == FULL_GUARD and payload["collected_at_us"] < profile.profile_valid_from_us:
        _fail("network_profile_mismatch")
    _cursor(payload["cursor_before"], nullable=True)
    _cursor(payload["cursor_after"], nullable=True)
    reports, entries = payload["reports"], payload["entries"]
    if (type(reports) is not list or len(reports) > len(REPORT_CODES)
            or any(type(code) is not str or code not in REPORT_CODES for code in reports)
            or len(set(reports)) != len(reports) or type(payload["caught_up"]) is not bool):
        _fail()
    if payload["caught_up"] and set(reports) & {"catching_up", "profile_drift", "journal_cursor_unavailable"}:
        _fail("inconsistent_network_coverage")
    if type(entries) is not list or len(entries) > MAX_ENTRIES:
        _fail("network_batch_limit")
    if "profile_drift" in reports and (entries or payload["cursor_after"] != payload["cursor_before"]):
        _fail("network_profile_drift")
    for entry in entries:
        if type(entry) is not dict or set(entry) not in ({"event"}, {"rejection"}):
            _fail()
        if "event" in entry:
            event = event_from_dict(entry["event"])
            if (event.source_id != profile.source_id or event.source_profile_revision != profile.revision
                    or event.parser_version != (FULL_PARSER_VERSION if profile.guard_version == FULL_GUARD else PARSER_VERSION)
                    or event.log_label not in profile.log_labels or event.ip_family not in profile.ip_families
                    or event.rejection_related != (event.log_label in profile.rejection_labels)):
                _fail("network_profile_mismatch")
            if (profile.guard_version == FULL_GUARD
                    and event.journal_realtime_us < profile.profile_valid_from_us):
                _fail("network_profile_mismatch")
            expected = {
                "logging_rate_limited": profile.logging_limit == "rate_limited",
                "logging_limits_unknown": profile.logging_limit == "unknown",
                "journal_retention_unknown": profile.retention == "unknown",
                "unsupported_protocol": event.protocol == "OTHER",
                "missing_transport_ports": event.protocol in ("TCP", "UDP") and
                    (event.src_port is None or event.dst_port is None),
            }
            if any((code in event.coverage) != required for code, required in expected.items()):
                _fail("network_profile_mismatch")
            if event.protocol == "TCP" and event.tcp_flags is not None and (
                    set(event.coverage) & {"truncated_transport_header", "fragmented_packet"}):
                _fail("invalid_network_event")
            local = (event.log_label in profile.local_input_labels
                     and event.ingress_interface in profile.local_input_interfaces
                     and event.egress_interface is None and "incomplete_interfaces" not in event.coverage)
            if (event.direction == "local_input") != local:
                _fail("network_profile_mismatch")
        else:
            row = entry["rejection"]
            if (type(row) is not dict or set(row) != _REJECTION_FIELDS
                    or type(row["code"]) is not str or row["code"] not in REJECTION_CODES
                    or type(row["boot_id"]) is not str or not _BOOT.fullmatch(row["boot_id"])
                    or any(type(row[name]) is not str or not _HASH.fullmatch(row[name])
                           for name in ("event_id", "content_hash"))):
                _fail("invalid_network_rejection")
            _cursor(row["journal_cursor"])
            _number(row["journal_realtime_us"])
            _number(row["journal_monotonic_us"], MAX_MONOTONIC_US)
            if row["event_id"] != event_identity(profile.source_id, row["boot_id"], row["journal_cursor"]):
                _fail("invalid_network_rejection")
    last_cursor = (next(iter(entries[-1].values()))["journal_cursor"] if entries else payload["cursor_before"])
    if payload["cursor_after"] != last_cursor:
        _fail("network_checkpoint_mismatch")
    if len(encode(payload)) > MAX_BATCH_BYTES:
        _fail("network_batch_limit")
    return payload


def validate_ack(ack: dict, batch: dict) -> None:
    """Bind the durable ACK to the full pending batch, including each result."""
    echoed = {key: batch[key] for key in _BATCH_FIELDS - {"entries"}}
    expected_fields = set(echoed) | {"payload_hash", "durable", "received_at_us", "results",
                                    "accepted", "rejected", "duplicates"}
    if type(ack) is not dict or set(ack) != expected_fields:
        _fail("invalid_network_ack")
    if (ack["durable"] is not True or ack["payload_hash"] != fingerprint(batch)
            or any(type(ack[key]) is not type(value) or ack[key] != value for key, value in echoed.items())):
        _fail("invalid_network_ack")
    _number(ack["received_at_us"])
    results = ack["results"]
    if type(results) is not list or len(results) != len(batch["entries"]):
        _fail("invalid_network_ack")
    counts = {"accepted": 0, "rejected": 0, "duplicates": 0}
    for result, entry in zip(results, batch["entries"]):
        row = next(iter(entry.values()))
        valid = "event" in entry
        if (type(result) is not dict or set(result) != {"event_id", "content_hash", "status", "code"}
                or any(result[key] != row[key] for key in ("event_id", "content_hash"))
                or result["code"] != (None if valid else row["code"])
                or result["status"] not in (("accepted", "duplicate") if valid else ("rejected", "duplicate"))):
            _fail("invalid_network_ack")
        counts["duplicates" if result["status"] == "duplicate" else result["status"]] += 1
    if any(type(ack[key]) is not int or ack[key] != value for key, value in counts.items()):
        _fail("invalid_network_ack")
