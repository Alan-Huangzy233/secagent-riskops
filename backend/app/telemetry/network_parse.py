"""Offline, bounded UFW kernel-journal normalization.

A SourceProfile is a trusted operator assertion, not authentication. Its local
input labels/interfaces must be verified against the effective rules and hooks,
including other rules reusing a label. The future collector must authenticate
source identity, obtain journal metadata itself, reject duplicate JSON keys and
bind observations to the profile effective at collection time. A caller-supplied
``_TRANSPORT`` field alone cannot establish that trust boundary.

This adapter accepts a conservative kernel text subset. It retains no raw line,
MAC address, packet payload or arbitrary journal fields. An accepted observation
is not proof of a connection, a final firewall verdict or source attribution.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
import hashlib
import ipaddress
import json
import re


SCHEMA_VERSION = 1
PARSER_VERSION = "ufw-kernel-v1"
MAX_MESSAGE_BYTES = 8192
MAX_CURSOR_BYTES = 2048
MAX_JOURNAL_FIELDS = 128
MAX_TOKENS = 256
MAX_REALTIME_US = 253402300799999999  # Last microsecond of UTC year 9999.
MAX_MONOTONIC_US = (1 << 63) - 1
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_BOOT = re.compile(r"[0-9a-f]{32}\Z")
_LABEL = re.compile(r"\[[A-Z0-9][A-Z0-9 _:-]{0,59}\]\Z")
_INTERFACE = re.compile(r"[A-Za-z0-9_.:@-]{1,15}\Z")
_PROTOCOL = re.compile(r"[A-Za-z0-9_-]{1,16}\Z")
_DECIMAL = re.compile(r"[0-9]{1,19}\Z")
_TCP_FLAGS = frozenset({"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"})
_CORE_FIELDS = frozenset({"IN", "OUT", "SRC", "DST", "PROTO", "SPT", "DPT", "WINDOW", "RES", "URGP"})
_OPTIONAL_FIELDS = frozenset({
    "MAC", "LEN", "TOS", "PREC", "TTL", "ID", "TC", "HOPLIMIT", "FLOWLBL",
    "SEQ", "ACK", "TYPE", "CODE", "MTU", "POINTER", "GATEWAY", "SPI",
    "UID", "GID", "MARK", "OPT",
})
_COVERAGE = frozenset({
    "logging_rate_limited", "logging_limits_unknown", "journal_retention_unknown",
    "unverified_local_input", "incomplete_interfaces", "missing_transport_ports",
    "tcp_flags_unavailable", "truncated_transport_header", "fragmented_packet",
    "unsupported_protocol", "ipv6_extension_headers",
})


class NetworkParseError(ValueError):
    """A safe, machine-readable rejection; never contains supplied field values."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code: str):
    raise NetworkParseError(code)


def _digest(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _ascii(value: object, *, maximum: int, empty: bool = False) -> bool:
    return (isinstance(value, str) and (empty or bool(value)) and len(value) <= maximum
            and all(32 <= ord(char) <= 126 for char in value))


def _tuple_strings(value: object, *, maximum: int, pattern: re.Pattern) -> bool:
    return (type(value) is tuple and len(value) <= maximum
            and all(isinstance(item, str) and pattern.fullmatch(item) for item in value)
            and len(set(value)) == len(value))


@dataclass(frozen=True)
class SourceProfile:
    """Stable enrollment context; exclude dynamic counters from ruleset_sha256.

    ``local_input_labels`` paired with ``local_input_interfaces`` assert that
    these labels with this interface shape identify local input unambiguously.
    Leave both empty if that assertion has not been verified. This is a narrow
    first-source contract; output/forward/NAT attribution is not implemented.
    Rate and retention details belong in their bounded context strings, not in
    changing counters. A profile revision changes with any stable context field.
    """

    source_id: str
    ruleset_sha256: str
    log_labels: tuple[str, ...]
    ip_families: tuple[int, ...] = (4, 6)
    rejection_labels: tuple[str, ...] = ()
    local_input_labels: tuple[str, ...] = ()
    local_input_interfaces: tuple[str, ...] = ()
    logging_limit: str = "unknown"
    retention: str = "unknown"
    logging_limit_context: str = "unspecified"
    retention_context: str = "unspecified"
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        _validate_profile(self)

    @property
    def revision(self) -> str:
        _validate_profile(self)
        payload = {field.name: getattr(self, field.name) for field in fields(self)}
        for key in ("log_labels", "ip_families", "rejection_labels", "local_input_labels", "local_input_interfaces"):
            payload[key] = sorted(payload[key])
        return _digest(payload)


def _validate_profile(profile: SourceProfile):
    if type(profile) is not SourceProfile:
        _fail("invalid_source_profile")
    if not isinstance(profile.source_id, str) or not _ID.fullmatch(profile.source_id):
        _fail("invalid_profile_source_id")
    if not isinstance(profile.ruleset_sha256, str) or not _HEX64.fullmatch(profile.ruleset_sha256):
        _fail("invalid_ruleset_digest")
    if type(profile.schema_version) is not int or profile.schema_version != SCHEMA_VERSION:
        _fail("unsupported_profile_version")
    for value in (profile.log_labels, profile.rejection_labels, profile.local_input_labels):
        if not _tuple_strings(value, maximum=16, pattern=_LABEL):
            _fail("invalid_profile_labels")
    if not profile.log_labels:
        _fail("invalid_profile_labels")
    if not set(profile.rejection_labels) <= set(profile.log_labels) or not set(profile.local_input_labels) <= set(profile.log_labels):
        _fail("unenrolled_profile_label")
    if (type(profile.ip_families) is not tuple or not 1 <= len(profile.ip_families) <= 2
            or any(type(item) is not int or item not in (4, 6) for item in profile.ip_families)
            or len(set(profile.ip_families)) != len(profile.ip_families)):
        _fail("invalid_profile_families")
    if not _tuple_strings(profile.local_input_interfaces, maximum=32, pattern=_INTERFACE):
        _fail("invalid_profile_interfaces")
    if bool(profile.local_input_labels) != bool(profile.local_input_interfaces):
        _fail("incomplete_local_input_profile")
    if profile.logging_limit not in ("rate_limited", "unlimited", "unknown"):
        _fail("invalid_logging_limit")
    if profile.retention not in ("bounded", "unknown"):
        _fail("invalid_retention")
    if not all(_ascii(value, maximum=256) for value in (profile.logging_limit_context, profile.retention_context)):
        _fail("invalid_profile_context")


@dataclass(frozen=True)
class NetworkEvent:
    source_id: str
    schema_version: int
    parser_version: str
    boot_id: str
    journal_cursor: str
    event_id: str
    content_hash: str
    journal_realtime_us: int
    journal_monotonic_us: int
    transport: str
    ip_family: int
    src_ip: str
    dst_ip: str
    protocol: str
    observed_protocol: str
    src_port: int | None
    dst_port: int | None
    tcp_flags: frozenset[str] | None
    ingress_interface: str | None
    egress_interface: str | None
    direction: str
    observation_point: str
    log_label: str
    final_outcome: str
    source_profile_revision: str
    coverage: tuple[str, ...]
    rejection_related: bool

    @property
    def key(self) -> tuple[str, str]:
        return self.source_id, self.event_id


def _identity(source_id: str, boot_id: str, journal_cursor: str) -> str:
    return _digest({"source_id": source_id, "boot_id": boot_id, "journal_cursor": journal_cursor})


def _content(event: NetworkEvent) -> dict:
    payload = {field.name: getattr(event, field.name) for field in fields(event)
               if field.name not in ("event_id", "content_hash")}
    if event.tcp_flags is not None:
        payload["tcp_flags"] = sorted(event.tcp_flags)
    return payload


def _address(value: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(value, str) or len(value) > 45 or "%" in value:
        _fail("invalid_ip_address")
    try:
        result = ipaddress.ip_address(value)
    except ValueError:
        _fail("invalid_ip_address")
    # A mapped IPv6 representation does not safely establish the observed wire
    # family. Require explicit original-family records instead of collapsing it.
    if isinstance(result, ipaddress.IPv6Address) and result.ipv4_mapped is not None:
        _fail("unsupported_mapped_address")
    return result


def _timestamp(value: object, *, maximum: int) -> int:
    if type(value) is int:
        result = value
    elif isinstance(value, str) and _DECIMAL.fullmatch(value):
        result = int(value)
    else:
        _fail("invalid_journal_timestamp")
    if not 0 <= result <= maximum:
        _fail("invalid_journal_timestamp")
    return result


def _port(value: str | None) -> int | None:
    if value is None:
        return None
    if not re.fullmatch(r"[0-9]{1,5}", value) or int(value) > 65535:
        _fail("invalid_transport_number")
    return int(value)


def _interface(value: str | None) -> str | None:
    if value in (None, ""):
        return None
    if not _INTERFACE.fullmatch(value):
        _fail("invalid_interface")
    return value


def parse_ufw(record: dict, *, profile: SourceProfile) -> NetworkEvent:
    """Normalize one journal-export object, raising only safe parse codes.

    Decimal timestamp strings follow journal JSON export. Consumed fields with
    array/non-UTF8 values, embedded newlines, oversized values, duplicate interpreted tokens and
    unsupported text layouts are rejected. Missing transport metadata remains
    unknown explicitly. Receipt timestamps from a future collector/server are
    intentionally not accepted here and must not replace journal receipt time.
    """
    _validate_profile(profile)
    if type(record) is not dict or len(record) > MAX_JOURNAL_FIELDS:
        _fail("invalid_journal_record")
    required = {"_TRANSPORT", "_BOOT_ID", "__CURSOR", "__REALTIME_TIMESTAMP", "__MONOTONIC_TIMESTAMP", "MESSAGE"}
    if not required <= record.keys():
        _fail("missing_journal_metadata")
    if record["_TRANSPORT"] != "kernel" or type(record["_TRANSPORT"]) is not str:
        _fail("untrusted_transport")
    boot = record["_BOOT_ID"]
    cursor = record["__CURSOR"]
    if not isinstance(boot, str) or not _BOOT.fullmatch(boot):
        _fail("invalid_boot_id")
    if not _ascii(cursor, maximum=MAX_CURSOR_BYTES):
        _fail("invalid_journal_cursor")
    realtime = _timestamp(record["__REALTIME_TIMESTAMP"], maximum=MAX_REALTIME_US)
    monotonic = _timestamp(record["__MONOTONIC_TIMESTAMP"], maximum=MAX_MONOTONIC_US)
    message = record["MESSAGE"]
    if not _ascii(message, maximum=MAX_MESSAGE_BYTES):
        _fail("invalid_message")
    message = message.strip()
    label = next((label for label in profile.log_labels if message.startswith(label + " ")), None)
    if label is None:
        _fail("unenrolled_log_label")
    body = message[len(label):].strip()
    # This explicit marker represents the kernel's inability to read a complete
    # transport header. Retain uncertainty instead of trusting surviving flags.
    body = re.sub(r"\bINCOMPLETE \[[0-9]{1,10} bytes\]", "INCOMPLETE", body)
    tokens = body.split()
    if not tokens or len(tokens) > MAX_TOKENS:
        _fail("invalid_message_tokens")
    values: dict[str, str] = {}
    positions: dict[str, int] = {}
    flags: set[str] = set()
    flag_positions: list[int] = []
    seen: dict[str, int] = {}
    truncated = False
    fragmented = False
    extension = False
    for index, token in enumerate(tokens):
        if "=" in token:
            key, value = token.split("=", 1)
            if key not in _CORE_FIELDS | _OPTIONAL_FIELDS:
                _fail("unsupported_message_field")
            seen[key] = seen.get(key, 0) + 1
            # UDP output legitimately has IP LEN and UDP LEN. No dictionary
            # overwrite is used for interpreted fields or other duplicated keys.
            if seen[key] > (2 if key == "LEN" else 1):
                _fail("duplicate_message_field")
            if key in _CORE_FIELDS:
                values[key] = value
                positions[key] = index
            if key == "OPT":
                extension = True
        elif token in _TCP_FLAGS:
            if token in flags:
                _fail("duplicate_tcp_flag")
            flags.add(token)
            flag_positions.append(index)
        elif token in ("DF", "MF"):
            if token == "MF":
                fragmented = True
        elif re.fullmatch(r"FRAG:[0-9a-fA-Fx]+", token):
            fragmented = True
            extension = True
        elif token == "INCOMPLETE":
            truncated = True
        elif token == "OPT" or token.startswith("("):
            _fail("unsupported_ip_options")
        else:
            _fail("unsupported_message_token")
    if not {"SRC", "DST", "PROTO"} <= values.keys():
        _fail("missing_packet_identity")
    src, dst = _address(values["SRC"]), _address(values["DST"])
    if src.version != dst.version:
        _fail("mixed_ip_families")
    if src.version not in profile.ip_families:
        _fail("unenrolled_ip_family")
    observed_protocol = values["PROTO"]
    if not _PROTOCOL.fullmatch(observed_protocol):
        _fail("invalid_protocol")
    protocol = observed_protocol if observed_protocol in ("TCP", "UDP") else "OTHER"
    src_port, dst_port = _port(values.get("SPT")), _port(values.get("DPT"))
    ingress, egress = _interface(values.get("IN")), _interface(values.get("OUT"))
    coverage: set[str] = set()
    if profile.logging_limit == "rate_limited":
        coverage.add("logging_rate_limited")
    elif profile.logging_limit == "unknown":
        coverage.add("logging_limits_unknown")
    if profile.retention == "unknown":
        coverage.add("journal_retention_unknown")
    if not {"IN", "OUT"} <= values.keys():
        coverage.add("incomplete_interfaces")
    direction = "unknown"
    if (label in profile.local_input_labels and ingress in profile.local_input_interfaces
            and "OUT" in values and egress is None):
        direction = "local_input"
    if direction == "unknown":
        coverage.add("unverified_local_input")
    if protocol in ("TCP", "UDP") and (src_port is None or dst_port is None):
        coverage.add("missing_transport_ports")
    if truncated:
        coverage.add("truncated_transport_header")
    if fragmented:
        coverage.add("fragmented_packet")
    if extension and src.version == 6:
        coverage.add("ipv6_extension_headers")
    if protocol == "OTHER":
        coverage.add("unsupported_protocol")
    tcp_flags = None
    if protocol == "TCP":
        for key in ("WINDOW", "URGP"):
            _port(values.get(key))
        if "RES" in values and not re.fullmatch(r"0x[0-9a-fA-F]{2}", values["RES"]):
            _fail("invalid_tcp_reserved_bits")
        complete = {"WINDOW", "RES", "URGP"} <= values.keys()
        if complete:
            if not positions["WINDOW"] < positions["RES"] < positions["URGP"]:
                _fail("invalid_tcp_layout")
            if any(not positions["RES"] < position < positions["URGP"] for position in flag_positions):
                _fail("invalid_tcp_layout")
        if complete and not truncated and not fragmented:
            tcp_flags = frozenset(flags)
        else:
            coverage.add("tcp_flags_unavailable")
    elif flags or {"WINDOW", "RES", "URGP"} & values.keys():
        _fail("inconsistent_transport_fields")
    event = NetworkEvent(
        source_id=profile.source_id, schema_version=SCHEMA_VERSION, parser_version=PARSER_VERSION,
        boot_id=boot, journal_cursor=cursor, event_id=_identity(profile.source_id, boot, cursor),
        content_hash="", journal_realtime_us=realtime, journal_monotonic_us=monotonic,
        transport="kernel", ip_family=src.version, src_ip=str(src), dst_ip=str(dst),
        protocol=protocol, observed_protocol=observed_protocol, src_port=src_port, dst_port=dst_port,
        tcp_flags=tcp_flags, ingress_interface=ingress, egress_interface=egress,
        direction=direction, observation_point=direction, log_label=label, final_outcome="unknown",
        source_profile_revision=profile.revision, coverage=tuple(sorted(coverage)),
        rejection_related=label in profile.rejection_labels,
    )
    object.__setattr__(event, "content_hash", _digest(_content(event)))
    validate_event(event)
    return event


def validate_event(event: NetworkEvent) -> None:
    """Reject malformed/replaced offline events; hashes are integrity, not auth.

    This does not authenticate a serialized event or re-enroll a source profile.
    Untrusted external callers must enter through an authenticated future ingest
    adapter rather than constructing NetworkEvent instances themselves.
    """
    if type(event) is not NetworkEvent:
        _fail("invalid_network_event")
    if not isinstance(event.source_id, str) or not _ID.fullmatch(event.source_id):
        _fail("invalid_event_source_id")
    if type(event.schema_version) is not int or event.schema_version != SCHEMA_VERSION or event.parser_version != PARSER_VERSION:
        _fail("unsupported_event_version")
    if not isinstance(event.boot_id, str) or not _BOOT.fullmatch(event.boot_id):
        _fail("invalid_boot_id")
    if not _ascii(event.journal_cursor, maximum=MAX_CURSOR_BYTES):
        _fail("invalid_journal_cursor")
    for value, maximum in ((event.journal_realtime_us, MAX_REALTIME_US), (event.journal_monotonic_us, MAX_MONOTONIC_US)):
        if type(value) is not int or not 0 <= value <= maximum:
            _fail("invalid_journal_timestamp")
    if event.transport != "kernel":
        _fail("untrusted_transport")
    src, dst = _address(event.src_ip), _address(event.dst_ip)
    if (type(event.ip_family) is not int or src.version != dst.version or src.version != event.ip_family
            or str(src) != event.src_ip or str(dst) != event.dst_ip):
        _fail("invalid_event_ip_family")
    if not isinstance(event.observed_protocol, str) or not _PROTOCOL.fullmatch(event.observed_protocol):
        _fail("invalid_protocol")
    expected_protocol = event.observed_protocol if event.observed_protocol in ("TCP", "UDP") else "OTHER"
    if event.protocol != expected_protocol:
        _fail("invalid_protocol")
    for port in (event.src_port, event.dst_port):
        if port is not None and (type(port) is not int or not 0 <= port <= 65535):
            _fail("invalid_transport_number")
    if event.tcp_flags is not None:
        if type(event.tcp_flags) is not frozenset or not event.tcp_flags <= _TCP_FLAGS or event.protocol != "TCP":
            _fail("invalid_tcp_flags")
    for interface in (event.ingress_interface, event.egress_interface):
        if interface is not None and (not isinstance(interface, str) or not _INTERFACE.fullmatch(interface)):
            _fail("invalid_interface")
    if event.direction not in ("unknown", "local_input") or event.observation_point != event.direction:
        _fail("invalid_observation_point")
    if event.direction == "local_input" and (event.ingress_interface is None or event.egress_interface is not None):
        _fail("invalid_local_input_shape")
    if not isinstance(event.log_label, str) or not _LABEL.fullmatch(event.log_label):
        _fail("invalid_log_label")
    if event.final_outcome != "unknown" or type(event.rejection_related) is not bool:
        _fail("invalid_outcome")
    if (type(event.coverage) is not tuple or len(event.coverage) > len(_COVERAGE) or any(not isinstance(item, str) or item not in _COVERAGE for item in event.coverage)
            or event.coverage != tuple(sorted(set(event.coverage)))):
        _fail("invalid_event_coverage")
    if (event.direction == "unknown") != ("unverified_local_input" in event.coverage):
        _fail("inconsistent_event_coverage")
    if event.protocol == "TCP" and (event.tcp_flags is None) != ("tcp_flags_unavailable" in event.coverage):
        _fail("inconsistent_event_coverage")
    for digest in (event.event_id, event.content_hash, event.source_profile_revision):
        if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            _fail("invalid_event_digest")
    if event.event_id != _identity(event.source_id, event.boot_id, event.journal_cursor):
        _fail("event_identity_mismatch")
    if event.content_hash != _digest(_content(event)):
        _fail("event_content_mismatch")
