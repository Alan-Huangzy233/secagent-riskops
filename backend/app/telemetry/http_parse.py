"""Normalize one structured HTTP access record, independently of SSH telemetry.

Source/service identity and event IDs come from the caller, not request headers.
This offline adapter expects the connection peer; proxy attribution is a later,
explicitly configured ingestion concern. It never consumes forwarded headers.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import re
from urllib.parse import unquote


PARSER_VERSION = "http-access-v1"
MAX_PATH_BYTES = 8192
DECODE_PASSES = 3
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_METHOD = re.compile(r"[A-Z][A-Z0-9_-]{0,31}\Z")
_FIELDS = {"timestamp", "client_ip", "method", "path", "status"}


@dataclass(frozen=True)
class HttpEvent:
    source_id: str
    service_id: str
    event_id: str
    timestamp: str
    event_ts: float
    client_ip: str
    method: str
    path: str
    decoded_path: str
    status: int

    @property
    def key(self) -> tuple[str, str]:
        return self.source_id, self.event_id


def normalize_http(record: dict, *, source_id: str, service_id: str, event_id: str) -> HttpEvent:
    """Validate a bounded JSON record; errors never include supplied values.

Keep the original encoded path (without a query) alongside a bounded decoded
view. Do not collapse dot segments before traversal rules have examined them.
"""
    for value in (source_id, service_id, event_id):
        if not isinstance(value, str) or not _ID.fullmatch(value):
            raise ValueError("invalid HTTP source, service or event identity")
    if not isinstance(record, dict) or set(record) != _FIELDS:
        raise ValueError("invalid HTTP record fields")
    timestamp = record["timestamp"]
    if not isinstance(timestamp, str) or len(timestamp) > 80:
        raise ValueError("invalid HTTP timestamp")
    try:
        at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if at.utcoffset() is None:
            raise ValueError
        at = at.astimezone(timezone.utc)
        seconds = at.timestamp()
    except (ValueError, OverflowError, OSError):
        raise ValueError("invalid HTTP timestamp") from None
    client_ip = record["client_ip"]
    try:
        if not isinstance(client_ip, str) or "%" in client_ip:
            raise ValueError
        address = ipaddress.ip_address(client_ip)
        # IPv4-mapped IPv6 peers represent the same endpoint as IPv4 peers.
        address = getattr(address, "ipv4_mapped", None) or address
        client_ip = str(address)
    except ValueError:
        raise ValueError("invalid HTTP client address") from None
    method, path, status = record["method"], record["path"], record["status"]
    if not isinstance(method, str) or not _METHOD.fullmatch(method):
        raise ValueError("invalid HTTP method")
    if type(status) is not int or not 100 <= status <= 599:
        raise ValueError("invalid HTTP response status")
    if (not isinstance(path, str) or not (path.startswith("/") or path == "*")
            or any(ord(char) < 32 or ord(char) == 127 for char in path)):
        raise ValueError("invalid HTTP request path")
    try:
        if len(path.encode("utf-8")) > MAX_PATH_BYTES:
            raise ValueError("HTTP request path too long")
        path = path.partition("?")[0]
        decoded = path
        for _ in range(DECODE_PASSES):
            following = unquote(decoded, encoding="utf-8", errors="strict")
            if following == decoded:
                break
            decoded = following
    except UnicodeError:
        raise ValueError("invalid HTTP path encoding") from None
    return HttpEvent(source_id, service_id, event_id,
                     at.isoformat(timespec="microseconds").replace("+00:00", "Z"),
                     seconds, client_ip, method, path, decoded, status)
