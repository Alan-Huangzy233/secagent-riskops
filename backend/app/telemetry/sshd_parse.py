"""Enrich an sshd MESSAGE without guessing a peer from arbitrary IP-like text.

The message grammar covers Ubuntu/OpenSSH journal formats.
Address-bearing rules consume a complete token and validate it with ipaddress;
daemon listen addresses and the destination of a timeout are never peers.
Unknown formats stay ``other`` so missing grammar remains observable.
"""
from __future__ import annotations

import ipaddress
import re


# Do not spell out IPv4/IPv6 in a regex: that can match only the IPv4 prefix of
# a malformed address, or the IPv6 prefix of an IPv4-mapped IPv6 address.
_IP = r"(?P<ip>\S+)"
_PORT = r"(?: port (?P<port>\S+))?"
_PRE = r"(?: \[preauth\])?"
_USER = r"(?P<user>\S*)"
_AUTH_TAIL = rf"(?: ssh2(?:: .*)?)?{_PRE}"

# In these messages a colon separates the peer/port from a reason. A lazy
# complete token allows the final separator colon while retaining IPv6 colons.
_REASON_PEER = r"(?P<ip>\S+?)(?: port (?P<port>[^\s:]+))?:\s+"
# Received-disconnect reasons start with a numeric protocol code. sshd can emit
# 'port 12345:11:' with no space. Its numeric-code suffix bounds the endpoint.
_CODE_PEER = r"(?P<ip>\S+)(?: port (?P<port>[^\s:]+))?:\s*"


def _rule(kind: str, expression: str) -> tuple[str, re.Pattern[str]]:
    return kind, re.compile(expression)


_RULES = [
    _rule("auth_success", rf"Accepted \S+ for (?:invalid user )?{_USER} from {_IP}{_PORT}{_AUTH_TAIL}"),
    _rule("session_open", r"pam_unix\(sshd:session\): session opened for user (?P<user>[^ (]+).*"),
    _rule("session_close", r"pam_unix\(sshd:session\): session closed for user (?P<user>[^ (]+).*"),
    _rule("auth_failure", rf"Failed \S+ for (?:invalid user )?{_USER} from {_IP}{_PORT}{_AUTH_TAIL}"),
    _rule("auth_failure", rf"error: maximum authentication attempts exceeded for (?:invalid user )?{_USER} from {_IP}{_PORT}{_AUTH_TAIL}"),
    _rule("auth_failure", rf"error: PAM: [^:]+ for (?:illegal user )?{_USER} from {_IP}{_PRE}"),
    _rule("auth_failure", rf"Authentication (?:failure|error|failed) for {_USER} from {_IP}{_PORT}{_PRE}"),
    _rule("invalid_user", rf"Invalid user {_USER} from {_IP}{_PORT}{_PRE}"),

    # The previously missing authenticating-user family, including blank users.
    _rule("preauth_abort", rf"Connection (?:closed|reset) by (?:invalid|authenticating) user {_USER} {_IP}{_PORT}{_PRE}"),
    _rule("preauth_abort", rf"Disconnected from (?:invalid|authenticating) user {_USER} {_IP}{_PORT}{_PRE}"),
    _rule("preauth_abort", rf"Disconnecting (?:invalid|authenticating) user {_USER} {_REASON_PEER}.*"),
    _rule("preauth_abort", rf"Connection (?:closed|reset) by {_IP}{_PORT} \[preauth\]"),
    _rule("preauth_abort", rf"Disconnected from {_IP}{_PORT} \[preauth\]"),

    _rule("disconnect", rf"Disconnected from user {_USER} {_IP}{_PORT}{_PRE}"),
    _rule("disconnect", rf"Received disconnect from {_CODE_PEER}[0-9]+:(?: disconnected by user(?: (?P<user>(?!\[preauth\]$)\S+))?)?{_PRE}"),
    _rule("disconnect", rf"Received disconnect from {_CODE_PEER}[0-9]+:.*"),
    _rule("disconnect", rf"Connection (?:closed|reset) by {_IP}{_PORT}"),
    _rule("disconnect", rf"Disconnected from {_IP}{_PORT}"),

    _rule("probe", rf"Did not receive identification string from {_IP}{_PORT}{_PRE}"),
    _rule("probe", rf"banner exchange: Connection from {_REASON_PEER}.*"),
    _rule("probe", rf"Bad protocol version identification .* from {_IP}{_PORT}{_PRE}"),
    # The peer is before the literal ' to '; the local destination is ignored.
    _rule("probe", rf"Timeout before authentication for connection from {_IP}{_PORT} to \S+(?: port \S+)?(?:, pid = [0-9]+)?{_PRE}"),
    _rule("probe", rf"Unable to negotiate with {_REASON_PEER}.*"),
    _rule("probe", rf"Connection from {_IP}{_PORT}(?: on \S+(?: port [0-9]+)?(?: rdomain .*)?)?"),
    _rule("probe", rf"error: kex_exchange_identification: .*: {_IP}{_PRE}"),
    _rule("probe", rf"ssh_dispatch_run_fatal: Connection from (?:user {_USER} )?{_REASON_PEER}.*"),
    _rule("probe", rf"error: Received disconnect from {_CODE_PEER}14:.*"),
    _rule("probe", r"error: kex_exchange_identification: .*"),
    _rule("probe", r"error: kex_protocol_error: .*"),
    _rule("probe", r"error: Protocol major versions differ.*"),
    _rule("probe", r"padding error: .*"),
    _rule("probe", r"Bad packet length [0-9]+\."),
    _rule("probe", r"fatal: userauth_pubkey: .*"),
    # MaxStartups rejection happens before authentication. Capture the bracketed
    # source endpoint only; the endpoint following ' on ' belongs to the server.
    _rule("probe", r"drop connection #[0-9]+ from \[(?P<ip>[^\]]+)\]:(?P<port>\S+) on \[[^\]]+\]:[0-9]+ past MaxStartups"),

    # Listening on 0.0.0.0/:: is daemon metadata, never evidence of a peer.
    _rule("daemon", r"Server listening on .*"),
    _rule("daemon", r"Received signal [0-9]+; terminating.*"),
    _rule("daemon", r"Received SIGHUP; restarting.*"),
    _rule("daemon", r"error: beginning MaxStartups throttling"),
    _rule("daemon", r"exited MaxStartups throttling after [0-9]{2}:[0-9]{2}:[0-9]{2}, [0-9]+ connections? dropped"),
    _rule("auth_failure", rf"userauth_pubkey: (?:signature algorithm|key type) \S+ not in \S+{_PRE}"),
]


def parse_sshd(message: str) -> dict[str, object]:
    """Return event_kind, canonical peer_ip, and username for one MESSAGE.

These are journal-record classifications, not unique connection counts. An
authentication abort does not prove an incorrect password was submitted.
"""
    unknown = {"event_kind": "other", "peer_ip": None, "username": None}
    if not isinstance(message, str):
        return unknown
    text = message.strip()
    for kind, pattern in _RULES:
        match = pattern.fullmatch(text)
        if match is None:
            continue
        groups = match.groupdict()
        peer = groups.get("ip")
        if peer is not None:
            # ipaddress accepts scoped IPv6, but sshd's peer token is unscoped;
            # reject brackets/zone IDs rather than silently dropping a suffix.
            if "%" in peer or "[" in peer or "]" in peer:
                return unknown
            try:
                peer = str(ipaddress.ip_address(peer))
            except ValueError:
                return unknown
        port = groups.get("port")
        if port is not None and (not re.fullmatch(r"[0-9]{1,5}", port) or not 1 <= int(port) <= 65535):
            return unknown
        return {"event_kind": kind, "peer_ip": peer, "username": groups.get("user") or None}
    return unknown


# Keep the supplied public interface. Consumers must distinguish evidence rows
# from unique attempts and avoid describing preauth aborts as wrong passwords.
FAILURE_KINDS = frozenset({"auth_failure", "invalid_user", "preauth_abort"})
