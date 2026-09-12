from __future__ import annotations

import ipaddress

import pytest

from app.telemetry.sshd_parse import FAILURE_KINDS, parse_sshd


PEER = "198.51.100.23"


@pytest.mark.parametrize("username", ["root", "jenkins", "cat", "admin", "ubuntu", "docker"])
@pytest.mark.parametrize("action", ["closed", "reset"])
def test_authenticating_user_abort_has_peer_and_account(username, action):
    assert parse_sshd(f"Connection {action} by authenticating user {username} {PEER} port 51412 [preauth]") == {
        "event_kind": "preauth_abort", "peer_ip": PEER, "username": username,
    }


@pytest.mark.parametrize("peer", [PEER, "2001:db8:abcd:0000:0000:0000:0000:0001", "::ffff:192.0.2.9"])
@pytest.mark.parametrize("source_port", ["", " port 12345"])
@pytest.mark.parametrize("destination_suffix", [" port 2222", ", pid = 296741", " port 2222, pid = 296741"])
def test_timeout_always_extracts_source_never_local_destination(peer, source_port, destination_suffix):
    assert parse_sshd(f"Timeout before authentication for connection from {peer}{source_port} to 203.0.113.10{destination_suffix}") == {
        "event_kind": "probe", "peer_ip": str(ipaddress.ip_address(peer)), "username": None,
    }


@pytest.mark.parametrize("address", ["0.0.0.0", "::", "203.0.113.10"])
def test_listening_address_is_not_a_peer(address):
    assert parse_sshd(f"Server listening on {address} port 2222.") == {
        "event_kind": "daemon", "peer_ip": None, "username": None,
    }


@pytest.mark.parametrize("message,kind", [
    (f"Invalid user  from {PEER} port 12345", "invalid_user"),
    (f"Connection closed by authenticating user  {PEER} port 12345 [preauth]", "preauth_abort"),
    (f"Disconnected from invalid user  {PEER} port 12345 [preauth]", "preauth_abort"),
    (f"Disconnecting authenticating user  {PEER} port 12345: Too many authentication failures [preauth]", "preauth_abort"),
    (f"Failed password for invalid user  from {PEER} port 12345 ssh2", "auth_failure"),
])
def test_empty_user_is_none_without_losing_the_address(message, kind):
    assert parse_sshd(message) == {"event_kind": kind, "peer_ip": PEER, "username": None}


@pytest.mark.parametrize("message,kind,user", [
    ("Accepted publickey for root from {ip} port 12345 ssh2: ED25519 SHA256:example", "auth_success", "root"),
    ("Failed keyboard-interactive/pam for invalid user admin from {ip} port 12345 ssh2", "auth_failure", "admin"),
    ("error: maximum authentication attempts exceeded for invalid user admin from {ip} port 12345 ssh2 [preauth]", "auth_failure", "admin"),
    ("error: PAM: Authentication failure for illegal user admin from {ip}", "auth_failure", "admin"),
    ("Authentication failure for admin from {ip}", "auth_failure", "admin"),
    ("Authentication error for admin from {ip}", "auth_failure", "admin"),
    ("Invalid user admin from {ip} port 12345", "invalid_user", "admin"),
    ("Connection reset by invalid user admin {ip} port 12345 [preauth]", "preauth_abort", "admin"),
    ("Disconnected from authenticating user admin {ip} port 12345 [preauth]", "preauth_abort", "admin"),
    ("Disconnecting invalid user admin {ip} port 12345: Too many authentication failures [preauth]", "preauth_abort", "admin"),
    ("Connection closed by {ip} port 12345 [preauth]", "preauth_abort", None),
    ("Disconnected from {ip} port 12345 [preauth]", "preauth_abort", None),
    ("Disconnected from user admin {ip} port 12345", "disconnect", "admin"),
    ("Received disconnect from {ip} port 12345: 11: disconnected by user admin", "disconnect", "admin"),
    ("Received disconnect from {ip} port 12345:11: disconnected by user", "disconnect", None),
    ("Received disconnect from {ip}: 11: disconnected by user", "disconnect", None),
    ("Received disconnect from {ip} port 12345: 11: disconnected by user [preauth]", "disconnect", None),
    ("Received disconnect from {ip} port 12345: 2: connection timeout [preauth]", "disconnect", None),
    ("Connection closed by {ip} port 12345", "disconnect", None),
    ("Connection reset by {ip}", "disconnect", None),
    ("Disconnected from {ip} port 12345", "disconnect", None),
    ("Did not receive identification string from {ip}", "probe", None),
    ("banner exchange: Connection from {ip} port 12345: invalid format", "probe", None),
    ("Bad protocol version identification 'hello from 192.0.2.9' from {ip} port 12345", "probe", None),
    ("Unable to negotiate with {ip} port 12345: no matching host key type found", "probe", None),
    ("Connection from {ip} port 12345 on 203.0.113.10 port 2222 rdomain \"\"", "probe", None),
    ("error: kex_exchange_identification: Connection closed by remote host: {ip}", "probe", None),
    ("ssh_dispatch_run_fatal: Connection from {ip} port 12345: incorrect signature", "probe", None),
    ("ssh_dispatch_run_fatal: Connection from user root {ip} port 12345: Connection corrupted", "probe", "root"),
    ("error: Received disconnect from {ip} port 12345: 14: No supported authentication methods available [preauth]", "probe", None),
])
@pytest.mark.parametrize("ip", [PEER, "2001:DB8::1", "::ffff:192.0.2.9"])
def test_address_bearing_message_families(message, kind, user, ip):
    assert parse_sshd(message.format(ip=ip)) == {
        "event_kind": kind, "peer_ip": str(ipaddress.ip_address(ip)), "username": user,
    }


@pytest.mark.parametrize("message,kind,user", [
    ("pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)", "session_open", "root"),
    ("pam_unix(sshd:session): session closed for user root", "session_close", "root"),
    ("error: kex_exchange_identification: client sent invalid protocol identifier", "probe", None),
    ("error: kex_protocol_error: type 20 seq 2", "probe", None),
    ("error: Protocol major versions differ: 2 vs. 1", "probe", None),
    ("padding error: need 123 block 8 mod 3", "probe", None),
    ("Bad packet length 0.", "probe", None),
    ("fatal: userauth_pubkey: parse publickey packet: incomplete message [preauth]", "probe", None),
    ("Received signal 15; terminating.", "daemon", None),
    ("Received SIGHUP; restarting.", "daemon", None),
    ("error: beginning MaxStartups throttling", "daemon", None),
    ("exited MaxStartups throttling after 00:00:01, 1 connections dropped", "daemon", None),
    ("userauth_pubkey: signature algorithm ssh-rsa not in PubkeyAcceptedAlgorithms [preauth]", "auth_failure", None),
    ("userauth_pubkey: key type ssh-dss not in PubkeyAcceptedAlgorithms", "auth_failure", None),
])
def test_known_messages_without_peer_do_not_invent_one(message, kind, user):
    assert parse_sshd(message) == {"event_kind": kind, "peer_ip": None, "username": user}


@pytest.mark.parametrize("source,destination", [
    (PEER, "203.0.113.10"),
    ("2001:db8::1", "2001:db8::2"),
    ("::ffff:192.0.2.1", "::ffff:192.0.2.2"),
])
def test_maxstartups_drop_extracts_bracketed_source_not_destination(source, destination):
    assert parse_sshd(f"drop connection #10 from [{source}]:44782 on [{destination}]:22 past MaxStartups") == {
        "event_kind": "probe", "peer_ip": str(ipaddress.ip_address(source)), "username": None,
    }


@pytest.mark.parametrize("source,port", [("999.1.1.1", "22"), ("2001:db8::1%eth0", "22"), (PEER, "22oops"), (PEER, "65536")])
def test_maxstartups_drop_rejects_malformed_source_endpoint(source, port):
    assert parse_sshd(f"drop connection #10 from [{source}]:{port} on [203.0.113.10]:22 past MaxStartups") == {
        "event_kind": "other", "peer_ip": None, "username": None,
    }


@pytest.mark.parametrize("bad_ip", [
    "999.1.2.3", "1.2.3.4suffix", "1.2.3.4.5", "2001:db8::1garbage", "2001:db8::1::2",
    "::ffff:999.1.2.3", "192.168.001.1", "198.51.100.7:22", "[2001:db8::1]", "fe80::1%eth0", "localhost",
])
def test_invalid_address_is_not_partially_extracted(bad_ip):
    assert parse_sshd(f"Connection closed by authenticating user root {bad_ip} port 12345 [preauth]") == {
        "event_kind": "other", "peer_ip": None, "username": None,
    }


@pytest.mark.parametrize("port", ["0", "65536", "12345abc", "12345:garbage", "-1", "１２３", "9" * 100])
@pytest.mark.parametrize("message", [
    "Failed password for root from {ip} port {port} ssh2",
    "Connection closed by authenticating user root {ip} port {port} [preauth]",
    "Disconnecting invalid user root {ip} port {port}: Too many authentication failures",
])
def test_malformed_port_does_not_match_valid_prefix(port, message):
    assert parse_sshd(message.format(ip=PEER, port=port))["event_kind"] == "other"


@pytest.mark.parametrize("message", [None, 17, "", "unknown sshd event from 198.51.100.23", "Timeout before authentication for connection from not-an-ip to 203.0.113.10 port 2222"])
def test_unknown_records_remain_observable(message):
    assert parse_sshd(message) == {"event_kind": "other", "peer_ip": None, "username": None}


def test_failure_kind_interface_separates_success_and_protocol_probes():
    assert FAILURE_KINDS == frozenset({"auth_failure", "invalid_user", "preauth_abort"})
    assert parse_sshd(f"Connection closed by authenticating user root {PEER} port 12345 [preauth]")["event_kind"] in FAILURE_KINDS
    assert parse_sshd(f"Accepted password for root from {PEER} port 12345 ssh2")["event_kind"] not in FAILURE_KINDS
