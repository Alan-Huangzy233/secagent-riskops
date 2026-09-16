from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import threading
from unittest.mock import Mock

import pytest

from app.telemetry import operator_auth
from app.telemetry.config import hash_operator_password
from app.telemetry.operator_auth import OperatorVerifier

USERNAME = "operator"
PASSWORD = "test-only-operator-password-123456"
CONFIG_HASH = "test-only-config-hash"


@pytest.fixture
def clock(monkeypatch):
    value = [100.0]
    monkeypatch.setattr(operator_auth.time, "monotonic", lambda: value[0])
    return value


@pytest.fixture
def password_check(monkeypatch):
    check = Mock(side_effect=lambda password, encoded: password == PASSWORD and encoded == CONFIG_HASH)
    monkeypatch.setattr(operator_auth, "verify_operator_password", check)
    return check


def check(verifier, username=USERNAME, password=PASSWORD, cfg_username=USERNAME, cfg_hash=CONFIG_HASH):
    return verifier.verify(username, password, cfg_username, cfg_hash)


def test_success_is_reused_without_storing_plaintext(clock, password_check):
    verifier = OperatorVerifier()
    assert check(verifier)
    assert check(verifier)
    assert password_check.call_count == 1
    assert isinstance(verifier._digest, bytes)
    assert len(verifier._digest) == 32
    assert not any(isinstance(value, str) for value in vars(verifier).values())
    assert PASSWORD not in repr(verifier)
    assert CONFIG_HASH not in repr(verifier)


def test_failures_never_hit_or_replace_success(clock, password_check):
    verifier = OperatorVerifier()
    assert check(verifier)
    original = (verifier._digest, verifier._expires_at)
    assert not check(verifier, password="incorrect")
    assert not check(verifier, password="incorrect")
    assert not check(verifier, username="incorrect")
    assert not check(verifier, username="incorrect")
    assert password_check.call_count == 5
    assert (verifier._digest, verifier._expires_at) == original
    assert check(verifier)
    assert password_check.call_count == 5


def test_ttl_is_fixed_and_expires_at_the_boundary(clock, password_check):
    verifier = OperatorVerifier()
    assert check(verifier)
    clock[0] = 159.9
    assert check(verifier)
    assert verifier._expires_at == 160.0
    assert password_check.call_count == 1
    clock[0] = 160.0
    assert check(verifier)
    assert password_check.call_count == 2
    clock[0] = 220.0
    assert check(verifier)
    assert password_check.call_count == 3


def test_configuration_changes_require_verification(clock, password_check):
    verifier = OperatorVerifier()
    assert check(verifier)
    assert not check(verifier, cfg_username="replacement")
    assert not check(verifier, cfg_hash="replacement-hash")
    assert password_check.call_count == 3
    assert check(verifier, username="replacement", cfg_username="replacement")
    assert password_check.call_count == 4
    assert check(verifier, username="replacement", cfg_username="replacement")
    assert password_check.call_count == 4
    # The single slot was replaced by the newly verified configured account.
    assert check(verifier)
    assert password_check.call_count == 5


def test_digest_fields_are_unambiguously_framed():
    verifier = OperatorVerifier()
    first = verifier._credential_digest("ab", "c", "d", "ef")
    assert first != verifier._credential_digest("a", "bc", "d", "ef")
    assert first != verifier._credential_digest("ab", "c", "de", "f")


def test_exception_is_not_cached_and_preserves_existing_success(clock, password_check):
    verifier = OperatorVerifier()
    password_check.side_effect = RuntimeError("test verification failed")
    assert not check(verifier)
    assert not check(verifier)
    assert password_check.call_count == 2
    assert verifier._digest is None
    password_check.side_effect = lambda password, encoded: password == PASSWORD and encoded == CONFIG_HASH
    assert check(verifier)
    original = (verifier._digest, verifier._expires_at)
    password_check.side_effect = RuntimeError("test verification failed")
    assert not check(verifier, password="incorrect")
    assert (verifier._digest, verifier._expires_at) == original
    assert check(verifier)
    assert password_check.call_count == 4


def test_fresh_instance_starts_empty(clock, password_check):
    assert check(OperatorVerifier())
    assert check(OperatorVerifier())
    assert password_check.call_count == 2


def test_concurrent_failures_do_not_block_or_replace_a_success(clock, monkeypatch):
    verifier = OperatorVerifier()
    started = threading.Event()
    release = threading.Event()

    def verify_password(password, encoded):
        if password == "incorrect":
            started.set()
            if not release.wait(timeout=5):
                raise RuntimeError("test worker was not released")
            return False
        return password == PASSWORD and encoded == CONFIG_HASH

    monkeypatch.setattr(operator_auth, "verify_operator_password", verify_password)
    assert check(verifier)
    original = (verifier._digest, verifier._expires_at)
    with ThreadPoolExecutor(max_workers=2) as pool:
        failed = pool.submit(check, verifier, password="incorrect")
        try:
            assert started.wait(timeout=5)
            cached = pool.submit(check, verifier)
            assert cached.result(timeout=5)
        finally:
            release.set()
        assert not failed.result(timeout=5)
    assert (verifier._digest, verifier._expires_at) == original
    assert check(verifier)


def test_concurrent_successes_remain_valid(clock, monkeypatch):
    verifier = OperatorVerifier()
    rendezvous = threading.Barrier(4)

    def verify_password(password, encoded):
        rendezvous.wait(timeout=5)
        return password == PASSWORD and encoded == CONFIG_HASH

    mock = Mock(side_effect=verify_password)
    monkeypatch.setattr(operator_auth, "verify_operator_password", mock)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: check(verifier), range(4)))
    assert results == [True] * 4
    assert mock.call_count == 4
    assert check(verifier)
    assert mock.call_count == 4


def test_real_pbkdf2_hash_is_still_verified():
    encoded = hash_operator_password(PASSWORD)
    assert encoded.split("$")[1] == "600000"
    verifier = OperatorVerifier()
    assert verifier.verify(USERNAME, PASSWORD, USERNAME, encoded)
    assert not verifier.verify(USERNAME, "incorrect", USERNAME, encoded)
    assert not verifier.verify("incorrect", PASSWORD, USERNAME, encoded)
    assert not verifier.verify(USERNAME, PASSWORD, USERNAME, "invalid-hash")


@pytest.mark.parametrize("password", [None, "x" * 1025, "\ud800"])
def test_invalid_values_fail_closed_without_caching(clock, password_check, password):
    verifier = OperatorVerifier()
    assert not check(verifier, password=password)
    assert verifier._digest is None
    assert password_check.call_count == 0
