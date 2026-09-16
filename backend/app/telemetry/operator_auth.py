"""Small, process-local cache of successful operator password verification."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time

from .config import verify_operator_password

_PROCESS_KEY = secrets.token_bytes(32)
_SUCCESS_TTL_SECONDS = 60.0


class OperatorVerifier:
    """Retain one keyed digest for 60 seconds, without retaining credentials.

    Cache hits do not extend the lifetime. The configured account and password
    hash are part of the digest, so configuration changes require verification.
    Failed or exceptional checks never replace an existing successful entry.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._digest: bytes | None = None
        self._expires_at = 0.0

    @staticmethod
    def _credential_digest(username: str, password: str, cfg_username: str, cfg_hash: str) -> bytes:
        digest = hmac.new(_PROCESS_KEY, b"riskops-operator-auth-v1", hashlib.sha256)
        for value in (username, password, cfg_username, cfg_hash):
            encoded = value.encode("utf-8")
            # Length prefixes prevent ambiguous concatenations of the fields.
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        return digest.digest()

    def verify(self, username: str, password: str, cfg_username: str, cfg_hash: str) -> bool:
        try:
            if not all(isinstance(value, str) for value in (username, password, cfg_username, cfg_hash)):
                return False
            if len(password) > 1024:
                return False
            username_ok = hmac.compare_digest(username.encode("utf-8"), cfg_username.encode("utf-8"))
            candidate = self._credential_digest(username, password, cfg_username, cfg_hash)
            with self._lock:
                if (self._digest is not None and time.monotonic() < self._expires_at
                        and hmac.compare_digest(candidate, self._digest)):
                    return True

            # Do not hold the cache lock during PBKDF2. An unrelated failed
            # request must not delay requests with already verified credentials.
            password_ok = verify_operator_password(password, cfg_hash)
            if not (username_ok and password_ok):
                return False
            with self._lock:
                expires_at = time.monotonic() + _SUCCESS_TTL_SECONDS
                self._digest = candidate
                self._expires_at = expires_at
            return True
        except Exception:
            # Authentication fails closed, without logging any supplied secret.
            return False
