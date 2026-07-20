"""Content-addressed evidence vault.

Raw inputs are stored keyed by the sha256 of their bytes. Because the key *is*
the hash, a later read can be re-verified against the key, and replay can pull
the exact original bytes back out (charter success criteria 2 and 8).
"""
from __future__ import annotations

from ..core.hashing import content_hash


class EvidenceStore:
    def __init__(self) -> None:
        self._blobs: dict[str, bytes] = {}

    def put(self, data: bytes) -> str:
        """Store raw bytes; return the ``sha256:...`` storage ref."""
        ref = content_hash(data)
        self._blobs[ref] = data
        return ref

    def get(self, ref: str) -> bytes:
        return self._blobs[ref]

    def verify(self, ref: str) -> bool:
        """True if the stored bytes still hash to their key."""
        return ref in self._blobs and content_hash(self._blobs[ref]) == ref
