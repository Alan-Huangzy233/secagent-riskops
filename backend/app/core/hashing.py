"""Content addressing and canonical hashing.

Two uses:
- Raw evidence is content-addressed so the audit trail can prove that a stored
  artifact was not altered after the fact (Threat Model TM-03).
- Authorization scope is reduced to a canonical ``policy_hash`` so an approval
  is cryptographically bound to the exact policy it approved (TM-05, TM-14).
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def content_hash(data: bytes) -> str:
    """Return a ``sha256:<hex>`` digest for raw bytes."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no insignificant whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def policy_hash(policy: dict[str, Any]) -> str:
    """Stable digest of a policy/scope object, independent of key order."""
    return "sha256:" + hashlib.sha256(canonical_json(policy).encode("utf-8")).hexdigest()
