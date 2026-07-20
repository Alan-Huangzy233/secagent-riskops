"""Deterministic identifier allocation.

IDs are sequential per prefix within a run (``INC-0001``, ``INC-0002`` ...).
Determinism matters: the same input replayed through the same pipeline must
produce the same identifiers, which is what makes replay verifiable.
"""
from __future__ import annotations

from collections import defaultdict


class IdFactory:
    def __init__(self) -> None:
        self._counters: dict[str, int] = defaultdict(int)

    def next(self, prefix: str) -> str:
        self._counters[prefix] += 1
        return f"{prefix}-{self._counters[prefix]:04d}"
