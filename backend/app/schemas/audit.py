"""Append-only, hash-chained audit event.

Each event stores the hash of the previous event; tampering with any record
breaks the chain for every later record (Threat Model TM-03). Corrections are
new events, never in-place edits.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AuditEvent(BaseModel):
    event_id: str
    event_type: str
    actor: str
    flow_id: str | None = None
    subject_ref: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    recorded_at: str
    prev_hash: str
    entry_hash: str
