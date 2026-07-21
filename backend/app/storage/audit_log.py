"""Append-only, hash-chained audit log.

Each entry commits to the previous entry's hash, so any later edit or deletion
is detectable by re-walking the chain (Threat Model TM-03). This is the
system's tamper-evidence primitive; the pipeline writes an event for every
material decision and state transition.
"""
from __future__ import annotations

from typing import Any

from ..core.clock import Clock
from ..core.hashing import canonical_json, content_hash
from ..core.ids import IdFactory
from ..schemas.audit import AuditEvent

GENESIS = "sha256:" + "0" * 64


class AuditLog:
    def __init__(self, clock: Clock, ids: IdFactory) -> None:
        self._clock = clock
        self._ids = ids
        self._events: list[AuditEvent] = []

    def record(
        self,
        event_type: str,
        actor: str,
        *,
        flow_id: str | None = None,
        subject_ref: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> AuditEvent:
        prev_hash = self._events[-1].entry_hash if self._events else GENESIS
        recorded_at = _iso(self._clock)
        event_id = self._ids.next("AUD")
        body = {
            "event_id": event_id,
            "event_type": event_type,
            "actor": actor,
            "flow_id": flow_id,
            "subject_ref": subject_ref,
            "payload": payload or {},
            "recorded_at": recorded_at,
            "prev_hash": prev_hash,
        }
        entry_hash = content_hash(canonical_json(body).encode("utf-8"))
        event = AuditEvent(**body, entry_hash=entry_hash)
        self._events.append(event)
        return event

    def events(self) -> list[AuditEvent]:
        return list(self._events)

    def verify_chain(self) -> bool:
        """Recompute every entry hash and confirm the chain is intact."""
        prev = GENESIS
        for event in self._events:
            body = event.model_dump(exclude={"entry_hash"})
            body["prev_hash"] = prev
            expected = content_hash(canonical_json(body).encode("utf-8"))
            if expected != event.entry_hash or event.prev_hash != prev:
                return False
            prev = event.entry_hash
        return True


def _iso(clock: Clock) -> str:
    from ..core.clock import isoformat

    return isoformat(clock.now())
