"""Injectable clock.

Wall-clock time is an external input. Injecting it keeps the pipeline
deterministic: a replay reuses the timestamp recorded on the original Flow so
re-execution reproduces byte-identical evidence and IDs.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    """Real wall-clock time, always timezone-aware UTC."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class FixedClock:
    """A frozen clock for deterministic runs, tests, and replay."""

    def __init__(self, moment: datetime) -> None:
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        self._moment = moment

    def now(self) -> datetime:
        return self._moment


def isoformat(moment: datetime) -> str:
    """Canonical, second-precision UTC ISO-8601 with a trailing Z."""
    return moment.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
