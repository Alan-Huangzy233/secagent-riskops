from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.core.clock import FixedClock
from app.samples import sample_sources
from app.services import Services

FIXED_MOMENT = datetime(2026, 7, 6, 21, 15, tzinfo=timezone.utc)


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(FIXED_MOMENT)


@pytest.fixture
def services(clock: FixedClock) -> Services:
    return Services.create(clock=clock)


@pytest.fixture
def sources():
    return sample_sources()
