"""Load the committed sample alerts as ingest sources.

Uses the sanitized files under ``examples/alerts`` so the demo and tests run
against the same inputs a first-time reader sees in the repo.
"""
from __future__ import annotations

from pathlib import Path

from .pipeline.ingest import RawSource

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ALERTS = _REPO_ROOT / "examples" / "alerts"


def sample_sources() -> list[RawSource]:
    return [
        RawSource(
            name="linux-auth-sample.log",
            source_type="linux_auth",
            media_type="text/plain",
            data=(_ALERTS / "linux-auth-sample.log").read_bytes(),
        ),
        RawSource(
            name="suricata-eve-sample.json",
            source_type="suricata_eve",
            media_type="application/json",
            data=(_ALERTS / "suricata-eve-sample.json").read_bytes(),
        ),
    ]
