from __future__ import annotations

from app.orchestrator import run_flow
from app.replay import diff_collections, reconstruct_sources, replay
from app.samples import sample_sources


def test_replay_reproduces_the_run(services, clock):
    svc, _ = run_flow(sample_sources(), svc=services)
    replay_svc, _ = replay(svc, clock)
    assert diff_collections(svc, replay_svc) == {}


def test_replay_reads_bytes_back_from_evidence_vault(services):
    svc, _ = run_flow(sample_sources(), svc=services)
    sources = reconstruct_sources(svc)
    # Two raw sources retained and pulled back out by content hash.
    assert {s.source_type for s in sources} == {"linux_auth", "suricata_eve"}
