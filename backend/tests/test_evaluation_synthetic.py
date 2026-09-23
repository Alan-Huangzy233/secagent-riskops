"""The synthetic dataset must be reproducible, parseable and keep its answers apart."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path

import pytest

from app.evaluation import synthetic
from app.telemetry.sshd_parse import parse_sshd


@pytest.fixture(scope="module")
def one_day():
    return synthetic.generate(synthetic.Config(days=1))


def test_the_same_seed_gives_identical_output_and_another_seed_does_not(one_day):
    assert synthetic.generate(synthetic.Config(days=1)) == one_day
    assert synthetic.generate(synthetic.Config(days=1, seed=7))[0] != one_day[0]


def test_the_events_carry_no_ground_truth(one_day):
    events, labels, _ = one_day
    assert all(set(event) == {"event_id", "host", "ts", "message"} for event in events)
    assert not any("attack" in event["message"] or "EP-" in event["message"] for event in events)
    assert [row["event_id"] for row in labels] == [event["event_id"] for event in events]
    assert {row["label"] for row in labels} - {"benign"} <= {f"attack:EP-{n:03d}" for n in range(1, 100)}


def test_every_message_is_one_the_production_parser_reads(one_day):
    kinds = Counter(parse_sshd(event["message"])["event_kind"] for event in one_day[0])
    assert "other" not in kinds
    assert {"auth_failure", "invalid_user", "preauth_abort", "auth_success"} <= set(kinds)


def test_events_are_ordered_inside_the_period_and_addresses_are_synthetic(one_day):
    events = one_day[0]
    stamps = [datetime.fromisoformat(event["ts"].replace("Z", "+00:00")) for event in events]
    assert stamps == sorted(stamps)
    start = synthetic.DEFAULT_START
    assert start <= stamps[0] and stamps[-1] < datetime(2026, 1, 6, tzinfo=timezone.utc)
    benchmark = ipaddress.ip_network("198.18.0.0/15")
    peers = {parse_sshd(event["message"])["peer_ip"] for event in events} - {None}
    assert peers and all(ipaddress.ip_address(peer) in benchmark for peer in peers)


def test_every_episode_leaves_attack_records_from_its_own_addresses(one_day):
    events, labels, episodes = one_day
    by_label: dict[str, set[str]] = {}
    for event, row in zip(events, labels):
        peer = parse_sshd(event["message"])["peer_ip"]
        if row["label"] != "benign" and peer:
            by_label.setdefault(row["label"].split(":", 1)[1], set()).add(peer)
    assert sorted(by_label) == [episode["episode_id"] for episode in episodes]
    for episode in episodes:
        assert by_label[episode["episode_id"]] <= set(episode["source_ips"])
        assert episode["synthetic"] is True and episode["scenario"] in synthetic.SCENARIOS


def test_episodes_scale_with_the_period_and_cover_every_scenario(one_day):
    counts = Counter(episode["scenario"] for episode in one_day[2])
    assert counts == {scenario: 2 for scenario in synthetic.SCENARIOS}


def test_the_manifest_fingerprints_what_was_written(tmp_path):
    manifest = synthetic.write(synthetic.Config(days=1), tmp_path)
    for name, digest in manifest["sha256"].items():
        assert hashlib.sha256((tmp_path / name).read_bytes()).hexdigest() == digest
    assert manifest["synthetic"] is True and manifest["seed"] == synthetic.DEFAULT_SEED
    assert manifest["events"] == manifest["benign_events"] + manifest["attack_events"]
    assert json.loads((tmp_path / "manifest.json").read_text()) == manifest


def test_the_committed_manifest_still_describes_what_the_generator_writes(tmp_path):
    published = Path(__file__).parents[2] / "examples" / "synthetic-sshd" / "manifest-1d.json"
    manifest = synthetic.write(synthetic.Config(days=1), tmp_path)
    assert synthetic.mismatches(manifest, json.loads(published.read_text())) == []
