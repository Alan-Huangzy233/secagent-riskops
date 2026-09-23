"""Correlation joins groups by shared records or one source close in time, never by guesswork."""
from __future__ import annotations

import pytest

from app.reduction import correlate
from app.reduction.dedup import AlertGroup


def group(group_id: str, evidence: tuple[str, ...], first: str, last: str, *, ip: str = "198.18.0.5",
          rule: str = "burst", hosts: tuple[str, ...] = ("web-01",)) -> AlertGroup:
    return AlertGroup(group_id, rule, ip, hosts, (group_id,), evidence, first, last)


def ids(incidents) -> list[list[str]]:
    return [[g.group_id for g in incident] for incident in incidents]


def test_groups_resting_on_a_common_record_are_one_incident_whatever_the_rule_or_host():
    incidents = correlate([
        group("A1", ("E1", "E2"), "2026-01-05T10:00:00Z", "2026-01-05T10:01:00Z"),
        group("A2", ("E2", "E9"), "2026-01-06T10:00:00Z", "2026-01-06T10:01:00Z", rule="cross_source",
              hosts=("api-01", "web-01")),
    ], gap_seconds=0)
    assert ids(incidents) == [["A1", "A2"]]


def test_one_source_is_joined_within_the_gap_and_split_beyond_it():
    groups = [group("A1", ("E1",), "2026-01-05T10:00:00Z", "2026-01-05T10:10:00Z"),
              group("A2", ("E2",), "2026-01-05T10:50:00Z", "2026-01-05T11:00:00Z"),
              group("A3", ("E3",), "2026-01-05T11:55:00Z", "2026-01-05T12:00:00Z"),
              group("A4", ("E4",), "2026-01-05T14:00:00Z", "2026-01-05T14:05:00Z")]
    assert ids(correlate(groups, gap_seconds=3600)) == [["A1", "A2", "A3"], ["A4"]]
    assert ids(correlate(groups, gap_seconds=600)) == [["A1"], ["A2"], ["A3"], ["A4"]]


def test_a_long_group_keeps_later_overlapping_activity_in_the_same_incident():
    groups = [group("A1", ("E1",), "2026-01-05T10:00:00Z", "2026-01-05T16:00:00Z"),
              group("A2", ("E2",), "2026-01-05T10:30:00Z", "2026-01-05T10:35:00Z"),
              group("A3", ("E3",), "2026-01-05T16:30:00Z", "2026-01-05T16:35:00Z")]
    assert ids(correlate(groups, gap_seconds=3600)) == [["A1", "A2", "A3"]]


def test_different_sources_are_never_joined_without_a_shared_record():
    groups = [group(f"A{n}", (f"E{n}",), "2026-01-05T10:00:00Z", "2026-01-05T10:01:00Z", ip=f"198.18.0.{n}")
              for n in range(1, 6)]
    assert ids(correlate(groups, gap_seconds=86400)) == [[f"A{n}"] for n in range(1, 6)]


def test_a_negative_gap_is_refused():
    with pytest.raises(ValueError):
        correlate([], gap_seconds=-1)
