"""Dedup collapses re-raised alerts of one detection and nothing else."""
from __future__ import annotations

import random

from app.reduction import deduplicate


def alert(alert_id: str, evidence: list[str], *, rule: str = "burst", ip: str = "198.18.0.5",
          hosts: tuple[str, ...] = ("web-01",), first: str = "2026-01-05T10:00:00Z",
          last: str = "2026-01-05T10:05:00Z") -> dict:
    return {"alert_id": alert_id, "rule_id": rule, "src_ip": ip, "hosts": list(hosts), "evidence": evidence,
            "first_ts": first, "last_ts": last}


def test_re_raised_alerts_that_share_records_become_one_group():
    groups = deduplicate([
        alert("A1", ["E1", "E2", "E3"], last="2026-01-05T10:02:00Z"),
        alert("A2", ["E2", "E3", "E4"], first="2026-01-05T10:01:00Z", last="2026-01-05T10:07:00Z"),
        alert("A3", ["E4", "E5"], first="2026-01-05T10:06:00Z", last="2026-01-05T10:12:00Z"),
    ])
    assert len(groups) == 1
    group = groups[0]
    assert group.group_id == "A1" and group.alert_ids == ("A1", "A2", "A3")
    assert group.evidence == ("E1", "E2", "E3", "E4", "E5")
    assert (group.first_ts, group.last_ts) == ("2026-01-05T10:00:00Z", "2026-01-05T10:12:00Z")


def test_separate_bursts_from_one_address_stay_separate():
    groups = deduplicate([alert("A1", ["E1", "E2", "E3"]), alert("A2", ["E7", "E8", "E9"])])
    assert [group.alert_ids for group in groups] == [("A1",), ("A2",)]


def test_other_rules_hosts_or_addresses_are_left_for_correlation():
    groups = deduplicate([
        alert("A1", ["E1", "E2", "E3"]),
        alert("A2", ["E1", "E2", "E3"], rule="slow_scan"),
        alert("A3", ["E1", "E2", "E3"], hosts=("web-01", "api-01")),
        alert("A4", ["E1", "E2", "E3"], ip="198.18.0.6"),
    ])
    assert len(groups) == 4


def test_the_result_does_not_depend_on_input_order():
    alerts = [alert(f"A{n}", [f"E{n}", f"E{n + 1}"]) for n in range(1, 30, 3)]
    alerts += [alert(f"B{n}", [f"E{n}", f"E{n + 1}"], rule="slow_scan") for n in range(1, 30, 2)]
    shuffled = alerts[:]
    random.Random(1).shuffle(shuffled)
    assert deduplicate(shuffled) == deduplicate(alerts)
