from __future__ import annotations

from copy import deepcopy
import random

import pytest

from app.telemetry.detection import detect_matches


def event(index, seconds=0, *, source="source-a", peer="198.51.100.23",
          user="root", kind="auth_failure"):
    return {"source_id": source, "event_id": str(index), "event_ts": seconds,
            "event_type": kind, "src_ip": peer, "ssh_user": user,
            "record_json": '{"message":"synthetic SSH evidence"}'}


def matches(rows, rule, triggers=None):
    if triggers is None:
        triggers = {(row["source_id"], row["event_id"]) for row in rows}
    return [match for match in detect_matches(rows, triggers) if match.rule_id == rule]


def test_slow_scan_catches_24_records_spread_over_95_minutes():
    rows = [event(index, index * 95 * 60 / 23) for index in range(24)]
    found = matches(rows, "slow_scan", {("source-a", "23")})
    assert len(found) == 1
    assert found[0].rule_version == 1
    assert found[0].window_seconds == 7200
    assert len(found[0].evidence) == 24
    assert "log records" in found[0].reason


@pytest.mark.parametrize("last,expected", [(7200, 1), (7200.001, 0)])
def test_slow_scan_window_boundary_is_inclusive(last, expected):
    rows = [event(index, index * 600) for index in range(11)] + [event(11, last)]
    assert len(matches(rows, "slow_scan")) == expected


def test_slow_scan_never_combines_two_hours_before_and_after_a_trigger():
    rows = [event(index, index * 1200) for index in range(12)]
    assert matches(rows, "slow_scan", {("source-a", "6")}) == []


@pytest.mark.parametrize("field,value", [("source_id", "source-b"),
                                         ("src_ip", "203.0.113.10")])
def test_local_rules_do_not_cross_source_or_peer_boundaries(field, value):
    rows = [event(index, index * 20, user=f"account-{index % 3}") for index in range(12)]
    for row in rows[5:]:
        row[field] = value
    assert matches(rows, "slow_scan") == []
    assert len(matches(rows, "multi_account")) == 1
    assert len(matches(rows, "multi_account")[0].evidence) == 7


@pytest.mark.parametrize("users,expected", [
    (["root", "admin", "guest", "root", "admin", "guest"], 1),
    (["root", "admin", None, "root", "admin", None], 0),
    (["root", "admin", "", "root", "admin", " "], 0),
    (["root", "root", " root ", "admin", "admin", ""], 0),
])
def test_multi_account_requires_three_nonempty_distinct_users(users, expected):
    rows = [event(index, index * 600, user=user) for index, user in enumerate(users)]
    assert len(matches(rows, "multi_account")) == expected


def test_multi_account_requires_six_records_in_one_window():
    rows = [event(index, index * 60, user=f"account-{index}") for index in range(5)]
    assert matches(rows, "multi_account") == []
    rows.append(event(5, 7201, user="account-5"))
    assert matches(rows, "multi_account") == []


def test_cross_source_can_trigger_when_neither_source_hits_its_local_threshold():
    rows = [event(index, index * 300, source=f"source-{index % 2}") for index in range(6)]
    found = matches(rows, "cross_source")
    assert len(found) == 1
    assert len(found[0].evidence) == 6
    assert {row["source_id"] for row in found[0].evidence} == {"source-0", "source-1"}
    assert matches(rows, "slow_scan") == []


def test_cross_source_requires_six_records_two_sources_and_one_peer():
    rows = [event(index, index * 60) for index in range(6)]
    assert matches(rows, "cross_source") == []
    rows[-1]["source_id"] = "source-b"
    rows[-1]["src_ip"] = "203.0.113.10"
    assert matches(rows, "cross_source") == []
    rows[-1]["src_ip"] = rows[0]["src_ip"]
    assert len(matches(rows, "cross_source")) == 1
    assert matches(rows[1:], "cross_source") == []


@pytest.mark.parametrize("last,expected", [(1800, 1), (1800.001, 0)])
def test_cross_source_rolling_window_boundary(last, expected):
    rows = [event(index, index * 60, source=f"source-{index % 2}") for index in range(5)]
    rows.append(event(5, last))
    assert len(matches(rows, "cross_source")) == expected


def test_expired_username_and_source_do_not_satisfy_diversity_thresholds():
    rows = [event("expired", 0, user="guest", source="source-b")]
    rows += [event(index, 8000 + index, user=f"account-{index % 2}") for index in range(6)]
    assert matches(rows, "cross_source") == []
    rows[0]["source_id"] = "source-a"
    assert matches(rows, "multi_account") == []


@pytest.mark.parametrize("kind", ["auth_failure", "invalid_user", "preauth_abort", "ssh_failure"])
def test_all_failure_kinds_participate(kind):
    rows = [event(index, index * 400, kind=kind) for index in range(12)]
    assert len(matches(rows, "slow_scan")) == 1


@pytest.mark.parametrize("kind", ["probe", "other", "disconnect", "session_open", "daemon"])
def test_non_authentication_records_do_not_count_as_failures(kind):
    rows = [event(index, index * 60, kind=kind) for index in range(12)]
    assert detect_matches(rows, {(row["source_id"], row["event_id"]) for row in rows}) == []


@pytest.mark.parametrize("kind", ["auth_success", "ssh_success"])
def test_success_after_failures_includes_failure_and_success_evidence(kind):
    rows = [event(index, index * 300) for index in range(3)]
    rows.append(event("success", 900, kind=kind, user="admin"))
    found = matches(rows, "success_after_failures", {("source-a", "success")})
    assert len(found) == 1
    assert [row["event_id"] for row in found[0].evidence] == ["0", "1", "2", "success"]
    # A late-arriving failure must also activate an already stored success.
    assert len(matches(rows, "success_after_failures", {("source-a", "0")})) == 1


@pytest.mark.parametrize("success_at,expected", [(1800, 1), (1800.001, 0), (0, 0), (-1, 0)])
def test_success_window_is_inclusive_at_start_and_strictly_after_failures(success_at, expected):
    rows = [event(index, 0) for index in range(3)] + [event("success", success_at, kind="auth_success")]
    assert len(matches(rows, "success_after_failures")) == expected


def test_success_must_follow_three_failures_on_its_own_source_and_peer():
    rows = [event(index, index * 100) for index in range(3)]
    rows += [event("success-b", 301, source="source-b", kind="auth_success"),
             event("success-ip", 301, peer="203.0.113.10", kind="auth_success"),
             event("early-success", 199, kind="auth_success")]
    assert matches(rows, "success_after_failures") == []


def test_unrelated_trigger_does_not_reemit_historical_matches():
    rows = [event(index, index * 60, user=f"account-{index % 3}") for index in range(12)]
    rows.append(event("unrelated", 20000))
    assert detect_matches(rows, {("source-a", "unrelated")}) == []
    assert detect_matches(rows, set()) == []


def test_success_trigger_is_not_a_trigger_for_failure_only_rules():
    rows = [event(index, index * 60, user=f"account-{index % 3}") for index in range(12)]
    rows.append(event("success", 750, kind="auth_success"))
    found = detect_matches(rows, {("source-a", "success")})
    assert [match.rule_id for match in found] == ["success_after_failures"]


def test_disjoint_matching_windows_remain_separate():
    rows = [event(index, index * 60) for index in range(12)]
    rows += [event(index + 12, 20000 + index * 60) for index in range(12)]
    found = matches(rows, "slow_scan")
    assert len(found) == 2
    assert [len(match.evidence) for match in found] == [12, 12]
    assert len(matches(rows, "slow_scan", {("source-a", "0")})) == 1


def test_overlapping_matches_merge_without_claiming_one_long_window():
    rows = [event(index, index * 600) for index in range(30)]
    found = matches(rows, "slow_scan")
    assert len(found) == 1
    assert len(found[0].evidence) == 30
    assert rows[-1]["event_ts"] - rows[0]["event_ts"] > found[0].window_seconds
    assert "linked by shared evidence" in found[0].reason


def test_success_windows_merge_only_when_they_share_failures():
    rows = [event(index, index * 100) for index in range(3)]
    rows += [event("success-a", 301, kind="auth_success"),
             event("success-b", 302, kind="auth_success")]
    rows += [event(index + 3, 5000 + index * 100) for index in range(3)]
    rows.append(event("success-c", 5301, kind="auth_success"))
    found = matches(rows, "success_after_failures")
    assert len(found) == 2
    assert [len(match.evidence) for match in found] == [5, 4]


def test_batch_order_is_irrelevant_and_input_is_not_mutated():
    rows = [event(index, index * 60, user=f"account-{index % 3}") for index in range(12)]
    before = deepcopy(rows)
    assert matches(rows, "slow_scan") == matches(list(reversed(rows)), "slow_scan")
    assert rows == before
    found = matches(rows, "slow_scan")
    found[0].evidence[0]["ssh_user"] = "changed"
    assert rows == before


def test_record_identity_dedup_is_per_source_and_does_not_invent_sessions():
    rows = [event(index, index) for index in range(6)]
    assert matches(rows + rows, "slow_scan") == []
    # Different journal records can describe one connection; these rules count
    # records explicitly and do not attempt to infer connection identity.
    rows += [event(index, index, source="source-b") for index in range(6)]
    assert len(matches(rows, "cross_source")) == 1
    assert len(matches(rows, "cross_source")[0].evidence) == 12


@pytest.mark.parametrize("bad_time", [None, "bad", float("nan"), float("inf"), True])
def test_invalid_timestamp_cannot_satisfy_threshold(bad_time):
    rows = [event(index, index) for index in range(11)] + [event(11, bad_time)]
    assert matches(rows, "slow_scan") == []


def test_missing_peer_is_never_correlated_and_normalized_aliases_work():
    rows = [event(index, index) for index in range(12)]
    rows[-1]["src_ip"] = None
    assert matches(rows, "slow_scan") == []
    rows[-1]["peer_ip"] = "198.51.100.23"
    for row in rows:
        row["event_kind"] = row.pop("event_type")
        row["username"] = row.pop("ssh_user")
    assert len(matches(rows, "slow_scan")) == 1


def test_large_dense_batch_produces_compact_complete_matches():
    rows = [event(index, index / 100, source=f"source-{index % 2}",
                  user=f"account-{index % 3}") for index in range(10000)]
    found = detect_matches(rows, {(row["source_id"], row["event_id"]) for row in rows})
    assert len(found) == 5  # Two local rules per source, one cross-source rule.
    assert sum(len(match.evidence) for match in found) == 30000


def test_large_success_batch_does_not_duplicate_shared_failure_evidence():
    rows = [event(index, index / 100) for index in range(3000)]
    rows += [event(f"success-{index}", 31 + index / 100, kind="auth_success") for index in range(3000)]
    found = matches(rows, "success_after_failures")
    assert len(found) == 1
    assert len(found[0].evidence) == 6000


def test_rolling_evidence_matches_exhaustive_reference_for_mixed_batches():
    rng = random.Random(4207)
    failure_kinds = {"auth_failure", "invalid_user", "preauth_abort", "ssh_failure"}
    definitions = {"slow_scan": (7200, 12, 0, 1),
                   "multi_account": (7200, 6, 3, 1),
                   "cross_source": (1800, 6, 0, 2)}

    def key(row):
        return row["source_id"], row["event_id"]

    for batch in range(35):
        rows = [event(index, rng.randrange(0, 15000), source=f"source-{rng.randrange(2)}",
                      user=rng.choice([None, "", "root", "admin", "guest"]),
                      kind=rng.choice(["auth_failure"] * 4 + ["preauth_abort", "ssh_failure",
                                                               "auth_success", "probe"]))
                for index in range(50)]
        triggers = {key(row) for row in rng.sample(rows, 6)}
        actual = detect_matches(list(reversed(rows)), triggers)
        for rule, (window, minimum, users, sources) in definitions.items():
            expected = set()
            failure_rows = [row for row in rows if row["event_type"] in failure_kinds]
            groups = [failure_rows] if rule == "cross_source" else [
                [row for row in failure_rows if row["source_id"] == source]
                for source in ("source-0", "source-1")]
            for group in groups:
                group.sort(key=lambda row: (row["event_ts"], key(row)))
                # Enumerate every possible interval, independently of the
                # production sliding counters and interval-compaction code.
                for start in range(len(group)):
                    for end in range(start + minimum, len(group) + 1):
                        candidate = group[start:end]
                        keys = {key(row) for row in candidate}
                        if (candidate[-1]["event_ts"] - candidate[0]["event_ts"] <= window
                                and keys & triggers
                                and len({row["ssh_user"] for row in candidate if row["ssh_user"]}) >= users
                                and len({row["source_id"] for row in candidate}) >= sources):
                            expected.update(keys)
            observed = {key(row) for match in actual if match.rule_id == rule for row in match.evidence}
            assert observed == expected, (batch, rule)

        expected = set()
        for success in [row for row in rows if row["event_type"] == "auth_success"]:
            failures = [row for row in rows if row["event_type"] in failure_kinds
                        and row["source_id"] == success["source_id"]
                        and success["event_ts"] - 1800 <= row["event_ts"] < success["event_ts"]]
            keys = {key(row) for row in failures} | {key(success)}
            if len(failures) >= 3 and keys & triggers:
                expected.update(keys)
        observed = {key(row) for match in actual if match.rule_id == "success_after_failures"
                    for row in match.evidence}
        assert observed == expected, (batch, "success_after_failures")
