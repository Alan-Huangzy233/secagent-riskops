"""Each scoring signal comes from the logs and moves the score for a stated reason."""
from __future__ import annotations

from app.reduction import score

T0 = 1_767_607_200.0  # 2026-01-05T10:00:00Z


def row(n: int, kind: str, user: str | None, *, at: float, ip: str = "198.18.0.5", host: str = "web-01") -> dict:
    return {"event_id": f"E{n}", "event_type": kind, "ssh_user": user, "event_ts": at, "src_ip": ip,
            "source_id": host}


def failures(user: str, count: int, *, start: float = T0, every: float = 5, first: int = 1, host: str = "web-01",
             kind: str = "auth_failure") -> list[dict]:
    return [row(first + n, kind, user, at=start + n * every, host=host) for n in range(count)]


def test_a_success_after_failures_against_a_real_account_is_surfaced_first():
    evidence = failures("amara", 20) + [row(99, "auth_success", "amara", at=T0 + 200)]
    verdict = score.assess(evidence, {})
    assert verdict.score == score.SUCCESS + score.EXISTING_ACCOUNT
    assert verdict.surfaced and verdict.priority == "P1"
    assert any("succeeded" in reason for reason in verdict.reasons)


def test_internet_noise_against_invalid_names_and_root_scores_nothing():
    evidence = failures("admin", 6, kind="invalid_user") + failures("admin", 6, first=20) + failures("root", 20, first=40)
    verdict = score.assess(evidence, {})
    assert verdict.score == 0 and not verdict.surfaced and verdict.priority is None and verdict.reasons == ()


def test_a_user_mistyping_from_a_known_source_stays_below_the_line():
    evidence = failures("amara", 4) + [row(99, "auth_success", "amara", at=T0 + 60)]
    baseline = {("198.18.0.5", "amara"): T0 - 86400}
    verdict = score.assess(evidence, baseline)
    assert verdict.score == score.SUCCESS + score.KNOWN_SOURCE + score.EXISTING_ACCOUNT
    assert not verdict.surfaced
    assert score.assess(evidence, {}).surfaced


def test_spraying_existing_accounts_across_hosts_adds_up():
    evidence = []
    for n, user in enumerate(["amara", "bjorn", "chen", "dalia", "emeka"]):
        evidence += failures(user, 1, first=n * 10, host="web-01") + failures(user, 1, first=n * 10 + 5, host="api-01")
    verdict = score.assess(evidence, {})
    assert verdict.score == score.EXISTING_ACCOUNT * score.EXISTING_ACCOUNT_CAP + score.SEVERAL_HOSTS
    assert verdict.priority == "P2"


def test_persistence_and_volume_are_counted():
    slow = failures("amara", 12, every=900)
    assert score.assess(slow, {}).score == score.EXISTING_ACCOUNT + score.PERSISTENT
    heavy = failures("amara", 60, every=2)
    assert score.assess(heavy, {}).score == score.EXISTING_ACCOUNT + score.VOLUME


def test_the_threshold_decides_what_is_surfaced():
    evidence = failures("amara", 12, every=900)
    assert score.assess(evidence, {}, threshold=30).surfaced is False
    assert score.assess(evidence, {}, threshold=20).surfaced is True


def test_the_baseline_keeps_the_earliest_clean_login():
    rows = [row(1, "auth_success", "amara", at=T0 + 50), row(2, "auth_success", "amara", at=T0),
            row(3, "auth_failure", "bjorn", at=T0 - 10), row(4, "auth_success", None, at=T0)]
    assert score.known_sources(rows) == {("198.18.0.5", "amara"): T0}
