"""The scoring rules of EVALUATION.md §3 on small cases worked out by hand."""
from __future__ import annotations

from app.evaluation import baselines, metrics

# Episode X owns alerts a1..a4, episode Y owns b1..b2, n1..n3 are benign.
OWNER = {"a1": "X", "a2": "X", "a3": "X", "a4": "X", "b1": "Y", "b2": "Y", "n1": "benign", "n2": "benign",
         "n3": "benign"}
EPISODES = ["X", "Y", "Z"]  # Z raised no alert at all


def incident(*alerts: str, surfaced: bool = True) -> dict:
    return {"alert_ids": list(alerts), "surfaced": surfaced}


def test_alert_labels_follow_the_majority_of_their_evidence():
    labels = {"e1": "attack:X", "e2": "attack:X", "e3": "attack:Y", "e4": "benign"}
    alerts = [{"alert_id": "A1", "evidence": ["e1", "e2", "e3"]}, {"alert_id": "A2", "evidence": ["e4"]},
              {"alert_id": "A3", "evidence": ["e3", "e1", "e4"]}]
    assert metrics.alert_labels(alerts, labels) == {"A1": "X", "A2": "benign", "A3": "X"}


def test_coverage_at_zero_and_one_half():
    incidents = [incident("a1", "n1"), incident("a2", "a3", "a4"), incident("b1", surfaced=False),
                 incident("n2", "n3")]
    loose = metrics.detection(incidents, OWNER, EPISODES, tau=0.0, seed=1)
    strict = metrics.detection(incidents, OWNER, EPISODES, tau=0.5, seed=1)
    assert (loose["detected"], loose["missed"], loose["no_alert_episodes"]) == (1, 2, 1)
    assert loose["detected_episodes"] == ["X"] and strict["detected_episodes"] == ["X"]
    assert loose["surfaced_incidents"] == 3 and loose["spurious_incidents"] == 1
    # At τ = 0.5 the one-alert incident no longer covers X: it holds a quarter of it.
    assert loose["precision"] == round(2 / 3, 4) and strict["precision"] == round(1 / 3, 4)
    assert loose["miss_rate"] == round(1 - 1 / 3, 4)


def test_the_miss_rate_interval_brackets_the_point_estimate():
    hits_half = [incident(f"x{n}") for n in range(0)]
    result = metrics.detection(hits_half, OWNER, EPISODES, tau=0.0, seed=3)
    assert result["miss_rate"] == 1.0 and result["miss_rate_ci95"] == [1.0, 1.0]
    result = metrics.detection([incident("a1"), incident("b1")], OWNER, EPISODES, tau=0.0, seed=3)
    low, high = result["miss_rate_ci95"]
    assert low <= result["miss_rate"] <= high and 0 <= low < high <= 1


def test_reduction_counts_only_what_reaches_the_analyst():
    result = metrics.reduction([incident("a1", "a2", "a3"), incident("b1"), incident("n1", surfaced=False)], 9)
    assert result == {"input_alerts": 9, "output_incidents": 2, "reduction_pct": round(100 * 7 / 9, 3),
                      "median_alerts_per_incident": 2.0, "p95_alerts_per_incident": 3}


def test_perfect_grouping_scores_one_and_mixing_is_caught():
    perfect = metrics.clustering([incident("a1", "a2", "a3", "a4"), incident("b1", "b2")], OWNER)
    assert perfect["v_measure"] == 1.0 and perfect["ari"] == 1.0
    assert perfect["mean_fragmentation"] == 1.0 and perfect["over_merged_incidents"] == 0
    mixed = metrics.clustering([incident("a1", "a2", "b1"), incident("a3", "a4", "b2")], OWNER)
    assert mixed["over_merged_incidents"] == 2 and mixed["mean_fragmentation"] == 2.0
    assert mixed["v_measure"] < 0.5


def test_the_permutation_control_keeps_the_label_counts():
    shuffled = metrics.permuted(OWNER, seed=5)
    assert sorted(shuffled.values()) == sorted(OWNER.values()) and set(shuffled) == set(OWNER)
    assert metrics.permuted(OWNER, seed=5) == shuffled


def raised(alert_id: str, at: str, *, rule: str = "burst", ip: str = "198.18.0.5",
           hosts: tuple[str, ...] = ("web-01",)) -> dict:
    return {"alert_id": alert_id, "rule_id": rule, "src_ip": ip, "hosts": list(hosts), "fired_at": at}


def test_the_baselines_follow_their_published_definitions():
    alerts = [raised("A1", "2026-01-05T10:00:00Z"), raised("A2", "2026-01-05T10:05:00Z"),
              raised("A3", "2026-01-05T10:30:00Z"), raised("A4", "2026-01-05T10:06:00Z", rule="slow_scan"),
              raised("A5", "2026-01-05T10:07:00Z", ip="198.18.0.6")]
    assert [i["alert_ids"] for i in baselines.b0_passthrough(alerts)] == [["A1"], ["A2"], ["A4"], ["A5"], ["A3"]]
    assert [i["alert_ids"] for i in baselines.b1_tuple_dedup(alerts, 600)] == [["A1", "A2"], ["A4"], ["A5"], ["A3"]]
    assert [i["alert_ids"] for i in baselines.b2_window_aggregation(alerts, 600)] == [["A1", "A2", "A5"], ["A4"],
                                                                                      ["A3"]]
    assert all(i["surfaced"] for i in baselines.b1_tuple_dedup(alerts))
