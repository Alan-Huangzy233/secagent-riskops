"""Episode-level scoring exactly as EVALUATION.md §3 and §5 define it.

A system's output is a list of incidents, each a set of alert ids and a
``surfaced`` flag. Ground truth reaches this module only here: every alert takes
the episode that owns most of its evidence records, or ``benign``.

* ``I`` covers ``E`` at τ when ``|I ∩ E| / |E| ≥ τ``; τ = 0 means any overlap.
* ``E`` is detected when a surfaced incident covers it. An episode that raised
  no alert at all is missed by definition and is also counted on its own line,
  so the rule layer's share of the misses stays visible.
* A surfaced incident is spurious when it holds no attack alert; it is correct at
  τ when it covers some episode at τ. Precision uses surfaced incidents.
"""
from __future__ import annotations

from collections import Counter
from math import comb, log
import random
from statistics import median

BOOTSTRAP_SAMPLES = 2000


def alert_labels(alerts: list[dict], labels: dict[str, str]) -> dict[str, str]:
    """``alert_id -> "benign" | episode_id`` from the labels of its evidence records."""
    result = {}
    for alert in alerts:
        attack = Counter(labels[record] for record in alert["evidence"] if labels[record] != "benign")
        result[alert["alert_id"]] = (min(attack, key=lambda key: (-attack[key], key)).split(":", 1)[1]
                                     if attack else "benign")
    return result


def _percentile(values: list[float], share: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(share * len(ordered)))] if ordered else 0.0


def _bootstrap(hits: list[bool], seed: int) -> tuple[float, float]:
    """95 % interval of the miss rate, resampling episodes."""
    if not hits:
        return 0.0, 0.0
    rng = random.Random(seed)
    rates = sorted(1 - sum(rng.choice(hits) for _ in hits) / len(hits) for _ in range(BOOTSTRAP_SAMPLES))
    return rates[int(0.025 * BOOTSTRAP_SAMPLES)], rates[int(0.975 * BOOTSTRAP_SAMPLES) - 1]


def detection(incidents: list[dict], owner: dict[str, str], episodes: list[str], *, tau: float,
              seed: int) -> dict:
    members: dict[str, set[str]] = {}
    for alert, label in owner.items():
        if label != "benign":
            members.setdefault(label, set()).add(alert)
    surfaced = [set(incident["alert_ids"]) for incident in incidents if incident["surfaced"]]

    def covers(incident: set[str], episode: str) -> bool:
        own = members.get(episode, set())
        overlap = len(incident & own)
        return overlap > 0 if tau == 0 else bool(own) and overlap / len(own) >= tau

    hits = [any(covers(incident, episode) for incident in surfaced) for episode in episodes]
    correct = sum(any(covers(incident, episode) for episode in members) for incident in surfaced)
    spurious = sum(all(owner[alert] == "benign" for alert in incident) for incident in surfaced)
    detected = sum(hits)
    recall = detected / len(episodes) if episodes else 0.0
    precision = correct / len(surfaced) if surfaced else 0.0
    low, high = _bootstrap(hits, seed)
    return {"tau": tau, "episodes": len(episodes), "detected": detected, "missed": len(episodes) - detected,
            "miss_rate": round(1 - recall, 4), "miss_rate_ci95": [round(low, 4), round(high, 4)],
            "no_alert_episodes": sum(episode not in members for episode in episodes),
            "surfaced_incidents": len(surfaced), "spurious_incidents": spurious,
            "precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
            "detected_episodes": sorted(e for e, hit in zip(episodes, hits) if hit)}


def reduction(incidents: list[dict], alert_count: int) -> dict:
    sizes = [len(incident["alert_ids"]) for incident in incidents if incident["surfaced"]]
    return {"input_alerts": alert_count, "output_incidents": len(sizes),
            "reduction_pct": round(100 * (1 - len(sizes) / alert_count), 3) if alert_count else 0.0,
            "median_alerts_per_incident": median(sizes) if sizes else 0,
            "p95_alerts_per_incident": _percentile(sizes, 0.95)}


def _entropy(counts: list[int]) -> float:
    total = sum(counts)
    return -sum(c / total * log(c / total) for c in counts if c) if total else 0.0


def clustering(incidents: list[dict], owner: dict[str, str]) -> dict:
    """Quality of the grouping over attack alerts: class = episode, cluster = incident."""
    pairs = [(owner[alert], index) for index, incident in enumerate(incidents)
             for alert in incident["alert_ids"] if owner[alert] != "benign"]
    if not pairs:
        return {"homogeneity": 0.0, "completeness": 0.0, "v_measure": 0.0, "ari": 0.0,
                "mean_fragmentation": 0.0, "over_merged_incidents": 0}
    joint = Counter(pairs)
    classes, clusters = Counter(c for c, _ in pairs), Counter(k for _, k in pairs)
    n = len(pairs)
    h_c, h_k = _entropy(list(classes.values())), _entropy(list(clusters.values()))
    h_c_given_k = -sum(v / n * log(v / clusters[k]) for (c, k), v in joint.items())
    h_k_given_c = -sum(v / n * log(v / classes[c]) for (c, k), v in joint.items())
    homogeneity = 1.0 if h_c == 0 else 1 - h_c_given_k / h_c
    completeness = 1.0 if h_k == 0 else 1 - h_k_given_c / h_k
    v = 2 * homogeneity * completeness / (homogeneity + completeness) if homogeneity + completeness else 0.0
    index = sum(comb(v_, 2) for v_ in joint.values())
    rows, cols = sum(comb(v_, 2) for v_ in classes.values()), sum(comb(v_, 2) for v_ in clusters.values())
    expected = rows * cols / comb(n, 2) if n > 1 else 0.0
    maximum = (rows + cols) / 2
    ari = (index - expected) / (maximum - expected) if maximum != expected else 1.0
    fragments = Counter(c for c, _ in joint)
    over_merged = sum(1 for k in clusters if len({c for c, kk in joint if kk == k}) > 1)
    return {"homogeneity": round(homogeneity, 4), "completeness": round(completeness, 4),
            "v_measure": round(v, 4), "ari": round(ari, 4),
            "mean_fragmentation": round(sum(fragments.values()) / len(fragments), 4),
            "over_merged_incidents": over_merged}


def permuted(owner: dict[str, str], seed: int) -> dict[str, str]:
    """B3: the same labels shuffled across alerts; the systems are not re-run."""
    alerts = sorted(owner)
    labels = [owner[alert] for alert in alerts]
    random.Random(seed).shuffle(labels)
    return dict(zip(alerts, labels))
