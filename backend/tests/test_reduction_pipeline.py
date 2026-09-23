"""From raw sshd lines to surfaced incidents, through the production parser and rules."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.evaluation.alerts import normalize, scheduled_alerts
from app.reduction import reduce_alerts

START = datetime(2026, 1, 6, 9, 0, tzinfo=timezone.utc)


def line(number: int, seconds: float, message: str, host: str) -> dict:
    stamp = (START + timedelta(seconds=seconds)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return {"event_id": f"E{number:07d}", "host": host, "ts": stamp, "message": message}


def scenario() -> list[dict]:
    rows, n = [], 0

    def add(seconds: float, message: str, host: str) -> None:
        nonlocal n
        n += 1
        rows.append(line(n, seconds, message, host))

    # Yesterday amara logged in cleanly from her usual address.
    add(-86400, "Accepted password for amara from 198.18.7.7 port 50000 ssh2", "web-02")
    # Today she mistypes four times, then gets in: the same source, nothing to see.
    for k in range(4):
        add(10 + 5 * k, f"Failed password for amara from 198.18.7.7 port {50001 + k} ssh2", "web-02")
    add(40, "Accepted password for amara from 198.18.7.7 port 50010 ssh2", "web-02")
    # A bot hammers root for twenty minutes and never gets in.
    for k in range(120):
        add(600 + 10 * k, f"Failed password for root from 198.18.9.9 port {40000 + k} ssh2", "mail-01")
    # An attacker guesses bjorn's password and succeeds.
    for k in range(40):
        add(3000 + 4 * k, f"Failed password for bjorn from 198.18.3.3 port {30000 + k} ssh2", "bastion-01")
    add(3170, "Accepted password for bjorn from 198.18.3.3 port 30100 ssh2", "bastion-01")
    return rows


def test_only_the_attack_reaches_an_analyst_and_everything_else_is_kept():
    records = normalize(scenario())
    alerts = scheduled_alerts(records)
    incidents = reduce_alerts(alerts, records)
    surfaced = [incident for incident in incidents if incident.surfaced]
    assert [incident.src_ips for incident in surfaced] == [("198.18.3.3",)]
    attack = surfaced[0]
    assert "success_after_failures" in attack.rules and attack.priority == "P1"
    assert attack.hosts == ("bastion-01",) and attack.reasons
    # Every alert lands in exactly one incident, surfaced or not.
    assert sorted(alert for incident in incidents for alert in incident.alert_ids) == \
        sorted(alert["alert_id"] for alert in alerts)
    assert {incident.src_ips for incident in incidents} >= {("198.18.9.9",), ("198.18.7.7",)}
    assert len(alerts) > len(incidents)


def test_the_same_input_always_yields_the_same_incidents():
    records = normalize(scenario())
    alerts = scheduled_alerts(records)
    assert reduce_alerts(alerts, records) == reduce_alerts(list(reversed(alerts)), records)
    assert [incident.to_dict()["alert_ids"][0] for incident in reduce_alerts(alerts, records)] == \
        sorted(incident.alert_ids[0] for incident in reduce_alerts(alerts, records))
