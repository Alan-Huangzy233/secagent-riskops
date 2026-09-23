"""Scheduled rule evaluation turns ongoing activity into repeated alerts."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json

from app.evaluation import alerts

START = datetime(2026, 1, 5, 10, 0, tzinfo=timezone.utc)


def event(number: int, seconds: float, message: str, host: str = "web-01") -> dict:
    stamp = (START + timedelta(seconds=seconds)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return {"event_id": f"E{number:07d}", "host": host, "ts": stamp, "message": message}


def failures(ip: str, count: int, every: float, *, host: str = "web-01", first: int = 1,
             offset: float = 0.0, user: str = "amara") -> list[dict]:
    return [event(first + n, offset + n * every, f"Failed password for {user} from {ip} port {40000 + n} ssh2", host)
            for n in range(count)]


def test_only_authentication_records_with_a_peer_reach_the_rules():
    records = alerts.normalize([
        event(1, 0, "Failed password for amara from 198.18.0.5 port 40000 ssh2"),
        event(2, 1, "pam_unix(sshd:session): session opened for user amara(uid=1001) by (uid=0)"),
        event(3, 2, "Did not receive identification string from 198.18.0.5 port 40001"),
        event(4, 3, "something sshd never prints"),
        event(5, 4, "Accepted password for amara from 198.18.0.5 port 40002 ssh2"),
    ])
    assert [(row["event_id"], row["event_type"]) for row in records] == [
        ("E0000001", "auth_failure"), ("E0000005", "auth_success")]
    assert records[0]["src_ip"] == "198.18.0.5" and records[0]["ssh_user"] == "amara"


def test_activity_below_every_threshold_raises_nothing():
    assert alerts.scheduled_alerts(alerts.normalize(failures("198.18.0.5", 2, 30))) == []


def test_an_ongoing_attack_raises_an_alert_on_every_run_that_sees_new_records():
    # One failure a minute for 20 minutes crosses the burst threshold and keeps
    # adding records, so each five-minute run fires again.
    raised = alerts.scheduled_alerts(alerts.normalize(failures("198.18.0.5", 20, 60)))
    bursts = [alert for alert in raised if alert["rule_id"] == "burst"]
    assert len(bursts) >= 4
    assert len({alert["fired_at"] for alert in bursts}) == len(bursts)
    assert all(alert["src_ip"] == "198.18.0.5" and alert["hosts"] == ["web-01"] for alert in bursts)
    assert [alert["alert_id"] for alert in raised] == [f"A{n:07d}" for n in range(1, len(raised) + 1)]


def test_a_finished_attack_stops_raising_alerts_while_its_window_still_matches():
    raised = alerts.scheduled_alerts(alerts.normalize(failures("198.18.0.5", 14, 20)))
    last_record = START + timedelta(seconds=13 * 20)
    fired = [datetime.fromisoformat(alert["fired_at"].replace("Z", "+00:00")) for alert in raised]
    assert raised and max(fired) - last_record < timedelta(seconds=alerts.TICK_SECONDS)


def test_the_same_peer_on_two_hosts_raises_a_cross_source_alert():
    records = alerts.normalize(failures("198.18.0.9", 4, 30, host="web-01")
                               + failures("198.18.0.9", 4, 30, host="api-01", first=10, offset=5))
    cross = [alert for alert in alerts.scheduled_alerts(records) if alert["rule_id"] == "cross_source"]
    assert cross and cross[0]["hosts"] == ["api-01", "web-01"]


def test_conversion_is_deterministic_and_never_needs_labels(tmp_path):
    rows = failures("198.18.0.5", 20, 60) + failures("198.18.1.7", 6, 10, host="mail-01", first=100,
                                                     offset=900, user="root")
    rows.sort(key=lambda row: row["ts"])
    (tmp_path / "events.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
    first = alerts.convert(tmp_path, tmp_path / "a.jsonl")
    second = alerts.convert(tmp_path, tmp_path / "b.jsonl")
    assert not (tmp_path / "labels.jsonl").exists()
    assert first == second and first["alerts"] > 0
    assert (tmp_path / "a.jsonl").read_bytes() == (tmp_path / "b.jsonl").read_bytes()
