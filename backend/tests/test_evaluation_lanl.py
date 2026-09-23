"""The LANL slice follows its published rule and keeps ground truth apart."""
from __future__ import annotations

import gzip
import json

from app.evaluation import alerts, lanl

DAY = lanl.DAY


def auth_line(time: int, src_user: str, dst_user: str, src: str, dst: str, orientation: str = "LogOn",
              result: str = "Success") -> str:
    return f"{time},{src_user},{dst_user},{src},{dst},Kerberos,Network,{orientation},{result}\n"


RED_TEAM = [(1 * DAY + 5, "U66@DOM1", "C17693", "C1003"),
            (3 * DAY + 10, "U66@DOM1", "C17693", "C305"), (3 * DAY + 20, "U66@DOM1", "C17693", "C728"),
            (4 * DAY + 30, "U737@DOM1", "C17693", "C999"),
            (5 * DAY + 40, "U66@DOM1", "C17693", "C123"),
            (9 * DAY, "U1@DOM1", "C1", "C2")]


def test_the_window_is_the_busiest_run_of_days():
    assert lanl.busiest_window(sorted(RED_TEAM)) == (3, 4)


def test_sampling_is_a_fixed_function_of_seed_and_name():
    picks = [name for name in (f"C{n}" for n in range(5000)) if lanl.sampled(name, 1, 15)]
    assert picks == [name for name in (f"C{n}" for n in range(5000)) if lanl.sampled(name, 1, 15)]
    assert 40 <= len(picks) <= 110
    assert picks != [name for name in (f"C{n}" for n in range(5000)) if lanl.sampled(name, 2, 15)]


def test_the_slice_labels_red_team_logons_and_reports_what_it_could_not_match():
    lines = [
        auth_line(1 * DAY + 5, "U66@DOM1", "U66@DOM1", "C17693", "C1003"),       # before the window
        auth_line(3 * DAY + 10, "U66@DOM1", "U66@DOM1", "C17693", "C305"),       # red team, matched
        auth_line(3 * DAY + 10, "U66@DOM1", "U66@DOM1", "C17693", "C305", "LogOff"),  # not an attempt
        auth_line(3 * DAY + 15, "U5@DOM1", "U5@DOM1", "C305", "C305", result="Fail"),  # involved host, benign
        auth_line(3 * DAY + 16, "U5@DOM1", "U5@DOM1", "C4", "C4"),              # unrelated, sampled out
        auth_line(4 * DAY + 30, "U737@DOM1", "U737@DOM1", "C17693", "C999"),     # red team, matched
        auth_line(6 * DAY + 1, "U66@DOM1", "U66@DOM1", "C17693", "C123"),        # after the window
    ]
    result = lanl.slice_auth(iter(lines), sorted(RED_TEAM), seed=1, per_mille=0)
    assert result["window"] == {"first_day": 3, "days": 3, "red_team_events": 4}
    assert [r["event_id"] for r in result["records"]] == ["L2", "L4", "L6"]
    assert [row["label"] for row in result["labels"]] == ["attack:EP-001", "benign", "attack:EP-002"]
    assert result["records"][1] == {"source_id": "C305", "event_id": "L4", "event_ts": float(3 * DAY + 15),
                                    "event_type": "auth_failure", "src_ip": "C305", "ssh_user": "U5@DOM1"}
    episodes = {e["episode_id"]: e for e in result["episodes"]}
    assert episodes["EP-001"]["account"] == "U66@DOM1" and episodes["EP-001"]["red_team_events"] == 2
    # The C728 red-team event has no LogOn record in the data: counted, not dropped.
    assert episodes["EP-001"]["unmatched_red_team_events"] == 1
    assert episodes["EP-003"]["unmatched_red_team_events"] == 1
    assert all("label" not in record for record in result["records"])


def test_a_truncated_gzip_prefix_is_read_up_to_where_it_ends(tmp_path):
    body = "".join(auth_line(3 * DAY + n, "U5@DOM1", "U5@DOM1", "C305", "C305") for n in range(2000)).encode()
    whole = gzip.compress(body)
    prefix = tmp_path / "auth-prefix.gz"
    prefix.write_bytes(whole[: len(whole) // 2])
    lines = list(lanl._lines(prefix))
    assert 0 < len(lines) < 2000 and lines[0].startswith(f"{3 * DAY},")


def test_the_written_slice_feeds_the_alert_layer_without_parsing(tmp_path):
    auth = tmp_path / "auth.txt"
    auth.write_text("".join(auth_line(3 * DAY + 10 * n, "U5@DOM1", "U5@DOM1", "C17693", "C305", result="Fail")
                            for n in range(8)))
    redteam = tmp_path / "redteam.txt"
    redteam.write_text("".join(f"{t},{u},{s},{d}\n" for t, u, s, d in RED_TEAM))
    manifest = lanl.write(auth, redteam, tmp_path / "slice", seed=1, per_mille=0)
    assert manifest["records"] == 8 and manifest["synthetic"] is False
    assert json.loads((tmp_path / "slice" / "manifest.json").read_text()) == manifest
    records = alerts.load_records(tmp_path / "slice")
    assert len(records) == 8 and records[0]["src_ip"] == "C17693"
    raised = alerts.scheduled_alerts(records)
    assert any(alert["rule_id"] == "burst" and alert["hosts"] == ["C305"] for alert in raised)
