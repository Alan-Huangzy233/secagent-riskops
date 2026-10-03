from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import random

import pytest

from app.evaluation import web
from app.telemetry.http_parse import MAX_PATH_BYTES, normalize_http
from app.telemetry.web_detection import detect_web, unique_events


START = datetime(2026, 1, 5, tzinfo=timezone.utc)


def record(path="/", *, seconds=0, status=200, client="198.51.100.23", method="GET"):
    return {"timestamp": (START + timedelta(seconds=seconds)).isoformat(), "client_ip": client,
            "method": method, "path": path, "status": status}


def event(index, path="/", *, source="web-a", service="public", **kwargs):
    return normalize_http(record(path, **kwargs), source_id=source, service_id=service, event_id=f"e{index}")


def scan(count=20, **kwargs):
    return [event(i, f"/missing-{i % 10}", seconds=i, status=404, **kwargs) for i in range(count)]


def rules(rows):
    return {finding.rule_id for finding in detect_web(rows)}


def test_normalization_keeps_attribution_and_original_path_but_removes_query():
    row = event(1, "/%2eenv?credential=PRIVATE", client="::ffff:198.51.100.23")
    assert row.client_ip == "198.51.100.23"
    assert row.path == "/%2eenv" and row.decoded_path == "/.env"
    assert row.source_id == "web-a" and row.service_id == "public"
    assert "PRIVATE" not in repr(row)


def test_timezones_and_ipv6_are_canonicalized():
    value = {**record(), "timestamp": "2026-01-05T02:00:00+02:00", "client_ip": "2001:db8::0001"}
    row = normalize_http(value, source_id="s", service_id="web", event_id="e")
    assert row.timestamp == "2026-01-05T00:00:00.000000Z"
    assert row.client_ip == "2001:db8::1"


@pytest.mark.parametrize("field,value", [
    ("timestamp", "2026-01-05T00:00:00"), ("timestamp", "not-a-time"),
    ("client_ip", "spoofed-host.example.invalid"), ("client_ip", "fe80::1%eth0"), ("client_ip", 123),
    ("method", "GET\nPOST"), ("method", None), ("status", True), ("status", "200"), ("status", 600),
    ("path", "https://example.invalid/.env"), ("path", "../.env"), ("path", "/x\x00"),
    ("path", "/" + "é" * MAX_PATH_BYTES), ("path", "/%ff"), ("path", "/\ud800"),
])
def test_invalid_values_are_rejected_without_echoing_records(field, value):
    with pytest.raises(ValueError) as error:
        normalize_http({**record(), field: value}, source_id="s", service_id="web", event_id="e")
    assert "example.invalid" not in str(error.value)


def test_unrecognized_fields_cannot_supply_identity_or_forwarded_peers():
    for field in ("source_id", "service_id", "x_forwarded_for", "authorization"):
        with pytest.raises(ValueError, match="fields"):
            normalize_http({**record(), field: "untrusted"}, source_id="s", service_id="web", event_id="e")


@pytest.mark.parametrize("path", ["/.env", "/.env.local", "/.git/config", "/old/wp-config.php.bak",
                                  "/%2Eenv", "/%252Eenv", "/.GIT/HEAD"])
def test_sensitive_resource_attempts_do_not_depend_on_response_status(path):
    for status in (200, 302, 403, 404, 500):
        findings = detect_web([event(1, path, status=status)])
        assert {finding.rule_id for finding in findings} == {"http_sensitive_resource"}
        assert "does not prove compromise" in findings[0].reason


@pytest.mark.parametrize("path", ["/../etc/passwd", "/a/%2e%2e/config", "/%252e%252e%252fetc/passwd",
                                  "/%25252e%25252e/etc/passwd", "/a\\..\\file"])
def test_traversal_uses_path_segments_and_bounded_decoding(path):
    assert "http_path_traversal" in rules([event(1, path)])


def test_four_layers_of_encoding_are_an_explicit_coverage_limit():
    assert not rules([event(1, "/%2525252e%2525252e/etc/passwd")])


@pytest.mark.parametrize("path", ["/", "/health", "/assets/release.zip", "/docs/version..html",
                                  "/docs/environment", "/news?q=/.env", "*", "/search?q=../../etc/passwd"])
def test_normal_access_and_query_text_do_not_trigger_path_rules(path):
    assert detect_web([event(1, path)]) == []


def test_scan_threshold_and_complete_evidence():
    rows = scan()
    assert detect_web(rows[:-1]) == []
    finding, = detect_web(rows)
    assert finding.rule_id == "http_multi_path_scan"
    assert finding.rule_version == 1 and finding.window_seconds == 300
    assert finding.evidence_ids == tuple(row.event_id for row in rows)
    assert "20 requests" in finding.reason


def test_scan_requires_diverse_paths_and_the_denied_ratio():
    assert not detect_web([event(i, "/health", status=404) for i in range(50)])
    rows = scan()
    assert rules(rows[:-4] + [replace(row, status=200) for row in rows[-4:]]) == {"http_multi_path_scan"}
    assert not rules(rows[:-5] + [replace(row, status=200) for row in rows[-5:]])
    # Query variants do not turn one URL into many distinct paths.
    assert not rules([event(i, f"/missing?q={i}", status=404) for i in range(25)])


@pytest.mark.parametrize("last,expected", [(300, True), (300.000001, False)])
def test_scan_window_boundary(last, expected):
    rows = [event(i, f"/x-{i}", seconds=i, status=404) for i in range(19)]
    rows.append(event(19, "/x-last", seconds=last, status=404))
    assert bool(detect_web(rows)) is expected


@pytest.mark.parametrize("field,value", [("source_id", "web-b"), ("service_id", "private"),
                                         ("client_ip", "203.0.113.8")])
def test_scan_never_combines_other_sources_services_or_peers(field, value):
    rows = scan()
    rows[-1] = replace(rows[-1], **{field: value})
    assert not detect_web(rows)


def test_duplicates_and_input_order_cannot_change_findings():
    rows = scan() + [event(100, "/../.env", seconds=30)]
    expected = detect_web(rows)
    shuffled = rows + rows[:10]
    random.Random(7).shuffle(shuffled)
    assert detect_web(shuffled) == expected
    assert len(unique_events(shuffled)) == len(rows)
    # Conflicting evidence is rejected, never resolved by arrival order.
    for values in ([rows[0], replace(rows[0], status=200)], [replace(rows[0], status=200), rows[0]]):
        with pytest.raises(ValueError, match="conflicting"):
            detect_web(values)


def test_dense_scan_coalesces_overlapping_windows_without_losing_evidence():
    rows = [event(i, f"/missing-{i % 30}", seconds=i / 100, status=404) for i in range(2000)]
    found, = detect_web(rows)
    assert len(found.evidence_ids) == len(rows)
    assert "1981 qualifying window(s)" in found.reason


def test_separate_scan_episodes_and_nearby_point_attempts():
    rows = scan() + [event(i + 20, f"/other-{i}", seconds=1000 + i, status=404) for i in range(20)]
    assert len(detect_web(rows)) == 2
    rows = [event(i, "/.env", seconds=seconds) for i, seconds in enumerate([0, 300, 600, 901])]
    findings = detect_web(rows)
    assert [finding.evidence_ids for finding in findings] == [("e0", "e1", "e2"), ("e3",)]


def test_login_success_or_failure_is_never_inferred_from_http_codes():
    rows = [event(i, "/login", method="POST", status=(200, 302, 401, 403)[i % 4]) for i in range(40)]
    assert detect_web(rows) == []


def write_input(path, records):
    path.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")


def test_replay_retains_occurrences_and_locatable_evidence_without_query(tmp_path):
    source = tmp_path / "access.jsonl"
    write_input(source, [record("/.env?credential=PRIVATE"), record("/.env?credential=PRIVATE")])
    result = web.replay(source, source_id="fixture", service_id="example")
    assert result == web.replay(source, source_id="fixture", service_id="example")
    assert result["records"] == 2 and len(result["evidence"]) == 2
    assert len(set(result["findings"][0]["evidence_ids"])) == 2
    assert set(result["findings"][0]["evidence_ids"]) == {row["event_id"] for row in result["evidence"]}
    assert "PRIVATE" not in json.dumps(result)


@pytest.mark.parametrize("raw", [b'{"PRIVATE":', b'\xffPRIVATE', b'[]\n', b'\n',
                                   json.dumps(record()).encode("utf-16")])
def test_replay_fails_on_malformed_input_without_partial_output(tmp_path, capsys, raw):
    source = tmp_path / "access.jsonl"
    source.write_bytes(json.dumps(record("/.env")).encode() + b"\n" + raw)
    assert web.main(["--input", str(source), "--source-id", "fixture", "--service-id", "example"]) == 1
    output = capsys.readouterr()
    assert output.out == "" and "line 2" in output.err and "PRIVATE" not in output.err


def test_valid_looking_duplicate_fields_are_not_silently_overwritten(tmp_path):
    source = tmp_path / "access.jsonl"
    source.write_text(json.dumps(record())[:-1] + ',"status":404}\n')
    with pytest.raises(ValueError, match="line 1"):
        web.replay(source, source_id="fixture", service_id="example")


@pytest.mark.parametrize("limit,value", [("MAX_RECORDS", 1), ("MAX_LINE_BYTES", 10), ("MAX_INPUT_BYTES", 10)])
def test_replay_enforces_size_limits(tmp_path, monkeypatch, limit, value):
    source = tmp_path / "access.jsonl"
    write_input(source, [record(), record()])
    monkeypatch.setattr(web, limit, value)
    with pytest.raises(ValueError, match="limit"):
        web.replay(source, source_id="fixture", service_id="example")


def test_check_mode_and_snapshot_drift(tmp_path, capsys):
    source, expected = tmp_path / "access.jsonl", tmp_path / "report.json"
    write_input(source, [record("/.env")])
    args = ["--input", str(source), "--source-id", "fixture", "--service-id", "example"]
    assert web.main(args) == 0
    expected.write_text(capsys.readouterr().out, encoding="utf-8")
    assert web.main([*args, "--check", str(expected)]) == 0
    assert capsys.readouterr().out == ""
    write_input(source, [record("/")])
    assert web.main([*args, "--check", str(expected)]) == 1
    assert "differs" in capsys.readouterr().err
