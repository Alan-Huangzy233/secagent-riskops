"""The exported timeline is checked from the file alone; any edit, removal or reordering is caught."""
from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from app import audit_timeline, safety_demo

PUBLISHED = Path(__file__).resolve().parents[2] / "examples" / "safety-demo" / "audit-timeline.jsonl"


@pytest.fixture(scope="module")
def rows() -> list[dict]:
    status, rows = safety_demo.run(out=io.StringIO())
    assert status == 0
    return rows


def test_an_export_verifies_from_the_file(rows, tmp_path):
    path = tmp_path / "timeline.jsonl"
    audit_timeline.export(rows, path)
    assert audit_timeline.load(path) == rows
    assert audit_timeline.main(["verify", str(path)]) == 0


@pytest.mark.parametrize("tamper", [
    lambda rows: rows[18]["payload"].update(approver="someone-else"),
    lambda rows: rows.pop(12),
    lambda rows: rows.insert(5, rows.pop(6)),
    lambda rows: rows[-1].update(recorded_at="2026-11-02T08:00:00Z"),
])
def test_an_edited_removed_or_reordered_event_is_caught(rows, tamper, tmp_path):
    forged = json.loads(json.dumps(rows))
    tamper(forged)
    ok, message = audit_timeline.verify(forged)
    assert not ok and "chain broken at event" in message
    path = tmp_path / "forged.jsonl"
    audit_timeline.export(forged, path)
    assert audit_timeline.main(["verify", str(path)]) == 1


def test_the_timeline_carries_all_four_segments_and_names_the_approver(rows):
    segments = {audit_timeline.SEGMENTS[row["event_type"]] for row in rows}
    assert {"AGENT", "TOOL", "POLICY", "APPROVAL", "EXECUTE", "VERIFY", "ROLLBACK"} <= segments
    lines = audit_timeline.render(rows)
    assert any("APPROVED by security-operator, bound to plan sha256:" in line for line in lines)
    assert any("FAIL on web-02: PasswordAuthentication is yes from" in line for line in lines)


def test_the_published_timeline_is_what_the_demo_produces(rows):
    assert PUBLISHED.read_text(encoding="utf-8") == "".join(
        json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n" for row in rows)
    assert "/tmp" not in PUBLISHED.read_text(encoding="utf-8")


def test_the_demo_leaves_the_committed_lab_copies_untouched():
    lab = PUBLISHED.parent / "lab"
    before = {path: path.read_bytes() for path in lab.rglob("*") if path.is_file()}
    assert safety_demo.run(out=io.StringIO())[0] == 0
    assert {path: path.read_bytes() for path in lab.rglob("*") if path.is_file()} == before
