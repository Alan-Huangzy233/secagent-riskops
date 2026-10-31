"""The local adapter must preserve authored contract and limitation cases."""

from app.agents import joint_triage
from app.evaluation.joint_ai_scenarios import scenarios
from app.telemetry.joint_ai_recorded import RecordedResponses, make_tape


def test_recorded_adapter_preserves_synthetic_response_oracles():
    rows = scenarios()
    snapshot = RecordedResponses.from_tape(make_tape([
        {"case": row["case"], "outcome": "response", "response_text": row["fake_response"]}
        for row in rows
    ]))
    for row in rows:
        raw = snapshot.response(row["case"])
        assert raw == row["fake_response"], row["id"]
        verdict, details = joint_triage.validate(raw, row["case"])
        assert verdict["verdict"] == row["expected_accepted"], row["id"]
        assert details["status"] == row["expected_status"], row["id"]
        assert sorted(item["code"] for item in details["reasons"]) == sorted(row["expected_reason_codes"]), row["id"]
        assert details["free_text_requires_review"] is True
