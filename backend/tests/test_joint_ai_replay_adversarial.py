"""Hostile local recordings cannot promote or leak unverified model claims."""
from copy import deepcopy
import json
import os
import stat

import pytest

from app.agents import joint_triage
from app.evaluation import joint_ai_replay as replay


PRIVATE_MARKER = "PRIVATE_RECORDING_DO_NOT_ECHO"


def local_tape():
    tape = replay.make_tape()
    tape["source"] = "local_recording"
    return tape


def result_case(report, scenario_id):
    return next(case for case in report["cases"] if case["scenario_id"] == scenario_id)


def test_frozen_protocol_binds_every_scenario_request():
    tape = replay.make_tape()
    assert tape["protocol"] == replay.protocol()
    assert len(tape["records"]) == len(tape["protocol"]["requests"])
    for record in tape["records"]:
        assert record["request_sha256"] == tape["protocol"]["requests"][record["scenario_id"]]
    assert replay.evaluate(tape)["contract_oracle"] == {"applicable": True, "passed": True}


@pytest.mark.parametrize("part", ["top", "protocol", "record"])
def test_unknown_fields_cannot_smuggle_prevalidated_results(part):
    tape = local_tape()
    value = {"top": tape, "protocol": tape["protocol"], "record": tape["records"][0]}[part]
    value["prevalidated"] = {"status": "valid", "verdict": "escalate"}
    with pytest.raises(replay.ReplayError):
        replay.evaluate(tape)


@pytest.mark.parametrize("field,value", [
    ("format", "foreign-format"), ("source", "production-verified"),
    ("source", True), ("records", {}), ("protocol", []),
])
def test_invalid_envelope_is_rejected(field, value):
    tape = local_tape()
    tape[field] = value
    with pytest.raises(replay.ReplayError):
        replay.evaluate(tape)


def test_missing_envelope_and_record_fields_are_rejected():
    original = local_tape()
    for field in original:
        tape = deepcopy(original)
        del tape[field]
        with pytest.raises(replay.ReplayError):
            replay.evaluate(tape)
    for field in original["records"][0]:
        tape = deepcopy(original)
        del tape["records"][0][field]
        with pytest.raises(replay.ReplayError):
            replay.evaluate(tape)


@pytest.mark.parametrize("field,value", [
    ("scenario_id", "unregistered-scenario"), ("scenario_id", True),
    ("request_sha256", "0" * 64), ("request_sha256", None),
    ("outcome", "validated"), ("outcome", True),
    ("response_text", {"status": "valid"}), ("response_text", None),
    ("response_text", "x" * (replay.MAX_RECORDED_RESPONSE_BYTES + 1)),
])
def test_unbound_or_invalid_record_is_rejected(field, value):
    tape = local_tape()
    tape["records"][0].update(outcome="response")
    tape["records"][0][field] = value
    with pytest.raises(replay.ReplayError):
        replay.evaluate(tape)


def test_duplicate_records_are_rejected_even_when_identical():
    tape = local_tape()
    tape["records"].append(deepcopy(tape["records"][0]))
    with pytest.raises(replay.ReplayError):
        replay.evaluate(tape)


def test_a_record_cannot_borrow_another_scenarios_fingerprint():
    tape = local_tape()
    tape["records"][0]["request_sha256"] = tape["records"][1]["request_sha256"]
    with pytest.raises(replay.ReplayError):
        replay.evaluate(tape)


def test_modified_protocol_is_rejected_before_responses_are_checked(monkeypatch):
    tape = local_tape()
    tape["protocol"]["requests"][tape["records"][0]["scenario_id"]] = "0" * 64
    def should_not_validate(*_args, **_kwargs):
        pytest.fail("An unbound protocol reached response validation")
    monkeypatch.setattr(joint_triage, "validate", should_not_validate)
    with pytest.raises(replay.ReplayError):
        replay.evaluate(tape)


def test_fake_reference_cannot_claim_changed_raw_text_was_authored():
    tape = replay.make_tape()
    tape["records"][0]["response_text"] = "{}"
    with pytest.raises(replay.ReplayError):
        replay.evaluate(tape)


def test_recording_is_revalidated_and_invalid_raw_text_is_not_valid_abstention():
    tape = local_tape()
    record = tape["records"][0]
    record.update(outcome="response", response_text="{}")
    report = replay.evaluate(tape)
    case = result_case(report, record["scenario_id"])
    assert case["status"] == "requires_review"
    assert case["proposed"] == "invalid"
    assert case["accepted"] == "abstain"
    assert "invalid_response" in case["reason_codes"]
    assert report["contract_oracle"] == {"applicable": False, "passed": None}
    assert report["self_reported_source"] is True
    assert report["live_qualified"] is False
    assert report["semantic_accuracy_measured"] is False
    assert report["replay_model_calls"] == report["replay_cost_usd"] == 0


def test_missing_and_unavailable_are_not_validated_abstentions():
    tape = local_tape()
    missing = tape["records"].pop()["scenario_id"]
    unavailable = tape["records"][0]
    unavailable.update(outcome="unavailable", response_text=None)
    report = replay.evaluate(tape)
    assert report["complete"] is False
    for scenario_id, state in ((missing, "missing"), (unavailable["scenario_id"], "unavailable")):
        case = result_case(report, scenario_id)
        assert case["proposed"] == case["accepted"] == case["status"] == state
    assert report["validation"]["counts"]["missing"] == 1
    assert report["validation"]["counts"]["unavailable"] == 1
    assert sum(report["validation"]["counts"].values()) == len(replay.protocol()["requests"])


def test_completely_missing_corpus_cannot_pass_contract_oracle():
    tape = replay.make_tape()
    tape["records"] = []
    report = replay.evaluate(tape)
    assert report["complete"] is False
    assert report["contract_oracle"]["passed"] is False
    assert report["validation"]["counts"].get("valid", 0) == 0
    assert report["validation"]["counts"]["missing"] == len(replay.protocol()["requests"])


def test_unavailable_record_cannot_retain_a_response():
    tape = local_tape()
    tape["records"][0].update(outcome="unavailable", response_text="{}")
    with pytest.raises(replay.ReplayError):
        replay.evaluate(tape)


@pytest.mark.parametrize("raw", [
    '{"verdict":"abstain","verdict":"escalate"}',
    '{"confidence":NaN}',
    '"' + PRIVATE_MARKER + '"',
])
def test_invalid_raw_response_never_becomes_a_valid_result(raw):
    tape = local_tape()
    record = tape["records"][0]
    record.update(outcome="response", response_text=raw)
    report = replay.evaluate(tape)
    case = result_case(report, record["scenario_id"])
    assert case["status"] == "requires_review"
    assert "invalid_response" in case["reason_codes"]
    assert PRIVATE_MARKER not in json.dumps(report)


def test_report_never_echoes_even_schema_valid_arbitrary_rationale():
    tape = local_tape()
    for record in tape["records"]:
        try:
            response = json.loads(record["response_text"])
        except (TypeError, ValueError):
            continue
        if isinstance(response, dict) and "rationale" in response:
            response["rationale"] = PRIVATE_MARKER + " /private/example/file https://example.invalid/"
            record["response_text"] = json.dumps(response)
            break
    else:
        pytest.fail("The reference corpus needs a schema-shaped response")
    report = replay.evaluate(tape)
    serialized = json.dumps(report)
    assert PRIVATE_MARKER not in serialized
    assert "/private/example/file" not in serialized
    assert "https://example.invalid/" not in serialized
    assert all(case["free_text_requires_review"] for case in report["cases"])


@pytest.mark.parametrize("level", ["top", "protocol", "record"])
def test_json_duplicate_keys_are_rejected_at_every_envelope_level(tmp_path, level):
    tape = local_tape()
    raw = json.dumps(tape)
    if level == "top":
        raw = raw.replace('{"format":', '{"format":"joint-ai-replay-v1","format":', 1)
    elif level == "protocol":
        name, value = next(iter(tape["protocol"].items()))
        token = json.dumps(name) + ": " + json.dumps(value)
        raw = raw.replace(token, token + ", " + token, 1)
    else:
        record = tape["records"][0]
        token = '"scenario_id": ' + json.dumps(record["scenario_id"])
        raw = raw.replace(token, token + ", " + token, 1)
    path = tmp_path / "duplicated.json"
    path.write_text(raw)
    with pytest.raises(replay.ReplayError):
        replay.load_tape(path)


@pytest.mark.parametrize("raw", [b"", b"[]", b"{", b"\xff", b'{"number":NaN}'])
def test_malformed_tapes_fail_with_fixed_error_without_input_echo(tmp_path, raw):
    path = tmp_path / PRIVATE_MARKER
    path.write_bytes(raw)
    with pytest.raises(replay.ReplayError) as captured:
        replay.load_tape(path)
    assert PRIVATE_MARKER not in str(captured.value)
    assert str(path) not in str(captured.value)


def test_private_output_is_exclusive_and_owner_only(tmp_path):
    path = tmp_path / "report.json"
    prior_umask = os.umask(0)
    try:
        replay.write_private(path, {"synthetic": True})
    finally:
        os.umask(prior_umask)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text()) == {"synthetic": True}
    original = path.read_bytes()
    with pytest.raises((replay.ReplayError, OSError)):
        replay.write_private(path, {"overwrite": True})
    assert path.read_bytes() == original


def test_existing_symlink_is_never_followed_or_overwritten(tmp_path):
    target = tmp_path / "existing.json"
    target.write_text(PRIVATE_MARKER)
    link = tmp_path / "output.json"
    link.symlink_to(target)
    with pytest.raises((replay.ReplayError, OSError)):
        replay.write_private(link, {"overwrite": True})
    assert link.is_symlink() and target.read_text() == PRIVATE_MARKER
    target.unlink()
    with pytest.raises((replay.ReplayError, OSError)):
        replay.write_private(link, {"overwrite": True})
    assert link.is_symlink() and not target.exists()


@pytest.mark.parametrize("argument", ["--live", "--keys-file", "--config", "--data", "--endpoint", "--budget-usd"])
def test_cli_has_no_live_configuration_or_arbitrary_data_switches(argument, capsys):
    assert replay.main([argument, PRIVATE_MARKER]) == 2
    output = capsys.readouterr()
    assert PRIVATE_MARKER not in output.out + output.err


def test_cli_missing_path_error_does_not_expose_path(tmp_path, capsys):
    path = tmp_path / PRIVATE_MARKER
    assert replay.main(["--tape", str(path)]) == 2
    output = capsys.readouterr()
    assert str(path) not in output.out + output.err
    assert PRIVATE_MARKER not in output.out + output.err


def test_cli_does_not_overwrite_recording_with_report(tmp_path, capsys):
    path = tmp_path / "tape.json"
    replay.write_private(path, replay.make_tape())
    original = path.read_bytes()
    assert replay.main(["--tape", str(path), "--out", str(path)]) == 2
    assert path.read_bytes() == original
    capsys.readouterr()


def test_over_contract_size_raw_text_is_measured_as_invalid_response():
    tape = local_tape()
    record = tape["records"][0]
    record.update(outcome="response", response_text="x" * (joint_triage.MAX_RESPONSE_BYTES + 1))
    case = result_case(replay.evaluate(tape), record["scenario_id"])
    assert case["status"] == "requires_review"
    assert case["reason_codes"] == ["invalid_response"]


@pytest.mark.parametrize("kind", ["directory", "fifo", "symlink"])
def test_input_must_be_a_regular_file_not_an_indirect_or_blocking_source(tmp_path, kind):
    path = tmp_path / "input"
    if kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        os.mkfifo(path)
    else:
        target = tmp_path / "valid.json"
        replay.write_private(target, replay.make_tape())
        path.symlink_to(target)
    with pytest.raises(replay.ReplayError):
        replay.load_tape(path)


def test_output_parent_symlink_cannot_redirect_artifact(tmp_path):
    directory = tmp_path / "real"
    directory.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(directory, target_is_directory=True)
    with pytest.raises(replay.ReplayError):
        replay.write_private(alias / "report.json", {"synthetic": True})
    assert list(directory.iterdir()) == []
