"""Private synthetic-only recordings identify raw responses, never trusted verdicts."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path

import pytest

from app.agents import joint_triage as joint
from app.telemetry import joint_ai_recorded as recorded
from test_joint_triage import fixture

PRIVATE = "PRIVATE_RECORDING_DO_NOT_ECHO"


def entry(case=None, response="authored raw response", outcome="response"):
    return {"case": fixture() if case is None else case, "outcome": outcome, "response_text": response}


def tape():
    return recorded.make_tape([entry()])


def save(tmp_path, value=None, *, raw=None):
    path = tmp_path / "recording.json"
    path.write_bytes(raw if raw is not None else json.dumps(tape() if value is None else value).encode())
    path.chmod(0o600)
    return path


def invalid(function, *args):
    with pytest.raises(recorded.RecordedResponseError) as caught:
        function(*args)
    assert str(caught.value) == "invalid_joint_recording"
    assert PRIVATE not in repr(caught.value)


def test_exact_raw_response_is_replayed_without_claiming_or_running_validation(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("A recording is not a prevalidated verdict")

    monkeypatch.setattr(joint, "validate", forbidden)
    case = fixture()
    raw = '{"verdict":"dismiss","rationale":"' + PRIVATE + '"}'
    value = recorded.make_tape([entry(case, raw)])
    snapshot = recorded.RecordedResponses.from_tape(value)
    assert snapshot.response(case) == raw
    assert value["source"] == "local_recording"
    assert set(value) == {"format", "source", "protocol", "records"}
    assert snapshot.digest == hashlib.sha256(joint.canonical(value).encode("ascii")).hexdigest()
    assert PRIVATE not in repr(snapshot)
    assert "provider" not in value and "model" not in value


def test_protocol_binds_all_versions_prompt_and_schema():
    value = recorded.protocol()
    assert set(value) == {"format", "dossier_version", "validator_version", "system_sha256",
                          "schema_sha256", "summary_version", "envelope_version"}
    assert value["format"] == "joint-recorded-response-v1"
    assert value["dossier_version"] == joint.VERSION
    assert value["validator_version"] == joint.VALIDATOR_VERSION
    assert value["system_sha256"] == hashlib.sha256(joint.SYSTEM.encode()).hexdigest()
    assert value["schema_sha256"] == hashlib.sha256(joint.canonical(joint.SCHEMA).encode()).hexdigest()
    assert value["summary_version"] == recorded.SUMMARY_VERSION
    assert value["envelope_version"] == recorded.ENVELOPE_VERSION
    original = recorded.protocol()
    value["format"] = "mutated"
    assert recorded.protocol() == original


def test_request_hash_is_canonical_and_has_no_circular_recording_dependency():
    case = fixture()
    before = deepcopy(case)
    first = recorded.request_sha256(case)
    assert recorded.request_sha256(dict(reversed(list(case.items())))) == first
    expected = {"protocol": recorded.protocol(), "case": case}
    assert first == hashlib.sha256(joint.canonical(expected).encode()).hexdigest()
    assert case == before
    a = recorded.make_tape([entry(case, "first")])
    b = recorded.make_tape([entry(case, "second")])
    assert a["records"][0]["request_sha256"] == b["records"][0]["request_sha256"] == first
    assert recorded.RecordedResponses.from_tape(a).digest != recorded.RecordedResponses.from_tape(b).digest


@pytest.mark.parametrize("change", ["revision", "port", "review_state", "order", "limitation", "account"])
def test_any_full_dossier_change_cannot_reuse_a_response(change):
    case = fixture()
    snapshot = recorded.RecordedResponses.from_tape(recorded.make_tape([entry(case)]))
    if change == "revision":
        case["revision"] = "R-" + "9" * 24
    elif change == "port":
        case["evidence"][0]["dst_port"] = 2222
    elif change == "review_state":
        case["review_state"] = "historical"
    elif change == "order":
        case["evidence"].reverse()
    elif change == "limitation":
        case["limitations"].append("network_coverage_limited")
    else:
        case["evidence"][2]["account"] = "U-" + "9" * 24
    joint.parse_dossier(case)
    with pytest.raises(recorded.RecordedResponseMissing, match="^joint_recording_missing$"):
        snapshot.response(case)


@pytest.mark.parametrize("change", ["missing", "extra", "raw_peer", "wrong_version", "model_instance"])
def test_invalid_dossier_never_enters_fingerprinting_or_lookup(change):
    case = fixture()
    snapshot = recorded.RecordedResponses.from_tape(tape())
    if change == "missing":
        del case["revision"]
    elif change == "extra":
        case["raw_log"] = PRIVATE
    elif change == "raw_peer":
        case["peer"] = "192.0.2.1"
    elif change == "wrong_version":
        case["dossier_version"] = 3
    else:
        case = joint.parse_dossier(case)
    invalid(recorded.request_sha256, case)
    invalid(snapshot.response, case)


def test_missing_and_explicitly_unavailable_are_distinct_from_an_abstention():
    case = fixture()
    empty = recorded.RecordedResponses.from_tape(recorded.make_tape([]))
    with pytest.raises(recorded.RecordedResponseMissing, match="^joint_recording_missing$"):
        empty.response(case)
    unavailable = recorded.make_tape([entry(case, None, "unavailable")])
    snapshot = recorded.RecordedResponses.from_tape(unavailable)
    with pytest.raises(recorded.RecordedResponseUnavailable, match="^joint_recording_unavailable$"):
        snapshot.response(case)
    assert snapshot.digest != empty.digest
    assert snapshot.digest != recorded.RecordedResponses.from_tape(tape()).digest


def test_snapshot_is_deeply_immutable_and_independent_of_the_input():
    value = tape()
    original = deepcopy(value)
    snapshot = recorded.RecordedResponses.from_tape(value)
    first_digest = snapshot.digest
    value["records"][0]["response_text"] = PRIVATE
    value["protocol"]["format"] = "changed"
    value["records"].clear()
    assert snapshot.response(fixture()) == original["records"][0]["response_text"]
    assert snapshot.digest == first_digest
    with pytest.raises((FrozenInstanceError, AttributeError)):
        snapshot.digest = "0" * 64
    with pytest.raises(TypeError):
        snapshot._records[recorded.request_sha256(fixture())] = ("response", PRIVATE)


def test_file_snapshot_does_not_hot_reload_changed_or_removed_files(tmp_path):
    path = save(tmp_path)
    snapshot = recorded.RecordedResponses.load(path)
    first_digest = snapshot.digest
    replacement = recorded.make_tape([entry(response="replacement")])
    path.write_text(json.dumps(replacement))
    newer = recorded.RecordedResponses.load(path)
    assert newer.digest != first_digest
    assert newer.response(fixture()) == "replacement"
    path.unlink()
    assert snapshot.digest == first_digest
    assert snapshot.response(fixture()) == "authored raw response"


@pytest.mark.parametrize("field", list(recorded.protocol()))
def test_altered_recorded_protocol_is_rejected_before_lookup(field):
    value = tape()
    value["protocol"][field] += "-changed"
    invalid(recorded.RecordedResponses.from_tape, value)


@pytest.mark.parametrize("target,field", [(joint, "VERSION"), (joint, "VALIDATOR_VERSION"),
                                         (joint, "SYSTEM"), (recorded, "SUMMARY_VERSION"),
                                         (recorded, "ENVELOPE_VERSION")])
def test_in_memory_snapshot_cannot_outlive_its_current_protocol(monkeypatch, target, field):
    value = tape()
    snapshot = recorded.RecordedResponses.from_tape(value)
    original_hash = recorded.request_sha256(fixture())
    monkeypatch.setattr(target, field, getattr(target, field) + "-changed")
    invalid(recorded.RecordedResponses.from_tape, value)
    invalid(snapshot.response, fixture())
    if target is not joint or field != "VERSION":
        assert recorded.request_sha256(fixture()) != original_hash


def test_schema_change_invalidates_recorded_protocol(monkeypatch):
    value = tape()
    snapshot = recorded.RecordedResponses.from_tape(value)
    schema = deepcopy(joint.SCHEMA)
    schema["description"] = "changed synthetic schema"
    monkeypatch.setattr(joint, "SCHEMA", schema)
    invalid(recorded.RecordedResponses.from_tape, value)
    invalid(snapshot.response, fixture())


@pytest.mark.parametrize("level", ["top", "protocol", "record"])
def test_extra_fields_cannot_supply_a_trusted_result_or_provider_identity(level):
    value = tape()
    part = {"top": value, "protocol": value["protocol"], "record": value["records"][0]}[level]
    part["validated"] = {"verdict": "escalate", "status": "valid", "provider": PRIVATE}
    invalid(recorded.RecordedResponses.from_tape, value)


@pytest.mark.parametrize("field,value", [("format", "joint-ai-replay-v1"), ("format", True),
                                        ("source", "authored_fake"), ("source", "verified-provider"),
                                        ("source", True), ("protocol", []), ("records", {})])
def test_foreign_formats_and_provenance_claims_cannot_be_promoted(field, value):
    changed = tape()
    changed[field] = value
    invalid(recorded.RecordedResponses.from_tape, changed)


def test_required_fields_cannot_be_missing():
    original = tape()
    for field in original:
        changed = deepcopy(original)
        del changed[field]
        invalid(recorded.RecordedResponses.from_tape, changed)
    for field in original["records"][0]:
        changed = deepcopy(original)
        del changed["records"][0][field]
        invalid(recorded.RecordedResponses.from_tape, changed)


@pytest.mark.parametrize("value", [None, True, "A" * 64, "0" * 63, "0" * 65, PRIVATE])
def test_record_request_identity_is_strict_sha256(value):
    changed = tape()
    changed["records"][0]["request_sha256"] = value
    invalid(recorded.RecordedResponses.from_tape, changed)


@pytest.mark.parametrize("conflict", [False, True])
def test_duplicate_request_hashes_are_rejected_even_when_identical(conflict):
    changed = tape()
    duplicate = deepcopy(changed["records"][0])
    if conflict:
        duplicate["response_text"] = "different raw response"
    changed["records"].append(duplicate)
    invalid(recorded.RecordedResponses.from_tape, changed)
    invalid(recorded.make_tape, [entry(), entry(response="different" if conflict else "authored raw response")])


@pytest.mark.parametrize("outcome,text", [(True, "response"), ("valid", "{}"),
                                         ("response", None), ("response", {}),
                                         ("response", "\ud800"), ("unavailable", "{}")])
def test_record_outcome_and_raw_text_are_strict(outcome, text):
    changed = tape()
    changed["records"][0].update(outcome=outcome, response_text=text)
    invalid(recorded.RecordedResponses.from_tape, changed)
    invalid(recorded.make_tape, [entry(response=text, outcome=outcome)])


def test_response_byte_limit_allows_validator_oversize_rejection_but_is_bounded():
    limit = recorded.MAX_RECORDED_RESPONSE_BYTES
    assert limit == joint.MAX_RESPONSE_BYTES + 1024
    for raw in ("x" * limit, "é" * (limit // 2)):
        snapshot = recorded.RecordedResponses.from_tape(recorded.make_tape([entry(response=raw)]))
        assert snapshot.response(fixture()) == raw
        assert joint.validate(raw, fixture())[1]["status"] == "requires_review"
    invalid(recorded.make_tape, [entry(response="x" * (limit + 1))])
    invalid(recorded.make_tape, [entry(response="é" * (limit // 2 + 1))])


def test_record_count_and_total_encoded_size_are_bounded():
    value = tape()
    record = value["records"][0]
    value["records"] = [{**record, "request_sha256": f"{n:064x}"} for n in range(recorded.MAX_RECORDS)]
    recorded.RecordedResponses.from_tape(value)
    value["records"].append({**record, "request_sha256": f"{recorded.MAX_RECORDS:064x}"})
    invalid(recorded.RecordedResponses.from_tape, value)
    value["records"].pop()
    for item in value["records"]:
        item["response_text"] = "x" * recorded.MAX_RECORDED_RESPONSE_BYTES
    invalid(recorded.RecordedResponses.from_tape, value)


def test_make_tape_accepts_bounded_iterables_without_retaining_cases():
    def entries():
        for n in range(2):
            case = fixture()
            case["revision"] = f"R-{n:024x}"
            yield entry(case, f"response-{n}")
    value = recorded.make_tape(entries())
    snapshot = recorded.RecordedResponses.from_tape(value)
    for item in entries():
        assert snapshot.response(item["case"]) == item["response_text"]
    assert all("case" not in item for item in value["records"])
    invalid(recorded.make_tape, None)
    invalid(recorded.make_tape, [{**entry(), "validated": True}])


def test_make_tape_stops_reading_an_unbounded_iterator():
    consumed = []
    def entries():
        for n in range(10_000):
            consumed.append(n)
            case = fixture()
            case["revision"] = f"R-{n:024x}"
            yield entry(case)
    invalid(recorded.make_tape, entries())
    assert len(consumed) == recorded.MAX_RECORDS + 1


def test_private_regular_file_matches_the_in_memory_snapshot(tmp_path):
    value = tape()
    path = save(tmp_path, value)
    path.chmod(0o400)
    assert recorded.RecordedResponses.load(path).digest == recorded.RecordedResponses.from_tape(value).digest


@pytest.mark.parametrize("mode", [0o640, 0o644, 0o666, 0o607])
def test_shared_file_permissions_are_rejected(tmp_path, mode):
    path = save(tmp_path)
    path.chmod(mode)
    invalid(recorded.RecordedResponses.load, path)


def test_file_owner_must_match_effective_user(tmp_path, monkeypatch):
    path = save(tmp_path)
    wrong_owner = os.geteuid() + 1
    monkeypatch.setattr(os, "geteuid", lambda: wrong_owner)
    invalid(recorded.RecordedResponses.load, path)


def test_relative_paths_and_parent_traversal_are_rejected(tmp_path, monkeypatch):
    path = save(tmp_path)
    monkeypatch.chdir(tmp_path)
    invalid(recorded.RecordedResponses.load, Path(path.name))
    invalid(recorded.RecordedResponses.load, tmp_path / "unused" / ".." / path.name)
    invalid(recorded.RecordedResponses.load, str(path) + "\x00")


def test_file_symlink_parent_symlink_and_hardlink_are_rejected(tmp_path):
    path = save(tmp_path)
    linked = tmp_path / "linked.json"
    linked.symlink_to(path)
    invalid(recorded.RecordedResponses.load, linked)
    linked.unlink()
    parent = tmp_path / "linked-parent"
    parent.symlink_to(tmp_path, target_is_directory=True)
    invalid(recorded.RecordedResponses.load, parent / path.name)
    os.link(path, linked)
    invalid(recorded.RecordedResponses.load, linked)
    invalid(recorded.RecordedResponses.load, path)


def test_nonregular_files_are_rejected_without_waiting_for_fifo_input(tmp_path):
    invalid(recorded.RecordedResponses.load, tmp_path)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    invalid(recorded.RecordedResponses.load, fifo)


def test_large_file_rejected_before_reading(tmp_path):
    path = save(tmp_path)
    with path.open("wb") as handle:
        handle.truncate(recorded.MAX_TAPE_BYTES + 1)
    invalid(recorded.RecordedResponses.load, path)


def test_file_changed_during_read_is_rejected(tmp_path, monkeypatch):
    path = save(tmp_path)
    original = os.fstat
    calls = []
    def changed(fd):
        calls.append(fd)
        if len(calls) == 2:
            path.write_bytes(b"{}")
        return original(fd)
    monkeypatch.setattr(os, "fstat", changed)
    invalid(recorded.RecordedResponses.load, path)
    assert len(calls) == 2


@pytest.mark.parametrize("level", ["top", "protocol", "record"])
def test_duplicate_json_keys_are_rejected_at_every_recording_level(tmp_path, level):
    value = tape()
    raw = json.dumps(value)
    if level == "top":
        raw = raw.replace('{"format":', '{"format":"joint-recorded-response-v1","format":', 1)
    elif level == "protocol":
        token = '"dossier_version": ' + json.dumps(value["protocol"]["dossier_version"])
        raw = raw.replace(token, token + ", " + token, 1)
    else:
        token = '"request_sha256": ' + json.dumps(value["records"][0]["request_sha256"])
        raw = raw.replace(token, token + ", " + token, 1)
    invalid(recorded.RecordedResponses.load, save(tmp_path, raw=raw.encode()))


@pytest.mark.parametrize("raw", [b"", b"[]", b"{", b"\xff", b'{"number":NaN}',
                                 b'{"number":Infinity}', b'{"number":-Infinity}',
                                 ('{"private":"' + PRIVATE + '"}').encode()])
def test_malformed_files_use_fixed_errors_without_echoing_content_or_paths(tmp_path, raw):
    path = tmp_path / PRIVATE
    path.write_bytes(raw)
    path.chmod(0o600)
    invalid(recorded.RecordedResponses.load, path)
    invalid(recorded.RecordedResponses.load, tmp_path / (PRIVATE + "-missing"))
