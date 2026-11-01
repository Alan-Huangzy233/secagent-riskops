"""Joint adapter boundaries use synthetic dossiers and in-memory HTTP only."""
from copy import deepcopy
import json
import socket

import httpx
import pytest

from app.agents import joint_triage as joint
from app.agents import joint_triage_api as adapter
from app.agents.triage_api import APIConfig, APIError
from app.agents.triage_budget import CallUncertain
from app.evaluation.joint_ai_scenarios import scenarios
from app.telemetry.ai_jobs import Jobs, Ledger
from test_joint_triage_transport_flow import calls, client, make_world, payload, profile


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("synthetic MockTransport required")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)


def changed(config, **values):
    return APIConfig.model_validate({**config.model_dump(mode="json"), **values})


@pytest.mark.parametrize("api_format", ["openai-responses", "openai-chat"])
def test_request_has_only_joint_protocol_and_independent_case_snapshot(api_format):
    config = profile(api_format)
    case = scenarios()[0]["case"]
    original = deepcopy(case)
    body = adapter.request(config, case)
    messages = body.get("input", body.get("messages"))
    assert messages[0]["content"] == joint.SYSTEM
    assert json.loads(messages[1]["content"].split("\n", 1)[1]) == original
    assert "tools" not in body and "previous_response_id" not in body
    case["evidence"].clear()
    assert json.loads(messages[1]["content"].split("\n", 1)[1]) == original
    if api_format == "openai-responses":
        assert body["store"] is False and body["service_tier"] == "default"
        body["text"]["format"]["schema"].clear()
        assert adapter.request(config, original)["text"]["format"]["schema"] == joint.SCHEMA


@pytest.mark.parametrize("update", [
    {"key_name": "OTHER_SYNTHETIC_KEY"}, {"max_input_tokens": 65537},
    {"max_output_tokens": 513}, {"effort": "medium"},
    {"endpoint": "https://other.example.invalid/v1/triage"},
    {"prices": {"as_of": "2026-01-02", "input": "1", "output": "3", "cache_read": "0.5", "cache_write": "1"}},
    {"prices": {"as_of": "2026-01-01", "input": "2", "output": "3", "cache_read": "0.5", "cache_write": "1"}},
])
def test_fingerprint_binds_whole_configuration_including_prices_and_input_limit(update):
    case, config = scenarios()[0]["case"], profile()
    assert adapter.fingerprint(config, case) != adapter.fingerprint(changed(config, **update), case)


@pytest.mark.parametrize("bad", ["envelope", "extra_private", "model_instance", "wrong_protocol"])
def test_request_rejects_non_dossier_inputs(bad):
    case = scenarios()[0]["case"]
    if bad == "envelope":
        case = {"case": case, "local_refs": {"private": "synthetic-local-only"}}
    elif bad == "extra_private":
        case["private"] = "synthetic-local-only"
    elif bad == "model_instance":
        case = joint.Dossier.model_construct(**case)
    else:
        case["dossier_version"] = 3
    with pytest.raises(ValueError, match="invalid_joint_dossier"):
        adapter.request(profile(), case)


def test_request_limit_applies_before_any_http_or_reservation():
    with pytest.raises(ValueError, match="joint_api_request_too_large"):
        adapter.request(changed(profile(), max_input_tokens=8192), scenarios()[0]["case"])


@pytest.mark.parametrize("kind", ["ssh", "joint"])
def test_adapter_requires_shared_joint_ledger(tmp_path, kind):
    queue = Jobs(tmp_path / "plain.sqlite", queue_kind=kind)
    with pytest.raises(ValueError, match="joint_api_shared_ledger_required"):
        adapter.JointAPITriage(profile(), "synthetic-key", ledger=Ledger(queue, {}))
    assert calls(queue) == []


def test_missing_key_rejects_new_call_without_reservation(tmp_path):
    w = make_world(tmp_path)
    api = adapter.JointAPITriage(w.config, None, ledger=Ledger(w.queue, w.job))
    with pytest.raises(ValueError, match="joint_api_key_required"):
        api.triage(w.case)
    assert calls(w.owner) == []


def test_paid_receipt_recovers_without_key_after_profile_and_validator_change(tmp_path, monkeypatch):
    w = make_world(tmp_path)
    api, requests = client(w)
    first = api.triage(w.case)
    monkeypatch.setattr(joint, "VALIDATOR_VERSION", "synthetic-new-validator")
    original = joint.validate
    seen = []
    def checked(text, case):
        seen.append(text)
        return original(text, case)
    monkeypatch.setattr(joint, "validate", checked)
    replay = adapter.JointAPITriage(changed(w.config, max_output_tokens=1024), None,
                                   ledger=Ledger(w.queue, w.job))
    result = replay.triage(w.case)
    assert result["verdict"] == first["verdict"] and len(requests) == 1
    assert result["metadata"]["evidence_validation"]["validator_version"] == "synthetic-new-validator"
    assert result["metadata"]["additional_usd"] == 0 and seen == [w.scenario["fake_response"]]


def test_unpaid_changed_protocol_never_reserves_or_sends(tmp_path, monkeypatch):
    w = make_world(tmp_path)
    api, requests = client(w)
    monkeypatch.setattr(joint, "VALIDATOR_VERSION", "synthetic-new-validator")
    with pytest.raises(ValueError, match="joint_api_request_changed"):
        api.triage(w.case)
    assert not requests and calls(w.owner) == []


@pytest.mark.parametrize("field", ["incident_id", "request_sha", "config_sha", "dossier_json", "run_id", "call_id"])
def test_caller_cannot_forge_persisted_job_binding(tmp_path, field):
    w = make_world(tmp_path)
    forged = {**w.job, field: "synthetic-forged-binding"}
    api, requests = client(w, job=forged)
    with pytest.raises(ValueError, match="joint_api_job_mismatch"):
        api.triage(w.case)
    assert not requests and calls(w.owner) == []


@pytest.mark.parametrize("raw", [
    '{"model":"synthetic-model","model":"synthetic-model","usage":{"input_tokens":100,"output_tokens":20}}',
    '{"model":"synthetic-model","usage":{"input_tokens":100,"input_tokens":0,"output_tokens":20}}',
    '{"model":"synthetic-model","usage":{"input_tokens":100,"output_tokens":20},"extra":NaN}',
    '{"model":"synthetic-model","usage":{"input_tokens":100,"output_tokens":20},"extra":Infinity}',
    '{"model":"synthetic-model","usage":{"input_tokens":100,"output_tokens":20},"extra":{"value":1e999}}',
    '{"model":"synthetic-model","usage":{"input_tokens":1e999,"output_tokens":20}}',
])
def test_ambiguous_http_json_keeps_reservation_and_cannot_be_retried(tmp_path, raw):
    w = make_world(tmp_path)
    api, requests = client(w, handler=lambda req: httpx.Response(200, content=raw.encode()))
    with pytest.raises(APIError, match="transport_or_json_error"):
        api.triage(w.case)
    assert calls(w.owner)[0]["charged"] is None
    with pytest.raises(CallUncertain):
        api.triage(w.case)
    assert len(requests) == 1 and w.owner.budget()["unresolved_calls"] == 1


@pytest.mark.parametrize("text", ["\ud800", "x" * (joint.MAX_RESPONSE_BYTES + 1)])
def test_bad_unicode_or_oversized_advice_does_not_lose_known_charge(tmp_path, text):
    w = make_world(tmp_path)
    raw = json.dumps(payload(w.config, text), ensure_ascii=True).encode()
    api, requests = client(w, handler=lambda req: httpx.Response(200, content=raw))
    result = api.triage(w.case)
    assert result["verdict"] == "abstain" and result["usd"] == 0.00016
    assert calls(w.owner)[0]["charged"] == 160
    receipt = json.loads(calls(w.owner)[0]["record"])
    assert receipt["response_json"].isascii()
    assert api.triage(w.case)["verdict"] == "abstain" and len(requests) == 1


@pytest.mark.parametrize("field", ["request_sha256", "case_sha256", "request_body_sha256", "call_id", "charged_micro_usd", "usage"])
def test_corrupt_paid_receipt_never_triggers_network_or_new_reservation(tmp_path, field):
    w = make_world(tmp_path)
    api, requests = client(w)
    api.triage(w.case)
    receipt = json.loads(calls(w.owner)[0]["record"])
    receipt[field] = 999 if field == "charged_micro_usd" else {} if field == "usage" else "0" * 64
    with w.owner.connection(write=True) as db:
        db.execute("UPDATE ai_calls SET record=?", (json.dumps(receipt),))
    with pytest.raises(ValueError, match="invalid_joint_api_receipt"):
        api.triage(w.case)
    assert len(requests) == 1 and len(calls(w.owner)) == 1


def test_receipt_charge_must_equal_shared_ledger_charge(tmp_path):
    w = make_world(tmp_path)
    api, requests = client(w)
    api.triage(w.case)
    with w.owner.connection(write=True) as db:
        db.execute("UPDATE ai_calls SET charged=161")
    with pytest.raises(ValueError, match="invalid_joint_api_receipt"):
        api.triage(w.case)
    assert len(requests) == 1


def test_explicit_endpoint_ignores_environment_and_redirects(tmp_path, monkeypatch):
    w = make_world(tmp_path)
    monkeypatch.setenv("HTTPS_PROXY", "https://proxy.example.invalid")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://other.example.invalid")
    api, requests = client(w, handler=lambda req: httpx.Response(302, headers={"Location": "https://redirect.example.invalid"}))
    with pytest.raises(APIError, match="http_302"):
        api.triage(w.case)
    assert len(requests) == 1 and str(requests[0].url) == w.config.endpoint
    assert calls(w.owner)[0]["charged"] is None
