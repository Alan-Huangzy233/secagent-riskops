"""API contracts, paid-call failure handling, shared budgets and replay isolation.

All network responses are synthetic MockTransport fixtures. No keys or paid
requests are used, including in the CLI integration tests.
"""
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
import json
from pathlib import Path
from threading import Barrier

import httpx
import pytest
from pydantic import ValidationError

from app.agents import model_triage
from app.agents.triage_api import APIConfig, APIError, APITriage, normalize, read_key, validate_verdict
from app.agents.triage_budget import BudgetLedger, CallUncertain
from app.evaluation import synthetic, triage

ROOT = Path(__file__).resolve().parents[2]
CASE = {"incident_id": "INC-TEST", "successful_logins": [],
        "record_sample": [{"event_id": "E1", "account": "synthetic-user"}]}
VERDICT = {"verdict": "escalate", "confidence": "high", "rationale": "The sampled record warrants review.",
           "evidence_ids": ["E1"], "attack_techniques": []}


def profile(name="openai-luna-low"):
    return APIConfig.load(ROOT / "examples" / "model-triage" / f"{name}.json")


def changed(config, **updates):
    return APIConfig.model_validate({**config.model_dump(), **updates})


def response(config, verdict=None, **overrides):
    text = json.dumps(VERDICT if verdict is None else verdict)
    if config.api_format == "openai-responses":
        value = {"model": config.model, "status": "completed",
                 "output": [{"type": "message", "content": [{"type": "output_text", "text": text}]}],
                 "usage": {"input_tokens": 1000, "output_tokens": 500,
                           "input_tokens_details": {"cached_tokens": 200},
                           "output_tokens_details": {"reasoning_tokens": 100}}}
    else:
        value = {"model": config.model, "choices": [{"finish_reason": "stop", "message": {"content": text}}],
                 "usage": {"prompt_tokens": 1000, "completion_tokens": 500,
                           "prompt_tokens_details": {"cached_tokens": 200}}}
    return {**value, **overrides}


def client(tmp_path, config=None, handler=None, *, tape="calls.jsonl", budget="10", ledger_name="budget.sqlite3"):
    config = config or profile()
    requests = []

    def send(request):
        requests.append(request)
        return handler(request) if handler else httpx.Response(200, json=response(config))

    live = APITriage(config, "test-key-do-not-persist", ledger=BudgetLedger(tmp_path / ledger_name, budget),
                     tape=tmp_path / tape, transport=httpx.MockTransport(send))
    return live, requests


@pytest.fixture(scope="module")
def dataset(tmp_path_factory):
    path = tmp_path_factory.mktemp("synthetic-day")
    synthetic.write(synthetic.Config(days=1), path)
    return path


@pytest.mark.parametrize("name", ["openai-luna-low", "deepseek-flash", "deepseek-flash-low", "zai-glm-flash-low"])
def test_official_profiles_send_their_exact_protocol_and_never_an_environment_endpoint(tmp_path, monkeypatch, name):
    config = profile(name)
    monkeypatch.setenv("OPENAI_BASE_URL", "https://unrelated.example.invalid")
    monkeypatch.setenv("HTTPS_PROXY", "https://unrelated.example.invalid")
    live, requests = client(tmp_path, config)
    call = live.triage(CASE)
    assert str(requests[0].url) == config.endpoint
    assert requests[0].headers["Authorization"] == "Bearer test-key-do-not-persist"
    body = json.loads(requests[0].content)
    assert body["model"] == config.model
    if config.api_format == "openai-responses":
        assert body["store"] is False and body["reasoning"] == {"effort": "low"}
        assert body["service_tier"] == "default"
        assert body["text"]["format"]["strict"] is True
        assert body["text"]["format"]["schema"] == model_triage.SCHEMA
        assert body["max_output_tokens"] == 8192
        user = body["input"][-1]["content"]
    else:
        assert body["response_format"] == {"type": "json_object"}
        assert body["thinking"] == {"type": config.thinking}
        assert body.get("reasoning_effort") == config.effort
        assert body["max_tokens"] == 8192
        user = body["messages"][-1]["content"]
    assert json.loads(user.split("\n", 1)[1]) == CASE
    assert not ({"fallbacks", "tools", "temperature"} & body.keys())
    assert call.metadata["validation"] == "valid"
    assert call.metadata["config"]["provider"] == config.provider
    assert call.input_tokens == 800 and call.cache_read_input_tokens == 200
    assert call.output_tokens == 500
    assert "test-key-do-not-persist" not in json.dumps(call.to_record())
    assert "test-key-do-not-persist" not in (tmp_path / "budget.sqlite3").read_bytes().decode(errors="ignore")


def test_custom_chat_endpoint_and_model_require_only_a_new_configuration(tmp_path):
    config = changed(profile("deepseek-flash"), provider="compatible", model="another-model",
                     endpoint="https://gateway.example.invalid/v1/chat/completions", thinking=None)
    live, requests = client(tmp_path, config)
    assert live.triage(CASE).model == "another-model"
    assert str(requests[0].url) == config.endpoint
    assert "thinking" not in json.loads(requests[0].content)


def test_cache_usage_and_reasoning_are_not_double_billed(tmp_path):
    config = profile()
    live, _ = client(tmp_path, config)
    call = live.triage(CASE)
    assert call.usd == 0.000332
    assert call.metadata["reasoning_tokens"] == 100
    assert live.ledger.summary()["charged_usd"] == call.usd
    ds = profile("deepseek-flash")
    payload = response(ds, usage={"prompt_tokens": 1000, "completion_tokens": 500, "prompt_cache_hit_tokens": 300})
    assert normalize(ds, payload)[3]["input_tokens"] == 700


@pytest.mark.parametrize("update,reason", [
    ({"verdict": "execute"}, "invalid_schema"),
    ({"evidence_ids": ["invented-record"]}, "unknown_evidence"),
    ({"evidence_ids": []}, "missing_evidence"),
    ({"confidence": None}, "invalid_schema"),
    ({"rationale": ""}, "invalid_schema"),
    ({"attack_techniques": "T1110"}, "invalid_schema"),
    ({"extra": "unexpected"}, "invalid_schema"),
])
def test_invalid_results_become_abstentions_and_retain_their_cost(tmp_path, update, reason):
    config = profile()
    live, _ = client(tmp_path, config, lambda _: httpx.Response(200, json=response(config, {**VERDICT, **update})))
    call = live.triage(CASE)
    assert call.verdict == "abstain" and not call.evidence_ids
    assert call.metadata["validation"] == reason and call.usd > 0


@pytest.mark.parametrize("text", ["no JSON", "[]", "null", '{"verdict":'])
def test_unparseable_or_incomplete_json_is_safe(text):
    assert validate_verdict(text, CASE)[0]["verdict"] == "abstain"


@pytest.mark.parametrize("name,override", [
    ("openai-luna-low", {"status": "incomplete"}),
    ("deepseek-flash", {"choices": [{"finish_reason": "length", "message": {"content": json.dumps(VERDICT)}}]}),
    ("zai-glm-flash-low", {"choices": [{"finish_reason": "sensitive", "message": {"content": None}}]}),
    ("openai-luna-low", {"output": [{"type": "message", "content": [{"type": "refusal", "refusal": "no"}]}]}),
])
def test_refusals_and_truncation_never_accept_partial_verdicts(tmp_path, name, override):
    config = profile(name)
    live, _ = client(tmp_path, config, lambda _: httpx.Response(200, json=response(config, **override)))
    call = live.triage(CASE)
    assert call.verdict == "abstain" and call.usd > 0


@pytest.mark.parametrize("kind", ["429", "503", "redirect", "timeout", "json", "usage", "negative", "other-model"])
def test_uncertain_calls_keep_reservations_and_are_never_automatically_retried(tmp_path, kind):
    config = profile()

    def send(request):
        if kind in ("429", "503"):
            return httpx.Response(int(kind), text="test-key-do-not-persist remote body")
        if kind == "redirect":
            return httpx.Response(307, headers={"Location": "https://different.example.invalid"})
        if kind == "timeout":
            raise httpx.ReadTimeout("test-key-do-not-persist", request=request)
        if kind == "json":
            return httpx.Response(200, text="test-key-do-not-persist invalid JSON")
        if kind == "usage":
            return httpx.Response(200, json=response(config, usage={}))
        if kind == "negative":
            return httpx.Response(200, json=response(config, usage={"input_tokens": -1, "output_tokens": 1}))
        return httpx.Response(200, json=response(config, model="unpriced-model"))

    live, requests = client(tmp_path, config, send)
    with pytest.raises(APIError) as error:
        live.triage(CASE)
    assert "test-key" not in str(error.value) and "remote body" not in str(error.value)
    assert len(requests) == 1
    summary = live.ledger.summary()
    assert summary["reserved_usd"] == config.reservation() / 1_000_000
    assert summary["charged_usd"] == 0 and summary["unresolved_calls"] == 1
    restarted, retried = client(tmp_path, config)
    with pytest.raises(CallUncertain):
        restarted.triage(CASE)
    assert not retried


def test_a_completed_call_is_recovered_after_a_crash_before_tape_append(tmp_path):
    first, requests = client(tmp_path)
    call = first.triage(CASE)
    assert len(requests) == 1
    assert not (tmp_path / "calls.jsonl").exists()
    restarted, requests = client(tmp_path)
    assert restarted.triage(CASE) == call
    assert not requests and restarted.ledger.summary()["attempts"] == 1


def test_switching_api_or_restarting_cannot_reset_the_shared_budget(tmp_path):
    config = profile()
    budget = str(Decimal(config.reservation()) / 1_000_000)
    first, _ = client(tmp_path, config, budget=budget)
    first.triage(CASE)
    second, requests = client(tmp_path, changed(config, provider="another"), budget=budget)
    with pytest.raises(model_triage.BudgetExceeded):
        second.triage(CASE)
    assert not requests and second.ledger.summary()["attempts"] == 1
    with pytest.raises(ValueError, match="original ceiling"):
        BudgetLedger(tmp_path / "budget.sqlite3", "10")


def test_independent_repeat_uses_a_new_tape_and_the_same_budget(tmp_path):
    first, _ = client(tmp_path)
    second, requests = client(tmp_path, tape="repeat.jsonl")
    first.triage(CASE)
    second.triage(CASE)
    assert len(requests) == 1 and second.ledger.summary()["attempts"] == 2


def test_concurrent_reservations_cannot_oversubscribe_the_budget(tmp_path):
    path = tmp_path / "shared.sqlite3"
    ledgers = [BudgetLedger(path, "1") for _ in range(4)]
    barrier = Barrier(4)

    def attempt(n):
        barrier.wait()
        try:
            ledgers[n].reserve(str(n), 700000)
            return True
        except model_triage.BudgetExceeded:
            return False

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(attempt, range(4))) == 1
    assert ledgers[0].summary()["reserved_usd"] == .7


def test_a_process_crash_keeps_pending_reservations_and_usage_overrun_halts_spending(tmp_path):
    path = tmp_path / "ledger.sqlite3"
    ledger = BudgetLedger(path, "1")
    ledger.reserve("crashed", 600000)
    restarted = BudgetLedger(path, "1")
    with pytest.raises(CallUncertain):
        restarted.reserve("crashed", 600000)
    with pytest.raises(model_triage.BudgetExceeded):
        restarted.reserve("next", 600000)
    restarted.reserve("overrun", 100000)
    restarted.complete("overrun", 200000, {"result": "example"})
    assert restarted.summary()["halted"]
    with pytest.raises(model_triage.BudgetExceeded):
        restarted.reserve("later", 1)


@pytest.mark.parametrize("update", [
    {"endpoint": "http://unsafe.example.invalid/v1"},
    {"endpoint": "https://key:secret@example.com/v1"},
    {"endpoint": "https://example.invalid/v1?api_key=secret"},
    {"max_output_tokens": True}, {"max_input_tokens": -1},
    {"thinking": "enabled"}, {"prices": {"input": "NaN"}},
    {"fallbacks": "default"}, {"api_format": "anthropic-messages"},
])
def test_unsupported_or_unsafe_configuration_is_rejected(update):
    with pytest.raises(ValidationError):
        changed(profile(), **update)


@pytest.mark.parametrize("update", [
    {"provider": "another"}, {"model": "another-model"}, {"effort": "medium"},
    {"endpoint": "https://other.example.invalid/v1/responses"}, {"max_output_tokens": 4096},
])
def test_recording_identity_includes_the_actual_request_and_destination(update):
    config = profile()
    assert config.fingerprint(CASE) != changed(config, **update).fingerprint(CASE)
    assert config.fingerprint(CASE) != model_triage.fingerprint(CASE)


def test_key_files_are_private_and_errors_do_not_echo_values(tmp_path):
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({"OPENAI_API_KEY": "REPLACE_ME"}))
    path.chmod(0o600)
    assert read_key(path, "OPENAI_API_KEY") == "REPLACE_ME"
    path.chmod(0o644)
    with pytest.raises(ValueError) as error:
        read_key(path, "OPENAI_API_KEY")
    assert "REPLACE_ME" not in str(error.value)


def test_request_size_is_bounded_before_any_reservation_or_network(tmp_path):
    live, requests = client(tmp_path)
    with pytest.raises(ValueError, match="byte limit"):
        live.triage({**CASE, "untrusted": "x" * 100000})
    assert not requests and live.ledger.summary()["attempts"] == 0


def test_new_recordings_replay_only_with_the_matching_configuration(tmp_path, dataset):
    config = profile()

    def send(request):
        case = json.loads(json.loads(request.content)["input"][-1]["content"].split("\n", 1)[1])
        verdict = {**VERDICT, "evidence_ids": [case["record_sample"][0]["event_id"]]}
        return httpx.Response(200, json=response(config, verdict))

    tape = tmp_path / "calls.jsonl"
    live, requests = client(tmp_path, config, send)
    first = triage.evaluate(dataset, tape, live=live, limit=3)
    assert first["judged"] == len(requests) == 3
    assert first == triage.evaluate(dataset, tape, config=config, limit=3)
    assert triage.evaluate(dataset, tape, config=changed(config, effort="high"), limit=3)["judged"] == 0
    assert triage.evaluate(dataset, tape, limit=3)["judged"] == 0
    triage.evaluate(dataset, tape, live=live, limit=3)
    assert len(requests) == 3


@pytest.mark.parametrize("kind", ["modified", "alternate"])
def test_live_input_cannot_be_replaced_by_production_logs_or_a_self_declared_manifest(tmp_path, dataset, kind):
    data = tmp_path / "dataset"
    data.mkdir()
    for name in ("events.jsonl", "labels.jsonl", "episodes.json", "manifest.json"):
        (data / name).write_bytes((dataset / name).read_bytes())
    if kind == "alternate":
        (data / "records.jsonl").write_text('{"production": true}\n')
    else:
        with (data / "events.jsonl").open("a") as handle:
            handle.write('{"production": true}\n')
        # Even a caller-edited manifest is not trusted.
        (data / "manifest.json").write_text('{"synthetic": true}')
    live, requests = client(tmp_path)
    with pytest.raises(ValueError):
        triage.evaluate(data, tmp_path / "calls.jsonl", live=live, limit=1)
    assert not requests and live.ledger.summary()["attempts"] == 0


def test_budget_and_api_failures_are_reported_as_unjudged_cases(tmp_path, dataset):
    live, requests = client(tmp_path, handler=lambda _: httpx.Response(429), budget=".000001")
    result = triage.evaluate(dataset, tmp_path / "calls.jsonl", live=live, limit=3)
    assert result["stopped_by_budget"] and result["judged"] == 0
    assert len(result["not_judged"]) == 3 and not requests
    live, requests = client(tmp_path, handler=lambda _: httpx.Response(429),
                            tape="error.jsonl", ledger_name="error-budget.sqlite3")
    result = triage.evaluate(dataset, tmp_path / "error.jsonl", live=live, limit=3)
    assert result["stopped_by_api"] == "http_429" and result["judged"] == 0 and len(requests) == 1


def test_cli_uses_explicit_profile_keys_and_shared_ledger_without_a_paid_connection(tmp_path, dataset, monkeypatch):
    monkeypatch.setattr(APITriage, "_send", lambda self, body: response(self.config, {**VERDICT, "verdict": "abstain",
                                                                                  "evidence_ids": []}))
    keys = tmp_path / "keys.json"
    keys.write_text('{"OPENAI_API_KEY": "REPLACE_ME"}')
    keys.chmod(0o600)
    args = ["--data", str(dataset), "--tape", str(tmp_path / "calls.jsonl"), "--out", str(tmp_path / "report.json"),
            "--config", str(ROOT / "examples/model-triage/openai-luna-low.json"), "--limit", "1"]
    assert triage.main(args + ["--live", "--keys-file", str(keys), "--ledger", str(tmp_path / "budget.sqlite3"),
                              "--budget-usd", "10"]) == 0
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["configuration"]["provider"] == "openai"
    assert report["shared_budget"]["attempts"] == 1
    assert "REPLACE_ME" not in (tmp_path / "report.json").read_text()
    assert triage.main(args) == 0


def test_legacy_tapes_keep_their_original_shape():
    tape = ROOT / "docs/eval/triage-tape-synthetic-7d.jsonl"
    original = json.loads(tape.read_text().splitlines()[0])
    assert model_triage.TriageCall.from_record(original).to_record() == original


@pytest.mark.parametrize("served", ["gpt-6-luna-2026-10-01", "gpt-6-luna-20261001"])
def test_dated_model_snapshots_use_the_requested_rate_card(served):
    config = profile()
    assert normalize(config, response(config, model=served))[0] == served


def test_a_similarly_named_but_different_model_has_no_implicit_price():
    config = profile()
    with pytest.raises(APIError, match="unpriced_served_model"):
        normalize(config, response(config, model="gpt-6-luna-expensive"))


def test_cli_rejects_colliding_output_and_key_paths_before_reading_secrets(tmp_path):
    private = tmp_path / "private.json"
    private.write_text("untouched")
    args = ["--data", str(tmp_path), "--tape", str(tmp_path / "calls.jsonl"),
            "--out", str(private), "--keys-file", str(private), "--live",
            "--config", str(ROOT / "examples/model-triage/openai-luna-low.json"),
            "--ledger", str(tmp_path / "budget.sqlite3"), "--budget-usd", "10"]
    with pytest.raises(SystemExit) as error:
        triage.main(args)
    assert error.value.code == 2 and private.read_text() == "untouched"

def test_openai_cache_writes_are_separate_from_ordinary_and_cached_input(tmp_path):
    config = profile()
    payload = response(config)
    payload["usage"]["input_tokens_details"]["cache_write_tokens"] = 300
    live, _ = client(tmp_path, config, lambda _: httpx.Response(200, json=payload))
    call = live.triage(CASE)
    assert (call.input_tokens, call.cache_read_input_tokens, call.cache_creation_input_tokens) == (500, 200, 300)
    assert call.usd == 0.000340


def test_unexpected_processing_tier_has_no_implicit_standard_price(tmp_path):
    config = profile()
    live, requests = client(tmp_path, config, lambda _: httpx.Response(
        200, json=response(config, service_tier="priority")))
    with pytest.raises(APIError, match="unpriced_service_tier"):
        live.triage(CASE)
    assert len(requests) == 1 and live.ledger.summary()["unresolved_calls"] == 1


def test_fractional_microdollar_budget_is_not_rounded_above_the_requested_ceiling(tmp_path):
    ledger = BudgetLedger(tmp_path / "tiny.sqlite3", "0.0000019")
    with pytest.raises(model_triage.BudgetExceeded):
        ledger.reserve("too-much", 2)
    assert ledger.summary()["budget_usd"] == 0.000001
