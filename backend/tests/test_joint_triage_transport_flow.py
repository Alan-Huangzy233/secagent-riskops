"""Synthetic HTTP/queue/accounting flows; no service enablement or live calls.

The harness explicitly finishes jobs. It is not production worker wiring and
does not qualify a provider's accuracy or permit outbound production evidence.
"""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import json
import socket
from threading import Event
from types import SimpleNamespace

import httpx
import pytest

from app.agents import joint_triage as joint
from app.agents import joint_triage_api as adapter
from app.agents.model_triage import BudgetExceeded
from app.agents.triage_api import APIConfig, APIError
from app.agents.triage_budget import CallUncertain
from app.evaluation.joint_ai_scenarios import scenarios
from app.telemetry.ai_jobs import Jobs, Ledger


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("only in-memory synthetic HTTP is allowed")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)


def profile(api_format="openai-responses"):
    return APIConfig.model_validate({
        "provider": "synthetic", "api_format": api_format,
        "endpoint": "https://model.example.invalid/v1/triage", "model": "synthetic-model",
        "key_name": "SYNTHETIC_KEY", "effort": "low", "max_output_tokens": 512,
        "prices": {"as_of": "2026-01-01", "input": "1", "output": "3",
                   "cache_read": "0.5", "cache_write": "1"},
    })


def payload(config, text, *, inputs=100, outputs=20):
    if config.api_format == "openai-responses":
        return {"model": config.model, "status": "completed", "service_tier": "default",
                "usage": {"input_tokens": inputs, "output_tokens": outputs},
                "output": [{"type": "message", "content": [{"type": "output_text", "text": text}]}]}
    return {"model": config.model, "usage": {"prompt_tokens": inputs, "completion_tokens": outputs},
            "choices": [{"finish_reason": "stop", "message": {"content": text}}]}


def make_world(tmp_path, scenario=None, config=None, *, total=1_000_000):
    scenario = deepcopy(scenario or scenarios()[0])
    config = config or profile()
    tick = SimpleNamespace(value=1_770_000_000.0)
    owner = Jobs(tmp_path / "owner.sqlite", clock=lambda: tick.value)
    owner.set_budget(total, total)
    queue = Jobs(tmp_path / "joint.sqlite", queue_kind="joint", budget_owner=owner,
                 clock=lambda: tick.value)
    case = scenario["case"]
    local_id = "JOINT-" + hashlib.sha256(scenario["id"].encode()).hexdigest()[:32]
    bundle = {"case": case, "meta": {"case_revision": 1, "private_note": "synthetic-local-only-note"},
              "local_refs": {"synthetic-reference": "synthetic-local-only-reference"}}
    jid = queue.enqueue(local_id, bundle, "synthetic-settings", adapter.fingerprint(config, case),
                        "synthetic-operator")
    job = queue.claim()
    assert job["id"] == jid
    return SimpleNamespace(owner=owner, queue=queue, tick=tick, case=case, job=job, config=config,
                           scenario=scenario, local_id=local_id)


def client(w, handler=None, job=None):
    requests = []
    def send(request):
        requests.append(request)
        if handler is not None:
            return handler(request)
        return httpx.Response(200, json=payload(w.config, w.scenario["fake_response"]))
    api = adapter.JointAPITriage(w.config, "synthetic-key", ledger=Ledger(w.queue, job or w.job),
                                transport=httpx.MockTransport(send))
    return api, requests


def calls(jobs):
    with jobs.connection() as db:
        return [dict(row) for row in db.execute("SELECT * FROM ai_calls")]


@pytest.mark.parametrize("api_format", ["openai-responses", "openai-chat"])
@pytest.mark.parametrize("scenario", scenarios(), ids=lambda row: row["id"])
def test_authored_corpus_through_http_and_shared_receipts(tmp_path, api_format, scenario):
    w = make_world(tmp_path, scenario, profile(api_format))
    api, requests = client(w)
    record = api.triage(w.case)
    assert record["verdict"] == scenario["expected_accepted"]
    validation = record["metadata"]["evidence_validation"]
    assert validation["status"] == scenario["expected_status"]
    assert [reason["code"] for reason in validation["reasons"]] == scenario["expected_reason_codes"]
    assert record["usd"] == 0.00016
    w.queue.finish(w.job, "review" if record["verdict"] == "abstain" else "complete", record=record)
    assert w.queue.get(w.job["id"])["result"] == record
    assert len(requests) == 1 and len(calls(w.owner)) == 1 and calls(w.queue) == []
    assert calls(w.owner)[0]["charged"] == 160
    stored = calls(w.owner)[0]["record"]
    assert "synthetic-key" not in stored and "synthetic-local-only" not in stored
    assert w.queue.budget() == w.owner.budget()
    sent = requests[0].content.decode()
    body = json.loads(sent)
    messages = body["input"] if api_format == "openai-responses" else body["messages"]
    assert json.loads(messages[-1]["content"].split("\n", 1)[1]) == w.case
    assert w.local_id not in sent
    assert "synthetic-local-only" not in sent and "synthetic-operator" not in sent
    assert "expected_verdict" not in sent and "fake_response" not in sent
    assert w.case["case_id"] in sent
    # Re-reading a complete reservation returns its checked receipt, not a send.
    assert api.triage(w.case)["verdict"] == record["verdict"]
    assert len(requests) == 1 and len(calls(w.owner)) == 1


def test_receipt_survives_validator_crash_and_restart_without_another_request(tmp_path, monkeypatch):
    w = make_world(tmp_path)
    api, requests = client(w)
    original = joint.validate
    def crash(*args, **kwargs):
        raise RuntimeError("synthetic interruption after billing")
    monkeypatch.setattr(joint, "validate", crash)
    with pytest.raises(Exception):
        api.triage(w.case)
    assert len(requests) == 1 and calls(w.owner)[0]["charged"] == 160
    assert calls(w.queue) == []
    w.tick.value += 301
    restored = Jobs(w.queue.path, queue_kind="joint", budget_owner=w.owner, clock=lambda: w.tick.value)
    recovered = restored.claim()
    assert recovered["call_id"] == w.job["call_id"]
    assert recovered["attempt_count"] == w.job["attempt_count"] == 1
    monkeypatch.setattr(joint, "validate", original)
    w.queue = restored
    replay, requests_after_restart = client(w, job=recovered)
    record = replay.triage(w.case)
    restored.finish(recovered, "complete", record=record)
    assert record["verdict"] == "escalate" and requests_after_restart == []
    assert len(calls(w.owner)) == 1 and restored.get(w.job["id"])["state"] == "complete"


@pytest.mark.parametrize("failure", ["timeout", "missing_usage", "unpriced_model", "redirect"])
def test_unknown_financial_outcome_retains_reservation_and_cannot_resend(tmp_path, failure):
    w = make_world(tmp_path)
    def fail(request):
        if failure == "timeout":
            raise httpx.ReadTimeout("synthetic remote content must not escape", request=request)
        if failure == "redirect":
            return httpx.Response(302, headers={"Location": "https://elsewhere.example.invalid"})
        response = payload(w.config, w.scenario["fake_response"])
        if failure == "missing_usage":
            response.pop("usage")
        else:
            response["model"] = "unpriced-model"
        return httpx.Response(200, json=response)
    api, requests = client(w, fail)
    with pytest.raises(APIError) as error:
        api.triage(w.case)
    assert "remote content" not in str(error.value)
    w.queue.retry_unsubmitted(w.job)
    assert w.queue.get(w.job["id"])["state"] == "uncertain"
    receipt = calls(w.owner)[0]
    assert receipt["charged"] is None and receipt["reserved"] == w.config.reservation()
    with pytest.raises(CallUncertain):
        api.triage(w.case)
    w.tick.value += 301
    assert w.queue.claim() is None and len(requests) == 1
    assert w.owner.budget()["reserved_usd"] == w.config.reservation() / 1_000_000


def test_known_charge_survives_malformed_proposal_envelope(tmp_path):
    w = make_world(tmp_path)
    response = payload(w.config, "unused")
    response["output"] = None
    api, requests = client(w, lambda _: httpx.Response(200, json=response))
    record = api.triage(w.case)
    assert record["verdict"] == "abstain" and record["usd"] == 0.00016
    assert calls(w.owner)[0]["charged"] == 160 and len(requests) == 1
    assert record["metadata"]["evidence_validation"]["status"] == "requires_review"


def test_paid_receipt_is_revalidated_instead_of_trusting_stored_verdict(tmp_path, monkeypatch):
    w = make_world(tmp_path)
    api, requests = client(w)
    assert api.triage(w.case)["verdict"] == "escalate"
    original = joint.validate
    observed = []
    def checked(text, case):
        observed.append(text)
        verdict, details = original(text, case)
        return {**verdict, "verdict": "abstain"}, details
    monkeypatch.setattr(joint, "validate", checked)
    assert api.triage(w.case)["verdict"] == "abstain"
    assert observed == [w.scenario["fake_response"]] and len(requests) == 1


def test_prior_ssh_commitment_blocks_joint_send_without_a_second_pool(tmp_path):
    config = profile()
    w = make_world(tmp_path, config=config, total=config.reservation())
    bundle = {"case": {"revision": "synthetic", "incident_id": "ssh"}, "meta": {}, "local_refs": {}}
    w.owner.enqueue("ssh", bundle, "synthetic-settings", "synthetic-ssh-request", "operator")
    ssh = w.owner.claim()
    Ledger(w.owner, ssh).reserve(ssh["call_id"], 1)
    api, requests = client(w)
    with pytest.raises(BudgetExceeded):
        api.triage(w.case)
    assert requests == [] and len(calls(w.owner)) == 1 and calls(w.queue) == []


def test_over_reservation_actual_usage_halts_both_queues(tmp_path):
    w = make_world(tmp_path)
    api, _ = client(w, lambda _: httpx.Response(200, json=payload(
        w.config, w.scenario["fake_response"], inputs=w.config.max_input_tokens * 2)))
    api.triage(w.case)
    assert calls(w.owner)[0]["charged"] > w.config.reservation()
    assert w.queue.budget()["halted"] and w.owner.budget()["halted"]


def test_concurrent_invocation_of_one_claim_makes_at_most_one_request(tmp_path):
    w = make_world(tmp_path)
    entered, release = Event(), Event()
    def send(_):
        entered.set()
        assert release.wait(5)
        return httpx.Response(200, json=payload(w.config, w.scenario["fake_response"]))
    first, requests = client(w, send)
    second, second_requests = client(w)
    with ThreadPoolExecutor(2) as pool:
        work = pool.submit(first.triage, deepcopy(w.case))
        try:
            assert entered.wait(5)
            with pytest.raises(CallUncertain):
                second.triage(w.case)
        finally:
            release.set()
        assert work.result(timeout=5)["verdict"] == "escalate"
    assert len(requests) == 1 and second_requests == [] and len(calls(w.owner)) == 1
