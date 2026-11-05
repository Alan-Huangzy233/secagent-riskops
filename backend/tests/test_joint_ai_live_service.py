"""Manual live-mode wiring over temporary stores and synthetic HTTP only."""
import hashlib
import json
import os
import socket
from types import SimpleNamespace

import httpx
import pytest

from app.agents import joint_triage, joint_triage_api
from app.telemetry import joint_ai_service as service_module
from app.telemetry.ai_jobs import Jobs, Ledger
from app.telemetry.ai_triage import Service as SSHService, Settings as SSHSettings
from app.telemetry.joint_ai_service import Service, Settings
from test_joint_ai_service import (
    AT, saved as saved, scheduled as scheduled, configured as configured, sources as sources,
    store_clock as store_clock, change_checkpoint, fake_result,
)
from test_joint_triage_transport_flow import profile, payload


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("only synthetic in-memory HTTP is allowed")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)


def ssh_service(path, telemetry, tick, *, config=None, total="1", daily="1"):
    config = config or profile()
    profile_path, keys_path = path / "profile.json", path / "keys.json"
    profile_path.write_text(config.model_dump_json())
    keys_path.write_text(json.dumps({config.key_name: "synthetic-not-a-real-key"}))
    keys_path.chmod(0o600)
    settings = SSHSettings(mode="api", database_path=path / "ssh-jobs.sqlite",
        profile_path=profile_path, keys_file=keys_path, allow_external=True, approved_summary_version=1,
        total_budget_usd=total, daily_budget_usd=daily)
    return SSHService(telemetry, settings, clock=lambda: tick.value)


@pytest.fixture
def world(saved, tmp_path):
    spec, case_id, _ = saved
    tick = SimpleNamespace(value=AT.timestamp())
    ssh = ssh_service(tmp_path, SimpleNamespace(path=spec.ssh_database_path), tick)
    settings = Settings(mode="api", database_path=tmp_path / "joint-api.sqlite", allow_external=True,
                        approved_summary_version="joint-summary-v1")
    w = SimpleNamespace(spec=spec, case_id=case_id, tick=tick, ssh=ssh, settings=settings,
                        requests=[], response=None, before_response=None)
    def send(request):
        w.requests.append(request)
        data = json.loads(request.content)
        text = data["input"][1]["content"] if "input" in data else data["messages"][1]["content"]
        case = json.loads(text.split("\n", 1)[1])
        if w.before_response:
            w.before_response()
        return w.response or httpx.Response(200, json=payload(w.ssh.profile, fake_result(case)))
    w.transport = httpx.MockTransport(send)
    w.service = reopen(w)
    return w


def reopen(w, **changes):
    settings = Settings.model_validate({**w.settings.model_dump(), **changes})
    return Service(w.spec, settings, ssh_service=w.ssh, transport=w.transport, clock=lambda: w.tick.value)


def enqueue(w):
    preview = w.service.preview(w.case_id, 1)
    return w.service.enqueue(w.case_id, 1, preview["preview_key"], "synthetic-operator")


def rows(jobs, table):
    with jobs.connection() as db:
        return [dict(row) for row in db.execute("SELECT * FROM " + table)]


def test_manual_api_requires_preview_submission_then_uses_only_approved_case(world, monkeypatch):
    w = world
    real_read = service_module.read_key
    reads = []
    monkeypatch.setattr(service_module, "read_key", lambda *args: reads.append(args) or real_read(*args))
    preview = w.service.preview(w.case_id, 1)
    assert preview["preview"]["mode"] == "local" and preview["preview"]["external_calls"] is False
    assert preview["execution"]["external_calls"] is True
    assert preview["execution"]["execution_binding"] == w.service.config_sha
    assert w.service.history(w.case_id) == []
    assert not w.service.run_once() and reads == [] and w.requests == []
    job = enqueue(w)
    assert enqueue(w)["id"] == job["id"] and reads == [] and w.requests == []
    assert w.service.run_once()
    saved_job = w.service.job(job["id"])
    assert saved_job["state"] == "complete" and saved_job["execution_mode"] == "api"
    assert saved_job["result"]["metadata"]["offline"] is False
    assert saved_job["result"]["metadata"]["stale_at_completion"] is False
    assert saved_job["result"]["usd"] == 0.00016
    assert len(reads) == len(w.requests) == 1
    assert reads[0] == (w.ssh.settings.keys_file, w.ssh.profile.key_name)
    body = json.loads(w.requests[0].content)
    assert body == joint_triage_api.request(w.ssh.profile, preview["case"])
    assert w.case_id not in w.requests[0].content.decode()
    assert "synthetic-operator" not in w.requests[0].content.decode()
    assert str(w.settings.database_path) not in w.requests[0].content.decode()
    assert rows(w.service.jobs, "ai_calls") == []
    assert len(rows(w.ssh.jobs, "ai_calls")) == 1
    assert w.service.status()["budget"] == w.ssh.jobs.budget()
    assert w.ssh.jobs.budget()["charged_usd"] == 0.00016
    assert not w.service.run_once()


@pytest.mark.parametrize("changes,reason", [
    ({"allow_external": False}, "joint_ai_external_calls_paused"),
    ({"approved_summary_version": None}, "joint_ai_summary_approval_required"),
    ({"approved_summary_version": "joint-summary-v0"}, "joint_ai_summary_approval_required"),
])
def test_pause_preserves_queued_attempts_and_history_without_key_reads(world, monkeypatch, changes, reason):
    w = world
    queued = enqueue(w)
    w.service = reopen(w, **changes)
    monkeypatch.setattr(service_module, "read_key", lambda *args: pytest.fail("paused key read"))
    status = w.service.status()
    assert status["enabled"] and status["paused"] and not status["external_calls"]
    assert status["pause_reason"] == reason
    assert w.service.preview(w.case_id, 1)["execution"] == status
    with pytest.raises(RuntimeError, match="joint_ai_paused"):
        enqueue(w)
    assert not w.service.run_once()
    assert w.service.job(queued["id"])["attempt_count"] == 0
    assert w.service.job(queued["id"])["state"] == "queued"
    assert w.service.history(w.case_id)[0]["execution_mode"] == "api"
    assert w.requests == [] and rows(w.ssh.jobs, "ai_calls") == []


def test_saved_ssh_authorization_does_not_approve_joint_summary(world, monkeypatch):
    w = world
    settings = Settings(mode="api", database_path=w.settings.database_path)
    w.service = Service(w.spec, settings, ssh_service=w.ssh)
    monkeypatch.setattr(service_module, "read_key", lambda *args: pytest.fail("status key read"))
    assert w.ssh.settings.allow_external and w.ssh.settings.approved_summary_version == 1
    assert not w.service.status()["external_calls"]
    with pytest.raises(RuntimeError, match="joint_ai_paused"):
        enqueue(w)


@pytest.mark.parametrize("when", ["before_enqueue", "before_send", "during_send"])
def test_stale_evidence_never_authorizes_new_calls_and_paid_result_is_marked(world, monkeypatch, when):
    w = world
    def invalidate():
        change_checkpoint(w.spec, lambda value: value.update(enabled=False))
    if when == "before_enqueue":
        invalidate()
        with pytest.raises(ValueError, match="joint_ai_request_changed"):
            enqueue(w)
        assert w.requests == []
        return
    job = enqueue(w)
    if when == "before_send":
        invalidate()
        monkeypatch.setattr(service_module, "read_key", lambda *args: pytest.fail("stale key read"))
    else:
        w.before_response = invalidate
    assert w.service.run_once()
    result = w.service.job(job["id"])
    assert result["stale"]
    if when == "before_send":
        assert result["state"] == "stale" and w.requests == []
    else:
        assert result["state"] == "complete"
        assert result["result"]["metadata"]["stale_at_completion"]
        assert len(w.requests) == 1


def test_paid_receipt_recovers_locally_while_paused_with_new_profile_and_stale_case(world, monkeypatch):
    w = world
    job = enqueue(w)
    original = joint_triage.validate
    def crash(*args, **kwargs):
        raise KeyboardInterrupt("synthetic process stop after durable settlement")
    monkeypatch.setattr(joint_triage, "validate", crash)
    with pytest.raises(KeyboardInterrupt):
        w.service.run_once()
    assert len(w.requests) == 1 and w.ssh.jobs.budget()["charged_usd"] == 0.00016
    original_call = rows(w.service.jobs, "ai_jobs")[0]["call_id"]
    monkeypatch.setattr(joint_triage, "validate", original)
    monkeypatch.setattr(service_module, "read_key", lambda *args: pytest.fail("recovery key read"))
    w.ssh.profile = w.ssh.profile.model_copy(update={"model": "synthetic-new-model"})
    w.ssh.config_sha = "synthetic-reloaded-ssh-configuration"
    w.tick.value += 601
    change_checkpoint(w.spec, lambda value: value.update(enabled=False))
    w.service = reopen(w, allow_external=False, approved_summary_version="joint-summary-v0")
    assert w.service.run_once()
    result = w.service.job(job["id"])
    assert result["state"] == "complete" and result["stale"]
    assert result["result"]["metadata"]["recovered"] is True
    assert result["result"]["metadata"]["additional_usd"] == 0
    assert result["result"]["metadata"]["model"] == "synthetic-model"
    assert result["attempt_count"] == 1
    assert rows(w.service.jobs, "ai_jobs")[0]["call_id"] == original_call
    assert len(w.requests) == 1 and w.ssh.jobs.budget()["charged_usd"] == 0.00016


def test_paid_uncertain_receipt_recovery_does_not_claim_older_unpaid_job(world, monkeypatch):
    w = world
    paid = enqueue(w)
    job = w.service.jobs.claim()
    result = joint_triage_api.JointAPITriage(w.ssh.profile, "synthetic-key",
        ledger=Ledger(w.service.jobs, job), transport=w.transport).triage(json.loads(job["dossier_json"]))
    assert result["usd"] > 0
    w.service.jobs.finish(job, "uncertain", error="synthetic_local_failure")
    bundle = w.service._bundle(w.case_id, 1)
    unpaid = w.service.jobs.enqueue(w.case_id, bundle, "synthetic-other-config", "synthetic-other-request",
                                   "synthetic-operator")
    with w.service.jobs.connection(write=True) as db:
        db.execute("UPDATE ai_jobs SET created=created-100 WHERE id=?", (unpaid,))
    w.service = reopen(w, allow_external=False)
    monkeypatch.setattr(service_module, "read_key", lambda *args: pytest.fail("paid recovery key read"))
    assert w.service.run_once()
    assert w.service.job(paid["id"])["state"] == "complete"
    assert w.service.job(unpaid)["state"] == "queued"
    assert w.service.job(unpaid)["attempt_count"] == 0
    assert not w.service.run_once()


def test_unknown_outcome_retains_shared_reservation_and_is_never_resent(world):
    w = world
    w.response = httpx.Response(200, json={"model": w.ssh.profile.model, "output": []})
    job = enqueue(w)
    assert w.service.run_once()
    assert w.service.job(job["id"])["state"] == "uncertain"
    assert w.ssh.jobs.budget()["reserved_usd"] == w.ssh.profile.reservation() / 1_000_000
    w.tick.value += 1000
    w.service = reopen(w)
    assert not w.service.run_once() and len(w.requests) == 1
    assert w.service.job(job["id"])["attempt_count"] == 1


def test_known_usage_bad_output_is_charged_and_returns_review(world):
    w = world
    w.response = httpx.Response(200, json=payload(w.ssh.profile, "synthetic malformed advice"))
    job = enqueue(w)
    assert w.service.run_once()
    saved_job = w.service.job(job["id"])
    assert saved_job["state"] == "review" and saved_job["result"]["verdict"] == "abstain"
    assert w.ssh.jobs.budget()["charged_usd"] == 0.00016
    assert w.ssh.jobs.budget()["reserved_usd"] == 0


def test_shared_ssh_spending_pauses_before_reading_key_and_budget_never_resets(world, monkeypatch):
    w = world
    job = enqueue(w)
    bundle = {"case": {"revision": "synthetic"}, "meta": {}, "local_refs": {}}
    w.ssh.jobs.enqueue("synthetic-ssh-case", bundle, "synthetic-config", "synthetic-request", "operator")
    ssh_job = w.ssh.jobs.claim()
    ledger = Ledger(w.ssh.jobs, ssh_job)
    ledger.reserve(ssh_job["call_id"], 990_000)
    ledger.complete(ssh_job["call_id"], 990_000, {"synthetic": True})
    monkeypatch.setattr(service_module, "read_key", lambda *args: pytest.fail("exhausted key read"))
    assert w.service.status()["pause_reason"] == "joint_ai_shared_budget_exhausted"
    assert not w.service.run_once()
    assert w.service.job(job["id"])["attempt_count"] == 0
    w.service = reopen(w)
    assert w.service.status()["budget"]["charged_usd"] == 0.99
    assert w.service.status()["budget"]["total_usd"] == 1
    assert not w.service.run_once() and w.requests == []


def test_actual_overrun_halts_same_owner_but_keeps_result(world):
    w = world
    w.response = httpx.Response(200, json=payload(w.ssh.profile, "invalid", inputs=150_000))
    job = enqueue(w)
    assert w.service.run_once()
    assert w.service.job(job["id"])["state"] == "review"
    assert w.service.status()["pause_reason"] == "joint_ai_shared_budget_exhausted"
    assert w.ssh.jobs.budget()["halted"]
    assert w.service.status()["budget"] == w.ssh.jobs.budget()


def test_changed_live_ssh_dependency_pauses_before_credentials(world, monkeypatch):
    w = world
    job = enqueue(w)
    monkeypatch.setattr(service_module, "read_key", lambda *args: pytest.fail("changed profile key read"))
    w.ssh.profile = w.ssh.profile.model_copy(update={"model": "synthetic-other-model"})
    assert w.service.status()["pause_reason"] == "joint_ai_existing_api_changed"
    assert not w.service.run_once()
    assert w.service.job(job["id"])["attempt_count"] == 0


def test_reloaded_profile_changes_stale_unpaid_request_without_key_read(world, monkeypatch):
    w = world
    job = enqueue(w)
    w.ssh.profile = w.ssh.profile.model_copy(update={"model": "synthetic-other-model"})
    w.ssh.config_sha = "synthetic-other-binding"
    w.service = reopen(w)
    monkeypatch.setattr(service_module, "read_key", lambda *args: pytest.fail("obsolete request key read"))
    assert w.service.run_once()
    assert w.service.job(job["id"])["state"] == "stale"
    assert w.requests == []


@pytest.mark.parametrize("path_name,suffix", [(name, suffix) for name in ("profile_path", "keys_file", "database_path")
                                              for suffix in ("", "-wal", "-shm", "-journal")])
def test_queue_cannot_overwrite_existing_profile_key_or_ledger_family(world, path_name, suffix):
    w = world
    protected = getattr(w.ssh.settings, path_name)
    before = protected.read_bytes()
    with pytest.raises(ValueError, match="joint_ai_path_conflict"):
        reopen(w, database_path=str(protected) + suffix)
    assert protected.read_bytes() == before


def test_queue_cannot_hardlink_existing_key(world, tmp_path):
    w = world
    candidate = tmp_path / "aliased-key.sqlite"
    os.link(w.ssh.settings.keys_file, candidate)
    before = w.ssh.settings.keys_file.read_bytes()
    with pytest.raises(ValueError, match="joint_ai_path_conflict"):
        reopen(w, database_path=candidate)
    assert w.ssh.settings.keys_file.read_bytes() == before


def test_missing_owner_is_not_replaced_and_status_fails_closed(world, monkeypatch):
    w = world
    enqueue(w)
    w.ssh.jobs.path.unlink()
    monkeypatch.setattr(service_module, "read_key", lambda *args: pytest.fail("owner missing key read"))
    assert w.service.status()["pause_reason"] == "joint_ai_shared_budget_unavailable"
    with pytest.raises(Exception):
        w.service.run_once()
    assert not w.ssh.jobs.path.exists() and w.requests == []


def test_api_rejects_fake_provider_missing_owner_and_new_private_paths(world, tmp_path):
    w = world
    for kwargs in ({}, {"ssh_service": w.ssh, "provider": lambda case: "fake"}):
        with pytest.raises(ValueError, match="joint_ai_existing_api_required"):
            Service(w.spec, w.settings, aliases=w.ssh.aliases, **kwargs)
    for name in ("profile_path", "keys_file", "total_budget_usd", "daily_budget_usd"):
        with pytest.raises(ValueError):
            Settings.model_validate({**w.settings.model_dump(), name: str(tmp_path / "other")})
    with pytest.raises(ValueError):
        Settings.model_validate({**w.settings.model_dump(), "allow_external": "true"})


def test_offline_history_survives_first_api_binding_with_original_mode(world):
    w = world
    path = w.settings.database_path.with_name("upgrade.sqlite")
    local = Service(w.spec, Settings(database_path=path), aliases=w.ssh.aliases, clock=lambda: w.tick.value)
    preview = local.preview(w.case_id, 1)
    old = local.enqueue(w.case_id, 1, preview["preview_key"], "synthetic-operator")
    assert local.run_once()
    original_alias = local.jobs.secret()
    w.service = reopen(w, database_path=path)
    new = enqueue(w)
    assert new["id"] != old["id"]
    assert w.service.jobs.secret() == original_alias
    assert w.service.job(old["id"])["execution_mode"] == "offline"
    assert w.service.job(old["id"])["result"]["usd"] == 0
    assert {row["execution_mode"] for row in w.service.history(w.case_id)} == {"offline", "api"}
    assert w.service.run_once() and len(w.requests) == 1


def test_recover_only_default_claim_behavior_remains_and_selector_is_strict(tmp_path):
    queue = Jobs(tmp_path / "queue.sqlite")
    queue.set_budget(100, 100)
    bundle = {"case": {"revision": "synthetic"}, "meta": {}, "local_refs": {}}
    unpaid = queue.enqueue("synthetic-unpaid", bundle, "a", "a", "operator")
    assert queue.claim(recover_only=True) is None
    assert queue.get(unpaid)["attempt_count"] == 0
    with pytest.raises(ValueError, match="invalid analysis recovery selector"):
        queue.claim(recover_only=1)
    job = queue.claim()
    assert job["id"] == unpaid and job["attempt_count"] == 1
    ledger = Ledger(queue, job)
    ledger.reserve(job["call_id"], 10)
    ledger.complete(job["call_id"], 5, {"synthetic": True})
    queue.finish(job, "uncertain")
    recovered = queue.claim(recover_only=True)
    assert recovered["call_id"] == job["call_id"] and recovered["attempt_count"] == 1
    assert queue.cached_call(recovered) == {"synthetic": True}


def test_environment_reuses_owner_and_protects_config_file_before_read(world, monkeypatch, tmp_path):
    w = world
    path = tmp_path / "joint-config.json"
    path.write_text(w.settings.model_dump_json())
    path.chmod(0o600)
    monkeypatch.setenv("RISKOPS_JOINT_AI_CONFIG", str(path))
    actual = Service.from_environment(w.spec, ssh_service=w.ssh, transport=w.transport)
    assert actual.enabled and actual.jobs.budget_owner is w.ssh.jobs
    assert actual.status()["model"] == w.ssh.profile.model
    monkeypatch.setenv("RISKOPS_JOINT_AI_CONFIG", str(w.ssh.settings.keys_file))
    unavailable = Service.from_environment(w.spec, ssh_service=w.ssh)
    assert not unavailable.enabled and unavailable.error == "joint_ai_configuration_unavailable"


def test_non_api_settings_fingerprint_stays_exact_legacy_material(world):
    w = world
    offline = Settings(database_path=w.settings.database_path.with_name("legacy.sqlite"))
    service = Service(w.spec, offline, aliases=w.ssh.aliases)
    settings = offline.model_dump(mode="json", exclude={"recording_path", "approved_summary_version"})
    material = {"settings": settings, "summary_version": service_module.VERSION,
        "envelope_version": service_module.ENVELOPE_VERSION, "dossier_version": joint_triage.VERSION,
        "validator_version": joint_triage.VALIDATOR_VERSION,
        "system_sha256": hashlib.sha256(joint_triage.SYSTEM.encode()).hexdigest()}
    assert service.config_sha == hashlib.sha256(service_module.canonical(material).encode()).hexdigest()
    assert "paused" not in service.status()
    assert "approved_summary_version" not in service.status()


@pytest.mark.parametrize("invalid_record", ["{", "null", "[]", "{}"])
def test_invalid_paid_receipt_finishes_review_without_starving_next_task(world, invalid_record):
    w = world
    paid = enqueue(w)
    job = w.service.jobs.claim()
    joint_triage_api.JointAPITriage(w.ssh.profile, "synthetic-key", ledger=Ledger(w.service.jobs, job),
                                  transport=w.transport).triage(json.loads(job["dossier_json"]))
    with w.ssh.jobs.connection(write=True) as db:
        db.execute("UPDATE ai_calls SET record=? WHERE id=?", (invalid_record, job["call_id"]))
    w.service.jobs.finish(job, "uncertain", error="synthetic_local_failure")
    # A new approved local configuration gives a second explicit manual request.
    w.tick.value += 1
    w.service = reopen(w, max_attempts=3)
    next_job = enqueue(w)
    assert w.service.run_once()
    broken = w.service.job(paid["id"])
    assert broken["state"] == "review" and broken["error_code"] == "invalid_analysis_record"
    assert broken["result"] is None and broken["attempt_count"] == 1
    assert w.service.run_once()
    assert w.service.job(next_job["id"])["state"] == "complete"
    assert not w.service.run_once() and len(w.requests) == 2
    assert w.ssh.jobs.budget()["charged_usd"] == 0.00032


def test_temporary_receipt_accounting_read_failure_recovers_locally(world, monkeypatch):
    from contextlib import contextmanager
    import sqlite3
    w = world
    queued = enqueue(w)
    original = joint_triage.validate
    monkeypatch.setattr(joint_triage, "validate", lambda *a: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        w.service.run_once()
    monkeypatch.setattr(joint_triage, "validate", original)
    w.tick.value += 601
    w.service = reopen(w, allow_external=False)
    original_check = joint_triage_api.JointAPITriage._checked
    original_accounting = w.service.jobs.accounting
    failed = []
    @contextmanager
    def temporary_failure(db, **kwargs):
        raise sqlite3.OperationalError("synthetic owner read failure")
        yield  # pragma: no cover
    def checked(client, *args, **kwargs):
        if not failed:
            failed.append(True)
            monkeypatch.setattr(w.service.jobs, "accounting", temporary_failure)
            try:
                return original_check(client, *args, **kwargs)
            finally:
                monkeypatch.setattr(w.service.jobs, "accounting", original_accounting)
        return original_check(client, *args, **kwargs)
    monkeypatch.setattr(joint_triage_api.JointAPITriage, "_checked", checked)
    monkeypatch.setattr(service_module, "read_key", lambda *args: pytest.fail("receipt recovery key read"))
    assert w.service.run_once()
    assert w.service.job(queued["id"])["state"] == "uncertain"
    assert w.service.run_once()
    restored = w.service.job(queued["id"])
    assert restored["state"] == "complete" and restored["result"]["metadata"]["recovered"]
    assert restored["attempt_count"] == 1 and len(w.requests) == 1
