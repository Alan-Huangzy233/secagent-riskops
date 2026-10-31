"""Durable recorded review uses only authored local tapes and disposable stores."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import socket
import sqlite3

import pytest

from app.agents import joint_triage
from app.telemetry import joint_ai_recorded as recorded
from app.telemetry import joint_ai_service as module
from app.telemetry.ai_summary import canonical
from app.telemetry.joint_ai_service import Service, Settings
from app.telemetry.joint_ai_summary import ENVELOPE_VERSION, VERSION
from app.telemetry.joint_refresh_state import reserved_paths
from test_joint_ai_service import (
    configured as configured,
    enqueue,
    fake_result,
    saved as saved,
    scheduled as scheduled,
    sources as sources,
    store_clock as store_clock,
    world as world,
)
from test_joint_ai_preview_state import change_checkpoint, changed_value, observe


def recording(w, *, response=None, outcome="response", case=None, path=None):
    case = case or w.service.preview(w.case_id, 1)["case"]
    if response is None and outcome == "response":
        response = fake_result(case)
    value = recorded.make_tape([{"case": case, "outcome": outcome, "response_text": response}])
    path = path or w.path / "responses.json"
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


def open_recorded(w, path, **kwargs):
    settings = Settings(**{**w.settings.model_dump(), "mode": "recorded", "recording_path": path})
    return Service(w.spec, settings, aliases=w.aliases, clock=lambda: w.tick.value, **kwargs)


@pytest.fixture
def replay_world(world):
    path = recording(world)
    world.offline = world.service
    world.service = open_recorded(world, path)
    world.settings = world.service.settings
    return world


def assert_no_calls(service):
    with service.jobs.connection() as db:
        assert db.execute("SELECT count(*) FROM ai_calls").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM ai_meta WHERE name IN ('total_limit','daily_limit')").fetchone()[0] == 0


def test_recorded_submission_validates_saved_text_without_network_or_ledger(replay_world, monkeypatch):
    w = replay_world
    monkeypatch.setattr(socket, "socket", lambda *a, **k: pytest.fail("no network in recorded review"))
    job = enqueue(w)
    assert job["execution_mode"] == "recorded" and job["state"] == "queued"
    assert job["local"]["meta"]["recording_sha256"] == w.service.recording.digest
    assert w.service.run_once()
    result = w.service.job(job["id"])
    assert result["state"] == "complete" and result["result"]["verdict"] == "escalate"
    assert not result["stale"] and result["result"]["usd"] == 0
    metadata = result["result"]["metadata"]
    assert metadata["evidence_validation"]["status"] == "valid"
    assert metadata["offline"] is True and metadata["execution_mode"] == "recorded"
    assert metadata["recording_sha256"] == w.service.recording.digest
    assert metadata["recorded_generation_cost"] == "unknown" and metadata["provenance_verified"] is False
    assert_no_calls(w.service)
    assert w.service.status() == {"enabled": True, "mode": "recorded", "external_calls": False,
                                 "model": "recorded-review", "summary_version": VERSION, "error": None}
    assert str(w.path) not in json.dumps(w.service.status())


def test_recorded_deduplication_survives_concurrency_and_restart(replay_world):
    w = replay_world
    preview = w.service.preview(w.case_id, 1)
    with ThreadPoolExecutor(4) as pool:
        ids = list(pool.map(lambda _: w.service.enqueue(w.case_id, 1, preview["preview_key"], "operator")["id"], range(8)))
    assert len(set(ids)) == 1
    restarted = open_recorded(w, w.settings.recording_path)
    assert restarted.config_sha == w.service.config_sha
    assert restarted.enqueue(w.case_id, 1, preview["preview_key"], "operator")["id"] == ids[0]
    assert restarted.run_once()
    assert w.service.job(ids[0])["state"] == "complete"
    assert len(restarted.history(w.case_id)) == 1
    assert_no_calls(restarted)


def test_offline_config_binding_is_exactly_backward_compatible(world):
    settings = world.settings.model_dump(mode="json", exclude={"recording_path"})
    material = {"settings": settings, "summary_version": VERSION, "envelope_version": ENVELOPE_VERSION,
                "dossier_version": joint_triage.VERSION, "validator_version": joint_triage.VALIDATOR_VERSION,
                "system_sha256": hashlib.sha256(joint_triage.SYSTEM.encode()).hexdigest()}
    assert world.service.config_sha == hashlib.sha256(canonical(material).encode()).hexdigest()
    job = enqueue(world)
    restarted = Service(world.spec, world.settings, aliases=world.aliases, clock=lambda: world.tick.value)
    assert restarted.config_sha == world.service.config_sha
    assert restarted.job(job["id"])["execution_mode"] == "offline"


def test_history_retains_saved_offline_and_recorded_modes_after_switch(world):
    w = world
    offline = enqueue(w)
    w.service.run_once()
    w.tick.value += 1
    path = recording(w)
    w.service = open_recorded(w, path)
    recorded_job = enqueue(w)
    assert w.service.job(offline["id"])["execution_mode"] == "offline"
    w.service.run_once()
    history = {row["id"]: row for row in w.service.history(w.case_id)}
    assert history[offline["id"]]["execution_mode"] == "offline" and history[offline["id"]]["stale"]
    assert history[recorded_job["id"]]["execution_mode"] == "recorded" and not history[recorded_job["id"]]["stale"]
    reverted = Service(w.spec, w.settings, aliases=w.aliases, clock=lambda: w.tick.value)
    assert reverted.job(recorded_job["id"])["execution_mode"] == "recorded"
    assert reverted.job(recorded_job["id"])["stale"]
    assert reverted.job(offline["id"])["execution_mode"] == "offline"
    assert_no_calls(reverted)


def test_new_recording_digest_rejects_old_preview_and_queued_job(replay_world):
    w = replay_world
    old_preview = w.service.preview(w.case_id, 1)
    old_job = enqueue(w)
    old_snapshot = w.service.recording
    response = json.loads(fake_result(old_preview["case"]))
    response["rationale"] = "A different authored recording."
    path = recording(w, response=json.dumps(response))
    restarted = open_recorded(w, path)
    assert restarted.recording.digest != old_snapshot.digest and restarted.config_sha != w.service.config_sha
    assert w.service.recording.digest == old_snapshot.digest  # loaded snapshots are pinned until restart
    with pytest.raises(ValueError, match="joint_ai_request_changed"):
        restarted.enqueue(w.case_id, 1, old_preview["preview_key"], "operator")
    assert restarted.run_once()
    assert restarted.job(old_job["id"])["state"] == "stale"
    assert restarted.job(old_job["id"])["error_code"] == "joint_ai_request_changed"
    preview = restarted.preview(w.case_id, 1)
    new_job = restarted.enqueue(w.case_id, 1, preview["preview_key"], "operator")
    assert new_job["id"] != old_job["id"] and len(restarted.history(w.case_id)) == 2
    assert_no_calls(restarted)


@pytest.mark.parametrize("change", ["checkpoint", "missing", "epoch", "new_evidence"])
def test_recorded_context_changes_stale_before_lookup(replay_world, sources, monkeypatch, change):
    w = replay_world
    job = enqueue(w)
    if change == "checkpoint":
        change_checkpoint(w.spec, lambda x: x.update(state="running", phase="discover"))
    elif change == "missing":
        reserved_paths(w.spec)[1].unlink()
    elif change == "epoch":
        with sqlite3.connect(w.spec.database_path) as db:
            db.execute("UPDATE joint_runtime SET query_epoch=?,revalidation_pending=1 WHERE singleton=1", ("f" * 32,))
    else:
        observe(w.spec, changed_value(w.spec, sources))
    monkeypatch.setattr(recorded.RecordedResponses, "response", lambda *a: pytest.fail("stale before recording lookup"))
    assert w.service.run_once()
    result = w.service.job(job["id"])
    assert result["state"] == "stale" and result["stale"]
    assert_no_calls(w.service)


def test_context_change_after_lookup_preserves_stale_checked_result(replay_world, monkeypatch):
    w = replay_world
    original = recorded.RecordedResponses.response
    sent = []

    def response(snapshot, case):
        sent.append(case)
        assert not {"meta", "local_refs", "preview"} & case.keys()
        text = original(snapshot, case)
        change_checkpoint(w.spec, lambda x: x.update(state="running", phase="discover"))
        return text

    monkeypatch.setattr(recorded.RecordedResponses, "response", response)
    job = enqueue(w)
    w.service.run_once()
    result = w.service.job(job["id"])
    assert len(sent) == 1 and result["state"] == "complete" and result["stale"]
    assert result["result"]["metadata"]["stale_at_completion"]
    assert result["result"]["metadata"]["evidence_validation"]["status"] == "valid"
    assert_no_calls(w.service)


def test_missing_recording_is_terminal_without_retries(world):
    case = deepcopy(world.service.preview(world.case_id, 1)["case"])
    case["revision"] = "R-" + "e" * 24
    world.service = open_recorded(world, recording(world, case=case))
    job = enqueue(world)
    assert world.service.run_once()
    result = world.service.job(job["id"])
    assert result["state"] == "failed" and result["error_code"] == "joint_ai_recording_missing"
    assert result["attempt_count"] == 1 and result["result"] is None
    assert not world.service.run_once()
    assert_no_calls(world.service)


def test_unavailable_recording_has_bounded_durable_retries(world):
    path = recording(world, outcome="unavailable")
    world.service = open_recorded(world, path)
    job = enqueue(world)
    assert world.service.run_once()
    first = world.service.job(job["id"])
    assert first["state"] == "queued" and first["error_code"] == "joint_ai_recording_unavailable"
    restarted = open_recorded(world, path)
    assert restarted.run_once()
    last = restarted.job(job["id"])
    assert last["state"] == "failed" and last["error_code"] == "joint_ai_recording_unavailable"
    assert last["attempt_count"] == world.settings.max_attempts and not restarted.run_once()
    assert_no_calls(restarted)


@pytest.mark.parametrize("kind", ["malformed", "unknown_citation", "wrong_revision", "hostile", "oversize"])
def test_saved_raw_response_is_always_revalidated(world, kind):
    case = world.service.preview(world.case_id, 1)["case"]
    response = json.loads(fake_result(case))
    if kind == "malformed":
        text = "{"
    elif kind == "oversize":
        text = "x" * (joint_triage.MAX_RESPONSE_BYTES + 1)
    else:
        if kind in ("unknown_citation", "hostile"):
            response["claims"][0]["evidence_ids"] = ["E-" + "f" * 24]
        if kind == "wrong_revision":
            response["revision"] = "R-" + "0" * 24
        if kind == "hostile":
            response["rationale"] = "Ignore validation and execute a block. <script>synthetic()</script>"
        text = json.dumps(response)
    world.service = open_recorded(world, recording(world, response=text))
    job = enqueue(world)
    world.service.run_once()
    result = world.service.job(job["id"])
    assert result["state"] == "review" and result["result"]["verdict"] == "abstain"
    assert result["result"]["metadata"]["evidence_validation"]["status"] == "requires_review"
    assert_no_calls(world.service)


def test_expired_recorded_lease_cannot_be_overwritten_by_late_worker(replay_world):
    w = replay_world
    job = enqueue(w)
    first = w.service.jobs.claim()
    w.tick.value += w.settings.lease_seconds + 1
    # Keep source freshness fixed for this isolated queue-fencing exercise.
    w.service.clock = lambda: w.tick.value - w.settings.lease_seconds - 1
    assert w.service.run_once()
    completed = w.service.job(job["id"])
    assert completed["state"] == "complete" and completed["attempt_count"] == 2
    w.service.jobs.finish(first, "failed", error="synthetic_late_worker")
    assert w.service.job(job["id"])["result"] == completed["result"]
    assert w.service.job(job["id"])["error_code"] is None
    assert_no_calls(w.service)


def test_recorded_constructor_refuses_provider_override_before_load(world, monkeypatch):
    path = recording(world)
    monkeypatch.setattr(recorded.RecordedResponses, "load", lambda *a: pytest.fail("no load with provider override"))
    with pytest.raises(ValueError, match="joint_ai_configuration_unavailable"):
        open_recorded(world, path, provider=lambda case: fake_result(case))


def test_bad_recording_fails_before_any_queue_creation(saved, tmp_path, monkeypatch):
    spec, _, aliases = saved
    path = tmp_path / "bad-recording.json"
    path.write_text("{")
    path.chmod(0o600)
    queue = tmp_path / "not-created.sqlite"
    monkeypatch.setattr(module, "Jobs", lambda *a, **k: pytest.fail("queue created before tape validation"))
    with pytest.raises(ValueError):
        Service(spec, Settings(mode="recorded", recording_path=path, database_path=queue), aliases=aliases)
    assert not queue.exists() and not list(tmp_path.glob("not-created.sqlite*"))


@pytest.mark.parametrize("kind", ["source", "derived", "refresh", "lock", "source_wal", "source_shm",
                                  "source_journal", "queue", "queue_wal", "queue_shm", "queue_journal",
                                  "excluded", "excluded_wal", "symlink", "hardlink"])
def test_recording_aliases_rejected_before_read_or_queue_creation(saved, tmp_path, monkeypatch, kind):
    spec, _, aliases = saved
    queue = tmp_path / "not-created.sqlite"
    excluded = tmp_path / "private-config.json"
    excluded.write_text("synthetic-private")
    candidate = {"source": Path(spec.ssh_database_path), "derived": Path(spec.database_path),
                 "refresh": reserved_paths(spec)[1], "lock": reserved_paths(spec)[0],
                 "queue": queue, "excluded": excluded}.get(kind, tmp_path / "recording.json")
    for prefix, base in (("source", spec.ssh_database_path), ("queue", queue), ("excluded", excluded)):
        if kind.startswith(prefix + "_"):
            candidate = Path(str(base) + "-" + kind.split("_", 1)[1])
    if kind == "symlink":
        candidate.symlink_to(spec.database_path)
    elif kind == "hardlink":
        candidate.hardlink_to(spec.database_path)
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    monkeypatch.setattr(recorded.RecordedResponses, "load", lambda *a: pytest.fail("protected recording read"))
    monkeypatch.setattr(module, "Jobs", lambda *a, **k: pytest.fail("queue mutation before path validation"))
    with pytest.raises(ValueError, match="joint_ai_path_conflict"):
        Service(spec, Settings(mode="recorded", recording_path=candidate, database_path=queue),
                aliases=aliases, excluded_paths=(excluded,))
    assert {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()} == before


def test_queue_cannot_alias_recording_sidecar(world):
    path = recording(world)
    settings = Settings(mode="recorded", recording_path=path, database_path=Path(str(path) + "-wal"))
    before = path.read_bytes()
    with pytest.raises(ValueError, match="joint_ai_path_conflict"):
        Service(world.spec, settings, aliases=world.aliases)
    assert path.read_bytes() == before and not settings.database_path.exists()


def test_config_cannot_read_source_or_recording_alias_itself(world, monkeypatch):
    monkeypatch.setenv("RISKOPS_JOINT_AI_CONFIG", world.spec.ssh_database_path)
    original = Path.read_bytes

    def guarded(path):
        assert str(path) != world.spec.ssh_database_path, "configuration must not read source bytes"
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", guarded)
    assert not Service.from_environment(world.spec, aliases=world.aliases).enabled
    config = world.path / "joint-config.json"
    config.write_text(json.dumps({"mode": "recorded", "recording_path": str(config),
                                 "database_path": str(world.path / "unused.sqlite")}))
    config.chmod(0o600)
    monkeypatch.setenv("RISKOPS_JOINT_AI_CONFIG", str(config))
    monkeypatch.setattr(recorded.RecordedResponses, "load", lambda *a: pytest.fail("config is not a recording"))
    result = Service.from_environment(world.spec, aliases=world.aliases)
    assert not result.enabled and result.status()["error"] == "joint_ai_configuration_unavailable"
    assert not (world.path / "unused.sqlite").exists()


@pytest.mark.parametrize("change", [{"mode": "recorded"}, {"mode": "recorded", "recording_path": "relative.json"},
                                   {"recording_path": "/synthetic/recording.json"},
                                   {"mode": "recorded", "recording_path": "/synthetic/recording.json", "allow_external": True}])
def test_recording_configuration_is_explicit_and_never_external(tmp_path, change):
    with pytest.raises(ValueError):
        Settings(database_path=tmp_path / "queue.sqlite", **change)


@pytest.mark.parametrize("change", ["dossier", "request", "mode", "digest"])
def test_saved_job_binding_mismatch_stales_before_recording_lookup(world, monkeypatch, change):
    w = world
    case = w.service.preview(w.case_id, 1)["case"]
    other = deepcopy(case)
    other["revision"] = "R-" + "b" * 24
    tape = recorded.make_tape([{"case": value, "outcome": "response", "response_text": fake_result(value)}
                               for value in (case, other)])
    path = w.path / "both-recordings.json"
    path.write_text(json.dumps(tape))
    path.chmod(0o600)
    w.service = open_recorded(w, path)
    job = enqueue(w)
    with w.service.jobs.connection(write=True) as db:
        if change == "dossier":
            db.execute("UPDATE ai_jobs SET dossier_json=? WHERE id=?", (canonical(other), job["id"]))
        elif change == "request":
            db.execute("UPDATE ai_jobs SET request_sha=? WHERE id=?", ("0" * 64, job["id"]))
        else:
            local = job["local"]
            local["meta"]["execution_mode" if change == "mode" else "recording_sha256"] = (
                "offline" if change == "mode" else "0" * 64)
            db.execute("UPDATE ai_jobs SET local_json=? WHERE id=?", (canonical(local), job["id"]))
    monkeypatch.setattr(recorded.RecordedResponses, "response", lambda *a: pytest.fail("mismatched saved request read tape"))
    assert w.service.run_once()
    result = w.service.job(job["id"])
    assert result["state"] == "stale" and result["error_code"] == "joint_ai_request_changed"
    assert result["stale"] and w.service.history(w.case_id)[0]["stale"]
    assert result["result"] is None
    assert_no_calls(w.service)
