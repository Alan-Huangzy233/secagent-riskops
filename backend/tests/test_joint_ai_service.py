"""Offline joint queue tests with authored evidence and disposable stores only."""

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from app.telemetry import joint_ai_service as module
from app.telemetry.ai_jobs import Jobs
from app.telemetry.joint_ai_service import Service, Settings
from app.telemetry.joint_refresh_state import reserved_paths
from test_joint_ai_preview_state import (
    AT,
    saved as saved,
    scheduled as scheduled,
    configured as configured,
    sources as sources,
    store_clock as store_clock,
    change_checkpoint,
    changed_value,
    observe,
)


@pytest.fixture
def world(saved, tmp_path):
    spec, case_id, aliases = saved
    tick = SimpleNamespace(value=AT.timestamp())
    settings = Settings(database_path=tmp_path / "joint-ai.sqlite")
    service = Service(spec, settings, aliases=aliases, clock=lambda: tick.value)
    return SimpleNamespace(
        service=service,
        spec=spec,
        case_id=case_id,
        aliases=aliases,
        settings=settings,
        tick=tick,
        path=tmp_path,
    )


def enqueue(w):
    preview = w.service.preview(w.case_id, 1)
    return w.service.enqueue(w.case_id, 1, preview["preview_key"], "operator")


def fake_result(case, *, verdict="escalate"):
    evidence = [
        row["event_id"] for row in case["evidence"] if row["kind"] == "network_tcp"
    ][:1]
    return json.dumps(
        {
            "verdict": verdict,
            "confidence": "medium",
            "revision": case["revision"],
            "rationale": "Authored synthetic proposal.",
            "evidence_ids": evidence,
            "attack_techniques": [],
            "claims": [{"kind": "network_observed", "evidence_ids": evidence}],
        }
    )


def test_disabled_creates_no_files_or_workers(tmp_path, monkeypatch):
    monkeypatch.delenv("RISKOPS_JOINT_AI_CONFIG", raising=False)
    monkeypatch.setattr(
        module, "Jobs", lambda *a, **kw: pytest.fail("disabled queue construction")
    )
    service = Service.from_environment(None)
    service.start()
    service.close()
    assert service.status() == {
        "enabled": False,
        "mode": "disabled",
        "external_calls": False,
        "model": None,
        "summary_version": "joint-summary-v1",
        "error": None,
    }
    assert (
        not service.run_once()
        and service.thread is None
        and not list(tmp_path.iterdir())
    )


def test_offline_submission_persists_checked_abstention_without_calls(world):
    w = world
    job = enqueue(w)
    assert job["state"] == "queued" and job["case_revision"] == 1 and not job["stale"]
    assert w.service.run_once()
    result = w.service.job(job["id"])
    assert result["state"] == "review" and result["result"]["verdict"] == "abstain"
    assert result["result"]["usd"] == 0 and result["result"]["metadata"]["offline"]
    assert result["result"]["metadata"]["evidence_validation"]["status"] == "valid"
    assert (
        "Offline workflow check"
        in result["result"]["metadata"]["evidence_validation"]["proposal"]["rationale"]
    )
    with w.service.jobs.connection() as db:
        assert db.execute("SELECT count(*) FROM ai_calls").fetchone()[0] == 0
        assert (
            db.execute(
                "SELECT count(*) FROM ai_meta WHERE name IN ('total_limit','daily_limit')"
            ).fetchone()[0]
            == 0
        )
    restored = Service(
        w.spec, w.settings, aliases=w.aliases, clock=lambda: w.tick.value
    )
    assert restored.job(job["id"])["result"] == result["result"]


def test_duplicate_concurrent_submissions_and_restart_have_one_job(world):
    w = world
    p = w.service.preview(w.case_id, 1)
    with ThreadPoolExecutor(4) as pool:
        ids = list(
            pool.map(
                lambda _: w.service.enqueue(w.case_id, 1, p["preview_key"], "operator")[
                    "id"
                ],
                range(8),
            )
        )
    assert len(set(ids)) == 1
    assert len(w.service.history(w.case_id)) == 1


def test_capture_time_does_not_change_preview_key(world):
    first = world.service.preview(world.case_id, 1)
    world.tick.value += 1
    second = world.service.preview(world.case_id, 1)
    assert first["preview"]["captured_at"] != second["preview"]["captured_at"]
    assert first["preview_key"] == second["preview_key"]


def test_expired_or_changed_preview_rejected_before_queue_write(world):
    p = world.service.preview(world.case_id, 1)
    change_checkpoint(world.spec, lambda x: x.update(state="running", phase="discover"))
    with pytest.raises(ValueError, match="joint_ai_request_changed"):
        world.service.enqueue(world.case_id, 1, p["preview_key"], "operator")
    assert world.service.history(world.case_id) == []


@pytest.mark.parametrize("change", ["checkpoint", "missing", "epoch", "new_evidence"])
def test_changed_saved_context_stales_before_provider(world, sources, change):
    w = world
    job = enqueue(w)
    if change == "checkpoint":
        change_checkpoint(w.spec, lambda x: x.update(state="running", phase="discover"))
    elif change == "missing":
        reserved_paths(w.spec)[1].unlink()
    elif change == "epoch":
        with sqlite3.connect(w.spec.database_path) as db:
            db.execute(
                "UPDATE joint_runtime SET query_epoch=?,revalidation_pending=1 WHERE singleton=1",
                ("f" * 32,),
            )
    else:
        observe(w.spec, changed_value(w.spec, sources))
    w.service.provider = lambda case: pytest.fail(
        "changed case must not reach provider"
    )
    assert w.service.run_once()
    assert w.service.job(job["id"])["state"] == "stale"
    assert w.service.job(job["id"])["stale"]


def test_fake_receives_only_aliased_case_and_result_becomes_stale_during_work(world):
    w = world
    job = enqueue(w)
    sent = []

    def fake(case):
        sent.append(case)
        assert case["dossier_version"] == "joint-v1"
        assert not {"meta", "local_refs", "preview", "preview_key"} & case.keys()
        change_checkpoint(w.spec, lambda x: x.update(state="running", phase="discover"))
        return fake_result(case)

    w.service.provider = fake
    w.service.run_once()
    result = w.service.job(job["id"])
    assert len(sent) == 1 and result["state"] == "complete" and result["stale"]
    assert result["result"]["metadata"]["stale_at_completion"]
    assert result["result"]["verdict"] == "escalate"


@pytest.mark.parametrize(
    "response", ["invalid", "dismiss", "revision", "unknown_evidence", "oversize"]
)
def test_invalid_fake_proposals_fail_to_review(world, response):
    def fake(case):
        value = json.loads(fake_result(case))
        if response == "invalid":
            return "{"
        if response == "oversize":
            return "x" * (64 * 1024 + 1)
        if response == "dismiss":
            value["verdict"] = "dismiss"
        if response == "revision":
            value["revision"] = "R-" + "0" * 24
        if response == "unknown_evidence":
            value["evidence_ids"] = ["E-" + "0" * 24]
        return json.dumps(value)

    job = enqueue(world)
    world.service.provider = fake
    world.service.run_once()
    result = world.service.job(job["id"])
    assert result["state"] == "review" and result["result"]["verdict"] == "abstain"
    assert (
        result["result"]["metadata"]["evidence_validation"]["status"]
        == "requires_review"
    )


def test_history_is_lightweight_bounded_and_revalidates_each_revision_once(
    world, monkeypatch
):
    w = world
    job = enqueue(w)
    w.service.run_once()
    original = w.service._bundle
    calls = []

    def counted(*args):
        calls.append(args)
        return original(*args)

    monkeypatch.setattr(w.service, "_bundle", counted)
    history = w.service.history(w.case_id)
    assert len(calls) == 1 and len(history) == 1
    assert history[0]["id"] == job["id"]
    assert set(history[0]) == {
        "id",
        "case_id",
        "case_revision",
        "state",
        "created",
        "updated",
        "stale",
        "current_review_state",
        "execution_mode",
        "error_code",
        "result",
    }
    assert history[0]["result"] == {"verdict": "abstain", "confidence": "low"}


def test_pre_submission_failures_have_bounded_retries(world):
    job = enqueue(world)

    def failed(case):
        raise RuntimeError("synthetic private detail")

    world.service.provider = failed
    assert (
        world.service.run_once() and world.service.job(job["id"])["state"] == "queued"
    )
    assert (
        world.service.run_once() and world.service.job(job["id"])["state"] == "failed"
    )
    assert not world.service.run_once()
    assert "synthetic private detail" not in json.dumps(world.service.job(job["id"]))


def test_expired_offline_lease_retries_and_late_worker_is_fenced(world):
    w = world
    job = enqueue(w)
    first = w.service.jobs.claim()
    w.tick.value += w.settings.lease_seconds + 1
    second = w.service.jobs.claim()
    assert second["id"] == first["id"] and second["attempt_count"] == 2
    w.service.jobs.finish(first, "complete", record={"verdict": "escalate"})
    assert w.service.jobs.get(job["id"])["state"] == "running"
    w.service.jobs.finish(second, "review", record={"verdict": "abstain"})
    assert w.service.jobs.get(job["id"])["result"] == {"verdict": "abstain"}


@pytest.mark.parametrize(
    "path_kind",
    [
        "ssh",
        "network",
        "derived",
        "refresh",
        "refresh_lock",
        "wal",
        "shm",
        "journal",
        "symlink",
        "hardlink",
        "excluded",
        "excluded_sidecar",
    ],
)
def test_protected_paths_rejected_before_any_queue_creation(saved, tmp_path, path_kind):
    spec, _, aliases = saved
    mapping = {
        "ssh": spec.ssh_database_path,
        "network": spec.network_database_path,
        "derived": spec.database_path,
        "refresh": reserved_paths(spec)[1],
        "refresh_lock": reserved_paths(spec)[0],
    }
    excluded = tmp_path / "private-config.json"
    excluded.write_text("{}")
    excluded.chmod(0o600)
    candidate = Path(mapping.get(path_kind, tmp_path / "queue.sqlite"))
    if path_kind in ("wal", "shm", "journal"):
        candidate = Path(spec.ssh_database_path + "-" + path_kind)
    if path_kind == "symlink":
        candidate.symlink_to(spec.database_path)
    if path_kind == "hardlink":
        candidate.hardlink_to(spec.database_path)
    if path_kind == "excluded":
        candidate = excluded
    if path_kind == "excluded_sidecar":
        candidate = Path(str(excluded) + "-wal")
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    with pytest.raises(ValueError, match="joint_ai_path_conflict"):
        Service(
            spec,
            Settings(database_path=candidate),
            aliases=aliases,
            excluded_paths=(excluded,),
        )
    assert {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()} == before


def test_bad_optional_config_disables_without_touching_existing_queue(
    saved, tmp_path, monkeypatch
):
    spec, _, aliases = saved
    ssh = Jobs(tmp_path / "ssh-ai.sqlite")
    before = ssh.secret()
    config = tmp_path / "joint-config.json"
    config.write_text(json.dumps({"database_path": str(ssh.path)}))
    config.chmod(0o600)
    monkeypatch.setenv("RISKOPS_JOINT_AI_CONFIG", str(config))
    service = Service.from_environment(spec, aliases=aliases)
    assert (
        not service.enabled
        and service.status()["error"] == "joint_ai_configuration_unavailable"
    )
    assert ssh.secret() == before and ssh.budget()["unresolved_calls"] == 0


@pytest.mark.parametrize(
    "change",
    [
        {"mode": "api"},
        {"mode": "recorded"},
        {"allow_external": True},
        {"keys_file": "/synthetic/key"},
    ],
)
def test_no_external_mode_or_credentials_can_be_configured(tmp_path, change):
    with pytest.raises(ValueError):
        Settings(database_path=tmp_path / "queue.sqlite", **change)


def test_thread_start_failure_is_optional_and_close_safe(world, monkeypatch):
    def cannot_start(self):
        raise RuntimeError("synthetic thread capacity")

    monkeypatch.setattr(module.threading.Thread, "start", cannot_start)
    with pytest.raises(RuntimeError, match="synthetic thread capacity"):
        world.service.start()
    assert world.service.thread is None
    world.service.close()


def test_noncurrent_pinned_rehearsal_still_abstains_without_false_current(world):
    change_checkpoint(
        world.spec, lambda value: value.update(state="running", phase="discover")
    )
    job = enqueue(world)
    assert job["stale"] and job["current_review_state"] != "current"
    world.service.run_once()
    result = world.service.job(job["id"])
    assert (
        result["state"] == "review"
        and result["result"]["verdict"] == "abstain"
        and result["stale"]
    )


def test_twenty_distinct_history_revisions_need_at_most_one_preview(world, monkeypatch):
    w = world
    original = w.service._bundle(w.case_id, 1)
    bundles = {}
    for revision in range(1, 26):
        bundle = json.loads(json.dumps(original))
        bundle["case"]["revision"] = "R-" + format(revision, "024x")
        bundle["meta"]["case_revision"] = revision
        job_id = w.service.jobs.enqueue(
            w.case_id, bundle, w.service.config_sha, str(revision), "operator"
        )
        w.tick.value += 1
        bundle["preview_key"] = w.service.jobs.get(job_id)["cache_key"]
        bundles[revision] = bundle
    detail_calls, preview_calls = [], []

    def detail(case_id, revision):
        detail_calls.append((case_id, revision))
        return {"current": {"revision": 25}}

    monkeypatch.setattr(
        module, "open_query", lambda *a, **kw: SimpleNamespace(case_detail=detail)
    )

    def current(case_id, revision):
        preview_calls.append((case_id, revision))
        return bundles[revision]

    monkeypatch.setattr(w.service, "_bundle", current)
    history = w.service.history(w.case_id)
    assert len(history) == 20 and len(detail_calls) == 1
    assert preview_calls == [(w.case_id, 25)]
    assert all(
        row["stale"] and row["current_review_state"] == "historical"
        for row in history
        if row["case_revision"] < 25
    )
