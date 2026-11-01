"""Crash and race coverage uses disposable queues and synthetic paid receipts."""

from concurrent.futures import ThreadPoolExecutor, TimeoutError
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import sqlite3
from threading import Barrier, Event
from types import SimpleNamespace

import pytest

from app.agents.model_triage import BudgetExceeded
from app.agents.triage_budget import CallUncertain
from app.telemetry.ai_jobs import Jobs, Ledger


@pytest.fixture
def world(tmp_path):
    tick = SimpleNamespace(value=datetime(2026, 1, 1, 23, 59, 50, tzinfo=timezone.utc).timestamp())
    owner_tick = SimpleNamespace(value=tick.value)
    owner = Jobs(tmp_path / "owner.sqlite", clock=lambda: owner_tick.value)
    owner.set_budget(100, 60)
    joint = Jobs(tmp_path / "joint.sqlite", queue_kind="joint", budget_owner=owner,
                 clock=lambda: tick.value)
    return SimpleNamespace(owner=owner, joint=joint, tick=tick, owner_tick=owner_tick)


def claimed(jobs, label="synthetic-case"):
    case = {"incident_id": label, "revision": "synthetic-revision", "dossier_version": 3}
    bundle = {"case": case, "meta": {"execution_mode": "offline"}, "local_refs": {}}
    request_sha = hashlib.sha256(json.dumps(case, sort_keys=True).encode()).hexdigest()
    job_id = jobs.enqueue(label, bundle, "synthetic-config", request_sha, "synthetic-operator")
    job = jobs.claim(lease_seconds=10)
    assert job["id"] == job_id
    return job


def table(path, name):
    # SQLite's normal WAL/SHM bookkeeping is not financial or queue state.
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
        db.row_factory = sqlite3.Row
        return [dict(row) for row in db.execute("SELECT * FROM " + name + " ORDER BY 1")]


def logical(path):
    return {name: table(path, name) for name in
            ("ai_meta", "ai_jobs", "ai_attempts", "ai_calls", "ai_audit")}


def reopen(w):
    owner = Jobs(w.owner.path, clock=lambda: w.owner_tick.value)
    return Jobs(w.joint.path, queue_kind="joint", budget_owner=owner, clock=lambda: w.tick.value)


def fail_audit(monkeypatch, jobs, event):
    original = jobs._audit

    def audit(db, job_id, current_event, **kwargs):
        if current_event == event:
            raise RuntimeError("synthetic_local_audit_failure")
        return original(db, job_id, current_event, **kwargs)

    monkeypatch.setattr(jobs, "_audit", audit)
    return original


def test_owner_reservation_survives_local_commit_failure_without_resubmission(world, monkeypatch):
    w = world
    job = claimed(w.joint)
    before = logical(w.joint.path)
    original = fail_audit(monkeypatch, w.joint, "budget_reserved")
    with pytest.raises(RuntimeError, match="synthetic_local_audit_failure"):
        Ledger(w.joint, job).reserve(job["call_id"], 20)
    assert logical(w.joint.path) == before
    assert table(w.owner.path, "ai_calls")[0]["id"] == job["call_id"]
    monkeypatch.setattr(w.joint, "_audit", original)

    w.joint.retry_unsubmitted(job)
    assert w.joint.get(job["id"])["state"] == "uncertain"
    w.tick.value += 11
    restored = reopen(w)
    assert restored.claim() is None
    assert restored.get(job["id"])["attempt_count"] == 1
    assert len(table(w.owner.path, "ai_calls")) == 1
    assert table(w.joint.path, "ai_calls") == []
    assert restored.budget()["unresolved_calls"] == 1


def test_crash_before_reservation_allows_new_attempt_but_fences_old_worker(world):
    w = world
    old = claimed(w.joint)
    w.tick.value += 11
    restored = reopen(w)
    new = restored.claim()
    assert new["attempt_count"] == 2 and new["call_id"] != old["call_id"]
    with pytest.raises(CallUncertain):
        Ledger(w.joint, old).reserve(old["call_id"], 20)
    assert table(w.owner.path, "ai_calls") == []
    Ledger(restored, new).reserve(new["call_id"], 20)
    assert [row["id"] for row in table(w.owner.path, "ai_calls")] == [new["call_id"]]


@pytest.mark.parametrize("failure_event", [None, "budget_settled"])
def test_settlement_before_finish_is_replayed_once_after_restart(world, monkeypatch, failure_event):
    w = world
    job = claimed(w.joint)
    ledger = Ledger(w.joint, job)
    ledger.reserve(job["call_id"], 20)
    receipt = {"synthetic": True, "response_text": "bounded receipt"}
    if failure_event:
        fail_audit(monkeypatch, w.joint, failure_event)
        with pytest.raises(RuntimeError, match="synthetic_local_audit_failure"):
            ledger.complete(job["call_id"], 12, receipt)
    else:
        ledger.complete(job["call_id"], 12, receipt)
    w.tick.value += 11
    restored = reopen(w)
    recovered = restored.claim()
    assert recovered["call_id"] == job["call_id"]
    assert recovered["attempt_count"] == job["attempt_count"] == 1
    assert recovered["lease_token"] != job["lease_token"]
    assert restored.cached_call(recovered) == receipt
    assert Ledger(restored, recovered).reserve(recovered["call_id"], 20) == receipt
    restored.finish(recovered, "review", record=receipt)
    assert restored.claim() is None
    assert restored.get(job["id"])["result"] == receipt
    assert len(table(w.owner.path, "ai_calls")) == 1
    assert restored.budget()["charged_usd"] == 0.000012
    assert restored.budget()["unresolved_calls"] == 0


def test_late_receipt_reopens_uncertain_job_without_new_attempt_and_fences_old_finish(world):
    w = world
    old = claimed(w.joint)
    ledger = Ledger(w.joint, old)
    ledger.reserve(old["call_id"], 20)
    w.tick.value += 11
    assert w.joint.claim() is None
    assert w.joint.get(old["id"])["state"] == "uncertain"
    receipt = {"synthetic": "late receipt"}
    ledger.complete(old["call_id"], 11, receipt)
    restored = reopen(w)
    recovered = restored.claim()
    assert recovered["attempt_count"] == 1 and recovered["call_id"] == old["call_id"]
    assert restored.cached_call(recovered) == receipt
    w.joint.finish(old, "failed", error="synthetic_late_worker")
    assert restored.get(old["id"])["state"] == "running"
    restored.finish(recovered, "review", record=receipt)
    w.joint.finish(old, "failed", error="synthetic_late_worker")
    assert restored.get(old["id"])["state"] == "review"
    assert restored.get(old["id"])["result"] == receipt
    assert len(table(w.owner.path, "ai_calls")) == 1
    assert table(w.joint.path, "ai_calls") == []


def test_unknown_outcome_and_failed_receipt_keep_reservation_across_restart(world):
    w = world
    job = claimed(w.joint)
    ledger = Ledger(w.joint, job)
    ledger.reserve(job["call_id"], 20)
    ledger.fail(job["call_id"], "synthetic_timeout")
    w.tick.value += 11
    restored = reopen(w)
    for _ in range(3):
        assert restored.claim() is None
    assert restored.get(job["id"])["state"] == "uncertain"
    with pytest.raises(CallUncertain):
        Ledger(restored, job).reserve(job["call_id"], 20)
    assert restored.budget()["reserved_usd"] == 0.000020
    assert len(table(w.owner.path, "ai_calls")) == 1


@pytest.mark.parametrize("operation", ["reserve", "complete", "fail", "cached", "retry", "claim", "budget", "reopen"])
def test_missing_owner_never_recreates_pool_or_changes_pending_job(world, operation):
    w = world
    job = claimed(w.joint)
    ledger = Ledger(w.joint, job)
    ledger.reserve(job["call_id"], 20)
    w.tick.value += 11
    before = logical(w.joint.path)
    saved = w.owner.path.with_name("retained-owner.sqlite")
    w.owner.path.rename(saved)
    operations = {
        "reserve": lambda: ledger.reserve(job["call_id"], 20),
        "complete": lambda: ledger.complete(job["call_id"], 10, {"synthetic": True}),
        "fail": lambda: ledger.fail(job["call_id"], "synthetic_timeout"),
        "cached": lambda: w.joint.cached_call(job),
        "retry": lambda: w.joint.retry_unsubmitted(job),
        "claim": w.joint.claim,
        "budget": w.joint.budget,
        "reopen": lambda: Jobs(w.joint.path, queue_kind="joint", budget_owner=w.owner),
    }
    with pytest.raises(ValueError, match="shared_budget_owner_unavailable"):
        operations[operation]()
    assert not w.owner.path.exists()
    assert logical(w.joint.path) == before
    assert table(saved, "ai_calls")[0]["charged"] is None


def test_byte_equivalent_owner_replacement_is_rejected_for_existing_and_reopened_queue(world):
    w = world
    job = claimed(w.joint)
    Ledger(w.joint, job).reserve(job["call_id"], 20)
    original_inode = w.owner.path.stat().st_ino
    clone = w.owner.path.with_name("cloned-owner.sqlite")
    with closing(sqlite3.connect(w.owner.path)) as source, closing(sqlite3.connect(clone)) as target:
        source.backup(target)
    clone.chmod(0o600)
    clone.replace(w.owner.path)
    assert w.owner.path.stat().st_ino != original_inode
    before = logical(w.joint.path)
    with pytest.raises(ValueError, match="shared_budget_owner_mismatch"):
        w.joint.retry_unsubmitted(job)
    replacement = Jobs(w.owner.path, clock=lambda: w.owner_tick.value)
    with pytest.raises(ValueError, match="shared_budget_owner_mismatch"):
        Jobs(w.joint.path, queue_kind="joint", budget_owner=replacement)
    assert logical(w.joint.path) == before
    assert len(table(w.owner.path, "ai_calls")) == 1


def test_bound_queue_cannot_reopen_without_owner_and_pending_receipt_stays_reserved(world):
    w = world
    job = claimed(w.joint)
    Ledger(w.joint, job).reserve(job["call_id"], 20)
    before = logical(w.joint.path)
    with pytest.raises(ValueError, match="shared_budget_owner_required"):
        Jobs(w.joint.path, queue_kind="joint")
    assert logical(w.joint.path) == before
    assert reopen(w).budget()["reserved_usd"] == 0.000020


def test_two_queues_contend_for_final_total_slot_atomically(world):
    w = world
    prior = claimed(w.owner, "prior-ssh")
    Ledger(w.owner, prior).reserve(prior["call_id"], 50)
    Ledger(w.owner, prior).complete(prior["call_id"], 50, {"synthetic": "prior"})
    w.owner.finish(prior, "review")
    w.owner_tick.value += 86400
    ssh = claimed(w.owner, "new-ssh")
    joint = claimed(w.joint, "new-joint")
    ready = Barrier(2)

    def reserve(jobs, job):
        ready.wait(timeout=5)
        try:
            Ledger(jobs, job).reserve(job["call_id"], 30)
            return "reserved"
        except BudgetExceeded:
            return "budget_exceeded"

    with ThreadPoolExecutor(2) as pool:
        futures = [pool.submit(reserve, jobs, job) for jobs, job in ((w.owner, ssh), (w.joint, joint))]
        assert sorted(f.result(timeout=10) for f in futures) == ["budget_exceeded", "reserved"]
    assert len(table(w.owner.path, "ai_calls")) == 2
    assert w.joint.budget()["reserved_usd"] == 0.000030
    assert w.joint.budget()["charged_usd"] == 0.000050
    assert table(w.joint.path, "ai_calls") == []


def test_owner_day_survives_joint_clock_skew_and_late_settlement(world):
    w = world
    w.tick.value += 7 * 86400
    first = claimed(w.joint, "before-midnight")
    ledger = Ledger(w.joint, first)
    ledger.reserve(first["call_id"], 40)
    assert table(w.owner.path, "ai_calls")[0]["day"] == "2026-01-01"
    w.owner_tick.value += 20
    second = claimed(w.owner, "after-midnight")
    Ledger(w.owner, second).reserve(second["call_id"], 60)
    assert w.joint.budget()["today_committed_usd"] == 0.000060
    ledger.complete(first["call_id"], 30, {"synthetic": "late previous day"})
    assert w.joint.budget()["today_committed_usd"] == 0.000060
    assert w.joint.budget()["charged_usd"] == 0.000030
    assert w.joint.budget()["reserved_usd"] == 0.000060
    third = claimed(w.joint, "still-daily-limited")
    with pytest.raises(BudgetExceeded):
        Ledger(w.joint, third).reserve(third["call_id"], 1)


@pytest.mark.parametrize("contender", ["retry", "claim"])
def test_committed_reserve_keeps_queue_locked_until_recovery_can_see_owner(world, monkeypatch, contender):
    w = world
    job = claimed(w.joint)
    committed, release, contender_started = Event(), Event(), Event()
    original = w.joint._audit

    def audit(db, job_id, event, **kwargs):
        if event == "budget_reserved":
            committed.set()
            assert release.wait(timeout=5)
        return original(db, job_id, event, **kwargs)

    monkeypatch.setattr(w.joint, "_audit", audit)

    def recover():
        contender_started.set()
        if contender == "claim":
            return w.joint.claim()
        return w.joint.retry_unsubmitted(job)

    with ThreadPoolExecutor(2) as pool:
        reserving = pool.submit(Ledger(w.joint, job).reserve, job["call_id"], 20)
        try:
            assert committed.wait(timeout=5)
            assert len(table(w.owner.path, "ai_calls")) == 1
            if contender == "claim":
                w.tick.value += 11
            recovering = pool.submit(recover)
            assert contender_started.wait(timeout=5)
            with pytest.raises(TimeoutError):
                recovering.result(timeout=0.1)
        finally:
            release.set()
        assert reserving.result(timeout=5) is None
        assert recovering.result(timeout=5) is None
    assert w.joint.get(job["id"])["state"] == "uncertain"
    assert w.joint.get(job["id"])["attempt_count"] == 1
    assert len(table(w.owner.path, "ai_calls")) == 1
    assert w.joint.claim() is None


def test_unsubmitted_retry_holds_lock_from_absent_owner_read_through_queue_update(world, monkeypatch):
    w = world
    job = claimed(w.joint)
    absent_read, release, reserve_started = Event(), Event(), Event()
    original = w.joint._finish

    def finish(db, current, state, **kwargs):
        if state == "queued" and kwargs.get("error") == "provider_unavailable":
            absent_read.set()
            assert release.wait(timeout=5)
        return original(db, current, state, **kwargs)

    monkeypatch.setattr(w.joint, "_finish", finish)

    def reserve():
        reserve_started.set()
        return Ledger(w.joint, job).reserve(job["call_id"], 20)

    with ThreadPoolExecutor(2) as pool:
        retrying = pool.submit(w.joint.retry_unsubmitted, job)
        try:
            assert absent_read.wait(timeout=5)
            reserving = pool.submit(reserve)
            assert reserve_started.wait(timeout=5)
            with pytest.raises(TimeoutError):
                reserving.result(timeout=0.1)
        finally:
            release.set()
        assert retrying.result(timeout=5) is None
        with pytest.raises(CallUncertain):
            reserving.result(timeout=5)
    assert table(w.owner.path, "ai_calls") == []
    assert w.joint.get(job["id"])["state"] == "queued"
    new = w.joint.claim()
    assert new["attempt_count"] == 2
    Ledger(w.joint, new).reserve(new["call_id"], 20)
    assert [row["id"] for row in table(w.owner.path, "ai_calls")] == [new["call_id"]]
