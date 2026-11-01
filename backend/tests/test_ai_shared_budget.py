"""Shared accounting uses only disposable queues and authored synthetic records."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
import sqlite3
from types import SimpleNamespace

import pytest

from app.agents.model_triage import BudgetExceeded
from app.agents.triage_budget import CallUncertain
from app.telemetry.ai_jobs import Jobs, Ledger, SHARED_QUEUE_KIND


def claimed(jobs, label="case"):
    case = {"incident_id": label, "revision": "synthetic-revision"}
    bundle = {"case": case, "meta": {"execution_mode": "offline"}, "local_refs": {}}
    jobs.enqueue(label, bundle, "synthetic-config", "request-" + label, "synthetic-operator", queue_limit=1000)
    return jobs.claim()


@pytest.fixture
def world(tmp_path):
    tick = SimpleNamespace(value=datetime(2026, 1, 1, 23, 59, tzinfo=timezone.utc).timestamp())
    owner = Jobs(tmp_path / "ssh.sqlite", clock=lambda: tick.value)
    owner.set_budget(100, 60)
    joint = Jobs(tmp_path / "joint.sqlite", queue_kind="joint", budget_owner=owner,
                 clock=lambda: tick.value)
    return SimpleNamespace(owner=owner, joint=joint, tick=tick)


def rows(jobs, table):
    with jobs.connection() as db:
        return [dict(row) for row in db.execute("SELECT * FROM " + table)]


def test_shared_limits_include_prior_ssh_spending_and_pending_reservations(world):
    w = world
    first = claimed(w.owner, "charged")
    ledger = Ledger(w.owner, first)
    ledger.reserve(first["call_id"], 30)
    ledger.complete(first["call_id"], 20, {"synthetic": True})
    second = claimed(w.owner, "uncertain")
    Ledger(w.owner, second).reserve(second["call_id"], 30)
    Ledger(w.owner, second).fail(second["call_id"], "synthetic_timeout")
    joint = claimed(w.joint)
    with pytest.raises(BudgetExceeded):
        Ledger(w.joint, joint).reserve(joint["call_id"], 11)
    Ledger(w.joint, joint).reserve(joint["call_id"], 10)
    assert w.joint.budget() == w.owner.budget()
    assert w.owner.budget()["today_committed_usd"] == 0.000060
    assert rows(w.joint, "ai_calls") == []
    assert len(rows(w.owner, "ai_calls")) == 3


def test_shared_binding_survives_restart_and_changes_no_owner_identity_or_schema(world):
    w = world
    before = rows(w.owner, "ai_meta")
    joint = Jobs(w.joint.path, queue_kind="joint", budget_owner=w.owner)
    assert joint.budget() == w.owner.budget()
    assert rows(w.owner, "ai_meta") == before
    with joint.connection() as db:
        binding = json.loads(db.execute("SELECT value FROM ai_meta WHERE name='shared_budget_owner'").fetchone()[0])
    assert binding["path"] == str(w.owner.path)
    assert binding["inode"] == w.owner.path.stat().st_ino
    assert set(binding) == {"version", "path", "device", "inode", "alias_sha256", "total_limit", "daily_limit"}
    with pytest.raises(ValueError, match="shared_budget_owner_required"):
        Jobs(joint.path, queue_kind="joint")
    with pytest.raises(ValueError, match="shared_budget_owner_controls_limits"):
        joint.set_budget(100, 60)


def test_other_owner_cannot_rebind_queue(world, tmp_path):
    other = Jobs(tmp_path / "other.sqlite")
    other.set_budget(100, 60)
    before = rows(world.joint, "ai_meta")
    with pytest.raises(ValueError, match="shared_budget_owner_mismatch"):
        Jobs(world.joint.path, queue_kind="joint", budget_owner=other)
    assert rows(world.joint, "ai_meta") == before


@pytest.mark.parametrize("mode", ["no_limits", "local_calls", "local_limits", "wrong_kind"])
def test_invalid_first_binding_never_creates_a_new_pool(tmp_path, mode):
    owner = Jobs(tmp_path / "owner.sqlite")
    if mode != "no_limits":
        owner.set_budget(100, 60)
    path = tmp_path / "joint.sqlite"
    if mode in ("local_calls", "local_limits"):
        joint = Jobs(path, queue_kind="joint")
        with joint.connection(write=True) as db:
            if mode == "local_calls":
                db.execute("INSERT INTO ai_calls VALUES('synthetic','2026-01-01',1,NULL,'uncertain',NULL,NULL)")
            else:
                db.execute("INSERT INTO ai_meta VALUES('total_limit','100')")
    before = rows(owner, "ai_meta")
    with pytest.raises(ValueError):
        Jobs(path, queue_kind="ssh" if mode == "wrong_kind" else "joint", budget_owner=owner)
    assert rows(owner, "ai_meta") == before
    assert rows(owner, "ai_calls") == []


def test_owner_missing_fails_closed_without_recreating_file(world):
    w = world
    job = claimed(w.joint)
    w.owner.path.unlink()
    with pytest.raises(ValueError, match="shared_budget_owner_unavailable"):
        Ledger(w.joint, job).reserve(job["call_id"], 10)
    assert not w.owner.path.exists()
    with pytest.raises(ValueError, match="shared_budget_owner_unavailable"):
        w.joint.claim()
    assert not w.owner.path.exists()


def test_owner_budget_changes_are_not_implicitly_accepted(world):
    w = world
    job = claimed(w.joint)
    with w.owner.connection(write=True) as db:
        db.execute("UPDATE ai_meta SET value='200' WHERE name='total_limit'")
    with pytest.raises(ValueError, match="shared_budget_owner_mismatch"):
        Ledger(w.joint, job).reserve(job["call_id"], 10)
    assert rows(w.owner, "ai_calls") == []


def test_last_daily_slot_is_shared_under_concurrent_reservations(world):
    w = world
    work = [(w.owner, claimed(w.owner)), (w.joint, claimed(w.joint))]
    def reserve(item):
        jobs, job = item
        try:
            Ledger(jobs, job).reserve(job["call_id"], 60)
            return "reserved"
        except BudgetExceeded:
            return "exhausted"
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(reserve, work)) == ["exhausted", "reserved"]
    assert w.joint.budget()["reserved_usd"] == 0.000060


def test_owner_clock_controls_daily_rollover_and_total_is_retained(world):
    w = world
    # A joint clock on a different day cannot bypass the owner's daily limit.
    w.joint.clock = lambda: w.tick.value + 86400
    one = claimed(w.joint, "first")
    Ledger(w.joint, one).reserve(one["call_id"], 60)
    w.joint.finish(one, "uncertain")
    two = claimed(w.joint, "second")
    with pytest.raises(BudgetExceeded):
        Ledger(w.joint, two).reserve(two["call_id"], 1)
    w.tick.value += 61
    Ledger(w.joint, two).reserve(two["call_id"], 40)
    three = claimed(w.joint, "third")
    with pytest.raises(BudgetExceeded):
        Ledger(w.joint, three).reserve(three["call_id"], 1)
    assert w.joint.budget()["today_committed_usd"] == 0.000040
    assert w.joint.budget()["reserved_usd"] == 0.000100


def test_reservation_failure_and_settlement_are_strict_and_idempotent(world):
    w = world
    job = claimed(w.joint)
    ledger = Ledger(w.joint, job)
    ledger.reserve(job["call_id"], 10)
    with pytest.raises(CallUncertain):
        ledger.reserve(job["call_id"], 10)
    with pytest.raises(ValueError, match="reservation changed"):
        ledger.reserve(job["call_id"], 11)
    ledger.fail(job["call_id"], "synthetic_timeout")
    before = rows(w.joint, "ai_audit")
    ledger.fail(job["call_id"], "synthetic_timeout")
    assert rows(w.joint, "ai_audit") == before
    with pytest.raises(ValueError, match="failure changed"):
        ledger.fail(job["call_id"], "other_error")
    ledger.complete(job["call_id"], 5, {"synthetic": "receipt"})
    before = rows(w.joint, "ai_audit")
    ledger.complete(job["call_id"], 5, {"synthetic": "receipt"})
    ledger.fail(job["call_id"], "synthetic_timeout")
    assert rows(w.joint, "ai_audit") == before
    assert ledger.reserve(job["call_id"], 10) == {"synthetic": "receipt"}
    with pytest.raises(ValueError, match="settlement changed"):
        ledger.complete(job["call_id"], 6, {"synthetic": "receipt"})
    assert w.joint.budget()["charged_usd"] == 0.000005


@pytest.mark.parametrize("amount", [True, 0, -1, 1.0, "1", 2**63])
def test_invalid_reservation_cannot_touch_owner(world, amount):
    job = claimed(world.joint)
    with pytest.raises(ValueError):
        Ledger(world.joint, job).reserve(job["call_id"], amount)
    assert rows(world.owner, "ai_calls") == []


@pytest.mark.parametrize("change", ["lease_token", "call_id", "request_sha", "attempt_count"])
def test_forged_attempt_cannot_reserve_shared_funds(world, change):
    job = claimed(world.joint)
    fake = {**job, change: 99 if change == "attempt_count" else "synthetic-forged"}
    with pytest.raises((ValueError, CallUncertain)):
        Ledger(world.joint, fake).reserve(fake["call_id"], 1)
    assert rows(world.owner, "ai_calls") == []


def test_late_overrun_settlement_halts_both_queues(world):
    w = world
    job = claimed(w.joint)
    ledger = Ledger(w.joint, job)
    ledger.reserve(job["call_id"], 10)
    w.tick.value += 301
    assert w.joint.claim() is None
    assert w.joint.get(job["id"])["state"] == "uncertain"
    ledger.complete(job["call_id"], 15, {"synthetic": "late-receipt"})
    restored = w.joint.claim()
    assert restored["call_id"] == job["call_id"]
    assert restored["attempt_count"] == job["attempt_count"]
    assert w.joint.cached_call(restored) == {"synthetic": "late-receipt"}
    assert w.owner.budget()["halted"] and w.joint.budget()["halted"]
    ssh = claimed(w.owner)
    with pytest.raises(BudgetExceeded):
        Ledger(w.owner, ssh).reserve(ssh["call_id"], 1)


def many_uncertain(tmp_path, count=105):
    tick = SimpleNamespace(value=100000)
    owner = Jobs(tmp_path / "many-owner.sqlite", clock=lambda: tick.value)
    owner.set_budget(1000, 1000)
    joint = Jobs(tmp_path / "many-joint.sqlite", queue_kind="joint", budget_owner=owner,
                 clock=lambda: tick.value)
    jobs = []
    for number in range(count):
        job = claimed(joint, "case-" + str(number))
        Ledger(joint, job).reserve(job["call_id"], 1)
        jobs.append(job)
    for job in jobs:
        joint.finish(job, "uncertain", error="provider_outcome_unknown")
    return owner, joint, tick, jobs


def test_many_unresolved_calls_do_not_starve_expired_running_job(tmp_path):
    owner, joint, tick, _ = many_uncertain(tmp_path)
    first = claimed(joint, "unsubmitted")
    tick.value += 301
    recovered = joint.claim()
    assert recovered["id"] == first["id"]
    assert recovered["attempt_count"] == 2
    assert recovered["call_id"] != first["call_id"]
    assert owner.budget()["unresolved_calls"] == 105


def test_rotating_receipt_scan_finds_late_receipt_after_first_hundred(tmp_path):
    owner, joint, _, jobs = many_uncertain(tmp_path)
    late = max(jobs, key=lambda job: job["id"])
    assert joint.claim() is None  # Advance the first bounded receipt scan.
    Ledger(joint, late).complete(late["call_id"], 1, {"synthetic": "last-receipt"})
    reopened = Jobs(joint.path, queue_kind="joint", budget_owner=owner, clock=joint.clock)
    restored = reopened.claim()
    assert restored["id"] == late["id"]
    assert restored["call_id"] == late["call_id"]
    assert restored["attempt_count"] == 1
    assert reopened.cached_call(restored) == {"synthetic": "last-receipt"}


def test_large_paid_receipt_preserves_known_cost_and_halts_overrun(world):
    job = claimed(world.joint)
    ledger = Ledger(world.joint, job)
    ledger.reserve(job["call_id"], 10)
    record = {"synthetic": "x" * (300 * 1024)}
    ledger.complete(job["call_id"], 20, record)
    assert world.joint.cached_call(job) == record
    assert world.owner.budget()["charged_usd"] == 0.000020
    assert world.owner.budget()["halted"]


def test_missing_local_queue_is_not_recreated(world):
    world.joint.path.unlink()
    with pytest.raises(sqlite3.OperationalError):
        world.joint.claim()
    assert not world.joint.path.exists()


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
@pytest.mark.parametrize("direction", ["owner_is_sidefile", "joint_is_sidefile"])
def test_sqlite_sidefile_overlap_rejected_before_owner_is_opened(tmp_path, suffix, direction):
    base = tmp_path / "queue.sqlite"
    owner_path = base if direction == "joint_is_sidefile" else base.with_name(base.name + suffix)
    joint_path = base.with_name(base.name + suffix) if direction == "joint_is_sidefile" else base
    owner = Jobs(owner_path)
    owner.set_budget(100, 60)
    before = owner.path.read_bytes()
    metadata = rows(owner, "ai_meta")
    with pytest.raises(ValueError, match="shared_budget_owner_mismatch"):
        Jobs(joint_path, queue_kind="joint", budget_owner=owner)
    assert owner.path.read_bytes() == before
    assert rows(owner, "ai_meta") == metadata
    assert rows(owner, "ai_calls") == []


@pytest.mark.parametrize("alias_kind", ["hardlink", "symlink"])
@pytest.mark.parametrize("suffix", ["", "-wal", "-shm", "-journal"])
def test_existing_sidefile_alias_cannot_damage_owner(tmp_path, alias_kind, suffix):
    owner = Jobs(tmp_path / "owner.sqlite")
    owner.set_budget(100, 60)
    local = tmp_path / "joint.sqlite"
    target = local.with_name(local.name + suffix)
    if alias_kind == "hardlink":
        os.link(owner.path, target)
    else:
        target.symlink_to(owner.path)
    before = owner.path.read_bytes()
    metadata = rows(owner, "ai_meta")
    with pytest.raises(ValueError, match="shared_budget_owner_mismatch"):
        Jobs(local, queue_kind="joint", budget_owner=owner)
    assert owner.path.read_bytes() == before
    assert rows(owner, "ai_meta") == metadata


# Frozen implementation from the pre-shared queue format. Keeping this guard
# independent of current Jobs proves rollback workers reject the new format.
def _legacy_kind_guard(self, db, *, initialize=False):
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
              if not row[0].startswith("sqlite_")}
    if not tables and initialize:
        # A foreign view-only or branded empty database is not a new queue.
        objects = [row[0] for row in db.execute("SELECT name FROM sqlite_master")
                   if not row[0].startswith("sqlite_")]
        if (objects or db.execute("PRAGMA application_id").fetchone()[0] != 0
                or db.execute("PRAGMA user_version").fetchone()[0] != 0):
            raise ValueError("analysis_queue_kind_mismatch")
        return
    required = {"ai_meta", "ai_jobs", "ai_attempts", "ai_calls", "ai_audit"}
    if tables != required:
        raise ValueError("analysis_queue_kind_mismatch")
    row = db.execute("SELECT value FROM ai_meta WHERE name='queue_kind'").fetchone()
    if row is not None:
        if row[0] != self.queue_kind:
            raise ValueError("analysis_queue_kind_mismatch")
        return
    if not initialize or self.queue_kind != "ssh":
        raise ValueError("analysis_queue_kind_mismatch")
    # Only the existing manual SSH format may acquire its missing marker.
    # Preserve its alias key, calls, uncertain reservations and audit rows.
    alias_row = db.execute("SELECT value FROM ai_meta WHERE name='alias_secret'").fetchone()
    if alias_row is None or not isinstance(alias_row[0], str) or len(alias_row[0]) != 64:
        raise ValueError("analysis_queue_kind_mismatch")
    try:
        bytes.fromhex(alias_row[0])
        for (raw,) in db.execute("SELECT dossier_json FROM ai_jobs"):
            case = json.loads(raw)
            if (not isinstance(case, dict) or case.get("dossier_version") not in (None, 3)
                    or not isinstance(case.get("incident_id"), str)
                    or not isinstance(case.get("revision"), str)):
                raise ValueError
    except (ValueError, TypeError):
        raise ValueError("analysis_queue_kind_mismatch") from None


def test_legacy_worker_cannot_recover_and_repeat_a_shared_reservation(world):
    w = world
    job = claimed(w.joint)
    Ledger(w.joint, job).reserve(job["call_id"], 10)
    w.tick.value += 301
    with sqlite3.connect(w.joint.path) as db:
        before = db.execute("SELECT * FROM ai_jobs").fetchall()
        with pytest.raises(ValueError, match="analysis_queue_kind_mismatch"):
            _legacy_kind_guard(SimpleNamespace(queue_kind="joint"), db, initialize=True)
        assert db.execute("SELECT * FROM ai_jobs").fetchall() == before
    assert w.joint.claim() is None
    assert w.joint.get(job["id"])["state"] == "uncertain"
    assert w.joint.get(job["id"])["attempt_count"] == 1
    with pytest.raises(CallUncertain):
        Ledger(w.joint, job).reserve(job["call_id"], 10)
    assert len(rows(w.owner, "ai_calls")) == 1


def test_binding_existing_offline_queue_preserves_history_and_alias(tmp_path):
    owner = Jobs(tmp_path / "owner.sqlite")
    owner.set_budget(100, 60)
    offline = Jobs(tmp_path / "offline.sqlite", queue_kind="joint")
    job = claimed(offline)
    offline.finish(job, "review", record={"synthetic": "offline-history"})
    preserved = {table: rows(offline, table) for table in ("ai_jobs", "ai_attempts", "ai_audit", "ai_calls")}
    alias = offline.secret()
    bound = Jobs(offline.path, queue_kind="joint", budget_owner=owner)
    assert bound.queue_kind == "joint" and bound.secret() == alias
    assert {table: rows(bound, table) for table in preserved} == preserved
    meta = {row["name"]: row["value"] for row in rows(bound, "ai_meta")}
    assert meta["queue_kind"] == SHARED_QUEUE_KIND
    assert "shared_budget_owner" in meta
    with pytest.raises(ValueError, match="shared_budget_owner_required"):
        offline.claim()


@pytest.mark.parametrize("broken", ["old_marker_with_binding", "new_marker_without_binding"])
def test_inconsistent_shared_marker_is_never_implicitly_repaired(world, broken):
    with sqlite3.connect(world.joint.path) as db:
        if broken == "old_marker_with_binding":
            db.execute("UPDATE ai_meta SET value='joint' WHERE name='queue_kind'")
        else:
            db.execute("DELETE FROM ai_meta WHERE name='shared_budget_owner'")
        before = db.execute("SELECT * FROM ai_meta ORDER BY name").fetchall()
    with pytest.raises(ValueError, match="shared_budget_owner_mismatch"):
        Jobs(world.joint.path, queue_kind="joint", budget_owner=world.owner)
    with sqlite3.connect(world.joint.path) as db:
        assert db.execute("SELECT * FROM ai_meta ORDER BY name").fetchall() == before


def test_failed_initial_binding_rolls_back_marker_and_binding_together(tmp_path):
    owner = Jobs(tmp_path / "owner.sqlite")
    owner.set_budget(100, 60)
    offline = Jobs(tmp_path / "offline.sqlite", queue_kind="joint")
    before = rows(offline, "ai_meta")
    with offline.connection(write=True) as db:
        db.execute("CREATE TRIGGER reject_binding BEFORE INSERT ON ai_meta "
                   "WHEN NEW.name='shared_budget_owner' BEGIN SELECT RAISE(ABORT,'synthetic-stop'); END")
    with pytest.raises(sqlite3.IntegrityError, match="synthetic-stop"):
        Jobs(offline.path, queue_kind="joint", budget_owner=owner)
    assert rows(offline, "ai_meta") == before
    with offline.connection(write=True) as db:
        db.execute("DROP TRIGGER reject_binding")
    bound = Jobs(offline.path, queue_kind="joint", budget_owner=owner)
    assert bound.budget() == owner.budget()


def test_competing_owners_cannot_both_bind_existing_offline_queue(tmp_path):
    from threading import Barrier

    owners = [Jobs(tmp_path / (str(number) + ".sqlite")) for number in range(2)]
    for owner in owners:
        owner.set_budget(100, 60)
    path = tmp_path / "joint.sqlite"
    Jobs(path, queue_kind="joint")
    barrier = Barrier(2)
    def bind(owner):
        barrier.wait(timeout=10)
        try:
            return Jobs(path, queue_kind="joint", budget_owner=owner)
        except ValueError:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(bind, owners))
    assert sum(jobs is not None for jobs in outcomes) == 1
    winner = next(jobs for jobs in outcomes if jobs is not None)
    meta = {row["name"]: row["value"] for row in rows(winner, "ai_meta")}
    assert meta["queue_kind"] == SHARED_QUEUE_KIND
    assert json.loads(meta["shared_budget_owner"])["path"] == str(winner.budget_owner.path)
    assert all(rows(owner, "ai_calls") == [] for owner in owners)


@pytest.mark.parametrize("kind", ["ssh", "joint"])
def test_unbound_queue_keeps_legacy_marker(tmp_path, kind):
    jobs = Jobs(tmp_path / "unbound.sqlite", queue_kind=kind)
    with jobs.connection() as db:
        assert db.execute("SELECT value FROM ai_meta WHERE name='queue_kind'").fetchone()[0] == kind
        _legacy_kind_guard(SimpleNamespace(queue_kind=kind), db)
