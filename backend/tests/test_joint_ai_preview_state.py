"""Saved-case preview freshness and races use only disposable synthetic stores."""
from contextlib import closing
from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
import sqlite3

import pytest

from app.telemetry import joint_ai_preview as preview_module
from app.telemetry import joint_case_store as store_module
from app.telemetry import joint_refresh_state as refresh_state
from app.telemetry.ai_summary import Aliases
from app.telemetry.joint_case_contract import AnchorRequest, validate_read
from app.telemetry.joint_case_query import open_query
from app.telemetry.joint_case_store import JointCaseStore
from app.telemetry.joint_config import JointRefreshConfig
from test_joint_refresh import (
    NOW, complete, configured as configured, scheduled as scheduled,
    sources as sources, store_clock as store_clock,
)
from test_joint_reader import read as read_sources, store_digest


SECRET = b"synthetic-preview-state-secret-01"
AT = NOW + timedelta(seconds=2)


@pytest.fixture
def saved(scheduled):
    _, spec = scheduled
    complete(spec)
    query = open_query(spec.database_path, spec.scope, spec.limits,
                       catalog_min_seq=spec.catalog_min_seq)
    item, = query.list_cases()["items"]
    return spec, item["case_id"], Aliases(SECRET)


def preview(saved, *, now=AT, revision=1):
    spec, case_id, aliases = saved
    return preview_module.preview(spec, case_id, revision, aliases, now=now)


def change_checkpoint(spec, change):
    path = refresh_state.reserved_paths(spec)[1]
    value = json.loads(path.read_text())
    change(value)
    path.write_text(json.dumps(value))


def context(result):
    return result["meta"]["snapshot_context"]


def query(spec):
    return open_query(spec.database_path, spec.scope, spec.limits,
                      catalog_min_seq=spec.catalog_min_seq)


def observe(spec, value):
    store = JointCaseStore.open(spec.database_path)
    store.begin_cycle()
    item = store.next_item()
    assert item is not None
    return store.publish(item, value)


def changed_value(spec, sources):
    _, ssh, _, network_case, at = sources
    ssh.ingest("auth-a", "example.invalid", "preview-late", [{
        "event_id": "preview-late-success", "timestamp": (at + timedelta(seconds=24)).isoformat(),
        "identifier": "sshd", "message": (
            f"Accepted publickey for exampleuser from {network_case['src_ip']} port 42000 ssh2"
        ),
    }])
    request = AnchorRequest(network_case["incident_id"], network_case["revision"])
    return validate_read(spec.scope, request, read_sources(sources), limits=spec.limits)


def test_recent_completed_refresh_allows_only_saved_snapshot_current(saved):
    result = preview(saved)
    assert result["case"]["review_state"] == "current"
    assert context(result)["freshness"] == "current"
    assert context(result)["case_revision"] == context(result)["current_revision"] == 1
    assert "cross_store_not_atomic" in result["case"]["limitations"]
    assert result["case"]["coverage_complete"] is None
    assert result["case"]["counts"]["network"]["included"] > 0
    assert result["case"]["counts"]["ssh"]["included"] > 0


@pytest.mark.parametrize("kind", ["missing", "invalid", "disabled", "store_id", "query_epoch", "config_sha256", "future"])
def test_unproven_checkpoint_never_establishes_freshness(saved, kind):
    spec, case_id, aliases = saved
    checkpoint = refresh_state.reserved_paths(spec)[1]
    if kind == "missing":
        checkpoint.unlink()
    elif kind == "invalid":
        checkpoint.write_text("{")
    elif kind == "disabled":
        spec = replace(spec, refresh=JointRefreshConfig())
    elif kind == "future":
        change_checkpoint(spec, lambda value: value.update(
            last_success_at=refresh_state.stamp(AT + timedelta(seconds=1))))
    else:
        def wrong_binding(value):
            value["binding"][kind] = "f" * len(value["binding"][kind])
        change_checkpoint(spec, wrong_binding)
    result = preview((spec, case_id, aliases))
    assert context(result)["freshness"] == "unknown"
    assert result["case"]["review_state"] == ("unknown" if kind in {"missing", "disabled"} else "unavailable")


def test_recent_heartbeat_does_not_refresh_old_full_success(saved):
    spec, _, _ = saved
    later = AT + timedelta(seconds=spec.refresh.stale_after_seconds + 2)
    change_checkpoint(spec, lambda value: value.update(last_attempt_at=refresh_state.stamp(later)))
    result = preview(saved, now=later)
    assert context(result)["freshness"] == "stale"
    assert result["case"]["review_state"] == "stale"


def test_running_discovery_with_old_success_and_ready_database_is_not_current(saved):
    spec, _, _ = saved
    change_checkpoint(spec, lambda value: value.update(
        phase="discover", state="running", last_attempt_at=refresh_state.stamp(AT)))
    base = query(spec).status()
    refresh = refresh_state.read_refresh_status(spec, base, now=AT)
    # This transition can precede begin_discovery: !stale alone is insufficient.
    assert base["state"] == "ready" and not refresh["stale"]
    result = preview(saved)
    assert context(result)["freshness"] != "current"
    assert result["case"]["review_state"] != "current"


def test_saved_historical_projection_does_not_adopt_new_revision_evidence(saved, sources):
    spec, _, _ = saved
    before = preview(saved)
    newer = changed_value(spec, sources)
    assert observe(spec, newer) == "published"
    historical = preview(saved)
    latest = preview(saved, revision=2)
    assert historical["case"]["review_state"] == "historical"
    assert context(historical)["case_revision"] == 1
    assert context(historical)["current_revision"] == 2
    assert historical["case"]["evidence"] == before["case"]["evidence"]
    assert historical["meta"]["projection_sha256"] == before["meta"]["projection_sha256"]
    assert latest["case"]["counts"]["ssh"]["retained"] == 4
    assert historical["case"]["counts"]["ssh"]["retained"] == 3


def test_restore_epoch_invalidates_summary_identity_and_requires_revalidation(saved):
    spec, _, _ = saved
    before = preview(saved)
    epoch = "f" * 32
    assert epoch != context(before)["query_epoch"]
    with closing(sqlite3.connect(spec.database_path)) as db:
        db.execute("UPDATE joint_runtime SET query_epoch=?, revalidation_pending=1, "
                   "recovery_discovery_done=0, recovery_refresh_cycle=NULL, "
                   "recovery_discovery_cycle=NULL WHERE singleton=1", (epoch,))
        db.commit()
    after = preview(saved)
    assert after["case"]["review_state"] == "revalidation_required"
    assert context(after)["query_epoch"] == epoch
    assert context(after)["revalidation_pending"]
    assert after["case"]["revision"] != before["case"]["revision"]
    assert after["case"]["evidence"] == before["case"]["evidence"]


@pytest.mark.parametrize("mutation", ["revision", "unchanged", "epoch", "sidecar"])
def test_change_during_summary_build_rejects_mixed_preview(saved, sources, monkeypatch, mutation):
    spec, case_id, _ = saved
    original = query(spec).ai_snapshot(case_id, 1)
    value = changed_value(spec, sources) if mutation == "revision" else original.observation
    original_build = preview_module.build
    calls = []

    def build_then_change(*args, **kwargs):
        result = original_build(*args, **kwargs)
        calls.append(True)
        if mutation in ("revision", "unchanged"):
            monkeypatch.setattr(store_module, "_now", lambda: refresh_state.stamp(NOW + timedelta(seconds=1.5)))
            assert observe(spec, value) == ("published" if mutation == "revision" else "unchanged")
        elif mutation == "epoch":
            with closing(sqlite3.connect(spec.database_path)) as db:
                db.execute("UPDATE joint_runtime SET query_epoch=?, revalidation_pending=1 WHERE singleton=1",
                           ("e" * 32,))
                db.commit()
        else:
            change_checkpoint(spec, lambda checkpoint: checkpoint.update(
                last_attempt_at=refresh_state.stamp(AT)))
        return result

    monkeypatch.setattr(preview_module, "build", build_then_change)
    with pytest.raises(preview_module.JointPreviewError, match="joint_preview_changed") as caught:
        preview(saved)
    assert caught.value.code == "joint_preview_changed"
    assert calls == [True]
    if mutation == "unchanged":
        after = query(spec).ai_snapshot(case_id, 1)
        assert after.observation == original.observation
        assert after.status["generation"] == original.status["generation"]
        assert after.detail["current"]["last_success"] != original.detail["current"]["last_success"]


def test_missing_revision_returns_none_without_creating_state(saved):
    spec, _, _ = saved
    directory = Path(spec.database_path).parent
    before = store_digest(spec.database_path)
    before_files = set(directory.iterdir())
    assert preview(saved, revision=999) is None
    assert store_digest(spec.database_path) == before
    assert set(directory.iterdir()) == before_files


def test_snapshot_reads_case_and_status_from_one_transaction_during_publish(saved, sources, monkeypatch):
    spec, case_id, _ = saved
    reader = query(spec)
    before = reader.ai_snapshot(case_id, 1)
    newer = changed_value(spec, sources)
    original_detail = reader._case_detail
    publishes = []

    def read_then_publish(db, identity, revision):
        detail = original_detail(db, identity, revision)
        publishes.append(observe(spec, newer))
        return detail

    monkeypatch.setattr(reader, "_case_detail", read_then_publish)
    during = reader.ai_snapshot(case_id, 1)
    assert publishes == ["published"]
    assert during == before
    after = query(spec).ai_snapshot(case_id, 1)
    assert after.status["generation"] == before.status["generation"] + 1
    assert after.detail["current"]["revision"] == 2
    assert during.detail["current"]["revision"] == 1


def test_preview_needs_no_sources_writers_queue_or_model(saved, sources, monkeypatch):
    spec, _, _ = saved
    paths = [Path(spec.database_path), *(Path(store.path) for store in sources[:2])]
    before = [store_digest(path) for path in paths]
    checkpoint = refresh_state.reserved_paths(spec)[1]
    before_checkpoint = checkpoint.read_bytes()
    directory = Path(spec.database_path).parent
    before_files = set(directory.iterdir())

    def forbidden(*args, **kwargs):
        pytest.fail("local preview attempted source, writer, queue or model access")

    for target in (
        "app.telemetry.joint_reader.read_joint_evidence",
        "app.telemetry.joint_refresh.tick",
        "app.telemetry.joint_refresh_state.writer_lock",
        "app.telemetry.joint_cli.run",
        "app.telemetry.joint_case_store.JointCaseStore._connection",
        "app.telemetry.ai_jobs.Jobs.__init__",
        "app.agents.triage_api.APITriage.triage",
        "app.agents.triage_api.APITriage._send",
        "socket.create_connection",
    ):
        monkeypatch.setattr(target, forbidden)
    result = preview(saved)
    assert result["case"]["review_state"] == "current"
    assert result["preview"]["external_calls"] is False
    assert [store_digest(path) for path in paths] == before
    assert checkpoint.read_bytes() == before_checkpoint
    assert set(directory.iterdir()) == before_files
