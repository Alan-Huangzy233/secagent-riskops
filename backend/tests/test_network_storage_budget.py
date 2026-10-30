"""Synthetic storage-budget boundaries and receipt-preserving expansion."""
from dataclasses import asdict
import sqlite3
from types import SimpleNamespace

from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from app.live_api import create_app
from app.telemetry.config import LiveConfig, NetworkIngestConfig, hash_operator_password
from app.telemetry.network_protocol import validate_ack
from app.telemetry.network_store import NetworkStore, NetworkStoreError
from app.telemetry.network_worker import NetworkWorker
from test_network_store import NOW, batch, entry, profile


MIB = 1024**2
GIB = 1024**3


def configuration(tmp_path, **changes):
    return NetworkIngestConfig.model_validate({
        "database_path": str(tmp_path / "synthetic-network.sqlite3"),
        "sources": [{"id": "synthetic-a", "hostname": "network.example.invalid",
                     "token_sha256": "b" * 64, "profiles": [asdict(profile())]}],
        **changes,
    })


@pytest.mark.parametrize("budget", [MIB, GIB, 2 * GIB])
def test_explicit_network_storage_budget_accepts_supported_boundaries(tmp_path, budget):
    config = configuration(tmp_path, max_storage_bytes=budget)
    assert config.max_storage_bytes == budget
    assert config.model_dump(exclude={"max_storage_bytes"}) == configuration(tmp_path).model_dump(
        exclude={"max_storage_bytes"})


def test_network_storage_default_remains_unchanged(tmp_path):
    assert configuration(tmp_path).max_storage_bytes == 256 * MIB


@pytest.mark.parametrize("budget", [2 * GIB + 1, MIB - 1, -1, True, False,
                                    float(GIB), str(GIB), None])
def test_network_storage_budget_rejects_out_of_bounds_or_non_integer_values(tmp_path, budget):
    with pytest.raises(ValidationError) as error:
        configuration(tmp_path, max_storage_bytes=budget)
    assert {item["loc"] for item in error.value.errors()} == {("max_storage_bytes",)}



def test_explicit_storage_budget_reaches_the_application_store(tmp_path, monkeypatch):
    # The real application startup applies this validated budget. No analysis
    # worker, AI service, provider, external request or large allocation is needed.
    monkeypatch.setattr(NetworkWorker, "start", lambda self: None)
    monkeypatch.setattr(NetworkWorker, "close", lambda self: None)
    config = LiveConfig(
        database_path=str(tmp_path / "synthetic-ssh.sqlite3"),
        notifications_enabled=False,
        sources=[{"id": "synthetic-ssh", "hostname": "ssh.example.invalid",
                  "token_sha256": "a" * 64}],
        operator_username="operator",
        operator_password_pbkdf2=hash_operator_password("synthetic-budget-test-password"),
        network_ingest=configuration(tmp_path, max_storage_bytes=2 * GIB),
    )
    application = create_app(config, control=SimpleNamespace(block_listener=None),
                             ai=SimpleNamespace())
    with TestClient(application):
        store = application.state.network_store
        assert store.max_storage_bytes == 2 * GIB
        assert store.status()["limits"]["storage_bytes"] == 2 * GIB
        assert store.status()["database_bytes"] < MIB


def saved_database(path):
    """Compare schema, receipt content, cursor state and version without writes."""
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as db:
        return (db.execute("PRAGMA application_id").fetchone()[0],
                db.execute("PRAGMA user_version").fetchone()[0], tuple(db.iterdump()))


def test_expansion_preserves_receipts_and_replay_and_unsafe_lowering_preserves_data(tmp_path):
    path = tmp_path / "synthetic-network.sqlite3"
    original = NetworkStore(path, max_storage_bytes=MIB)
    first = batch(0, [entry(0), entry(1, reject=True)])
    first_ack = original.ingest(first, profile(), now_us=NOW)
    checkpoint = first["cursor_after"]
    old_page_limit = original.status()["page_limit"]

    # Find the actual SQLite limit using bounded authored batches. This exercises
    # the same reserved WAL budget with only a few hundred KiB of temporary data.
    for index in range(1, 40):
        pending = batch(index, [entry(index * 10 + offset,
            cursor=f"synthetic-long-{index}-{offset}-" + "x" * 1900)
            for offset in range(10)], before=checkpoint)
        before = saved_database(path)
        try:
            original.ingest(pending, profile(), now_us=NOW)
        except NetworkStoreError as error:
            assert str(error) == "storage_capacity_exceeded"
            assert saved_database(path) == before
            break
        checkpoint = pending["cursor_after"]
    else:
        pytest.fail("Synthetic batches did not reach the bounded storage limit")

    assert original.sources()[0]["checkpoint"] == checkpoint
    preserved_counts = original.status()["counts"]
    expanded = NetworkStore(path, max_storage_bytes=2 * MIB)
    assert saved_database(path) == before
    assert expanded.ingest(first, profile(), now_us=NOW) == first_ack
    assert saved_database(path) == before

    recovered_ack = expanded.ingest(pending, profile(), now_us=NOW)
    validate_ack(recovered_ack, pending)
    after = expanded.status()
    assert after["counts"] == {**preserved_counts,
        "events": preserved_counts["events"] + 10,
        "receipts": preserved_counts["receipts"] + 10,
        "batches": preserved_counts["batches"] + 1}
    assert after["page_count"] > old_page_limit
    assert expanded.sources()[0]["checkpoint"] == pending["cursor_after"]

    # Once new pages are used, restoring the old quota must fail rather than
    # truncate evidence. Keeping the expanded quota remains a valid recovery.
    committed = saved_database(path)
    with pytest.raises(NetworkStoreError, match="storage_capacity_exceeded"):
        NetworkStore(path, max_storage_bytes=MIB)
    assert saved_database(path) == committed
    reopened = NetworkStore(path, max_storage_bytes=2 * MIB)
    assert reopened.healthcheck() is True
    assert reopened.ingest(pending, profile(), now_us=NOW) == recovered_ack
    assert reopened.ingest(first, profile(), now_us=NOW) == first_ack
    assert saved_database(path) == committed
