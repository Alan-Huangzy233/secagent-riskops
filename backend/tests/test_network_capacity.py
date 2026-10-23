"""Capacity warnings survive a full network database without inventing attacks."""
from types import SimpleNamespace
import pytest

from app.telemetry.network_worker import NetworkWorker, capacity_health
from app.telemetry.store import TelemetryStore


def status(**updates):
    value = {"counts": {"events": 0, "receipts": 0, "batches": 0},
             "limits": {"events": 100, "receipts": 100, "batches": 100,
                        "storage_bytes": 10000},
             "storage_bytes": 0, "page_count": 0, "page_limit": 100,
             "exhausted": []}
    value.update(updates)
    return value


@pytest.mark.parametrize("resource", ["events", "receipts", "batches", "storage", "database_pages"])
def test_capacity_threshold_is_deduplicated_and_recovery_is_visible(tmp_path, resource):
    console = TelemetryStore(tmp_path / "console.sqlite")
    current = status()
    store = SimpleNamespace(status=lambda: current)
    def set_usage(value):
        if resource in current["counts"]:
            current["counts"][resource] = value
        elif resource == "storage":
            current["storage_bytes"] = value * 100
        else:
            current["page_count"] = value
    set_usage(69)
    capacity_health(store, console, 1000)
    console.run_notifications([], now=1000)
    assert console.list_notifications(kind="network_collection")["total"] == 0
    set_usage(70)
    capacity_health(store, console, 1001)
    capacity_health(store, console, 1002)
    console.run_notifications([], now=1002)
    notice, = console.list_notifications(kind="network_collection")["items"]
    assert notice["payload"]["conditions"] == ["capacity_" + resource]
    assert notice["payload"]["usage_percent"][resource] == 70.0
    set_usage(69)
    capacity_health(store, console, 1003)
    console.run_notifications([], now=1003)
    notices = console.list_notifications(kind="network_collection")
    assert notices["total"] == 2 and notices["items"][0]["payload"]["active"] is False
    assert console.list_notifications(kind="network_incident")["total"] == 0


def test_capacity_warning_is_written_before_analysis_capacity_failure(tmp_path, monkeypatch):
    console = TelemetryStore(tmp_path / "console.sqlite")
    store = SimpleNamespace(status=lambda: status(page_count=100, exhausted=["storage"]))
    def full(*_args):
        raise RuntimeError("synthetic full store")
    monkeypatch.setattr("app.telemetry.network_worker.network_incidents.process", full)
    worker = NetworkWorker(store, console)
    with pytest.raises(RuntimeError, match="synthetic full store"):
        worker.tick(now=1000)
    console.run_notifications([], now=1000)
    notice, = console.list_notifications(kind="network_collection")["items"]
    assert notice["payload"]["exhausted"] == ["storage"]
    assert console.list_notifications(kind="network_incident")["total"] == 0


def test_capacity_notice_failure_does_not_block_analysis_and_is_retried(tmp_path, monkeypatch):
    from app.telemetry.network_store import NetworkStore
    import app.telemetry.network_worker as module
    network = NetworkStore(tmp_path / "network.sqlite")
    console = TelemetryStore(tmp_path / "console.sqlite")
    original = module.capacity_health
    calls = []
    def temporary_failure(*args):
        calls.append(True)
        if len(calls) == 1:
            raise RuntimeError("synthetic console write failure")
        return original(*args)
    monkeypatch.setattr(module, "capacity_health", temporary_failure)
    worker = NetworkWorker(network, console)
    assert worker.tick(now=1000)["caught_up"]
    status = network.analysis_status()
    assert status["last_run"] is not None
    assert status["last_error"] == "网络容量通知暂时失败，将自动重试"
    assert worker.tick(now=1001)["caught_up"]
    assert len(calls) == 2 and network.analysis_status()["last_error"] is None
