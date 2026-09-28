"""Durable console delivery, recovery, authenticated reading and daily totals."""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import json
import time
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.telemetry import notifications
from app.telemetry import store as module
from app.telemetry.notifications import NotificationWorker
from app.telemetry.store import TelemetryStore
from test_dashboard_control import run_dashboard
from test_live_api import PASSWORD, TOKEN_A, client as client, config as config, password_hash as password_hash
from test_live_scoring import NOW, activity, store as store


def inbox(store, kind="incident"):
    return store.list_notifications(kind=kind)["items"]


def tick(store, offset=0, **kwargs):
    return store.run_notifications(["source-a"], now=NOW.timestamp() + offset, **kwargs)


def test_delivery_survives_restart_replay_and_read_is_not_triage(store):
    rows, _ = activity(store)
    activity(store, offset=1000, peer="198.51.100.8", success=False, invalid=True)
    assert not inbox(store), "GET must not run the worker"
    tick(store)
    item, = inbox(store)
    assert item["payload"]["score"] == 62
    assert store.read_notifications([item["id"], item["id"]]) == {"changed": 1}
    store.ingest("source-a", "source-a", "batch-0", rows)
    store.ingest("source-a", "source-a", "replay", rows)
    reopened = TelemetryStore(store.path)
    tick(reopened, 1)
    same, = inbox(reopened)
    assert same["id"] == item["id"] and same["read_at"] is not None
    assert reopened.triage_counts()["pending"] == 2
    assert reopened.read_notifications([item["id"]]) == {"changed": 0}


def test_coalesces_new_evidence_until_cooldown_and_does_not_repeat_unchanged(store):
    activity(store)
    tick(store)
    activity(store, offset=10)
    tick(store, 30)
    assert len(inbox(store)) == 1
    activity(store, offset=20)
    tick(store, 3599)
    assert len(inbox(store)) == 1
    tick(store, 3600)
    assert len(inbox(store)) == 2
    assert inbox(store)[0]["payload"]["evidence_count"] > inbox(store)[1]["payload"]["evidence_count"]
    tick(store, 7200)
    assert len(inbox(store)) == 2


def test_priority_escalation_bypasses_cooldown(store):
    activity(store, user="root")
    tick(store)
    assert inbox(store)[0]["payload"]["priority"] == "P2"
    activity(store, offset=10)
    tick(store, 1)
    assert [x["payload"]["priority"] for x in inbox(store)] == ["P1", "P2"]


@pytest.mark.parametrize("change", ["resolved", "acknowledged", "unscored", "merged"])
def test_revalidates_pending_notifications_before_delivery(store, change):
    activity(store)
    incident = store.list_incidents()[0]["incident_id"]
    if change in ("resolved", "acknowledged"):
        store.set_triage([incident], change, actor="operator")
    else:
        with store._connection(write=True) as db:
            if change == "merged":
                db.execute("UPDATE incidents SET status='merged' WHERE incident_id=?", (incident,))
            else:
                db.execute("DELETE FROM incident_scores")
    tick(store)
    assert not inbox(store)
    if change == "unscored":
        store.backfill_scores()
        tick(store, 1)
        assert len(inbox(store)) == 1


def test_partial_write_failure_rolls_back_and_retry_survives_restart(store):
    activity(store)

    def broken(db, row, now):
        notifications.deliver_console(db, row, now)
        raise RuntimeError("private details must not appear")

    result = tick(store, deliver=broken)
    assert result["failed"] >= 1
    snapshot = store.list_notifications()
    assert not snapshot["items"] and snapshot["retrying"] >= 1
    assert "private details" not in json.dumps(snapshot)
    with store._connection() as db:
        error = db.execute("SELECT last_error FROM notification_outbox LIMIT 1").fetchone()[0]
    assert "private details" not in error
    store = TelemetryStore(store.path)
    tick(store, 29)
    assert not inbox(store)
    tick(store, 30)
    assert len(inbox(store)) == 1
    tick(store, 31)
    assert len(inbox(store)) == 1 and store.list_notifications()["retrying"] == 0


def test_two_workers_cannot_deliver_twice(store):
    activity(store)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: tick(store), range(2)))
    assert len(inbox(store)) == 1
    assert len(inbox(store, "briefing")) == 1


def test_source_failure_recovery_and_historical_gaps_do_not_flood(store, monkeypatch):
    store.ingest("source-a", "source-a", "first", [], error="read failed", reports=[{"code": "read_failed"}])
    tick(store)
    message, = inbox(store, "collection")
    assert message["payload"]["active"] is True
    tick(store, 1)
    assert len(inbox(store, "collection")) == 1
    monkeypatch.setattr(module, "_now", lambda: NOW + timedelta(seconds=5))
    store.ingest("source-a", "source-a", "recovered", [])
    tick(store, 5)
    assert len(inbox(store, "collection")) == 2
    assert inbox(store, "collection")[0]["payload"]["active"] is False
    tick(store, 6)
    assert len(inbox(store, "collection")) == 2
    tick(store, 400)
    assert len(inbox(store, "collection")) == 3, "a fresh outage after recovery must be shown immediately"
    tick(store, 3606)
    assert "offline" in inbox(store, "collection")[0]["payload"]["conditions"]


def test_daily_briefing_is_utc_snapshot_and_counts_low_and_unknown(store, monkeypatch):
    yesterday = NOW - timedelta(days=1)
    monkeypatch.setattr(module, "_now", lambda: yesterday)
    # The event time is also yesterday; accepted_at and event time are distinct.
    for offset, peer, success in ((0, "198.51.100.7", True), (1000, "198.51.100.8", False)):
        rows = [{"event_id": f"{offset}-{i}", "timestamp": (yesterday + timedelta(seconds=i)).isoformat(),
                 "identifier": "sshd", "message": f"Failed password for invalid user training from {peer} port 42000 ssh2"}
                for i in range(4)]
        if success:
            rows.append({"event_id": "success", "timestamp": (yesterday + timedelta(seconds=5)).isoformat(),
                         "identifier": "sshd", "message": f"Accepted publickey for root from {peer} port 42000 ssh2"})
        store.ingest("source-a", "source-a", str(offset), rows)
    tick(store)
    brief, = inbox(store, "briefing")
    p = brief["payload"]
    assert p["date"] == yesterday.date().isoformat()
    assert p["log_count"] == 9 and p["new_incidents"] == 2
    assert p["attention"] == 1 and p["low"] == 1 and p["unscored"] == 0
    tick(store, 60)
    assert inbox(store, "briefing") == [brief]
    tick(store, 86400)
    assert len(inbox(store, "briefing")) == 2


def test_backlog_skips_days_outside_retention_explicitly(store):
    with store._connection(write=True) as db:
        notifications._set(db, "briefing_date", (NOW - timedelta(days=90)).date().isoformat())
    tick(store)
    assert inbox(store, "briefing")[0]["payload"]["skipped_days"] > 0


def test_health_monitor_uses_published_snapshots_and_flags_unknown(tmp_path):
    snapshots = tmp_path / "backups"
    snapshots.mkdir()
    good = snapshots / (NOW.strftime("live-%Y%m%dT%H%M%S%f") + ".sqlite")
    good.write_bytes(b"verified fixture")
    (snapshots / ".live-20990101T010101000000.sqlite.tmp").write_bytes(b"partial")
    def usage(_):
        return SimpleNamespace(total=100 * 1024**3, free=20 * 1024**3)
    checks = notifications.monitor_health(tmp_path / "database", [snapshots], NOW.timestamp(), disk_usage=usage)
    assert [x["status"] for x in checks] == ["ok", "ok"]
    checks = notifications.monitor_health(tmp_path / "database", [snapshots], NOW.timestamp() + 37 * 3600, disk_usage=usage)
    assert checks[1]["status"] == "stale"
    checks = notifications.monitor_health(tmp_path / "database", [tmp_path / "missing"], NOW.timestamp(),
                                         disk_usage=lambda _: SimpleNamespace(total=100 * 1024**3, free=100))
    assert [x["status"] for x in checks] == ["low", "unknown"]


def test_health_notifications_deduplicate_and_recovery_is_visible(store):
    bad = [{"key": "capacity", "status": "low", "title": "low"}]
    good = [{"key": "capacity", "status": "ok", "title": "recovered"}]
    tick(store, health=bad)
    tick(store, 1, health=bad)
    assert len(inbox(store, "health")) == 1
    tick(store, 2, health=good)
    assert len(inbox(store, "health")) == 2
    assert inbox(store, "health")[0]["payload"]["active"] is False


def test_api_reads_require_operator_and_mark_read_requires_csrf(client):
    assert client.get("/api/notifications").status_code == 401
    assert client.get("/api/notifications", headers={"Authorization": "Bearer " + TOKEN_A}).status_code == 401
    auth = ("operator", PASSWORD)
    store = client.app.state.store
    store.run_notifications([], now=NOW.timestamp())
    item, = store.list_notifications()["items"]
    assert client.post("/api/notifications/read", auth=auth, json={"ids": [item["id"]]}).status_code == 403
    csrf = client.get("/api/controls", auth=auth).json()["csrf_token"]
    headers = {"X-RiskOps-CSRF": csrf}
    assert client.post("/api/notifications/read", auth=auth, headers=headers, json={"ids": [True]}).status_code == 422
    assert client.post("/api/notifications/read", auth=auth, headers={**headers, "Origin": "https://other.invalid"},
                       json={"ids": [item["id"]]}).status_code == 403
    response = client.post("/api/notifications/read", auth=auth, headers=headers, json={"ids": [item["id"]]})
    assert response.json() == {"changed": 1}
    snapshot = client.get("/api/notifications?unread=true", auth=auth).json()
    assert snapshot["items"] == [] and snapshot["backup_monitor_configured"] is False
    assert client.get("/api/notifications?kind=unknown", auth=auth).status_code == 422
    assert client.get("/api/notifications?page=0", auth=auth).status_code == 422


def test_worker_runs_without_browser_and_stops(store):
    config = SimpleNamespace(sources=[], notification_backup_directories=(), heartbeat_timeout_seconds=300)
    worker = NotificationWorker(store, config, interval=.02)
    worker.start()
    try:
        deadline = time.monotonic() + 5
        while not store.list_notifications()["last_run"] and time.monotonic() < deadline:
            time.sleep(.01)
        assert store.list_notifications()["last_run"]
    finally:
        worker.close()
    assert not worker.thread.is_alive()


def test_config_rejects_relative_backup_paths(config):
    with pytest.raises(ValidationError):
        type(config).model_validate({**config.model_dump(), "notification_backup_directories": ["relative"]})


def test_console_renders_untrusted_text_read_action_and_keeps_data_on_error():
    run_dashboard(r"""
const state={items:[{id:7,kind:'incident',read_at:null,delivered_at:100,payload:{title:'<img src=x onerror=attack()>',incident_id:'inc',priority:'P1',score:62,src_ip:'192.0.2.7',source_ids:['source-a'],evidence_count:5}}],page:1,total_pages:1,total:1,unread:1,pending:0,retrying:0,enabled:true,health:[],last_run:Date.now()/1000};
renderNotifications(state);
assert.equal($('notification-rows').children[0].children[2].children[0].tag,'strong');
assert.equal($('notification-rows').children[0].children[2].children[0].textContent,state.items[0].payload.title);
controlsData={csrf_token:'test-csrf'};
route=(path,options)=>{if(options.method==='POST'){assert.equal(path,'/api/notifications/read');assert.equal(options.headers['X-RiskOps-CSRF'],'test-csrf');assert.deepEqual(JSON.parse(options.body),{ids:[7]});return response({changed:1});}return response({...state,items:[{...state.items[0],read_at:200}],unread:0});};
await readNotifications([7],$('notification-read-page'));
assert.equal($('notification-rows').children[0].children[3].textContent,'已读');
assert.equal($('notification-read-page').disabled,true);
route=()=>{throw new Error('offline');};await loadNotifications();
assert.equal($('notification-rows').children.length,1);
assert.match($('notification-status').textContent,/已保留/);
assert(calls.every(x=>!x.path.includes('/api/incidents/triage')));
""")


def test_briefing_resumes_keyset_pages_and_excludes_late_arrivals(store, monkeypatch):
    when = (NOW - timedelta(days=1)).isoformat()
    for source in ("source-a", "source-b", "source-c"):
        for batch in range(2):
            rows = [{"event_id": str(batch * 500 + index), "timestamp": when,
                     "identifier": "cron", "message": "scheduled synthetic job"}
                    for index in range(500 if batch == 0 else 1)]
            store.ingest(source, source, str(batch), rows)
    assert notifications.advance_briefing(store, NOW.timestamp()) is True
    assert store.list_notifications()["briefing_in_progress"] == (NOW - timedelta(days=1)).date().isoformat()
    monkeypatch.setattr(module, "_now", lambda: NOW + timedelta(seconds=1))
    store.ingest("source-a", "source-a", "late", [{"event_id": "late", "timestamp": when,
        "identifier": "cron", "message": "late synthetic job"}])
    restarted = TelemetryStore(store.path)
    assert notifications.advance_briefing(restarted, NOW.timestamp() + 1) is False
    tick(restarted, 1)
    brief, = inbox(restarted, "briefing")
    assert brief["payload"]["log_count"] == 1503
    assert brief["payload"]["data_as_of"] == NOW.timestamp()
    assert restarted.list_notifications()["briefing_in_progress"] is None


def test_failed_historical_query_does_not_block_urgent_delivery(store, monkeypatch):
    import sqlite3
    activity(store)

    def slow(*args):
        raise sqlite3.OperationalError("interrupted")

    monkeypatch.setattr(notifications, "advance_briefing", slow)
    tick(store)
    assert len(inbox(store)) == 1
    assert store.list_notifications()["briefing_error"] == "简报汇总暂时失败，将自动重试"


def test_multiple_workers_checkpoint_briefing_once(store):
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: notifications.advance_briefing(store, NOW.timestamp()), range(2)))
    tick(store)
    brief, = inbox(store, "briefing")
    assert brief["payload"]["log_count"] == 0
