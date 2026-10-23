"""Bounded network analysis and crash-safe delivery to the local console."""
import json
import threading
import time

from . import network_incidents, notifications


def publish(store, console, now, *, limit=50, after_import=None):
    """Import revisions once, without holding locks on both SQLite databases."""
    if type(limit) is not int or not 1 <= limit <= 200:
        raise ValueError("Invalid network notification limit")
    with store.connection() as db:
        rows = [dict(row) for row in db.execute(
            "SELECT * FROM network_notice_outbox WHERE pending=1 ORDER BY topic LIMIT ?", (limit,))]
    for row in rows:
        with console._connection(write=True) as db:
            key = "network-import:" + row["topic"]
            previous = notifications._get(db, key, 0)
            if row["revision"] > previous:
                payload = json.loads(row["payload_json"])
                if row["cancelled"]:
                    db.execute("UPDATE notification_outbox SET state='cancelled' "
                               "WHERE topic=? AND state='pending'", (row["topic"],))
                else:
                    notifications.enqueue(db, row["topic"], "network_incident", payload, now,
                        priority=1, object_id=payload["incident_id"])
                notifications._set(db, key, row["revision"])
        if after_import:
            after_import()
        with store.connection(write=True) as db:
            db.execute("UPDATE network_notice_outbox SET pending=0 WHERE topic=? AND revision=?",
                       (row["topic"], row["revision"]))
    return len(rows)


def source_health(store, console, sources, heartbeat_timeout, now):
    """Current source health is separate from attack candidates and scores."""
    rows = {row["source_id"]: row for row in store.sources()}
    conditions = []
    for source in sources:
        row = rows.get(source.id)
        codes = []
        if row is None:
            codes.append("never_seen")
        else:
            last = row["last_report"]
            if now * 1_000_000 - row["received_at_us"] > heartbeat_timeout * 1_000_000:
                codes.append("stale")
            if now * 1_000_000 - last["collected_at_us"] > heartbeat_timeout * 1_000_000:
                codes.append("delayed")
            if not last["caught_up"]:
                codes.append("catching_up")
            codes.extend(code for code in last["reports"] if code != "coverage_start")
            if any(result["code"] is not None for result in last["results"]):
                codes.append("rejected_records")
        conditions.append((source.id, sorted(set(codes))))
    with console._connection(write=True) as db:
        for source_id, codes in conditions:
            notifications._condition(db, "network-source:" + source_id,
                "network_collection", bool(codes),
                {"title": "网络采集异常" if codes else "网络采集已恢复",
                 "source_id": source_id, "conditions": codes,
                 "note": "采集状态与安全事件分别展示；历史缺口仍保留在网络检测状态中。"}, now)


def capacity_health(store, console, now):
    """Warn before permanent receipt history fills; never prune replay evidence."""
    status = store.status()
    ratios = {name: status["counts"][name] / status["limits"][name]
              for name in ("events", "receipts", "batches")}
    ratios["storage"] = status["storage_bytes"] / status["limits"]["storage_bytes"]
    # The database's write budget reserves room for its WAL and SHM files.
    ratios["database_pages"] = status["page_count"] / status["page_limit"]
    nearing = sorted(name for name, ratio in ratios.items() if ratio >= .7)
    with console._connection(write=True) as db:
        notifications._condition(db, "network-capacity", "network_collection", bool(nearing),
            {"title": "网络采集容量接近上限" if nearing else "网络采集容量已恢复",
             "conditions": ["capacity_" + name for name in nearing],
             "usage_percent": {name: round(value * 100, 1) for name, value in ratios.items()},
             "exhausted": status["exhausted"],
             "note": "达到配额后会保留待发送数据并停止新增写入；请先处理容量，勿删除采集游标或去重记录。"}, now)


class NetworkWorker:
    def __init__(self, store, console, *, sources=(), heartbeat_timeout=180,
                 notify=True, interval=5):
        self.store, self.console = store, console
        self.sources, self.heartbeat_timeout = sources, heartbeat_timeout
        self.notify, self.interval = notify, interval
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._run, name="network-analysis", daemon=True)

    def start(self):
        self.thread.start()

    def close(self):
        self.stop.set()
        if self.thread.ident is not None:
            self.thread.join(timeout=15)

    def tick(self, now=None):
        with self.lock:
            moment = time.time() if now is None else now
            capacity_error = None
            if self.notify:
                # Full network storage must still report through the console.
                # A broken notice destination must not prevent local analysis.
                try:
                    capacity_health(self.store, self.console, moment)
                except Exception:
                    capacity_error = "网络容量通知暂时失败，将自动重试"
            result = network_incidents.process(self.store, moment)
            if self.notify:
                publish(self.store, self.console, moment)
                source_health(self.store, self.console, self.sources, self.heartbeat_timeout, moment)
            if capacity_error:
                with self.store.write_connection() as db:
                    network_incidents.set_meta(db, "last_error", capacity_error)
            return result

    def _run(self):
        while not self.stop.is_set():
            delay = self.interval
            try:
                if not self.tick()["caught_up"]:
                    delay = 1
            except Exception:
                # A full database may also reject this metadata write. The
                # unchanged last_run and receipt backlog remain observable.
                try:
                    with self.store.connection(write=True) as db:
                        network_incidents.set_meta(db, "last_error", "网络检测暂时失败，将自动重试")
                except Exception:
                    pass
            self.stop.wait(delay)
