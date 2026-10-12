"""HTTP analysis and an idempotent bridge to the existing console inbox."""
import json
import threading
import time

from . import http_incidents, notifications


def publish(store, console, now, *, limit=50, after_import=None):
    with store.connection() as db:
        rows = [dict(r) for r in db.execute("SELECT * FROM http_notice_outbox WHERE pending=1 ORDER BY topic LIMIT ?", (limit,))]
    for row in rows:
        # Never hold both DB locks. The destination remembers imported source
        # revisions; a crash after its commit safely retries the same delivery.
        with console._connection(write=True) as db:
            key = "http-import:" + row["topic"]
            previous = notifications._get(db, key, 0)
            if row["revision"] > previous:
                payload = json.loads(row["payload_json"])
                if row["cancelled"]:
                    db.execute("UPDATE notification_outbox SET state='cancelled' WHERE topic=? AND state='pending'", (row["topic"],))
                else:
                    notifications.enqueue(db, row["topic"], "http_incident", payload, now,
                                          priority=2 if payload["assessment"]["priority"] == "P2" else 1,
                                          object_id=payload["incident_id"])
                notifications._set(db, key, row["revision"])
        if after_import:
            after_import()  # Test the crash window after destination COMMIT.
        with store.connection(write=True) as db:
            db.execute("UPDATE http_notice_outbox SET pending=0 WHERE topic=? AND revision=?", (row["topic"], row["revision"]))
    return len(rows)


class HttpWorker:
    def __init__(self, store, console, *, notify=True, interval=5):
        self.store, self.console, self.notify, self.interval = store, console, notify, interval
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._run, name="http-analysis", daemon=True)

    def start(self):
        self.thread.start()

    def close(self):
        self.stop.set()
        self.thread.join(timeout=15)

    def tick(self, now=None):
        with self.lock:
            moment = time.time() if now is None else now
            result = http_incidents.process(self.store, moment)
            if self.notify:
                publish(self.store, self.console, moment)
            return result

    def _run(self):
        while not self.stop.is_set():
            delay = self.interval
            try:
                result = self.tick()
                if not result["caught_up"]:
                    delay = 1
            except Exception:
                try:
                    with self.store.connection(write=True) as db:
                        http_incidents.set_meta(db, "last_error", "HTTP 检测暂时失败，将自动重试")
                except Exception:
                    pass
            self.stop.wait(delay)
