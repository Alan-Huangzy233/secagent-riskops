"""One bounded, authenticated-console snapshot prepared outside request handlers.

The cache is process-local and rebuilt on restart. It contains display data,
never credentials, CSRF tokens, control plans or AI submissions. Detailed reads
and all mutations continue through their original, independently checked APIs.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import threading
import time


REFRESH_SECONDS = 15
MAX_AGE_SECONDS = 120
MAX_BYTES = 4 * 1024 * 1024


def build_summary(store, config):
    reported = {item["source_id"]: item for item in store.list_sources(limit=200, offset=0)}
    now = datetime.now(timezone.utc)
    sources = []
    totals = {"events": 0, "incidents": 0, "ssh_failures": 0, "ssh_successes": 0}
    for source in config.sources:
        row = dict(reported.get(source.id, {}))
        row.update({"source_id": source.id, "hostname": source.hostname})
        last_seen = row.get("last_seen")
        connection_status = "never_seen"
        if last_seen:
            age = (now - datetime.fromisoformat(last_seen.replace("Z", "+00:00"))).total_seconds()
            failing = "source_error" in ((row.get("collection") or {}).get("open") or [])
            if row.get("collection") is None:
                failing = bool(row.get("last_error"))
            connection_status = "offline" if age > config.heartbeat_timeout_seconds else ("error" if failing else "online")
        row["connection_status"] = connection_status
        sources.append(row)
        for total, counter in (("events", "event_count"), ("incidents", "incident_count"),
                               ("ssh_failures", "ssh_failure_count"), ("ssh_successes", "ssh_success_count")):
            totals[total] += int(row.get(counter, 0))
    # Correlated incidents can belong to multiple sources, but count once here.
    triage = store.triage_counts()
    totals["incidents"] = triage["total"]
    return {"generated_at": now.isoformat(), "retention_days": config.retention_days,
            "heartbeat_timeout_seconds": config.heartbeat_timeout_seconds, "sources": sources,
            "totals": totals, "triage_counts": triage}


def build_bootstrap(store, config):
    return {"summary": build_summary(store, config),
            "events": store.paginate_events(limit=50),
            "incidents": store.paginate_incidents(limit=50, include_evidence=False,
                                                  triage="pending", focus="all", sort="score")}


class ConsoleCache:
    def __init__(self, build, *, enabled=True, clock=time.monotonic):
        self.build, self.enabled, self.clock = build, enabled, clock
        self.lock, self.build_lock = threading.Lock(), threading.Lock()
        self.stop, self.wake = threading.Event(), threading.Event()
        self.thread = None
        self.data = self.built_at = self.generated_at = None
        self.revision = self.published_revision = 0
        self.generation = 0
        self.refreshing = self.failed = False

    def start(self):
        if self.enabled and self.thread is None:
            self.thread = threading.Thread(target=self._run, name="console-cache", daemon=True)
            self.thread.start()

    def close(self):
        self.stop.set()
        self.wake.set()
        if self.thread is not None:
            self.thread.join(timeout=3)

    def invalidate(self):
        if self.enabled:
            with self.lock:
                self.revision += 1
            self.wake.set()

    def refresh_once(self):
        if not self.enabled or self.stop.is_set() or not self.build_lock.acquire(blocking=False):
            return False
        started = self.clock()
        generated = datetime.now(timezone.utc).isoformat()
        with self.lock:
            revision = self.revision
            self.refreshing = True
        try:
            data = json.dumps(self.build(), ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
            if len(data) > MAX_BYTES:
                raise ValueError("console snapshot exceeds its bound")
            with self.lock:
                if self.stop.is_set():
                    return False
                self.data, self.built_at, self.generated_at = data, started, generated
                self.published_revision = revision
                self.generation += 1
                self.failed = False
            return True
        except Exception:
            # Keep the last good snapshot only within MAX_AGE_SECONDS. Never
            # return exception messages that could contain evidence or paths.
            with self.lock:
                self.failed = True
            return False
        finally:
            with self.lock:
                self.refreshing = False
            self.build_lock.release()

    def read(self):
        if not self.enabled:
            return {"state": "disabled", "data": None}
        with self.lock:
            age = max(0.0, self.clock() - self.built_at) if self.built_at is not None else None
            data = self.data if age is not None and age <= MAX_AGE_SECONDS else None
            state = "ready" if data is not None else ("unavailable" if self.failed else "warming")
            result = {"state": state, "generated_at": self.generated_at, "age_seconds": age,
                      "generation": self.generation, "refreshing": self.refreshing,
                      "stale": self.failed or self.revision != self.published_revision or age is None or age > REFRESH_SECONDS,
                      "refresh_seconds": REFRESH_SECONDS, "max_age_seconds": MAX_AGE_SECONDS,
                      "error": "refresh_failed" if self.failed else None}
        # Deserialize outside the lock. Each reader owns its returned data and
        # cannot modify the shared snapshot or hold up the background publisher.
        result["data"] = json.loads(data) if data is not None else None
        return result

    def _run(self):
        while not self.stop.is_set():
            self.wake.clear()
            started = self.clock()
            self.refresh_once()
            # Bursts of ingestion share one rebuild, with at least two seconds
            # between starts. Readers never trigger their own database queries.
            if self.stop.wait(max(0, 2 - (self.clock() - started))):
                break
            self.wake.wait(max(0, REFRESH_SECONDS - (self.clock() - started)))
