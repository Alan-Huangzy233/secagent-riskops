#!/usr/bin/env python3
"""Bounded SSH journal polling with a durable, per-source retry spool.

Run with a systemd timer: telemetry_collector.py --once --config CONFIG.
The configured SSH argv is executed verbatim (no shell or appended command).
Its stdin receives one JSON request. Its stdout must contain journal JSONL and
a final checkpoint envelope; see parse_export(). Tokens never enter the spool.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
import signal
import ssl
import subprocess
import sys
import threading
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener
import uuid

MAX_BATCH_BYTES = 1_000_000  # API limit is 1 MiB; leave room for schema changes.
MAX_EXPORT_BYTES = 4 * 1024 * 1024
MAX_MESSAGE_BYTES = 4096
MAX_RECORDS = 200
SOURCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class CollectorError(Exception):
    """A public, non-sensitive reason code; never include command output."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def encode(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def load_config(path: Path) -> dict[str, Any]:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
        endpoint = urlsplit(config["endpoint"])
        if (endpoint.username or endpoint.password or endpoint.fragment
                or endpoint.scheme not in ("http", "https")
                or not endpoint.hostname
                or (endpoint.scheme == "http" and endpoint.hostname not in
                    ("127.0.0.1", "localhost", "::1"))):
            raise ValueError("endpoint")
        if not isinstance(config["state_dir"], str) or not config["state_dir"]:
            raise ValueError("state_dir")
        sources = config["sources"]
        if not isinstance(sources, list) or not 1 <= len(sources) <= 100:
            raise ValueError("sources")
        seen = set()
        for source in sources:
            sid = source["id"]
            if not isinstance(sid, str) or not SOURCE_ID.fullmatch(sid) or sid in seen:
                raise ValueError("source_id")
            seen.add(sid)
            if not isinstance(source["hostname"], str) or not 1 <= len(source["hostname"]) <= 253:
                raise ValueError("hostname")
            if not isinstance(source["token"], str) or not 24 <= len(source["token"]) <= 512 or "\n" in source["token"] or "\r" in source["token"]:
                raise ValueError("token")
            argv = source["ssh_command"]
            if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x and "\x00" not in x for x in argv):
                raise ValueError("ssh_command")
        for key, default, minimum, maximum in (
            ("ssh_timeout_seconds", 20, 1, 120),
            ("http_timeout_seconds", 10, 1, 120),
            ("max_spool_bytes", 16 * 1024 * 1024, 1024, 1024 * 1024 * 1024),
        ):
            value = config.setdefault(key, default)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError(key)
        return config
    except (OSError, UnicodeError, ValueError, TypeError, KeyError):
        raise CollectorError("invalid_config") from None


def fsync_directory(path: Path) -> None:
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def atomic_write(path: Path, value: Any) -> None:
    temporary = path.with_name(path.name + ".tmp")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encode(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def collector_lock(state_dir: Path):
    """Prevent a manual invocation racing the systemd timer or another run."""
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_file = state_dir / "collector.lock"
    with lock_file.open("a+b") as stream:
        if os.name == "nt":
            import msvcrt
            stream.seek(0)
            if stream.read(1) == b"":
                stream.write(b"0")
                stream.flush()
            stream.seek(0)
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                raise CollectorError("collector_locked") from None
            try:
                yield
            finally:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise CollectorError("collector_locked") from None
            try:
                yield
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)


def ssh_export(source: dict, cursor: str | None, timeout: int) -> bytes:
    request = encode({"source_id": source["id"], "cursor": cursor,
                      "limit": MAX_RECORDS, "since_minutes": 10}) + b"\n"
    try:
        process = subprocess.Popen(source["ssh_command"], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   start_new_session=(os.name != "nt"))
    except OSError:
        raise CollectorError("ssh_start_failed") from None
    chunks: list[bytes] = []
    overflow = threading.Event()

    def stop() -> None:
        try:
            if os.name != "nt":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except OSError:
            pass

    def read_output() -> None:
        size = 0
        try:
            while True:
                chunk = process.stdout.read(65536)
                if not chunk:
                    return
                size += len(chunk)
                if size > MAX_EXPORT_BYTES:
                    overflow.set()
                    stop()
                    return
                chunks.append(chunk)
        except (OSError, ValueError):
            overflow.set()

    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    try:
        try:
            process.stdin.write(request)
            process.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        try:
            result = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            stop()
            process.wait(timeout=5)
            raise CollectorError("ssh_timeout") from None
        reader.join(timeout=2)
        if reader.is_alive():
            stop()
            reader.join(timeout=2)
            raise CollectorError("ssh_output_timeout")
        if overflow.is_set():
            raise CollectorError("ssh_output_limit")
        if result != 0:
            raise CollectorError("ssh_export_failed")
        return b"".join(chunks)
    finally:
        if process.poll() is None:
            stop()
            process.wait(timeout=5)
        reader.join(timeout=2)
        process.stdin.close()
        process.stdout.close()


def report(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def parse_export(data: bytes, previous_cursor: str | None) -> tuple[list[dict], str | None, list[dict]]:
    """Validate the entire export before allowing any cursor advancement.

    Final line: {"__riskops_checkpoint__": str|null,
                 "cursor_status": "ok"|"initial"|"reset",
                 "gap_reason": null|str}.
    On invalid/expired cursors the exporter may recover the last ten minutes,
    but MUST report reset; the potentially missing interval stays visible.
    """
    try:
        lines = data.decode("utf-8").splitlines()
        if not lines or len(lines) > MAX_RECORDS + 1 or any(not line.strip() for line in lines):
            raise ValueError("lines")
        values = [json.loads(line) for line in lines]
        if not all(isinstance(value, dict) for value in values):
            raise ValueError("objects")
        checkpoint = values[-1]
        if "__riskops_checkpoint__" not in checkpoint:
            raise ValueError("checkpoint")
        next_cursor = checkpoint["__riskops_checkpoint__"]
        if next_cursor is not None and (not isinstance(next_cursor, str) or not 1 <= len(next_cursor) <= 512):
            raise ValueError("checkpoint_cursor")
        status = checkpoint.get("cursor_status", "initial" if previous_cursor is None else "ok")
        if status not in ("ok", "initial", "reset"):
            raise ValueError("cursor_status")
        if previous_cursor is not None and status == "initial":
            raise ValueError("unexpected_initial")
        reports = []
        if status == "reset":
            reports.append(report("retention_gap", "Previous journal cursor is unavailable; recovered only the exporter's recent window. Earlier events may be missing."))
        elif previous_cursor is None:
            reports.append(report("coverage_start", "No saved cursor: collection starts from the last ten minutes. Earlier history is outside coverage; server-side event deduplication handles overlap."))
        records = []
        truncated = 0
        seen = set()
        for value in values[:-1]:
            event_id = value["__CURSOR"]
            if not isinstance(event_id, str) or not 1 <= len(event_id) <= 512 or event_id in seen or event_id == previous_cursor:
                raise ValueError("event_cursor")
            seen.add(event_id)
            timestamp = value["__REALTIME_TIMESTAMP"]
            if isinstance(timestamp, bool) or not str(timestamp).isdigit():
                raise ValueError("timestamp")
            timestamp = datetime.fromtimestamp(int(timestamp) / 1_000_000, timezone.utc)
            message = value["MESSAGE"]
            if not isinstance(message, str):
                raise ValueError("message")
            message_bytes = message.encode("utf-8")
            if len(message_bytes) > MAX_MESSAGE_BYTES:
                message = message_bytes[:MAX_MESSAGE_BYTES].decode("utf-8", errors="ignore")
                truncated += 1
            unit, identifier, priority = value.get("_SYSTEMD_UNIT"), value.get("SYSLOG_IDENTIFIER"), value.get("PRIORITY")
            for optional in (unit, identifier):
                if optional is not None and (not isinstance(optional, str) or len(optional) > 256):
                    raise ValueError("metadata")
            if priority is not None and (type(priority) not in (str, int) or len(str(priority)) > 16):
                raise ValueError("priority")
            records.append({"event_id": event_id, "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                            "message": message, "unit": unit, "priority": priority, "identifier": identifier})
        if records and next_cursor != records[-1]["event_id"]:
            raise ValueError("checkpoint_mismatch")
        if not records and status != "reset" and next_cursor != previous_cursor:
            raise ValueError("empty_checkpoint_mismatch")
        if truncated:
            reports.append(report("message_truncated", f"{truncated} journal messages exceeded 4096 UTF-8 bytes and were explicitly truncated; full messages remain in the source journal while retained."))
        return records, next_cursor, reports
    except (UnicodeError, ValueError, TypeError, KeyError, OverflowError, OSError):
        raise CollectorError("invalid_journal_export") from None


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward a source credential to a redirected host.


def post_batch(endpoint: str, token: str, body: dict, timeout: int) -> dict:
    request = Request(endpoint, data=encode(body), method="POST",
                      headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    try:
        # Explicit TLS configuration retains certificate/hostname verification
        # without inheriting SSLKEYLOGFILE, which can expose session secrets.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_default_certs()
        opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler(context=context))
        with opener.open(request, timeout=timeout) as response:
            if not 200 <= response.status < 300:
                raise CollectorError("http_rejected")
            payload = response.read(65537)
            if len(payload) > 65536:
                raise CollectorError("invalid_ack")
            return json.loads(payload)
    except HTTPError:
        raise CollectorError("http_rejected") from None
    except (URLError, TimeoutError, OSError, HTTPException):
        raise CollectorError("http_unavailable") from None
    except (ValueError, UnicodeError):
        raise CollectorError("invalid_ack") from None


def read_json(path: Path, code: str) -> dict:
    try:
        if path.stat().st_size > MAX_EXPORT_BYTES:
            raise ValueError("size")
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("object")
        return value
    except (ValueError, OSError, UnicodeError):
        raise CollectorError(code) from None


def build_pending(source: dict, cursor: str | None, fetch: Callable, timeout: int) -> dict:
    source_error = None
    try:
        records, next_cursor, reports = parse_export(fetch(source, cursor, timeout), cursor)
    except CollectorError as exc:
        source_error = str(exc)
        records, next_cursor = [], cursor
        reports = [report(source_error, "Source collection failed; no journal cursor was advanced. Check collector connectivity and the restricted exporter.")]
    body = {"batch_id": str(uuid.uuid4()), "source_id": source["id"], "hostname": source["hostname"],
            "collected_at": utc_now(), "records": records, "reports": reports}
    if len(encode(body)) > MAX_BATCH_BYTES:
        reports.append(report("batch_limited", "Only a prefix of this export fits the ingestion limit; remaining records will be fetched after the last acknowledged cursor."))
        while records and len(encode(body)) > MAX_BATCH_BYTES:
            records.pop()
        if not records:
            raise CollectorError("record_exceeds_batch_limit")
        next_cursor = records[-1]["event_id"]
    return {"version": 1, "body": body, "next_cursor": next_cursor, "source_error": source_error}


def collect_source(config: dict, source: dict, fetch: Callable = ssh_export,
                   send: Callable = post_batch) -> dict:
    directory = Path(config["state_dir"])
    sid = source["id"]
    state_path = directory / (sid + ".state.json")
    pending_path = directory / (sid + ".pending.json")
    if pending_path.exists():
        pending = read_json(pending_path, "invalid_spool")
    else:
        state = read_json(state_path, "invalid_cursor_state") if state_path.exists() else {"cursor": None}
        cursor = state.get("cursor")
        if "cursor" not in state or (cursor is not None and (not isinstance(cursor, str) or not 1 <= len(cursor) <= 512)):
            raise CollectorError("invalid_cursor_state")
        pending = build_pending(source, cursor, fetch, config["ssh_timeout_seconds"])
        spool_bytes = sum(path.stat().st_size for path in directory.glob("*.pending.json"))
        if spool_bytes + len(encode(pending)) > config["max_spool_bytes"]:
            raise CollectorError("spool_capacity_reached")
        atomic_write(pending_path, pending)
    body = pending.get("body")
    next_cursor = pending.get("next_cursor")
    if (pending.get("version") != 1 or "next_cursor" not in pending
            or not isinstance(body, dict) or body.get("source_id") != sid
            or body.get("hostname") != source["hostname"]
            or not isinstance(body.get("batch_id"), str) or not body["batch_id"]
            or not isinstance(body.get("records"), list)
            or not all(isinstance(record, dict) for record in body["records"])
            or pending.get("source_error") not in (None, "ssh_start_failed", "ssh_timeout",
                    "ssh_output_timeout", "ssh_output_limit", "ssh_export_failed", "invalid_journal_export")
            or (next_cursor is not None and (not isinstance(next_cursor, str) or not 1 <= len(next_cursor) <= 512))
            or (body["records"] and body["records"][-1].get("event_id") != next_cursor)
            or len(encode(body)) > MAX_BATCH_BYTES):
        raise CollectorError("invalid_spool")
    ack = send(config["endpoint"], source["token"], body, config["http_timeout_seconds"])
    if not isinstance(ack, dict) or ack.get("durable") is not True or ack.get("batch_id") != body["batch_id"]:
        raise CollectorError("invalid_ack")
    # Commit the cursor first. A crash before deleting the pending file safely
    # resends the identical batch; both server deduplication and this commit are
    # idempotent. A 2xx response alone never advances a cursor.
    atomic_write(state_path, {"cursor": next_cursor, "last_ack_at": utc_now()})
    pending_path.unlink()
    fsync_directory(directory)
    return {"source_id": sid, "status": "source_error" if pending.get("source_error") else "acknowledged",
            "code": pending.get("source_error"), "records": len(body["records"])}


def run_once(config: dict, fetch: Callable = ssh_export, send: Callable = post_batch) -> list[dict]:
    results = []
    with collector_lock(Path(config["state_dir"])):
        for source in config["sources"]:
            try:
                results.append(collect_source(config, source, fetch, send))
            except CollectorError as exc:
                results.append({"source_id": source["id"], "status": "error", "code": str(exc)})
            except OSError:
                results.append({"source_id": source["id"], "status": "error", "code": "local_storage_failed"})
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/etc/secagent-riskops/collector.json"))
    parser.add_argument("--once", action="store_true", required=True)
    args = parser.parse_args()
    try:
        results = run_once(load_config(args.config))
    except (CollectorError, OSError) as exc:
        code = str(exc) if isinstance(exc, CollectorError) else "local_storage_failed"
        print(json.dumps({"status": "error", "code": code}), file=sys.stderr)
        return 1
    for result in results:
        print(json.dumps(result))  # Identifiers/counts/codes only; no log contents.
    return int(any(result["status"] != "acknowledged" for result in results))


if __name__ == "__main__":
    sys.exit(main())
