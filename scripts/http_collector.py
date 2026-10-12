#!/usr/bin/env python3
"""Collect a local structured HTTP log with a durable spool and ACK-only cursor.

Run on the log host using --once --config CONFIG. Requires the project's Python
package and the sibling telemetry_collector.py transport/filesystem helpers.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
from urllib.parse import urlsplit
import uuid

from app.telemetry.http_parse import normalize_http
from app.telemetry.http_store import HttpBatch
from telemetry_collector import (CollectorError, SOURCE_ID, atomic_write, collector_lock, encode,
                                 fsync_directory, post_batch, read_json, utc_now)

MAX_READ_BYTES = 1024 * 1024
MAX_LINE_BYTES = 32768
MAX_BATCH_BYTES = 900_000
MAX_RECORDS = 200


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def load_config(path):
    try:
        config = read_json(path, "invalid_config")
        if set(config) - {"endpoint", "state_dir", "streams", "http_timeout_seconds", "max_spool_bytes",
                          "max_pages_per_run", "max_seconds_per_stream", "rotation_quiet_seconds"}:
            raise ValueError
        endpoint = urlsplit(config["endpoint"])
        if (endpoint.scheme not in ("http", "https") or not endpoint.hostname or endpoint.username
                or endpoint.password or endpoint.query or endpoint.fragment or endpoint.path != "/api/http/batches"
                or (endpoint.scheme == "http" and endpoint.hostname not in ("127.0.0.1", "localhost", "::1"))):
            raise ValueError
        if not Path(config["state_dir"]).is_absolute():
            raise ValueError
        streams, seen = config["streams"], set()
        if not isinstance(streams, list) or not 1 <= len(streams) <= 200:
            raise ValueError
        for stream in streams:
            if set(stream) != {"source_id", "service_id", "path", "rotated_path", "token"}:
                raise ValueError
            key = (stream["source_id"], stream["service_id"])
            if any(not isinstance(v, str) or not SOURCE_ID.fullmatch(v) for v in key) or key in seen:
                raise ValueError
            seen.add(key)
            current, rotated = Path(stream["path"]), Path(stream["rotated_path"])
            if (not current.is_absolute() or not rotated.is_absolute() or current == rotated
                    or current.parent != rotated.parent):
                raise ValueError
            token = stream["token"]
            if not isinstance(token, str) or not 24 <= len(token) <= 512 or any(ord(c) < 33 or ord(c) > 126 for c in token):
                raise ValueError
        for name, default, low, high in (("http_timeout_seconds", 10, 1, 120),
                                         ("max_spool_bytes", 16*1024*1024, 1024, 1024**3),
                                         ("max_pages_per_run", 5, 1, 50),
                                         ("max_seconds_per_stream", 20, 1, 300),
                                         ("rotation_quiet_seconds", 5, 1, 300)):
            value = config.setdefault(name, default)
            if type(value) is not int or not low <= value <= high:
                raise ValueError
        return config
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        raise CollectorError("invalid_config") from None


def identity(config, stream):
    return digest({"endpoint": config["endpoint"], **{k: v for k, v in stream.items() if k != "token"}})


def validate_cursor(cursor):
    if cursor is None:
        return
    if (not isinstance(cursor, dict) or set(cursor) != {"device", "inode", "offset", "generation", "anchor", "prefix"}
            or any(type(cursor[k]) is not int or cursor[k] < 0 for k in ("device", "inode", "offset"))
            or any(not isinstance(cursor[k], str) or len(cursor[k]) != size
                   or any(c not in "0123456789abcdef" for c in cursor[k])
                   for k, size in (("generation", 32), ("anchor", 64), ("prefix", 64)))):
        raise CollectorError("invalid_cursor_state")


def open_log(path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError("not a regular file")
    return os.fdopen(fd, "rb")


def anchors(handle, offset):
    # Bypass the buffered reader: cached bytes can hide a concurrent rewrite.
    tail = os.pread(handle.fileno(), min(offset, 256), max(0, offset - 256))
    prefix = os.pread(handle.fileno(), min(offset, 256), 0)
    return hashlib.sha256(tail).hexdigest(), hashlib.sha256(prefix).hexdigest()


def unique_fields(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("duplicate field")
        result[k] = v
    return result


def build_pending(config, stream, cursor):
    body = {"source_id": stream["source_id"], "service_id": stream["service_id"],
            "batch_id": str(uuid.uuid4()), "collected_at": utc_now(), "records": [], "rejected": [], "reports": [], "caught_up": False}
    next_cursor = cursor
    handle = None
    try:
        handle = open_log(stream["path"])
        info = os.fstat(handle.fileno())
        using_rotated = False
        if cursor and (info.st_dev, info.st_ino) != (cursor["device"], cursor["inode"]):
            try:
                old = open_log(stream["rotated_path"])
                old_info = os.fstat(old.fileno())
                if (old_info.st_dev, old_info.st_ino) == (cursor["device"], cursor["inode"]):
                    handle.close()
                    handle, info, using_rotated = old, old_info, True
                else:
                    old.close()
            except OSError:
                pass
            if not using_rotated:
                body["reports"].append("rotation_gap")
        same_file = cursor and (info.st_dev, info.st_ino) == (cursor["device"], cursor["inode"])
        offset = cursor["offset"] if same_file else 0
        generation = cursor["generation"] if same_file else uuid.uuid4().hex
        if same_file and (info.st_size < offset or anchors(handle, offset) != (cursor["anchor"], cursor["prefix"])):
            body["reports"].append("file_truncated")
            offset, generation = 0, uuid.uuid4().hex
        handle.seek(offset)
        start_offset = offset
        observed = hashlib.sha256()
        for _ in range(MAX_RECORDS):
            start = handle.tell()
            raw = handle.readline(MAX_LINE_BYTES + 1)
            if not raw:
                break
            if len(raw) > MAX_LINE_BYTES:
                body["reports"].append("line_too_long")
                handle.seek(start)
                break
            if handle.tell() - start_offset > MAX_READ_BYTES:
                handle.seek(start)
                break
            if not raw.endswith(b"\n"):
                body["reports"].append("partial_line")
                handle.seek(start)
                break
            event_id = f"{generation}:{start}"
            try:
                record = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_fields)
                event = normalize_http(record, source_id=stream["source_id"], service_id=stream["service_id"], event_id=event_id)
                if event.event_ts > time.time() + 300:
                    raise ValueError("future timestamp")
                clean = {k: v for k, v in asdict(event).items() if k in ("event_id", "timestamp", "client_ip", "method", "path", "status")}
                collection, item = body["records"], clean
            except (ValueError, UnicodeError, RecursionError):
                collection, item = body["rejected"], {"event_id": event_id, "code": "invalid_record"}
            collection.append(item)
            if len(encode(body)) > MAX_BATCH_BYTES - 512:
                collection.pop()
                handle.seek(start)
                break
            observed.update(raw)
        offset = handle.tell()
        final = os.fstat(handle.fileno())
        if final.st_size < offset:
            # A truncate during the read invalidates this entire uncommitted page.
            raise OSError("log changed during read")
        if hashlib.sha256(os.pread(handle.fileno(), offset - start_offset, start_offset)).digest() != observed.digest():
            raise OSError("log changed during read")
        if same_file and start_offset and anchors(handle, start_offset) != (cursor["anchor"], cursor["prefix"]):
            raise OSError("log changed before cursor")
        anchor, prefix = anchors(handle, offset)
        next_cursor = {"device": info.st_dev, "inode": info.st_ino, "generation": generation,
                       "offset": offset, "anchor": anchor, "prefix": prefix}
        more = offset < final.st_size
        if using_rotated and not more:
            if time.time() - final.st_mtime < config["rotation_quiet_seconds"]:
                body["reports"].append("rotation_wait")
            else:
                # Old file drained after its quiet interval. The next ACKed page
                # starts the current file under a fresh generation.
                with open_log(stream["path"]) as current:
                    info = os.fstat(current.fileno())
                    if (info.st_dev, info.st_ino) == (next_cursor["device"], next_cursor["inode"]):
                        raise OSError("rotation changed during read")
                    anchor, prefix = anchors(current, 0)
                    next_cursor = {"device": info.st_dev, "inode": info.st_ino, "generation": uuid.uuid4().hex,
                                   "offset": 0, "anchor": anchor, "prefix": prefix}
                more = True
        if more and not any(code in body["reports"] for code in ("partial_line", "line_too_long")):
            body["reports"].append("catching_up")
        body["caught_up"] = not more and not body["reports"]
    except OSError:
        body.update(records=[], rejected=[], reports=["file_unavailable"], caught_up=False)
        next_cursor = cursor
    finally:
        if handle is not None:
            handle.close()
    pending = {"version": 1, "identity": identity(config, stream), "body": body,
               "base_cursor": cursor, "next_cursor": next_cursor}
    return {**pending, "checksum": digest(pending)}


def collect_page(config, stream, send=post_batch):
    root = Path(config["state_dir"])
    name = digest([stream["source_id"], stream["service_id"]])
    state_path, spool = root / (name + ".state.json"), root / (name + ".pending.json")
    state = read_json(state_path, "invalid_cursor_state") if state_path.exists() else {"identity": identity(config, stream), "cursor": None}
    if state.get("identity") != identity(config, stream) or "cursor" not in state:
        raise CollectorError("stream_configuration_changed")
    cursor = state["cursor"]
    validate_cursor(cursor)
    if spool.exists():
        pending = read_json(spool, "invalid_spool")
    else:
        pending = build_pending(config, stream, cursor)
        if sum(p.stat().st_size for p in root.glob("*.pending.json")) + len(encode(pending)) > config["max_spool_bytes"]:
            raise CollectorError("spool_capacity_reached")
        atomic_write(spool, pending)
    try:
        if (pending.get("version") != 1 or pending.get("identity") != identity(config, stream)
                or pending.get("checksum") != digest({k: v for k, v in pending.items() if k != "checksum"})
                or cursor not in (pending["base_cursor"], pending["next_cursor"])):
            raise ValueError
        validate_cursor(pending["next_cursor"])
        body = pending["body"]
        HttpBatch.model_validate(body)
        if (body["source_id"], body["service_id"]) != (stream["source_id"], stream["service_id"]):
            raise ValueError
    except (ValueError, TypeError, KeyError):
        raise CollectorError("invalid_spool") from None
    ack = send(config["endpoint"], stream["token"], body, config["http_timeout_seconds"])
    if (not isinstance(ack, dict) or ack.get("durable") is not True
            or any(ack.get(k) != body[k] for k in ("source_id", "service_id", "batch_id"))):
        raise CollectorError("invalid_ack")
    atomic_write(state_path, {"identity": identity(config, stream), "cursor": pending["next_cursor"]})
    spool.unlink()
    fsync_directory(root)
    return {"records": len(body["records"]), "rejected": len(body["rejected"]),
            "reports": body["reports"], "caught_up": body["caught_up"]}


def run_once(config, send=post_batch):
    results = []
    with collector_lock(Path(config["state_dir"])):
        for stream in config["streams"]:
            began = time.monotonic()
            result = {"source_id": stream["source_id"], "service_id": stream["service_id"],
                      "status": "acknowledged", "records": 0, "rejected": 0, "pages": 0,
                      "reports": [], "caught_up": False}
            try:
                for _ in range(config["max_pages_per_run"]):
                    page = collect_page(config, stream, send)
                    result["pages"] += 1
                    result["records"] += page["records"]
                    result["rejected"] += page["rejected"]
                    result["reports"] = sorted(set(result["reports"] + page["reports"]))
                    result["caught_up"] = page["caught_up"]
                    if ("catching_up" not in page["reports"] or time.monotonic() - began >= config["max_seconds_per_stream"]):
                        break
                if result["rejected"] or set(result["reports"]) - {"catching_up"}:
                    result["status"] = "degraded"
            except (CollectorError, OSError) as exc:
                result.update(status="error", caught_up=False,
                              code=str(exc) if isinstance(exc, CollectorError) else "local_storage_failed")
            result["duration_ms"] = round((time.monotonic() - began)*1000)
            results.append(result)
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--once", action="store_true", required=True)
    args = parser.parse_args(argv)
    try:
        results = run_once(load_config(args.config))
    except (CollectorError, OSError) as exc:
        print(json.dumps({"status": "error", "code": str(exc) if isinstance(exc, CollectorError) else "local_storage_failed"}), file=sys.stderr)
        return 1
    for result in results:
        print(json.dumps(result))
    return int(any(r["status"] != "acknowledged" for r in results))


if __name__ == "__main__":
    raise SystemExit(main())
