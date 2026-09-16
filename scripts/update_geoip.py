#!/usr/bin/env python3
"""Download DB-IP Lite monthly databases; individual lookup IPs never leave this host."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import tempfile
import time
from typing import BinaryIO
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener
from uuid import uuid4

import maxminddb


DOWNLOAD_HOST = "download.db-ip.com"
MAX_COMPRESSED = 256 * 1024 * 1024
MAX_UNCOMPRESSED = 512 * 1024 * 1024
CHUNK_SIZE = 128 * 1024
DOWNLOAD_SECONDS = 240
VERSION_PATTERN = re.compile(r"[0-9]{4}-(?:0[1-9]|1[0-2])-[0-9a-f]{32}")


def valid_month(value: str) -> str:
    if not re.fullmatch(r"[0-9]{4}-(?:0[1-9]|1[0-2])", value):
        raise argparse.ArgumentTypeError("month must be YYYY-MM")
    try:
        datetime.strptime(value, "%Y-%m")
    except ValueError as exc:
        raise argparse.ArgumentTypeError("month must be YYYY-MM") from exc
    return value


class SameHostRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlsplit(newurl)
        if (parsed.scheme != "https" or parsed.hostname != DOWNLOAD_HOST
                or parsed.port not in (None, 443) or parsed.username or parsed.password):
            raise ValueError("database redirect left the permitted HTTPS download host")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_opener():
    # An explicit verified context also avoids the optional SSLKEYLOGFILE
    # behavior of create_default_context.  Ignore inherited proxy variables.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_default_certs()
    return build_opener(ProxyHandler({}), HTTPSHandler(context=context), SameHostRedirects())


class BoundedReader:
    def __init__(self, stream: BinaryIO, limit: int, deadline: float):
        self.stream, self.limit, self.deadline = stream, limit, deadline
        self.count = 0

    def read(self, size: int = -1) -> bytes:
        if time.monotonic() > self.deadline:
            raise TimeoutError("database download exceeded its time limit")
        # gzip normally requests bounded reads; keep even an unbounded request
        # bounded before it reaches the response object.
        size = min(size if size >= 0 else CHUNK_SIZE, self.limit - self.count + 1)
        value = self.stream.read(size)
        self.count += len(value)
        if self.count > self.limit:
            raise ValueError("compressed database exceeds the size limit")
        return value


def download_database(kind: str, month: str, destination: Path, *, opener=None,
                      compressed_limit: int = MAX_COMPRESSED,
                      uncompressed_limit: int = MAX_UNCOMPRESSED) -> str:
    if kind not in ("city", "asn"):
        raise ValueError("unsupported database kind")
    month = valid_month(month)
    url = f"https://{DOWNLOAD_HOST}/free/dbip-{kind}-lite-{month}.mmdb.gz"
    opener = opener or download_opener()
    request = Request(url, headers={"User-Agent": "secagent-riskops-geoip/1.0",
                                   "Accept-Encoding": "identity"})
    digest = hashlib.sha256()
    deadline = time.monotonic() + DOWNLOAD_SECONDS
    with opener.open(request, timeout=30) as response:
        if response.status != 200:
            raise ValueError("database download did not return HTTP 200")
        length = response.headers.get("Content-Length")
        if length is not None and int(length) > compressed_limit:
            raise ValueError("compressed database exceeds the size limit")
        reader = BoundedReader(response, compressed_limit, deadline)
        with gzip.GzipFile(fileobj=reader) as archive, destination.open("xb") as output:
            total = 0
            while True:
                data = archive.read(min(CHUNK_SIZE, uncompressed_limit - total + 1))
                if not data:
                    break
                total += len(data)
                if total > uncompressed_limit:
                    raise ValueError("uncompressed database exceeds the size limit")
                output.write(data)
                digest.update(data)
            output.flush()
            os.fsync(output.fileno())
    destination.chmod(0o644)
    return digest.hexdigest()


def validate_database(path: Path, kind: str) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_UNCOMPRESSED:
        raise ValueError("database file is missing or unsafe")
    with maxminddb.open_database(str(path)) as reader:
        metadata = reader.metadata()
        if (kind not in metadata.database_type.lower() or metadata.ip_version != 6
                or metadata.build_epoch <= 0 or metadata.node_count <= 0):
            raise ValueError("unexpected database metadata")
        # These are local MMDB reads, not DNS requests or external lookups.
        for ip in ("8.8.8.8", "2001:4860:4860::8888"):
            record = reader.get(ip)
            if not isinstance(record, dict):
                raise ValueError("database is missing its IPv4/IPv6 verification records")
            if kind == "city":
                country = record.get("country", {})
                if not isinstance(country, dict) or not isinstance(country.get("iso_code"), str):
                    raise ValueError("unexpected city database schema")
            else:
                asn = record.get("autonomous_system_number")
                organization = record.get("autonomous_system_organization")
                if (not isinstance(asn, int) or isinstance(asn, bool) or not 0 < asn <= 4294967295
                        or not isinstance(organization, str)):
                    raise ValueError("unexpected ASN database schema")
        return {"database_type": metadata.database_type,
                "build_epoch": metadata.build_epoch, "ip_version": metadata.ip_version}


def existing_release(directory: Path, month: str) -> dict | None:
    manifest_path = directory / "current.json"
    try:
        if manifest_path.is_symlink() or manifest_path.stat().st_size > 16384:
            return None
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        name = manifest["directory"]
        if (manifest["release"] != month or not isinstance(name, str)
                or not VERSION_PATTERN.fullmatch(name) or not name.startswith(month + "-")):
            return None
        version = directory / name
        if version.is_symlink() or version.resolve().parent != directory.resolve():
            return None
        for kind in ("city", "asn"):
            validate_database(version / f"{kind}.mmdb", kind)
        return manifest
    except (OSError, ValueError, TypeError, KeyError, maxminddb.InvalidDatabaseError):
        return None


@contextmanager
def update_lock(directory: Path):
    # Linux production runs take an advisory lock shared by manual runs and
    # the systemd timer.  The lock is released by the kernel after a crash.
    with (directory / ".update.lock").open("a+b") as handle:
        if os.name == "posix":
            import fcntl
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def update(directory: Path, month: str, *, downloader=download_database,
           validator=validate_database) -> tuple[dict, bool]:
    month = valid_month(month)
    if not directory.is_absolute():
        raise ValueError("database directory must be absolute")
    directory.mkdir(parents=True, exist_ok=True, mode=0o755)
    if directory.is_symlink():
        raise ValueError("database directory must not be a symlink")
    directory = directory.resolve()
    with update_lock(directory):
        current = existing_release(directory, month)
        if current is not None:
            return current, False
        name = f"{month}-{uuid4().hex}"
        manifest = {"directory": name, "release": month,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                    "provider": "DB-IP Lite", "license": "CC BY 4.0", "databases": {}}
        with tempfile.TemporaryDirectory(prefix=".download-", dir=directory) as temporary:
            stage = Path(temporary)
            for kind in ("city", "asn"):
                target = stage / f"{kind}.mmdb"
                digest = downloader(kind, month, target)
                manifest["databases"][kind] = {**validator(target, kind), "sha256": digest}
            stage.chmod(0o755)
            if os.name == "posix":
                descriptor = os.open(stage, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            # A request reads current.json once, then opens both files from
            # this immutable version.  Do not delete historical versions
            # while another process might still be using them.
            os.replace(stage, directory / name)
        manifest_temp = directory / f".current-{uuid4().hex}.tmp"
        try:
            with manifest_temp.open("x", encoding="utf-8") as output:
                json.dump(manifest, output, ensure_ascii=False, indent=2)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            manifest_temp.chmod(0o644)
            os.replace(manifest_temp, directory / "current.json")
            if os.name == "posix":
                descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        finally:
            manifest_temp.unlink(missing_ok=True)
        return manifest, True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--month", type=valid_month,
                        default=datetime.now(timezone.utc).strftime("%Y-%m"))
    args = parser.parse_args()
    manifest, changed = update(args.directory, args.month)
    print(f"DB-IP Lite {manifest['release']}: {'updated' if changed else 'already valid'}")


if __name__ == "__main__":
    main()
