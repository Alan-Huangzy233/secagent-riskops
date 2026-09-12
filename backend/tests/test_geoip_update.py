from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.request import Request

import pytest


_SPEC = importlib.util.spec_from_file_location(
    "update_geoip", Path(__file__).parents[2] / "scripts" / "update_geoip.py"
)
updater = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(updater)


class Response(io.BytesIO):
    status = 200

    def __init__(self, body, *, advertised_length=None):
        super().__init__(body)
        self.headers = {} if advertised_length is None else {"Content-Length": str(advertised_length)}


class Opener:
    def __init__(self, response):
        self.response = response
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return self.response


def fake_download(kind, month, target):
    payload = (kind + ":" + month).encode()
    target.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def fake_validate(path, kind):
    if not path.is_file() or not path.read_bytes().startswith(kind.encode() + b":"):
        raise ValueError("bad database")
    return {"database_type": f"DBIP-{kind}", "ip_version": 6, "build_epoch": 1788220800}


def publish(directory, month="2026-09", **kwargs):
    return updater.update(directory, month, downloader=kwargs.get("downloader", fake_download),
                          validator=kwargs.get("validator", fake_validate))


@pytest.mark.parametrize("month", ["2026-00", "2026-13", "2026-9", "0000-01", "2026-09/../../secret"])
def test_rejects_invalid_month_before_creating_output(tmp_path, month):
    output = tmp_path / "database"
    with pytest.raises(argparse.ArgumentTypeError):
        publish(output, month)
    assert not output.exists()


def test_download_streams_gzip_from_fixed_host_and_records_uncompressed_hash(tmp_path):
    data = b"pretend mmdb bytes" * 1000
    opener = Opener(Response(gzip.compress(data)))
    target = tmp_path / "city.mmdb"
    digest = updater.download_database("city", "2026-09", target, opener=opener)
    assert target.read_bytes() == data
    assert digest == hashlib.sha256(data).hexdigest()
    request, timeout = opener.requests[0]
    assert request.full_url == "https://download.db-ip.com/free/dbip-city-lite-2026-09.mmdb.gz"
    assert request.data is None
    assert timeout == 30


@pytest.mark.parametrize("advertised_length", [None, 1000])
def test_rejects_oversized_compressed_download_with_or_without_content_length(tmp_path, advertised_length):
    body = gzip.compress(bytes(range(256)) * 10)
    opener = Opener(Response(body, advertised_length=advertised_length))
    with pytest.raises(ValueError, match="compressed database exceeds"):
        updater.download_database("city", "2026-09", tmp_path / "city.mmdb",
                                   opener=opener, compressed_limit=20)


def test_rejects_gzip_bomb_and_corrupt_gzip(tmp_path):
    with pytest.raises(ValueError, match="uncompressed database exceeds"):
        updater.download_database("city", "2026-09", tmp_path / "large.mmdb",
                                   opener=Opener(Response(gzip.compress(b"A" * 10000))),
                                   uncompressed_limit=50)
    corrupt = bytearray(gzip.compress(b"database contents"))
    corrupt[-8] ^= 1  # gzip CRC, not merely an invalid HTTP Content-Length.
    with pytest.raises(gzip.BadGzipFile):
        updater.download_database("asn", "2026-09", tmp_path / "corrupt.mmdb",
                                   opener=Opener(Response(corrupt)))


@pytest.mark.parametrize("url", ["http://download.db-ip.com/file", "https://other.example/file",
                                      "https://download.db-ip.com:444/file",
                                      "https://user:password@download.db-ip.com/file"])
def test_rejects_redirect_outside_verified_download_origin(url):
    handler = updater.SameHostRedirects()
    with pytest.raises(ValueError, match="permitted HTTPS"):
        handler.redirect_request(Request("https://download.db-ip.com/free/file"),
                                 None, 302, "Found", {}, url)


def test_allows_https_redirect_within_download_origin():
    result = updater.SameHostRedirects().redirect_request(
        Request("https://download.db-ip.com/free/file"), None, 302, "Found", {},
        "https://download.db-ip.com/free/file2")
    assert result.full_url == "https://download.db-ip.com/free/file2"


def test_publishes_complete_pair_then_reuses_month_without_network(tmp_path, monkeypatch):
    directory = tmp_path / "geoip"
    manifest, changed = publish(directory)
    assert changed
    assert json.loads((directory / "current.json").read_text()) == manifest
    assert updater.VERSION_PATTERN.fullmatch(manifest["directory"])
    assert manifest["updated_at"].endswith("+00:00")
    for kind in ("city", "asn"):
        path = directory / manifest["directory"] / f"{kind}.mmdb"
        assert path.read_bytes() == f"{kind}:2026-09".encode()
        assert manifest["databases"][kind]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(updater, "validate_database", fake_validate)

    def no_download(*args):
        pytest.fail("valid current-month database must not access network")

    again, changed = publish(directory, downloader=no_download)
    assert not changed
    assert again == manifest


@pytest.mark.parametrize("failure", ["download", "validation"])
def test_failed_second_database_keeps_old_pair_and_manifest(tmp_path, failure):
    directory = tmp_path / "geoip"
    previous, _ = publish(directory, "2026-08")
    manifest_bytes = (directory / "current.json").read_bytes()

    def download(kind, month, target):
        if kind == "asn" and failure == "download":
            target.write_bytes(b"partial")
            raise OSError("connection dropped")
        return fake_download(kind, month, target)

    def validate(path, kind):
        if kind == "asn" and failure == "validation":
            raise ValueError("unexpected database schema")
        return fake_validate(path, kind)

    with pytest.raises((OSError, ValueError)):
        publish(directory, downloader=download, validator=validate)
    assert (directory / "current.json").read_bytes() == manifest_bytes
    assert {path.name for path in directory.iterdir()} == {previous["directory"], "current.json", ".update.lock"}


def test_manifest_publish_failure_preserves_previous_pointer(tmp_path, monkeypatch):
    directory = tmp_path / "geoip"
    previous, _ = publish(directory, "2026-08")
    manifest_bytes = (directory / "current.json").read_bytes()
    replace = updater.os.replace

    def failing_replace(source, destination):
        if Path(destination).name == "current.json":
            raise OSError("simulated manifest write failure")
        return replace(source, destination)

    monkeypatch.setattr(updater.os, "replace", failing_replace)
    with pytest.raises(OSError, match="simulated"):
        publish(directory)
    assert (directory / "current.json").read_bytes() == manifest_bytes
    assert (directory / previous["directory"] / "asn.mmdb").read_bytes() == b"asn:2026-08"
    assert not list(directory.glob(".current-*.tmp"))


def test_corrupt_current_file_causes_new_pair_without_removing_old_version(tmp_path, monkeypatch):
    directory = tmp_path / "geoip"
    previous, _ = publish(directory)
    (directory / previous["directory"] / "asn.mmdb").write_bytes(b"corrupt")
    monkeypatch.setattr(updater, "validate_database", fake_validate)
    fresh, changed = publish(directory)
    assert changed
    assert fresh["directory"] != previous["directory"]
    assert (directory / previous["directory"]).is_dir()
    assert (directory / fresh["directory"] / "asn.mmdb").read_bytes() == b"asn:2026-09"


def test_tampered_manifest_never_opens_database_outside_named_directory(tmp_path, monkeypatch):
    directory = tmp_path / "geoip"
    directory.mkdir()
    (directory / "current.json").write_text(json.dumps({"release": "2026-09", "directory": "../outside"}))

    def forbid_validation(*args):
        pytest.fail("unsafe manifest path must not be opened")

    monkeypatch.setattr(updater, "validate_database", forbid_validation)
    assert updater.existing_release(directory, "2026-09") is None


class Reader:
    def __init__(self, kind, *, record=None, ipv6=True, ip_version=6):
        self.kind, self.record, self.ipv6, self.ip_version = kind, record, ipv6, ip_version

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def metadata(self):
        return SimpleNamespace(database_type=f"DBIP-{self.kind}-Lite", ip_version=self.ip_version,
                               build_epoch=1788220800, node_count=100)

    def get(self, ip):
        if ":" in ip and not self.ipv6:
            return None
        if self.record is not None:
            return self.record
        return ({"country": {"iso_code": "US"}} if self.kind == "city" else
                {"autonomous_system_number": 15169, "autonomous_system_organization": "Google LLC"})


@pytest.mark.parametrize("kind", ["city", "asn"])
def test_validates_expected_mmdb_metadata_and_both_ip_families(tmp_path, monkeypatch, kind):
    path = tmp_path / f"{kind}.mmdb"
    path.write_bytes(b"fake fixture")
    monkeypatch.setattr(updater.maxminddb, "open_database", lambda value: Reader(kind))
    metadata = updater.validate_database(path, kind)
    assert metadata["database_type"] == f"DBIP-{kind}-Lite"
    assert metadata["ip_version"] == 6


@pytest.mark.parametrize("reader", [Reader("country"), Reader("city", ipv6=False),
                                          Reader("city", ip_version=4), Reader("city", record={"bad": True})])
def test_rejects_wrong_city_database_or_missing_ipv6(tmp_path, monkeypatch, reader):
    path = tmp_path / "city.mmdb"
    path.write_bytes(b"fake fixture")
    monkeypatch.setattr(updater.maxminddb, "open_database", lambda value: reader)
    with pytest.raises(ValueError):
        updater.validate_database(path, "city")


@pytest.mark.parametrize("record", [{"autonomous_system_number": True, "autonomous_system_organization": "x"},
                                          {"autonomous_system_number": 15169},
                                          {"autonomous_system_number": 4294967296,
                                           "autonomous_system_organization": "x"}])
def test_rejects_invalid_asn_schema(tmp_path, monkeypatch, record):
    path = tmp_path / "asn.mmdb"
    path.write_bytes(b"fake fixture")
    monkeypatch.setattr(updater.maxminddb, "open_database", lambda value: Reader("asn", record=record))
    with pytest.raises(ValueError, match="ASN database schema"):
        updater.validate_database(path, "asn")
