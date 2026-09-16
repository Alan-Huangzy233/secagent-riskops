from datetime import datetime, timezone
import json
from types import SimpleNamespace

import pytest

from app.telemetry.geoip import GeoIPLookup
from app.telemetry import geoip


def dataset(tmp_path, **overrides):
    manifest = {"directory": "2026-09-" + "a" * 32, "release": "2026-09",
                "updated_at": "2026-09-09T00:00:00+00:00"}
    manifest.update(overrides)
    (tmp_path / "current.json").write_text(json.dumps(manifest))
    return GeoIPLookup(tmp_path)


def readers(monkeypatch, *, absent=False, epoch=None):
    calls = []
    class Reader:
        def __init__(self, path):
            self.kind = path.stem
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def metadata(self):
            return SimpleNamespace(build_epoch=epoch or datetime.now(timezone.utc).timestamp())
        def get(self, ip):
            calls.append((self.kind, ip))
            if absent:
                return None
            if self.kind == "asn":
                return {"autonomous_system_number": 15169, "autonomous_system_organization": "Google LLC"}
            return {"country": {"iso_code": "US", "names": {"zh-CN": "美国", "en": "United States"}},
                    "subdivisions": [{"names": {"en": "California"}}],
                    "city": {"names": {"zh-CN": "山景城"}},
                    "location": {"latitude": 37.4, "longitude": -122.1}}
    monkeypatch.setattr(geoip.maxminddb, "open_database", Reader)
    return calls


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.1", "192.168.1.1", "::1", "fe80::1",
                                    "fc00::1", "224.0.0.1", "ff02::1", "0.0.0.0", "::",
                                    "100.64.1.1", "192.0.2.10", "2001:db8::1", "::ffff:10.0.0.1"])
def test_special_addresses_never_open_database(tmp_path, monkeypatch, ip):
    def forbidden(*args):
        pytest.fail("special address queried a database")
    monkeypatch.setattr(geoip.maxminddb, "open_database", forbidden)
    result = dataset(tmp_path).lookup(ip)
    assert result["status"] == "not_public"
    assert result["country"] is None


@pytest.mark.parametrize("ip", ["", " ", "example.com", "https://8.8.8.8", "8.8.8.8/32", "fe80::1%eth0",
                                    "1.2.3.999", "8.8.8.8:443", "[::1]", "010.0.0.1"])
def test_literal_only_no_dns_or_urls(tmp_path, ip):
    with pytest.raises(ValueError):
        GeoIPLookup(tmp_path).lookup(ip)


@pytest.mark.parametrize("ip,version,lookup_ip", [("8.8.8.8", 4, "8.8.8.8"),
                                                       ("2001:4860:4860::8888", 6, "2001:4860:4860::8888"),
                                                       ("::ffff:8.8.8.8", 6, "8.8.8.8")])
def test_local_city_asn_and_language(tmp_path, monkeypatch, ip, version, lookup_ip):
    calls = readers(monkeypatch)
    result = dataset(tmp_path).lookup(ip)
    assert result["status"] == "ok"
    assert result["version"] == version
    assert result["country"] == "美国"
    assert result["region"] == "California"
    assert result["city"] == "山景城"
    assert result["asn"] == 15169
    assert result["network_name"] == "Google LLC"
    assert result["database_stale"] is False
    assert calls == [("city", lookup_ip), ("asn", lookup_ip)]


def test_unknown_and_stale_dataset(tmp_path, monkeypatch):
    readers(monkeypatch, absent=True, epoch=1)
    result = dataset(tmp_path).lookup("8.8.8.8")
    assert result["status"] == "not_found"
    assert result["database_stale"] is True


def test_missing_corrupt_and_unsafe_manifest_degrade(tmp_path, monkeypatch):
    assert GeoIPLookup(None).lookup("8.8.8.8")["status"] == "unavailable"
    assert GeoIPLookup(tmp_path).lookup("8.8.8.8")["status"] == "unavailable"
    for override in ({"directory": "../escape"}, {"release": "2026-08"}, {"updated_at": "2026-09-09"}):
        assert dataset(tmp_path, **override).lookup("8.8.8.8")["status"] == "unavailable"
    lookup = dataset(tmp_path)
    def broken(*args):
        raise geoip.maxminddb.InvalidDatabaseError("private filesystem path")
    monkeypatch.setattr(geoip.maxminddb, "open_database", broken)
    assert "private filesystem" not in json.dumps(lookup.lookup("8.8.8.8"))
    assert lookup.lookup("8.8.8.8")["status"] == "unavailable"


def test_one_manifest_snapshot_and_version_reloaded(tmp_path, monkeypatch):
    lookup = dataset(tmp_path)
    readers(monkeypatch)
    original = geoip.maxminddb.open_database
    opened = []
    def swapping_reader(path):
        opened.append(path.parent.name)
        dataset(tmp_path, directory="2026-09-" + "b" * 32)
        return original(path)
    monkeypatch.setattr(geoip.maxminddb, "open_database", swapping_reader)
    assert lookup.lookup("8.8.8.8")["status"] == "ok"
    assert opened == ["2026-09-" + "a" * 32] * 2
    lookup.lookup("8.8.8.8")
    assert opened[2:] == ["2026-09-" + "b" * 32] * 2
