import hashlib
import io
import json
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from http.client import IncompleteRead
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit

import pytest

from app.telemetry import abuseipdb
from app.telemetry.abuseipdb import AbuseIPDBClient


@pytest.fixture
def client(tmp_path):
    path = tmp_path / "abuseipdb.key"
    path.write_text("test-key-1234567890\n", encoding="ascii")
    return AbuseIPDBClient(path)


def response(ip="8.8.8.8", **changes):
    data = dict(ipAddress=ip, abuseConfidenceScore=42, totalReports=12,
                numDistinctUsers=4, lastReportedAt="2026-09-10T12:34:56+00:00")
    data.update(changes)
    return json.dumps({"data": data}).encode()


class FakeResponse(io.BytesIO):
    status = 200


def mock_api(monkeypatch, payload=None, error=None):
    calls = []

    class Opener:
        def open(self, request, timeout):
            calls.append((request, timeout))
            if error:
                raise error
            return FakeResponse(payload if payload is not None else response())

    monkeypatch.setattr(abuseipdb, "_opener", Opener)
    return calls


@pytest.mark.parametrize("value", ["", "example.com", "https://8.8.8.8", "8.8.8.8/32", "fe80::1%eth0", "999.1.1.1", "8.8.8.8\r\nKey: x", None, 42])
def test_rejects_nonliteral_ips_without_network(client, monkeypatch, value):
    calls = mock_api(monkeypatch)
    with pytest.raises(ValueError):
        client.lookup(value)
    assert not calls


@pytest.mark.parametrize("value", ["127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.1.1", "100.64.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "::", "::1", "fe80::1", "fc00::1", "ff02::1", "2001:db8::1", "::ffff:10.0.0.1"])
def test_nonpublic_addresses_never_leave_server(client, monkeypatch, value):
    calls = mock_api(monkeypatch)
    result = client.lookup(value)
    assert result["status"] == "not_public"
    assert result["score"] is None
    assert result["report_url"] is None
    assert not calls


def test_fixed_readonly_api_contract_and_cache(client, monkeypatch):
    calls = mock_api(monkeypatch)
    first = client.lookup(" 8.8.8.8 ")
    second = client.lookup("8.8.8.8")
    assert first["status"] == "ok"
    assert first["score"] == 42
    assert first["total_reports"] == 12
    assert first["distinct_reporters"] == 4
    assert first["max_age_days"] == 90
    assert first["checked_at"]
    assert first["cached"] is False and second["cached"] is True
    assert len(calls) == 1
    request, timeout = calls[0]
    url = urlsplit(request.full_url)
    assert (url.scheme, url.netloc, url.path) == ("https", "api.abuseipdb.com", "/api/v2/check")
    assert parse_qs(url.query) == {"ipAddress": ["8.8.8.8"], "maxAgeInDays": ["90"]}
    assert request.method == "GET"
    assert request.data is None
    assert request.get_header("Key") == "test-key-1234567890"
    assert request.get_header("Accept") == "application/json"
    assert timeout == 8
    assert "test-key" not in json.dumps(first)
    first["score"] = 99
    assert client.lookup("8.8.8.8")["score"] == 42


@pytest.mark.parametrize("ip", ["2606:4700:4700::1111", "::ffff:8.8.8.8"])
def test_ipv6_and_mapped_ipv4(client, monkeypatch, ip):
    canonical = "8.8.8.8" if ip.startswith("::ffff") else ip
    calls = mock_api(monkeypatch, response(ip=canonical))
    result = client.lookup(ip)
    assert result["status"] == "ok" and result["ip"] == canonical
    assert parse_qs(urlsplit(calls[0][0].full_url).query)["ipAddress"] == [canonical]


@pytest.mark.parametrize("raw", [b"", b"abc\r\nInjected: bad", b"abc def", b"x" * 513, "非ASCII".encode(), b"key=bad"])
def test_invalid_key_files_never_call_api(tmp_path, monkeypatch, raw):
    path = tmp_path / "key"
    path.write_bytes(raw)
    client = AbuseIPDBClient(path)
    calls = mock_api(monkeypatch)
    assert client.has_key() is False
    assert client.lookup("8.8.8.8")["status"] == "not_configured"
    assert not calls


def test_missing_key_or_directory_is_not_configured(tmp_path, monkeypatch):
    calls = mock_api(monkeypatch)
    for path in (None, tmp_path / "missing", tmp_path):
        client = AbuseIPDBClient(path)
        assert client.has_key() is False
        assert client.lookup("8.8.8.8")["status"] == "not_configured"
    assert not calls


def test_cache_expiration_and_key_rotation(client, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(abuseipdb.time, "monotonic", lambda: clock[0])
    calls = mock_api(monkeypatch)
    assert client.has_key()
    client.lookup("8.8.8.8")
    clock[0] += 299
    assert client.lookup("8.8.8.8")["cached"]
    clock[0] += 2
    assert not client.lookup("8.8.8.8")["cached"]
    client.key_file.write_text("new-key-1234567890")
    assert not client.lookup("8.8.8.8")["cached"]
    assert len(calls) == 3
    client.key_file.unlink()
    assert client.lookup("8.8.8.8")["status"] == "not_configured"


@pytest.mark.parametrize("payload", [b"not json", b"[1]", b'{}', b'{"data":[]}', b"x" * 65537,
    response(ip="1.1.1.1"), response(abuseConfidenceScore=True), response(abuseConfidenceScore=-1),
    response(abuseConfidenceScore=101), response(abuseConfidenceScore="42"),
    response(totalReports=-1), response(numDistinctUsers=True), response(lastReportedAt="not a date"),
    response(lastReportedAt="2026-09-10T12:34:56"), b"[" * 1100 + b"]" * 1100],
    ids=lambda payload: hashlib.sha256(payload).hexdigest()[:10])
def test_rejects_malformed_or_mismatched_results(client, monkeypatch, payload):
    calls = mock_api(monkeypatch, payload)
    result = client.lookup("8.8.8.8")
    assert result["status"] == "unavailable"
    assert result["score"] is None
    client.lookup("8.8.8.8")
    assert len(calls) == 2  # Invalid results are never cached.


@pytest.mark.parametrize("code", [301, 302, 307, 308, 401, 403, 500, 503])
def test_http_failures_are_sanitized_and_not_cached(client, monkeypatch, code):
    calls = []

    class Opener:
        def open(self, request, timeout):
            calls.append(request)
            raise HTTPError(request.full_url, code, "secret-key upstream body", {}, io.BytesIO(b"secret-key"))

    monkeypatch.setattr(abuseipdb, "_opener", Opener)
    result = client.lookup("8.8.8.8")
    assert result["status"] == "unavailable"
    assert "secret-key" not in json.dumps(result)
    client.lookup("8.8.8.8")
    assert len(calls) == 2


@pytest.mark.parametrize("error", [URLError("secret-key"), TimeoutError("secret-key"), OSError("secret-key"), ssl.SSLError("secret-key"), IncompleteRead(b"secret-key")])
def test_transport_errors_are_sanitized(client, monkeypatch, error):
    mock_api(monkeypatch, error=error)
    result = client.lookup("8.8.8.8")
    assert result["status"] == "unavailable"
    assert "secret-key" not in json.dumps(result)


@pytest.mark.parametrize("retry", ["120", "999999999999999999999", "Thu, 12 Sep 2026 00:00:00 GMT", "-1", "garbage"])
def test_rate_limit_backoff_is_bounded_and_key_specific(client, monkeypatch, retry):
    clock = [1000.0]
    monkeypatch.setattr(abuseipdb.time, "monotonic", lambda: clock[0])
    calls = []

    class Opener:
        def open(self, request, timeout):
            calls.append(request)
            raise HTTPError(request.full_url, 429, "secret", {"Retry-After": retry}, io.BytesIO(b"secret"))

    monkeypatch.setattr(abuseipdb, "_opener", Opener)
    assert client.lookup("8.8.8.8")["status"] == "rate_limited"
    assert client.lookup("1.1.1.1")["status"] == "rate_limited"
    assert len(calls) == 1
    assert client._retry_after <= 1060
    clock[0] += 61
    client.lookup("8.8.8.8")
    assert len(calls) == 2
    client.key_file.write_text("rotated-key")
    client.lookup("8.8.8.8")
    assert len(calls) == 3


def test_no_environment_proxies_tls_keylog_or_redirects(monkeypatch, tmp_path):
    keylog = tmp_path / "tls-secrets.txt"
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    captured = []
    monkeypatch.setattr(abuseipdb, "build_opener", lambda *handlers: captured.extend(handlers))
    abuseipdb._opener()
    proxy, https, redirects = captured
    assert proxy.proxies == {}
    assert https._context.verify_mode == ssl.CERT_REQUIRED
    assert https._context.check_hostname is True
    assert https._context.keylog_filename is None
    assert not keylog.exists()
    assert redirects.redirect_request(None, None, 302, "", {}, "https://other.example/") is None


def test_outbound_concurrency_is_bounded_and_recovers(client, monkeypatch):
    entered = threading.Barrier(3)
    release = threading.Event()

    class Opener:
        def open(self, request, timeout):
            entered.wait(timeout=3)
            assert release.wait(timeout=3)
            ip = parse_qs(urlsplit(request.full_url).query)["ipAddress"][0]
            return FakeResponse(response(ip=ip))

    monkeypatch.setattr(abuseipdb, "_opener", Opener)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(client.lookup, "8.8.8.8")
        second = pool.submit(client.lookup, "1.1.1.1")
        entered.wait(timeout=3)
        try:
            assert client.lookup("9.9.9.9")["status"] == "unavailable"
        finally:
            release.set()
        assert first.result()["status"] == "ok"
        assert second.result()["status"] == "ok"
    assert client._slots.acquire(blocking=False)
    client._slots.release()


def test_lru_is_bounded(client, monkeypatch):
    monkeypatch.setattr(abuseipdb, "_CACHE_LIMIT", 2)

    class Opener:
        def open(self, request, timeout):
            ip = parse_qs(urlsplit(request.full_url).query)["ipAddress"][0]
            return FakeResponse(response(ip=ip))

    monkeypatch.setattr(abuseipdb, "_opener", Opener)
    client.lookup("8.8.8.8")
    client.lookup("1.1.1.1")
    client.lookup("8.8.8.8")
    client.lookup("9.9.9.9")
    assert len(client._cache) == 2
    assert client.lookup("8.8.8.8")["cached"]
    assert not client.lookup("1.1.1.1")["cached"]
