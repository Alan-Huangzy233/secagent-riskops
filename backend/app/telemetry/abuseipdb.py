"""Explicit, operator-triggered AbuseIPDB checks; no reporting or log upload."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import ssl
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener

_API = "https://api.abuseipdb.com/api/v2/check"
_BODY_LIMIT = 64 * 1024
_KEY_LIMIT = 512
_CACHE_TTL = 300
_CACHE_LIMIT = 256
_KEY_TOKEN = re.compile(r"[A-Za-z0-9_-]{1,512}\Z")
_UNAVAILABLE = "AbuseIPDB 暂时不可用，请稍后手动重试；日志采集不受影响。"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # An API redirect must never forward the Key header to another origin.
        return None


def _opener():
    # Explicit SSLContext also avoids SSLKEYLOGFILE, which create_default_context
    # otherwise honors. Environment proxies must not receive IP queries or keys.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_default_certs()
    return build_opener(ProxyHandler({}), HTTPSHandler(context=context), _NoRedirect())


def _address(value: str):
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > 45 or any(c in value for c in "%/"):
        raise ValueError("请输入完整的 IPv4 或 IPv6 地址，不支持域名、URL、网段或接口后缀。")
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        raise ValueError("请输入有效的 IPv4 或 IPv6 地址。") from None
    return getattr(address, "ipv4_mapped", None) or address


def _public(address) -> bool:
    return bool(address.is_global and not any((address.is_private, address.is_reserved,
                                              address.is_multicast, address.is_unspecified,
                                              address.is_loopback, address.is_link_local)))


def _count(value):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**31 - 1:
        raise ValueError("invalid count")
    return value


def _reported_at(value):
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("invalid timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp missing timezone")
    return parsed.isoformat()


class AbuseIPDBClient:
    """Keep the key on the server and cache only validated results in memory.

    ``lookup`` is intentionally not called by ingestion or GeoIP lookup. The
    authenticated manual API route owns the user's decision to send this IP.
    """

    def __init__(self, key_file: str | Path | None):
        self.key_file = Path(key_file) if key_file else None
        self._cache: OrderedDict[tuple[str, str], tuple[float, dict]] = OrderedDict()
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(2)
        self._fingerprint: str | None = None
        self._retry_after = 0.0

    def _key(self) -> str | None:
        if self.key_file is None:
            return None
        try:
            if not self.key_file.is_file():
                return None
            with self.key_file.open("rb") as stream:
                raw = stream.read(_KEY_LIMIT + 1)
            if len(raw) > _KEY_LIMIT:
                return None
            value = raw.decode("ascii").strip()
            return value if _KEY_TOKEN.fullmatch(value) else None
        except (OSError, UnicodeError):
            return None

    def has_key(self) -> bool:
        """Whether a bounded, syntactically valid key file is readable (no API call)."""
        return self._key() is not None

    @staticmethod
    def _result(address) -> dict:
        return dict(ip=str(address), status="unavailable", score=None, total_reports=None,
                    distinct_reporters=None, last_reported_at=None, checked_at=None,
                    cached=False, max_age_days=90, notice=_UNAVAILABLE,
                    report_url=f"https://www.abuseipdb.com/check/{quote(str(address), safe='')}")

    def lookup(self, ip: str) -> dict:
        address = _address(ip)
        result = self._result(address)
        if not _public(address):
            result.update(status="not_public", report_url=None,
                          notice="仅支持公网 IP；此地址不会发送给 AbuseIPDB。")
            return result
        key = self._key()
        if key is None:
            with self._lock:
                self._cache.clear()
                self._fingerprint = None
                self._retry_after = 0.0
            result.update(status="not_configured", notice="尚未配置可用的 AbuseIPDB API Key。")
            return result
        fingerprint = hashlib.sha256(key.encode("ascii")).hexdigest()
        cache_key = (fingerprint, str(address))
        with self._lock:
            now = time.monotonic()
            if self._fingerprint != fingerprint:
                self._cache.clear()
                self._retry_after = 0.0
                self._fingerprint = fingerprint
            for expired in [entry for entry, (expires, _) in self._cache.items() if expires <= now]:
                del self._cache[expired]
            cached = self._cache.get(cache_key)
            if cached is not None:
                self._cache.move_to_end(cache_key)
                return dict(cached[1], cached=True)
            if self._retry_after > now:
                result.update(status="rate_limited", notice="AbuseIPDB 查询额度暂受限制，请稍后重试。")
                return result
        if not self._slots.acquire(blocking=False):
            result.update(notice="已有 IP 风险查询正在进行，请稍后重试。")
            return result
        try:
            request = Request(_API + "?" + urlencode({"ipAddress": str(address), "maxAgeInDays": 90}),
                              headers={"Key": key, "Accept": "application/json"}, method="GET")
            with _opener().open(request, timeout=8) as response:
                if response.status != 200:
                    return result
                raw = response.read(_BODY_LIMIT + 1)
                if len(raw) > _BODY_LIMIT:
                    return result
            payload = json.loads(raw.decode("utf-8"))
            data = payload["data"]
            if not isinstance(data, dict) or _address(data["ipAddress"]) != address:
                return result
            score = data["abuseConfidenceScore"]
            if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
                return result
            result.update(status="ok", score=score, total_reports=_count(data.get("totalReports")),
                          distinct_reporters=_count(data.get("numDistinctUsers")),
                          last_reported_at=_reported_at(data.get("lastReportedAt")),
                          checked_at=datetime.now(timezone.utc).isoformat(),
                          notice="风险分来自近 90 天的 AbuseIPDB 举报数据；低分或零举报不代表安全。")
            with self._lock:
                # A request made with an old key may finish after a key rotation.
                if self._fingerprint == fingerprint:
                    self._cache[cache_key] = (time.monotonic() + _CACHE_TTL, dict(result))
                    self._cache.move_to_end(cache_key)
                    while len(self._cache) > _CACHE_LIMIT:
                        self._cache.popitem(last=False)
            return result
        except HTTPError as error:
            try:
                if error.code == 429:
                    header = error.headers.get("Retry-After", "60") if error.headers else "60"
                    wait = min(60, max(1, int(header))) if re.fullmatch(r"[0-9]{1,8}", header) else 60
                    with self._lock:
                        if self._fingerprint == fingerprint:
                            self._retry_after = max(self._retry_after, time.monotonic() + wait)
                    result.update(status="rate_limited", notice="AbuseIPDB 查询额度暂受限制，请稍后重试。")
                elif error.code in (401, 403):
                    result.update(notice="AbuseIPDB 拒绝了 API 凭证，请检查服务器上的 Key 与账户权限。")
            finally:
                error.close()
            return result
        except (OSError, URLError, HTTPException, ValueError, KeyError, TypeError, UnicodeError, RecursionError):
            # Never include upstream response bodies, URLs, key values, or exceptions.
            return result
        finally:
            self._slots.release()
