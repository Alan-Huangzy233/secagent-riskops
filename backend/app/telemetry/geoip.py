"""Local-only IP classification and DB-IP Lite lookup. Never resolves or sends IPs."""
from __future__ import annotations

import ipaddress
import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path

import maxminddb

_VERSION = re.compile(r"\d{4}-(?:0[1-9]|1[0-2])-[0-9a-f]{32}")
_NOTICE = "属地为数据库中的近似位置，不能确定实际使用者位置；VPN / 代理通常显示出口位置。"


def _name(record):
    if not isinstance(record, dict):
        return None
    names = record.get("names", {})
    if not isinstance(names, dict):
        return None
    value = names.get("zh-CN") or names.get("en")
    return value[:256] if isinstance(value, str) else None


def _coordinate(value, bound):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and abs(value) <= bound else None


def _address_type(address):
    for attribute, kind, label in (
        ("is_unspecified", "unspecified", "未指定地址"),
        ("is_loopback", "loopback", "本机回环地址"),
        ("is_link_local", "link_local", "链路本地地址"),
        ("is_multicast", "multicast", "组播地址"),
    ):
        if getattr(address, attribute):
            return kind, label
    if address.version == 4 and address in ipaddress.ip_network("100.64.0.0/10"):
        return "shared", "运营商共享地址（CGNAT）"
    if address.is_private or address.is_reserved or not address.is_global:
        return "private_or_reserved", "私有、文档示例或保留地址"
    return "public", "公网地址"


class GeoIPLookup:
    def __init__(self, directory: str | Path | None):
        self.directory = Path(directory).resolve() if directory else None

    def lookup(self, value: str) -> dict:
        if not isinstance(value, str) or not value.strip() or len(value.strip()) > 45 or any(c in value for c in "%/"):
            raise ValueError("请输入完整的 IPv4 或 IPv6 地址，不支持域名、URL、网段或接口后缀。")
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError:
            raise ValueError("请输入有效的 IPv4 或 IPv6 地址。") from None
        lookup_address = getattr(address, "ipv4_mapped", None) or address
        kind, label = _address_type(lookup_address)
        result = dict(ip=str(address), version=address.version, lookup_ip=str(lookup_address),
                      address_type=kind, address_type_label=label, status="not_public",
                      country_code=None, country=None, region=None, city=None,
                      latitude=None, longitude=None, asn=None, network_name=None,
                      database_release=None, database_updated_at=None, database_stale=None,
                      notice="此类地址没有可查询的公网属地；不会向外部服务发送查询。")
        if kind != "public":
            return result
        result.update(status="unavailable", notice="本地 IP 属地库暂不可用；日志采集不受影响。")
        if self.directory is None:
            return result
        try:
            with (self.directory / "current.json").open("rb") as manifest_file:
                raw = manifest_file.read(16385)
            if len(raw) > 16384:
                raise ValueError("manifest too large")
            manifest = json.loads(raw)
            version = manifest["directory"]
            if not isinstance(version, str) or not _VERSION.fullmatch(version):
                raise ValueError("invalid database version")
            release = manifest["release"]
            if release != version[:7]:
                raise ValueError("database release mismatch")
            updated = datetime.fromisoformat(manifest["updated_at"].replace("Z", "+00:00"))
            if updated.tzinfo is None:
                raise ValueError("database time missing zone")
            paths = [(self.directory / version / f"{kind}.mmdb").resolve() for kind in ("city", "asn")]
            if not all(path.is_relative_to(self.directory) for path in paths):
                raise ValueError("database path escaped directory")
            records = []
            build_times = []
            # A reader belongs to this request, so an atomic manifest update never closes
            # another request's mmap. Both reads use the same captured version directory.
            for path in paths:
                with maxminddb.open_database(path) as reader:
                    build_times.append(reader.metadata().build_epoch)
                    records.append(reader.get(str(lookup_address)) or {})
            city, asn = records
            if not isinstance(city, dict) or not isinstance(asn, dict):
                raise ValueError("invalid MMDB record")
            subdivisions = city.get("subdivisions") or []
            location = city.get("location") or {}
            country = city.get("country") or {}
            as_number = asn.get("autonomous_system_number")
            network_name = asn.get("autonomous_system_organization")
            result.update(
                status="ok" if city or asn else "not_found",
                country_code=country.get("iso_code"), country=_name(country),
                region=" / ".join(filter(None, (_name(part) for part in subdivisions))) or None,
                city=_name(city.get("city")), latitude=_coordinate(location.get("latitude"), 90),
                longitude=_coordinate(location.get("longitude"), 180),
                asn=as_number if isinstance(as_number, int) and not isinstance(as_number, bool) and 0 < as_number <= 4294967295 else None,
                network_name=network_name[:512] if isinstance(network_name, str) else None,
                database_release=release, database_updated_at=updated.isoformat(),
                database_stale=datetime.now(timezone.utc).timestamp() - min(build_times) > 62 * 86400,
                notice=_NOTICE if city or asn else "本地数据库未收录此地址；不会转发到外部查询服务。",
            )
        except (OSError, ValueError, KeyError, TypeError, AttributeError, maxminddb.InvalidDatabaseError):
            # Do not expose filesystem paths or break ingestion on a missing/corrupt dataset.
            return result
        return result
