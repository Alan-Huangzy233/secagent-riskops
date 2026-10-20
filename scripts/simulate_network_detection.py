#!/usr/bin/env python3
"""Exercise authored firewall fixtures offline; never read a host's logs.

Run from the repository root with PYTHONPATH=backend. This is a deterministic
rule demonstration, not a detection-accuracy or production-capacity benchmark.
"""
from dataclasses import asdict
import json

from app.telemetry.network_detection import detect_network
from app.telemetry.network_parse import SourceProfile, parse_ufw


def simulate() -> dict:
    profile = SourceProfile(
        source_id="synthetic-firewall", ruleset_sha256="a" * 64,
        log_labels=("[UFW BLOCK]",), ip_families=(4, 6),
        rejection_labels=("[UFW BLOCK]",), local_input_labels=("[UFW BLOCK]",),
        local_input_interfaces=("eth0",), logging_limit="rate_limited", retention="unknown",
    )
    scenarios = (
        ("ipv4-probe", "192.0.2.10", "198.51.100.20", "TCP", True),
        ("ipv6-probe", "2001:db8::10", "2001:db8:1::20", "TCP", True),
        ("udp-hopping", "192.0.2.11", "198.51.100.20", "UDP", True),
        ("one-port-retries", "192.0.2.12", "198.51.100.20", "TCP", False),
    )
    events = []
    for name, src, dst, protocol, distinct in scenarios:
        for index in range(10):
            port = 8000 + index if distinct else 8000
            header = "LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=1" if ":" not in src else (
                "LEN=80 TC=0 HOPLIMIT=64 FLOWLBL=0")
            suffix = "WINDOW=1024 RES=0x00 SYN URGP=0" if protocol == "TCP" else "LEN=20"
            record = {
                "_TRANSPORT": "kernel", "_BOOT_ID": "1" * 32,
                "__CURSOR": f"synthetic-{name}-{index}",
                "__REALTIME_TIMESTAMP": str(1_800_000_000_000_000 + index * 1_000_000),
                "__MONOTONIC_TIMESTAMP": str(1_000_000 + index * 1_000_000),
                "MESSAGE": (f"[UFW BLOCK] IN=eth0 OUT= SRC={src} DST={dst} {header} "
                            f"PROTO={protocol} SPT=45000 DPT={port} {suffix}"),
            }
            events.append(parse_ufw(record, profile=profile))
    # A replay duplicate must not inflate port or evidence counts.
    report = detect_network(reversed(events + events[:1]))
    if (len(report.findings) != 2 or report.unique_count != 40
            or report.duplicate_count != 1
            or {finding.src_ip for finding in report.findings} != {"192.0.2.10", "2001:db8::10"}
            or any(len(finding.evidence_ids) != 10 for finding in report.findings)):
        raise RuntimeError("synthetic network rule expectations failed")
    return {"mode": "synthetic_offline_network", "report_version": 1,
            "scenarios": [scenario[0] for scenario in scenarios], "report": asdict(report)}


if __name__ == "__main__":
    print(json.dumps(simulate(), sort_keys=True, indent=2))
