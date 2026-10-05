"""Replay bounded structured HTTP access logs; never contact a host or an AI.

This is a reproducible rule exercise, not an accuracy benchmark. The output
contains local evidence, including client addresses and query-free paths.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import sys

from ..telemetry.http_parse import PARSER_VERSION, normalize_http
from ..telemetry.web_detection import RULE_VERSION, detect_web, unique_events

MAX_RECORDS = 50_000
MAX_LINE_BYTES = 32_768
MAX_INPUT_BYTES = 32 * 1024 * 1024


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate HTTP JSON field")
        result[key] = value
    return result


def replay(path: Path, *, source_id: str, service_id: str) -> dict:
    events = []
    size = 0
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while raw := stream.readline(MAX_LINE_BYTES + 1):
            index = len(events) + 1
            size += len(raw)
            if index > MAX_RECORDS or len(raw) > MAX_LINE_BYTES or size > MAX_INPUT_BYTES:
                raise ValueError("HTTP replay input exceeds its record, line or total byte limit")
            digest.update(raw)
            try:
                # An input line is one occurrence: identical requests on two
                # lines remain distinct. Line numbers alone are scoped to this
                # replay below, after the entire input hash is known.
                record = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_fields)
                events.append(normalize_http(record, source_id=source_id, service_id=service_id,
                                             event_id=f"line-{index}"))
            except (ValueError, UnicodeError, RecursionError):
                raise ValueError(f"invalid HTTP access record at line {index}") from None
    file_hash = digest.hexdigest()
    events = unique_events(replace(event, event_id=f"{file_hash}:{event.event_id}") for event in events)
    findings = detect_web(events)
    referenced = {(finding.source_id, event_id) for finding in findings for event_id in finding.evidence_ids}
    return {
        "report_version": 1, "parser_version": PARSER_VERSION, "rule_version": RULE_VERSION,
        "mode": "offline_http_rule_replay", "input_sha256": file_hash,
        "source_id": source_id, "service_id": service_id,
        "records": len(events), "findings": [asdict(finding) for finding in findings],
        "evidence": [asdict(event) for event in events if event.key in referenced],
        "limitations": ["Request patterns do not establish exploitation or authentication outcomes.",
                        "No live HTTP ingestion, production scoring, notification or model call.",
                        "Source/service identity is supplied by the operator; forwarded headers are not used.",
                        "Paths are decoded at most three times; request bodies and queries are not inspected."],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--service-id", required=True)
    parser.add_argument("--check", type=Path, help="Compare with a previously saved report; do not write")
    args = parser.parse_args(argv)
    try:
        report = replay(args.input, source_id=args.source_id, service_id=args.service_id)
        rendered = json.dumps(report, sort_keys=True, ensure_ascii=False, indent=2) + "\n"
        if args.check:
            if args.check.read_text(encoding="utf-8") != rendered:
                raise ValueError("HTTP replay differs from the expected report")
        else:
            sys.stdout.write(rendered)
    except OSError:
        print("HTTP replay could not read an input file", file=sys.stderr)
        return 1
    except UnicodeError:
        print("HTTP replay input is not valid UTF-8", file=sys.stderr)
        return 1
    except ValueError as exc:
        # Validation errors deliberately omit input values and raw log lines.
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
