"""Replay raw responses against built-in synthetic joint dossiers, without a model.

Authored fake responses qualify the replay/validation contract only. Local
recordings have unverified provenance. Neither is production model acceptance.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import stat

from ..agents import joint_triage as joint
from .joint_ai_scenarios import SUITE, scenarios

FORMAT = "joint-ai-replay-v1"
MAX_TAPE_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 256
# Permit an over-limit model response to reach the contract's size rejection,
# without allowing an unbounded recording to consume memory.
MAX_RECORDED_RESPONSE_BYTES = joint.MAX_RESPONSE_BYTES + 1024
REASON_CODES = frozenset({"invalid_response", "unknown_evidence", "stale_revision",
                         "unsupported_claim", "evidence_not_current",
                         "missing_observed_evidence", "missing_supported_claim"})
OUTCOMES = ("escalate", "abstain", "invalid", "unavailable", "missing")


class ReplayError(ValueError):
    """A fixed diagnostic; never include local paths or rejected input text."""


def _canonical(value):
    try:
        return joint.canonical(value)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise ReplayError("invalid_joint_replay_tape") from None


def _digest(value):
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _rows():
    rows = scenarios()
    if not 1 <= len(rows) <= MAX_RECORDS or len({r["id"] for r in rows}) != len(rows):
        raise ReplayError("invalid_joint_synthetic_corpus")
    for row in rows:
        joint.parse_dossier(row["case"])
    return rows


def _protocol(rows):
    policy = {"suite": SUITE, "format": FORMAT, "dossier_version": joint.VERSION,
              "validator_version": joint.VALIDATOR_VERSION,
              "system_sha256": hashlib.sha256(joint.SYSTEM.encode()).hexdigest(),
              "schema_sha256": _digest(joint.SCHEMA)}
    # Labels and fake-response oracles are part of this versioned corpus, but
    # never part of the candidate dossier or its model-facing prompt.
    return {**policy, "corpus_sha256": _digest(rows),
            "requests": {r["id"]: _digest({"policy": policy, "case": r["case"]}) for r in rows}}


def protocol():
    return _protocol(_rows())


def make_tape():
    rows = _rows()
    binding = _protocol(rows)
    return {"format": FORMAT, "source": "authored_fake", "protocol": binding,
            "records": [{"scenario_id": r["id"], "request_sha256": binding["requests"][r["id"]],
                         "outcome": "response", "response_text": r["fake_response"]} for r in rows]}


def _records(tape, rows):
    try:
        if (type(tape) is not dict or set(tape) != {"format", "source", "protocol", "records"}
                or tape["format"] != FORMAT
                or tape["source"] not in ("authored_fake", "local_recording")
                or len(_canonical(tape).encode("ascii")) > MAX_TAPE_BYTES
                or _canonical(tape["protocol"]) != _canonical(_protocol(rows))
                or type(tape["records"]) is not list or len(tape["records"]) > len(rows)):
            raise ReplayError("invalid_joint_replay_tape")
        by_id, result, fingerprints = {r["id"]: r for r in rows}, {}, set()
        for record in tape["records"]:
            if type(record) is not dict or set(record) != {
                    "scenario_id", "request_sha256", "outcome", "response_text"}:
                raise ReplayError("invalid_joint_replay_tape")
            identity, fingerprint = record["scenario_id"], record["request_sha256"]
            if (type(identity) is not str or identity not in by_id or identity in result
                    or type(fingerprint) is not str or fingerprint in fingerprints
                    or fingerprint != tape["protocol"]["requests"][identity]):
                raise ReplayError("invalid_joint_replay_tape")
            text = record["response_text"]
            if record["outcome"] == "response":
                if type(text) is not str or len(text.encode("utf-8")) > MAX_RECORDED_RESPONSE_BYTES:
                    raise ReplayError("invalid_joint_replay_tape")
            elif record["outcome"] != "unavailable" or text is not None:
                raise ReplayError("invalid_joint_replay_tape")
            if tape["source"] == "authored_fake" and (
                    record["outcome"] != "response" or text != by_id[identity]["fake_response"]):
                raise ReplayError("invalid_joint_replay_tape")
            result[identity] = record
            fingerprints.add(fingerprint)
        return result
    except (ValueError, KeyError, TypeError, RecursionError, UnicodeError):
        raise ReplayError("invalid_joint_replay_tape") from None


def _metrics(items, field):
    matrix = {expected: dict.fromkeys(OUTCOMES, 0) for expected in ("escalate", "abstain")}
    for item in items:
        matrix[item["expected"]][item[field]] += 1
    matched = sum(matrix[label][label] for label in matrix)
    return {"total": len(items), "matched": matched,
            "agreement": round(matched / len(items), 4) if items else None, "matrix": matrix}


def evaluate(tape):
    """Revalidate raw text; never accept a saved verdict or validation result."""
    rows = _rows()
    records = _records(tape, rows)
    items, oracle, dimensions = [], [], Counter()
    for row in rows:
        record = records.get(row["id"])
        state = "missing" if record is None else record["outcome"]
        item = {"scenario_id": row["id"], "family": row["family"], "track": row["track"],
                "expected": row["expected_verdict"], "proposed": state, "accepted": state,
                "status": state, "reason_codes": [], "free_text_requires_review": True}
        if state == "response":
            verdict, details = joint.validate(record["response_text"], row["case"])
            codes = sorted({r["code"] for r in details["reasons"]})
            if not set(codes) <= REASON_CODES or details["status"] not in ("valid", "requires_review"):
                raise ReplayError("joint_replay_validator_changed")
            proposal = details["proposal"]
            # Only authored IDs and fixed vocabulary enter the report. In
            # particular, do not persist the proposal/rationale from details.
            item.update(proposed=proposal["verdict"] if proposal else "invalid",
                        accepted=verdict["verdict"], status=details["status"], reason_codes=codes)
            dimensions["responses"] += 1
            if proposal is not None:
                dimensions["schema_valid"] += 1
                dimensions["revision_matches"] += "stale_revision" not in codes
                dimensions["citations_known"] += "unknown_evidence" not in codes
                dimensions["typed_support_passed"] += not {
                    "unknown_evidence", "unsupported_claim", "missing_observed_evidence",
                    "missing_supported_claim"}.intersection(codes)
            if tape["source"] == "authored_fake":
                oracle.append(item["status"] == row["expected_status"]
                              and item["accepted"] == row["expected_accepted"]
                              and codes == sorted(row["expected_reason_codes"]))
        items.append(item)
    counts = Counter(item["status"] for item in items)
    complete = counts["missing"] == 0 and counts["unavailable"] == 0
    applicable = tape["source"] == "authored_fake"
    return {"format": FORMAT, "suite": SUITE, "source": tape["source"],
            "self_reported_source": True, "protocol": _protocol(rows), "complete": complete,
            "replay_model_calls": 0, "replay_cost_usd": 0,
            "recorded_generation_cost": "not_applicable" if applicable else "unknown",
            "live_qualified": False, "semantic_accuracy_measured": False,
            "scope": "authored synthetic policy labels and typed validation only; not model or production accuracy",
            "decision_scope": "decision track only, including missing and unavailable cases",
            "proposed": _metrics([i for i in items if i["track"] == "decision"], "proposed"),
            "accepted": _metrics([i for i in items if i["track"] == "decision"], "accepted"),
            "by_track": {track: {field: _metrics([i for i in items if i["track"] == track], field)
                                  for field in ("proposed", "accepted")}
                         for track in ("decision", "guardrail", "boundary")},
            "validation": {"counts": {key: counts[key] for key in
                                       ("valid", "requires_review", "missing", "unavailable")},
                           "dimensions": {key: dimensions[key] for key in
                                          ("responses", "schema_valid", "revision_matches",
                                           "citations_known", "typed_support_passed")},
                           "reason_counts": dict(sorted(Counter(c for i in items for c in i["reason_codes"]).items())),
                           "free_text_requires_review": True},
            "contract_oracle": {"applicable": applicable,
                                "passed": complete and len(oracle) == len(rows) and all(oracle)
                                if applicable else None}, "cases": items}


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReplayError("invalid_joint_replay_tape")
        result[key] = value
    return result


def _constant(_):
    raise ReplayError("invalid_joint_replay_tape")


def load_tape(path):
    try:
        descriptor = os.open(Path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_TAPE_BYTES:
                raise ReplayError("invalid_joint_replay_tape")
            raw = stream.read(MAX_TAPE_BYTES + 1)
        if len(raw) > MAX_TAPE_BYTES:
            raise ReplayError("invalid_joint_replay_tape")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
        _records(value, _rows())
        return value
    except (OSError, ValueError, TypeError, RecursionError, UnicodeError):
        raise ReplayError("invalid_joint_replay_tape") from None


def write_private(path, value):
    """Create a private artifact exactly once. Never overwrite a prior run."""
    try:
        path = Path(path)
        if any(parent.is_symlink() for parent in path.parents):
            raise ReplayError("joint_replay_output_unavailable")
        encoded = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except (OSError, ValueError, TypeError, RecursionError, UnicodeError):
        raise ReplayError("joint_replay_output_unavailable") from None


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ReplayError("invalid_joint_replay_arguments")


def main(argv=None):
    parser = _Parser(description=__doc__, allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--make-fake-tape", type=Path, metavar="PATH")
    mode.add_argument("--tape", type=Path, metavar="PATH")
    parser.add_argument("--out", type=Path, metavar="PATH")
    try:
        args = parser.parse_args(argv)
        if args.make_fake_tape:
            if args.out:
                raise ReplayError("invalid_joint_replay_arguments")
            write_private(args.make_fake_tape, make_tape())
            print(json.dumps({"synthetic_tape_created": True, "model_calls": 0}))
            return 0
        report = evaluate(load_tape(args.tape))
        if args.out:
            write_private(args.out, report)
            print(json.dumps({key: report[key] for key in
                              ("complete", "replay_model_calls", "contract_oracle", "live_qualified")}))
        else:
            print(json.dumps(report, sort_keys=True, indent=2))
        return 0 if report["complete"] and report["contract_oracle"]["passed"] is not False else 2
    except ReplayError as error:
        print(json.dumps({"error": str(error)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
