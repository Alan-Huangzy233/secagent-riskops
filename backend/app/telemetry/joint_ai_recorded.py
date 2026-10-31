"""Strict, immutable local response snapshots for offline joint review.

A recording identifies an exact aliased request; it does not authenticate a
provider or certify a verdict. Returned raw text always needs current joint
validation. This module has no client, credentials, queue, or live fallback.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Mapping

from ..agents import joint_triage as joint
from .joint_ai_summary import ENVELOPE_VERSION, VERSION as SUMMARY_VERSION

FORMAT = "joint-recorded-response-v1"
MAX_TAPE_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 256
# Oversized model output can still reach the validator's deterministic refusal.
MAX_RECORDED_RESPONSE_BYTES = joint.MAX_RESPONSE_BYTES + 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class RecordedResponseError(ValueError):
    """A fixed error that never contains file paths or rejected content."""

    def __init__(self):
        super().__init__("invalid_joint_recording")


class RecordedResponseMissing(RecordedResponseError):
    def __init__(self):
        ValueError.__init__(self, "joint_recording_missing")


class RecordedResponseUnavailable(RecordedResponseError):
    def __init__(self):
        ValueError.__init__(self, "joint_recording_unavailable")


def _canonical(value):
    try:
        return joint.canonical(value)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise RecordedResponseError() from None


def _digest(value):
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def protocol() -> dict:
    """A fresh copy of the exact contract used to identify local requests."""
    return {"format": FORMAT, "dossier_version": joint.VERSION,
            "validator_version": joint.VALIDATOR_VERSION,
            "system_sha256": hashlib.sha256(joint.SYSTEM.encode()).hexdigest(),
            "schema_sha256": _digest(joint.SCHEMA), "summary_version": SUMMARY_VERSION,
            "envelope_version": ENVELOPE_VERSION}


def request_sha256(case: dict) -> str:
    """Bind the full strict dossier, including revision, to the current protocol."""
    try:
        # Materialize the validated model so later caller mutation cannot enter
        # the request between validation and serialization.
        dossier = joint.parse_dossier(case).model_dump(mode="json")
        return _digest({"protocol": protocol(), "case": dossier})
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise RecordedResponseError() from None


def _record_text(outcome, text):
    if type(outcome) is not str:
        raise RecordedResponseError()
    if outcome == "unavailable":
        if text is not None:
            raise RecordedResponseError()
    elif outcome == "response":
        if (type(text) is not str or len(text) > MAX_RECORDED_RESPONSE_BYTES
                or len(text.encode("utf-8")) > MAX_RECORDED_RESPONSE_BYTES):
            raise RecordedResponseError()
    else:
        raise RecordedResponseError()


def _checked(tape):
    try:
        if (type(tape) is not dict or set(tape) != {"format", "source", "protocol", "records"}
                or type(tape["format"]) is not str or tape["format"] != FORMAT
                or type(tape["source"]) is not str or tape["source"] != "local_recording"
                or type(tape["protocol"]) is not dict
                or type(tape["records"]) is not list or len(tape["records"]) > MAX_RECORDS):
            raise RecordedResponseError()
        expected = protocol()
        if (set(tape["protocol"]) != set(expected)
                or any(type(value) is not str or value != expected[key]
                       for key, value in tape["protocol"].items())):
            raise RecordedResponseError()
        records, total = {}, 0
        for record in tape["records"]:
            if type(record) is not dict or set(record) != {"request_sha256", "outcome", "response_text"}:
                raise RecordedResponseError()
            identity = record["request_sha256"]
            if type(identity) is not str or not _SHA256.fullmatch(identity) or identity in records:
                raise RecordedResponseError()
            _record_text(record["outcome"], record["response_text"])
            total += len(_canonical(record))
            if total > MAX_TAPE_BYTES:
                raise RecordedResponseError()
            records[identity] = (record["outcome"], record["response_text"])
        encoded = _canonical(tape).encode("ascii")
        if len(encoded) > MAX_TAPE_BYTES:
            raise RecordedResponseError()
        return hashlib.sha256(encoded).hexdigest(), _canonical(expected), MappingProxyType(records)
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise RecordedResponseError() from None


def make_tape(entries) -> dict:
    """Create a bounded in-memory tape from explicit cases and raw responses.

    This helper neither runs a model nor claims verified response provenance.
    It writes no files and accepts no saved verdict or validation metadata.
    """
    try:
        records = []
        for entry in entries:
            if (len(records) >= MAX_RECORDS or type(entry) is not dict
                    or set(entry) != {"case", "outcome", "response_text"}):
                raise RecordedResponseError()
            _record_text(entry["outcome"], entry["response_text"])
            records.append({"request_sha256": request_sha256(entry["case"]),
                            "outcome": entry["outcome"], "response_text": entry["response_text"]})
        tape = {"format": FORMAT, "source": "local_recording", "protocol": protocol(), "records": records}
        _checked(tape)
        return tape
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise RecordedResponseError() from None


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise RecordedResponseError()
        value[key] = item
    return value


def _constant(_):
    raise RecordedResponseError()


def _file_identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_uid,
            info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)


def _private_bytes(path):
    """Open every component without following links; read one private snapshot."""
    directory = descriptor = None
    try:
        path = Path(path)
        if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
            raise RecordedResponseError()
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        directory = os.open(path.anchor, directory_flags)
        for component in path.parts[1:-1]:
            child = os.open(component, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=directory)
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                    or before.st_mode & 0o077 or before.st_nlink != 1
                    or before.st_size > MAX_TAPE_BYTES):
                raise RecordedResponseError()
            raw = stream.read(MAX_TAPE_BYTES + 1)
            after = os.fstat(stream.fileno())
            if (len(raw) > MAX_TAPE_BYTES or len(raw) != before.st_size
                    or _file_identity(before) != _file_identity(after)):
                raise RecordedResponseError()
            return raw
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)


@dataclass(frozen=True, slots=True, init=False)
class RecordedResponses:
    """An immutable snapshot: later file replacement is not a hot reload.

    The source label is self-reported and unverified. ``digest`` covers all raw
    responses and availability markers as well as the protocol. Bind it to the
    queue configuration; it is deliberately absent from the request fingerprint
    to avoid a circular dependency when constructing a recording.
    """

    digest: str
    _protocol_text: str = field(repr=False)
    _records: Mapping[str, tuple[str, str | None]] = field(repr=False)

    @classmethod
    def from_tape(cls, tape) -> RecordedResponses:
        digest, protocol_text, records = _checked(tape)
        instance = object.__new__(cls)
        object.__setattr__(instance, "digest", digest)
        object.__setattr__(instance, "_protocol_text", protocol_text)
        object.__setattr__(instance, "_records", records)
        return instance

    @classmethod
    def load(cls, path) -> RecordedResponses:
        try:
            raw = _private_bytes(path)
            tape = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
            return cls.from_tape(tape)
        except (OSError, ValueError, TypeError, KeyError, RecursionError, UnicodeError):
            raise RecordedResponseError() from None

    def response(self, case: dict) -> str:
        if self._protocol_text != _canonical(protocol()):
            raise RecordedResponseError()
        record = self._records.get(request_sha256(case))
        if record is None:
            raise RecordedResponseMissing()
        outcome, text = record
        if outcome == "unavailable":
            raise RecordedResponseUnavailable()
        return text
