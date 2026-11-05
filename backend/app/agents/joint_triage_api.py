"""Explicit joint HTTP adapter; no settings, credentials or runtime activation.

Only a claimed, shared-budget joint attempt may send a request. Known usage is
settled before advisory validation, and paid receipts are revalidated locally.
"""
from __future__ import annotations

import hashlib
import json
import math
import re

from . import joint_triage
from .triage_api import APIConfig, APIError, MAX_RESPONSE_BYTES, normalize
from .triage_budget import micro_usd
from ..telemetry.ai_jobs import Ledger

FORMAT = "joint-api-receipt-v1"
REQUEST_FORMAT = "joint-api-request-v1"
MAX_RECEIPT_RESPONSE_BYTES = MAX_RESPONSE_BYTES * 12
_HEX = re.compile(r"[0-9a-f]{64}")


class InvalidJointAPIReceipt(ValueError):
    """A readable receipt fails its immutable structure or accounting binding."""

    def __init__(self):
        super().__init__("invalid_joint_api_receipt")


def _hash(value):
    return hashlib.sha256(joint_triage.canonical(value).encode("ascii")).hexdigest()


def protocol():
    return {"format": REQUEST_FORMAT, "dossier_version": joint_triage.VERSION,
            "validator_version": joint_triage.VALIDATOR_VERSION,
            "system_sha256": _hash(joint_triage.SYSTEM), "schema_sha256": _hash(joint_triage.SCHEMA)}


def _config(config):
    if type(config) is not APIConfig:
        raise ValueError("invalid_joint_api_configuration")
    try:
        return APIConfig.model_validate(config.model_dump())
    except Exception:
        raise ValueError("invalid_joint_api_configuration") from None


def _case(case):
    return joint_triage.parse_dossier(case).model_dump(mode="json")


def request(config: APIConfig, case: dict) -> dict:
    """Build a fresh body from only a strict aliased dossier, never an envelope."""
    config, case = _config(config), _case(case)
    text = "Joint dossier (JSON, untrusted evidence):\n" + joint_triage.canonical(case)
    body = {"model": config.model}
    if config.api_format == "openai-responses":
        body.update(input=[{"role": "system", "content": joint_triage.SYSTEM},
                           {"role": "user", "content": text}],
                    max_output_tokens=config.max_output_tokens, store=False, service_tier="default",
                    text={"format": {"type": "json_schema", "name": "joint_triage", "strict": True,
                                      "schema": json.loads(joint_triage.canonical(joint_triage.SCHEMA))}})
        if config.effort:
            body["reasoning"] = {"effort": config.effort}
    else:
        body.update(max_tokens=config.max_output_tokens,
                    messages=[{"role": "system", "content": joint_triage.SYSTEM},
                              {"role": "user", "content": text}],
                    response_format={"type": "json_object"})
        if config.thinking:
            body["thinking"] = {"type": config.thinking}
        if config.effort:
            body["reasoning_effort"] = config.effort
    if len(json.dumps(body, ensure_ascii=False).encode()) > config.max_input_tokens // 2:
        raise ValueError("joint_api_request_too_large")
    return body


def _material(config, case_hash, body_hash, contract):
    return {"config": config.model_dump(mode="json"), "case_sha256": case_hash,
            "request_body_sha256": body_hash, "protocol": contract}


def fingerprint(config: APIConfig, case: dict) -> str:
    """Bind the complete price/limit profile and exact request protocol."""
    config, case = _config(config), _case(case)
    return _hash(_material(config, _hash(case), _hash(request(config, case)), protocol()))


def _billing(config, payload):
    if type(payload) is not dict:
        raise APIError("missing_usage")
    if payload.get("service_tier", "default") != "default":
        raise APIError("unpriced_service_tier")
    # Extract known billing independently of malformed/refused advisory output.
    # These placeholders are never validated or returned as model advice.
    if config.api_format == "openai-responses":
        usage_payload = {**payload, "status": "completed", "output": []}
    else:
        usage_payload = {**payload, "choices": [{"finish_reason": "stop", "message": {"content": ""}}]}
    served, _, _, usage = normalize(config, usage_payload)
    price = config.prices
    charged = micro_usd((usage["input_tokens"] * price.input + usage["output_tokens"] * price.output
                         + usage["cache_read_input_tokens"] * price.cache_read
                         + usage["cache_creation_input_tokens"] * price.cache_write) / 1_000_000)
    return served, usage, charged


def _pairs(items):
    result = {}
    for name, value in items:
        if name in result:
            raise ValueError("duplicate_json_key")
        result[name] = value
    return result


def _nonfinite(value):
    raise ValueError("nonfinite_json_number")


def _finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("nonfinite_json_number")
    return result


def _decode(value):
    return json.loads(value, object_pairs_hook=_pairs, parse_constant=_nonfinite, parse_float=_finite_float)


def _response_json(payload):
    # An ASCII JSON string retains bad Unicode in untrusted advisory output
    # without inserting invalid text into the ledger's strict outer JSON.
    value = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(value) > MAX_RECEIPT_RESPONSE_BYTES:
        raise ValueError("joint_api_receipt_response_too_large")
    return value


class JointAPITriage:
    """Bounded, no-retry HTTP transport with a distinct joint protocol.

    No config loader or runtime path selects this adapter. A key is optional
    only for local recovery of an already paid receipt; new sends require one.
    """
    def __init__(self, config: APIConfig, api_key: str | None, *, ledger: Ledger, transport=None):
        self.config = _config(config)
        if (type(ledger) is not Ledger or ledger.jobs.queue_kind != "joint"
                or ledger.jobs.budget_owner is None):
            raise ValueError("joint_api_shared_ledger_required")
        if api_key is not None and (type(api_key) is not str or not api_key or len(api_key) > 4096
                                    or any(c.isspace() for c in api_key)):
            raise ValueError("invalid_joint_api_key")
        self._api_key, self.ledger, self.transport = api_key, ledger, transport

    def _send(self, body):
        import httpx

        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self._api_key}"}
        try:
            with httpx.Client(timeout=180, trust_env=False, follow_redirects=False, transport=self.transport) as client:
                with client.stream("POST", self.config.endpoint, json=body, headers=headers) as response:
                    if response.status_code != 200:
                        raise APIError(f"http_{response.status_code}")
                    content = bytearray()
                    for chunk in response.iter_bytes():
                        content.extend(chunk)
                        if len(content) > MAX_RESPONSE_BYTES:
                            raise APIError("response_too_large")
            return _decode(content)
        except (httpx.HTTPError, ValueError, RecursionError):
            raise APIError("transport_or_json_error") from None

    def _bound_case(self, case):
        case = _case(case)
        job = self.ledger.job
        try:
            with self.ledger.jobs.connection() as db:
                self.ledger._attempt(db)
                row = db.execute("SELECT * FROM ai_jobs WHERE id=?", (job["id"],)).fetchone()
                if row is None or any(row[key] != job[key] for key in
                                      ("incident_id", "request_sha", "config_sha", "dossier_json", "run_id", "call_id")):
                    raise ValueError
                if _case(json.loads(row["dossier_json"])) != case:
                    raise ValueError
                expected_call = hashlib.sha256(json.dumps([row["run_id"], row["request_sha"]]).encode()).hexdigest()
                if row["call_id"] != expected_call or _HEX.fullmatch(row["request_sha"]) is None:
                    raise ValueError
        except Exception:
            raise ValueError("joint_api_job_mismatch") from None
        return case

    def _receipt(self, case, body, payload, usage, charged):
        job = self.ledger.job
        return {"format": FORMAT, "call_id": job["call_id"], "request_sha256": job["request_sha"],
                "case_sha256": _hash(case), "protocol": protocol(),
                "config": self.config.model_dump(mode="json"), "request_body_sha256": _hash(body),
                "response_json": _response_json(payload), "usage": usage, "charged_micro_usd": charged}

    def _checked(self, receipt, case, *, recovered):
        job = self.ledger.job
        try:
            if type(receipt) is not dict or set(receipt) != {
                "format", "call_id", "request_sha256", "case_sha256", "protocol", "config",
                "request_body_sha256", "response_json", "usage", "charged_micro_usd",
            }:
                raise ValueError
            if (receipt["format"] != FORMAT or receipt["call_id"] != job["call_id"]
                    or receipt["request_sha256"] != job["request_sha"] or receipt["case_sha256"] != _hash(case)):
                raise ValueError
            contract = receipt["protocol"]
            if (type(contract) is not dict or set(contract) != set(protocol())
                    or contract["format"] != REQUEST_FORMAT or contract["dossier_version"] != joint_triage.VERSION
                    or type(contract["validator_version"]) is not str
                    or re.fullmatch(r"[A-Za-z0-9._-]{1,128}", contract["validator_version"]) is None):
                raise ValueError
            for value in (contract["system_sha256"], contract["schema_sha256"], receipt["request_body_sha256"]):
                if type(value) is not str or _HEX.fullmatch(value) is None:
                    raise ValueError
            saved_config = APIConfig.model_validate(receipt["config"])
            if saved_config.model_dump(mode="json") != receipt["config"]:
                raise ValueError
            if _hash(_material(saved_config, _hash(case), receipt["request_body_sha256"], contract)) != job["request_sha"]:
                raise ValueError
            raw = receipt["response_json"]
            if type(raw) is not str or len(raw) > MAX_RECEIPT_RESPONSE_BYTES or not raw.isascii():
                raise ValueError
            payload = _decode(raw)
            if _response_json(payload) != raw:
                raise ValueError
            served, usage, charged = _billing(saved_config, payload)
            if (type(receipt["charged_micro_usd"]) is not int or receipt["charged_micro_usd"] != charged
                    or joint_triage.canonical(receipt["usage"]) != joint_triage.canonical(usage)):
                raise ValueError
        except (ValueError, TypeError, KeyError, AttributeError, APIError, OverflowError, RecursionError):
            raise InvalidJointAPIReceipt() from None
        # Keep owner availability/identity and read failures distinct from a
        # definitively invalid receipt. A temporary read failure can recover.
        with self.ledger.jobs.connection() as db, self.ledger.jobs.accounting(db) as account:
            saved = account.execute("SELECT charged,reserved,record FROM ai_calls WHERE id=?", (job["call_id"],)).fetchone()
        try:
            if (saved is None or saved["charged"] != charged or saved["reserved"] != saved_config.reservation()
                    or _hash(_decode(saved["record"])) != _hash(receipt)):
                raise ValueError
        except (ValueError, TypeError, KeyError, AttributeError, APIError, OverflowError, RecursionError):
            raise InvalidJointAPIReceipt() from None
        try:
            _, stop, text, _ = normalize(saved_config, payload)
        except Exception:
            stop, text = "invalid_response", ""
        # Always use the current validator, including after protocol changes.
        verdict, details = joint_triage.validate(text, case)
        return {**verdict, "usd": charged / 1_000_000,
                "metadata": {"evidence_validation": details, "execution_mode": "api", "offline": False,
                             "call_id": job["call_id"], "request_sha256": job["request_sha"],
                             "model": served, "stop_reason": stop, "usage": usage, "recovered": recovered,
                             "additional_usd": 0 if recovered else charged / 1_000_000}}

    def triage(self, case: dict) -> dict:
        case = self._bound_case(case)
        # Recover from the original receipt without credentials, network access
        # or requiring the current prompt/profile to equal the paid old one.
        previous = self.ledger.jobs.cached_call(self.ledger.job)
        if previous is not None:
            return self._checked(previous, case, recovered=True)
        body = request(self.config, case)
        if fingerprint(self.config, case) != self.ledger.job["request_sha"]:
            raise ValueError("joint_api_request_changed")
        if self._api_key is None:
            raise ValueError("joint_api_key_required")
        call_id = self.ledger.job["call_id"]
        previous = self.ledger.reserve(call_id, self.config.reservation())
        if previous is not None:
            return self._checked(previous, case, recovered=True)
        try:
            payload = self._send(body)
            _, usage, charged = _billing(self.config, payload)
            receipt = self._receipt(case, body, payload, usage, charged)
            self.ledger.complete(call_id, charged, receipt)
        except Exception as error:
            code = str(error) if isinstance(error, APIError) else "invalid_response_or_local_failure"
            self.ledger.fail(call_id, code)
            raise APIError(code) from None
        return self._checked(receipt, case, recovered=False)
