"""Configurable HTTP adapters for offline-first triage evaluation.

Only explicit endpoints/keys are used. No proxy environment, redirects, SDK
fallbacks, retries, tools, or server-side conversation storage are enabled.
"""
from __future__ import annotations

from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
import time
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .model_triage import SCHEMA, SYSTEM_PROMPT, TriageCall, render
from .triage_budget import BudgetLedger, micro_usd

FORMAT_VERSION = 2
SYSTEM = SYSTEM_PROMPT + "\n\nReturn only a JSON object matching this schema:\n" + json.dumps(SCHEMA, sort_keys=True)
MAX_RESPONSE_BYTES = 2_000_000


class APIError(RuntimeError):
    """Sanitized failure code; never contains a remote body, key, or dossier."""


class Prices(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    as_of: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    input: Decimal = Field(gt=0, le=1000)
    output: Decimal = Field(gt=0, le=1000)
    cache_read: Decimal = Field(ge=0, le=1000)
    cache_write: Decimal = Field(ge=0, le=1000)


class APIConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    provider: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,39}$")
    api_format: Literal["openai-responses", "openai-chat", "anthropic-messages"]
    endpoint: str
    model: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")
    key_name: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,79}$")
    effort: Literal["none", "minimal", "low", "medium", "high", "xhigh", "max"] | None = None
    thinking: Literal["enabled", "disabled"] | None = None
    max_output_tokens: int = Field(default=8192, strict=True, ge=256, le=32768)
    # Conservative input reservation, including provider framing. Request bytes
    # are limited to half this allowance; actual usage is checked on settlement.
    max_input_tokens: int = Field(default=65536, strict=True, ge=8192, le=131072)
    prices: Prices

    @model_validator(mode="after")
    def valid_endpoint_and_modes(self):
        endpoint = urlsplit(self.endpoint)
        if (endpoint.scheme != "https" or not endpoint.hostname or endpoint.username is not None
                or endpoint.password is not None or endpoint.query or endpoint.fragment
                or not endpoint.path or any(c.isspace() for c in self.endpoint)):
            raise ValueError("endpoint must be an explicit HTTPS URL without credentials, query, or fragment")
        if self.thinking is not None and self.api_format != "openai-chat":
            raise ValueError("thinking is supported only for the chat adapter")
        if self.thinking == "disabled" and self.effort is not None:
            raise ValueError("omit effort when thinking is disabled")
        return self

    @classmethod
    def load(cls, path: Path) -> APIConfig:
        return cls.model_validate_json(path.read_text(encoding="utf-8"))

    @property
    def label(self) -> str:
        mode = f"thinking {self.thinking}" if self.thinking else "default thinking"
        return f"{self.provider}/{self.model}, {mode}, effort {self.effort or 'default'}"

    def request(self, case: dict) -> dict:
        user = render(case)
        body = {"model": self.model}
        if self.api_format == "openai-responses":
            body.update(input=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}],
                        max_output_tokens=self.max_output_tokens, store=False, service_tier="default",
                        text={"format": {"type": "json_schema", "name": "triage", "strict": True, "schema": SCHEMA}})
            if self.effort:
                body["reasoning"] = {"effort": self.effort}
        else:
            body.update(max_tokens=self.max_output_tokens, messages=[{"role": "user", "content": user}])
            if self.api_format == "anthropic-messages":
                body["system"] = SYSTEM
                body["output_config"] = {"format": {"type": "json_schema", "schema": SCHEMA}}
                if self.effort:
                    body["output_config"]["effort"] = self.effort
            else:
                body["messages"].insert(0, {"role": "system", "content": SYSTEM})
                body["response_format"] = {"type": "json_object"}
                if self.thinking:
                    body["thinking"] = {"type": self.thinking}
                if self.effort:
                    body["reasoning_effort"] = self.effort
        if len(json.dumps(body, ensure_ascii=False).encode()) > self.max_input_tokens // 2:
            raise ValueError("request exceeds the configured input byte limit")
        return body

    def fingerprint(self, case: dict) -> str:
        material = {"format_version": FORMAT_VERSION, "provider": self.provider,
                    "api_format": self.api_format, "endpoint": self.endpoint, "request": self.request(case)}
        return hashlib.sha256(json.dumps(material, sort_keys=True, ensure_ascii=False).encode()).hexdigest()

    def reservation(self) -> int:
        input_rate = max(self.prices.input, self.prices.cache_read, self.prices.cache_write)
        # Token count * USD per million = micro-USD.
        return micro_usd((self.max_input_tokens * input_rate
                          + self.max_output_tokens * self.prices.output) / 1_000_000)


def _count(usage: dict, key: str, *, optional: bool = False) -> int:
    value = usage.get(key, 0 if optional else None)
    if type(value) is not int or value < 0:
        raise APIError("invalid_usage")
    return value


def _details(usage: dict, key: str) -> dict:
    value = usage.get(key, {})
    if not isinstance(value, dict):
        raise APIError("invalid_usage")
    return value


def normalize(config: APIConfig, payload: dict) -> tuple[str, str, str, dict]:
    """Return served model, stop reason, output text and normalized usage."""
    if not isinstance(payload, dict) or not isinstance(payload.get("usage"), dict):
        raise APIError("missing_usage")
    served = payload.get("model")
    # A dated snapshot of the requested model is allowed; a fallback to a
    # different model has no known price and keeps the full reservation.
    snapshot = re.escape(config.model) + r"-(?:\d{8}|\d{4}-\d{2}-\d{2})"
    if not isinstance(served, str) or not (served == config.model or re.fullmatch(snapshot, served)):
        raise APIError("unpriced_served_model")
    usage = payload["usage"]
    written = reasoning = 0
    if config.api_format == "anthropic-messages":
        inputs, outputs = _count(usage, "input_tokens"), _count(usage, "output_tokens")
        cached = _count(usage, "cache_read_input_tokens", optional=True)
        written = _count(usage, "cache_creation_input_tokens", optional=True)
        stop = payload.get("stop_reason")
        text = "".join(block["text"] for block in payload["content"] if block.get("type") == "text")
        accepted = stop == "end_turn"
    elif config.api_format == "openai-responses":
        if payload.get("service_tier", "default") != "default":
            raise APIError("unpriced_service_tier")
        inputs, outputs = _count(usage, "input_tokens"), _count(usage, "output_tokens")
        cached = _count(_details(usage, "input_tokens_details"), "cached_tokens", optional=True)
        written = _count(_details(usage, "input_tokens_details"), "cache_write_tokens", optional=True)
        reasoning = _count(_details(usage, "output_tokens_details"), "reasoning_tokens", optional=True)
        stop = payload.get("status")
        text = "".join(block["text"] for item in payload["output"] if item.get("type") == "message"
                       for block in item["content"] if block.get("type") == "output_text")
        accepted = stop == "completed"
        inputs -= cached + written
    else:
        inputs, outputs = _count(usage, "prompt_tokens"), _count(usage, "completion_tokens")
        cached = _count(usage, "prompt_cache_hit_tokens") if "prompt_cache_hit_tokens" in usage else _count(
            _details(usage, "prompt_tokens_details"), "cached_tokens", optional=True)
        reasoning = _count(_details(usage, "completion_tokens_details"), "reasoning_tokens", optional=True)
        choices = payload["choices"]
        if len(choices) != 1:
            raise APIError("invalid_choices")
        stop = choices[0].get("finish_reason")
        text = choices[0]["message"].get("content") or ""
        accepted = stop == "stop" and not choices[0]["message"].get("refusal")
        inputs -= cached
    if inputs < 0 or reasoning > outputs:
        raise APIError("invalid_usage")
    if not isinstance(stop, str) or not re.fullmatch(r"[a-z_]{1,64}", stop) or not isinstance(text, str):
        raise APIError("invalid_response")
    return served, stop, text if accepted else "", {
        "input_tokens": inputs, "output_tokens": outputs, "cache_read_input_tokens": cached,
        "cache_creation_input_tokens": written, "reasoning_tokens": reasoning}


def validate_verdict(text: str, case: dict) -> tuple[dict, str]:
    """Shape and evidence membership checks; no claim of semantic correctness."""
    valid_ids = {row["event_id"] for key in ("record_sample", "successful_logins") for row in case.get(key, [])}
    status = "invalid_json"
    try:
        value = json.loads(text)
        status = "invalid_schema"
        if (not isinstance(value, dict) or set(value) != set(SCHEMA["required"])
                or value["verdict"] not in ("escalate", "dismiss", "abstain")
                or value["confidence"] not in ("low", "medium", "high")
                or not isinstance(value["rationale"], str) or not value["rationale"].strip()
                or len(value["rationale"]) > 16000
                or any(not isinstance(value[key], list) or len(value[key]) > 100
                       or any(not isinstance(item, str) or len(item) > 256 for item in value[key])
                       for key in ("evidence_ids", "attack_techniques"))):
            raise ValueError
        status = "unknown_evidence"
        if any(event_id not in valid_ids for event_id in value["evidence_ids"]):
            raise ValueError
        status = "missing_evidence"
        if value["verdict"] != "abstain" and not value["evidence_ids"]:
            raise ValueError
        return value, "valid"
    except (ValueError, TypeError):
        return {"verdict": "abstain", "confidence": "low", "rationale": f"no verdict: {status}",
                "evidence_ids": [], "attack_techniques": []}, status


def read_key(path: Path, key_name: str, *, single: bool = False) -> str:
    # Errors intentionally omit file contents and supplied values.
    try:
        if path.stat().st_mode & 0o077 or path.stat().st_size > 16384:
            raise ValueError
        content = path.read_text(encoding="utf-8")
        value = content.strip() if single else json.loads(content)[key_name]
        if not isinstance(value, str) or not value or len(value) > 4096 or any(c.isspace() for c in value):
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError):
        raise ValueError("key file must be private (0600) and contain the configured, non-empty key") from None
    return value


class APITriage:
    def __init__(self, config: APIConfig, api_key: str, *, ledger: BudgetLedger, tape: Path, transport=None):
        if not api_key or any(c.isspace() for c in api_key):
            raise ValueError("a non-empty API key without whitespace is required")
        self.config, self._api_key, self.ledger = config, api_key, ledger
        self.run_id = str(tape.resolve())
        self.transport = transport

    def _send(self, body: dict) -> dict:
        import httpx

        headers = {"Content-Type": "application/json"}
        key = self._api_key
        if self.config.api_format == "anthropic-messages":
            headers.update({"x-api-key": key, "anthropic-version": "2023-06-01"})
        else:
            headers["Authorization"] = f"Bearer {self._api_key}"
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
            return json.loads(content)
        except (httpx.HTTPError, ValueError):
            raise APIError("transport_or_json_error") from None

    def triage(self, case: dict) -> TriageCall:
        config = self.config
        fingerprint = config.fingerprint(case)
        call_id = hashlib.sha256(json.dumps([self.run_id, fingerprint]).encode()).hexdigest()
        previous = self.ledger.reserve(call_id, config.reservation())
        if previous is not None:
            return TriageCall.from_record(previous)
        started = time.perf_counter()
        try:
            payload = self._send(config.request(case))
            served, stop, text, usage = normalize(config, payload)
            verdict, validation = validate_verdict(text, case)
            price = config.prices
            charged = micro_usd((usage["input_tokens"] * price.input + usage["output_tokens"] * price.output
                                 + usage["cache_read_input_tokens"] * price.cache_read
                                 + usage["cache_creation_input_tokens"] * price.cache_write) / 1_000_000)
            reasoning = usage.pop("reasoning_tokens")
            call = TriageCall(
                incident_id=case["incident_id"], prompt_sha256=fingerprint,
                verdict=verdict["verdict"], confidence=verdict["confidence"], rationale=verdict["rationale"],
                evidence_ids=tuple(verdict["evidence_ids"]), attack_techniques=tuple(verdict["attack_techniques"]),
                model=served, stop_reason=stop, **usage, usd=charged / 1_000_000,
                latency_seconds=round(time.perf_counter() - started, 3),
                metadata={"format_version": FORMAT_VERSION, "config": config.model_dump(mode="json"),
                          "validation": validation, "reasoning_tokens": reasoning})
            self.ledger.complete(call_id, charged, call.to_record())
            return call
        except Exception as error:
            code = str(error) if isinstance(error, APIError) else "invalid_response_or_local_failure"
            self.ledger.fail(call_id, code)
            raise APIError(code) from None
