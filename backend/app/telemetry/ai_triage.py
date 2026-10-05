"""Opt-in manual triage: preview, durable jobs, checked advice and review.

No environment configuration means no worker, files, credentials or model calls.
Offline and recorded modes never instantiate a network client.
"""
from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..agents import triage_evidence
from ..agents.model_triage import BudgetExceeded, RecordedTriage, TriageCall
from ..agents.triage_api import APIConfig, APIError, APITriage, read_key
from ..agents.triage_budget import CallUncertain, micro_usd
from .ai_jobs import Jobs, Ledger
from .ai_summary import Aliases, VERSION, build, canonical, inventory


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    mode: Literal["offline", "recorded", "api"] = "offline"
    database_path: Path
    context_file: Path | None = None
    profile_path: Path | None = None
    recording_path: Path | None = None
    keys_file: Path | None = None
    allow_external: bool = False
    approved_summary_version: Literal[1] | None = None
    total_budget_usd: Decimal = Field(default=Decimal(0), ge=0, le=1000)
    daily_budget_usd: Decimal = Field(default=Decimal(0), ge=0, le=1000)
    http_paths: tuple[str, ...] = Field(default=(), max_length=50)
    max_events: int = Field(default=40, strict=True, ge=1, le=40)
    queue_limit: int = Field(default=100, strict=True, ge=1, le=1000)
    lease_seconds: int = Field(default=300, strict=True, ge=240, le=600)
    max_attempts: int = Field(default=2, strict=True, ge=1, le=3)

    @model_validator(mode="after")
    def valid(self):
        paths = [self.database_path, self.context_file, self.profile_path, self.recording_path, self.keys_file]
        supplied = [p.resolve() for p in paths if p is not None]
        if any(p is not None and not p.is_absolute() for p in paths) or len(set(supplied)) != len(supplied):
            raise ValueError("analysis paths must be absolute and distinct")
        if any(not p.startswith("/") or len(p) > 2048 or "?" in p or "#" in p for p in self.http_paths):
            raise ValueError("approved HTTP paths must be bounded exact paths without query or fragment")
        if self.mode != "offline" and self.profile_path is None:
            raise ValueError("a model profile is required")
        if self.mode == "recorded" and self.recording_path is None:
            raise ValueError("a recording is required")
        if self.mode == "api" and (not self.allow_external or self.approved_summary_version != VERSION
                                  or self.keys_file is None or not 0 < self.daily_budget_usd <= self.total_budget_usd):
            raise ValueError("API mode requires explicit field approval, keys and positive total/daily budgets")
        if self.mode != "api" and self.allow_external:
            raise ValueError("offline modes cannot allow external calls")
        return self


class Service:
    def __init__(self, telemetry, settings: Settings | None = None, *, provider=None, clock=None, error=None):
        self.telemetry, self.settings, self.provider, self.error = telemetry, settings, provider, error
        self.stop = threading.Event()
        self.thread = None
        self.jobs = self.profile = None
        if settings is None:
            return
        if settings.database_path.resolve() == Path(telemetry.path).resolve():
            raise ValueError("analysis queue must use a separate database")
        self.profile = APIConfig.load(settings.profile_path) if settings.profile_path else None
        inventory(settings.context_file)  # Validate private context before enabling the feature.
        self.jobs = Jobs(settings.database_path, **({"clock": clock} if clock else {}))
        self.aliases = Aliases(self.jobs.secret())
        material = {"settings": settings.model_dump(mode="json"),
                    "profile": self.profile.model_dump(mode="json") if self.profile else None,
                    "summary_version": VERSION, "dossier_version": triage_evidence.VERSION,
                    "validator_version": triage_evidence.VALIDATOR_VERSION,
                    "system_sha256": hashlib.sha256(triage_evidence.SYSTEM.encode()).hexdigest()}
        self.config_sha = hashlib.sha256(canonical(material).encode()).hexdigest()
        if settings.mode == "api":
            self.jobs.set_budget(micro_usd(settings.total_budget_usd), micro_usd(settings.daily_budget_usd))

    @classmethod
    def from_environment(cls, telemetry):
        path = os.environ.get("RISKOPS_AI_CONFIG")
        if not path:
            return cls(telemetry)
        try:
            p = Path(path)
            if not p.is_absolute() or p.stat().st_mode & 0o077 or p.stat().st_size > 64 * 1024:
                raise ValueError
            return cls(telemetry, Settings.model_validate_json(p.read_bytes()))
        except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
            # Collection and manual handling remain available if optional AI is misconfigured.
            return cls(telemetry, error="analysis_configuration_unavailable")

    @property
    def enabled(self):
        return self.settings is not None

    def status(self):
        return {"enabled": self.enabled, "mode": self.settings.mode if self.enabled else "disabled",
                "model": self.profile.model if self.profile else ("offline-review" if self.enabled else None),
                "external_calls": bool(self.enabled and self.settings.mode == "api"),
                "summary_version": VERSION, "error": self.error,
                "budget": self.jobs.budget() if self.jobs else None}

    def _require(self):
        if not self.enabled:
            raise ValueError("manual AI analysis is not configured")

    def _bundle(self, incident_id):
        self._require()
        snapshot = self.telemetry.ai_snapshot(incident_id, self.settings.max_events)
        if snapshot is None:
            raise KeyError("incident not found")
        context, context_sha = inventory(self.settings.context_file)
        bundle = build(snapshot, self.aliases, context, context_sha, http_paths=self.settings.http_paths)
        bundle["meta"].update(execution_mode=self.settings.mode,
                              model=self.profile.model if self.profile else "offline-review")
        bundle["incident_id"] = snapshot["incident_id"]
        bundle["related_incident_ids"] = snapshot["related_incident_ids"]
        bundle["preview_key"] = hashlib.sha256(canonical([bundle["case"], self.config_sha]).encode()).hexdigest()
        return bundle

    def preview(self, incident_id):
        bundle = self._bundle(incident_id)
        return {**bundle, "execution": self.status(),
                "history": [self.job(jid, current=bundle) for jid in self.jobs.history(bundle["related_incident_ids"])]}

    def request_sha(self, case):
        return self.profile.fingerprint(case) if self.profile else hashlib.sha256(
            canonical(["offline-review-v1", self.config_sha, case]).encode()).hexdigest()

    def enqueue(self, incident_id, preview_key, actor):
        bundle = self._bundle(incident_id)
        if preview_key != bundle["preview_key"]:
            raise ValueError("evidence or configuration changed; preview again")
        job_id = self.jobs.enqueue(bundle["incident_id"], bundle, self.config_sha,
                                   self.request_sha(bundle["case"]), actor, queue_limit=self.settings.queue_limit)
        return self.job(job_id, current=bundle)

    def job(self, job_id, *, current=None):
        self._require()
        job = self.jobs.get(job_id)
        if job is None:
            raise KeyError("analysis job not found")
        if current is None:
            try:
                current = self._bundle(job["incident_id"])
            except (KeyError, ValueError, OSError):
                current = None
        job["stale"] = current is None or current["preview_key"] != job["cache_key"]
        job["execution_mode"] = job["local"]["meta"]["execution_mode"]
        return job

    def feedback(self, job_id, verdict, note, actor):
        self._require()
        self.jobs.feedback(job_id, verdict, note, actor)
        return self.job(job_id)

    def _offline_call(self, case, fingerprint):
        proposal = {"verdict": "abstain", "confidence": "low",
                    "rationale": "Offline workflow check only; no model was called. Human review is required.",
                    "evidence_ids": [], "attack_techniques": [], "revision": case["revision"],
                    "dismissal_basis": "none", "claims": []}
        verdict, details = triage_evidence.validate(canonical(proposal), case)
        return TriageCall(
            incident_id=case["incident_id"], prompt_sha256=fingerprint,
            verdict=verdict["verdict"], confidence=verdict["confidence"], rationale=verdict["rationale"],
            evidence_ids=(), attack_techniques=(), model="offline-review", stop_reason="offline",
            input_tokens=0, output_tokens=0, cache_creation_input_tokens=0, cache_read_input_tokens=0,
            usd=0.0, latency_seconds=0.0, metadata={"evidence_validation": details, "offline": True})

    def _checked(self, call, case, fingerprint, mode):
        if call.incident_id != case["incident_id"] or call.prompt_sha256 != fingerprint:
            raise ValueError("result does not match the requested dossier")
        proposal = (call.metadata or {}).get("evidence_validation", {}).get("proposal")
        verdict, details = triage_evidence.validate(canonical(proposal), case)
        code = details["reasons"][0]["code"] if details["reasons"] else "valid"
        checked = replace(call, verdict=verdict["verdict"], confidence=verdict["confidence"],
                          rationale=verdict["rationale"], evidence_ids=tuple(verdict["evidence_ids"]),
                          attack_techniques=tuple(verdict["attack_techniques"]),
                          metadata={**(call.metadata or {}), "evidence_validation": details, "validation": code,
                                    "execution_mode": mode,
                                    "additional_usd": call.usd if mode == "api" else 0.0})
        if len(canonical(checked.to_record()).encode()) > 256 * 1024:
            raise ValueError("analysis record exceeds limit")
        return checked

    def run_once(self):
        if not self.enabled:
            return False
        job = self.jobs.claim(lease_seconds=self.settings.lease_seconds, max_attempts=self.settings.max_attempts)
        if job is None:
            return False
        case = json.loads(job["dossier_json"])
        try:
            cached = self.jobs.cached_call(job)
            if cached is None:
                current = self._bundle(job["incident_id"])
                if current["preview_key"] != job["cache_key"] or job["config_sha"] != self.config_sha:
                    self.jobs.finish(job, "stale", error="evidence_or_configuration_changed")
                    return True
            ledger = Ledger(self.jobs, job)
            if cached is not None:
                call = TriageCall.from_record(cached)
            elif self.provider is not None:
                call = self.provider(case, job, ledger)
            elif self.settings.mode == "offline":
                call = self._offline_call(case, job["request_sha"])
            elif self.settings.mode == "recorded":
                call = RecordedTriage(self.settings.recording_path).lookup(case, request_sha256=job["request_sha"])
                if call is None:
                    self.jobs.finish(job, "review", error="recording_missing")
                    return True
            else:
                key = read_key(self.settings.keys_file, self.profile.key_name)
                call = APITriage(self.profile, key, ledger=ledger, tape=Path(job["run_id"])).triage(case)
            try:
                call = self._checked(call, case, job["request_sha"], json.loads(job["local_json"])["meta"]["execution_mode"])
            except (ValueError, TypeError, KeyError, AttributeError):
                self.jobs.finish(job, "review", error="invalid_analysis_record")
                return True
            state = "review" if call.verdict == "abstain" else "complete"
            self.jobs.finish(job, state, record=call.to_record())
        except BudgetExceeded:
            self.jobs.finish(job, "budget_exhausted", error="budget_exhausted")
        except (APIError, CallUncertain):
            self.jobs.finish(job, "uncertain", error="provider_outcome_unknown")
        except KeyError:
            self.jobs.finish(job, "stale", error="incident_no_longer_available")
        except Exception:
            # No raw log, key, remote body or exception text enters user-facing errors.
            self.jobs.retry_unsubmitted(job, max_attempts=self.settings.max_attempts)
        return True

    def start(self):
        if not self.enabled or self.thread:
            return
        def work():
            while not self.stop.is_set():
                try:
                    busy = self.run_once()
                except Exception:
                    busy = False
                self.stop.wait(0.1 if busy else 1.0)
        self.thread = threading.Thread(target=work, name="manual-ai-triage", daemon=True)
        self.thread.start()

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=5)
