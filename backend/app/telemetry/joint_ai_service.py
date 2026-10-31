"""Explicitly enabled, local-only manual review of saved joint observations.

A separate typed queue reuses leases and audit records. No provider client,
credentials, paid ledger or automatic response action is available here.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
import time
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..agents import joint_triage
from .ai_jobs import Jobs
from .ai_summary import Aliases, canonical
from . import joint_ai_recorded
from .joint_ai_preview import preview as saved_preview
from .joint_ai_summary import ENVELOPE_VERSION, VERSION
from .joint_config import JointRuntimeSpec
from .joint_case_query import open_query


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    mode: Literal["offline", "recorded"] = "offline"
    database_path: Path
    recording_path: Path | None = None
    allow_external: Literal[False] = False
    queue_limit: int = Field(default=100, strict=True, ge=1, le=1000)
    lease_seconds: int = Field(default=300, strict=True, ge=240, le=600)
    max_attempts: int = Field(default=2, strict=True, ge=1, le=3)

    @model_validator(mode="after")
    def valid(self):
        if not self.database_path.is_absolute() or "\x00" in str(self.database_path):
            raise ValueError("invalid_joint_ai_configuration")
        if self.mode == "recorded":
            if (self.recording_path is None or not self.recording_path.is_absolute()
                    or "\x00" in str(self.recording_path)):
                raise ValueError("invalid_joint_ai_configuration")
        elif self.recording_path is not None:
            raise ValueError("invalid_joint_ai_configuration")
        return self


def _family(path):
    return [Path(str(path) + suffix) for suffix in ("", "-wal", "-shm", "-journal")]


def _validate_paths(path, spec, excluded_paths):
    protected = []
    for source in (spec.database_path, spec.network_database_path, spec.ssh_database_path,
                   spec.http_database_path, *excluded_paths):
        if source is not None:
            protected.extend(_family(source))
    protected.extend(Path(str(spec.database_path) + suffix)
                     for suffix in (".refresh.json", ".refresh.lock"))
    protected_resolved = {p.resolve() for p in protected}
    protected_inodes = {(p.stat().st_dev, p.stat().st_ino) for p in protected if p.exists()}
    # SQLite creates siblings; protect them as well as the main file. Refuse
    # aliasing even when the direct file name differs (hard links or symlinks).
    for candidate in _family(path):
        if candidate.is_symlink() or candidate.resolve() in protected_resolved:
            raise ValueError("joint_ai_path_conflict")
        if any(parent.is_symlink() for parent in candidate.parents):
            raise ValueError("joint_ai_path_conflict")
        if any(p.is_dir() and candidate.resolve().is_relative_to(p.resolve()) for p in protected):
            raise ValueError("joint_ai_path_conflict")
        if candidate.exists():
            info = candidate.stat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or (info.st_dev, info.st_ino) in protected_inodes):
                raise ValueError("joint_ai_path_conflict")
        if candidate != path and candidate.exists() and not path.exists():
            raise ValueError("joint_ai_path_conflict")


class Service:
    def __init__(self, spec, settings=None, *, aliases=None, clock=time.time,
                 provider=None, error=None, excluded_paths=()):
        self.spec, self.settings, self.aliases = spec, settings, aliases
        self.clock, self.provider, self.error = clock, provider, error
        self.jobs = None
        self.recording = None
        self.thread = None
        self.stop = threading.Event()
        if settings is None:
            return
        settings = Settings.model_validate(settings.model_dump())
        if not isinstance(spec, JointRuntimeSpec) or type(aliases) is not Aliases:
            raise ValueError("joint_ai_configuration_unavailable")
        if not isinstance(aliases.secret, bytes) or not 32 <= len(aliases.secret) <= 128:
            raise ValueError("joint_ai_configuration_unavailable")
        _validate_paths(settings.database_path, spec, excluded_paths)
        if settings.mode == "recorded":
            if provider is not None:
                raise ValueError("joint_ai_configuration_unavailable")
            # Validate all aliases before opening a recording or creating a queue.
            _validate_paths(settings.recording_path, spec, (*excluded_paths, settings.database_path))
            _validate_paths(settings.database_path, spec, (*excluded_paths, settings.recording_path))
            self.recording = joint_ai_recorded.RecordedResponses.load(settings.recording_path)
        self.settings = settings
        settings_material = settings.model_dump(mode="json")
        if settings.mode == "offline":
            # Preserve the exact existing offline binding and idempotence keys.
            settings_material.pop("recording_path")
        material = {"settings": settings_material, "summary_version": VERSION,
                    "envelope_version": ENVELOPE_VERSION, "dossier_version": joint_triage.VERSION,
                    "validator_version": joint_triage.VALIDATOR_VERSION,
                    "system_sha256": hashlib.sha256(joint_triage.SYSTEM.encode()).hexdigest()}
        if self.recording is not None:
            material.update(recording_sha256=self.recording.digest,
                            recording_protocol=joint_ai_recorded.protocol())
        self.config_sha = hashlib.sha256(canonical(material).encode()).hexdigest()
        self.jobs = Jobs(settings.database_path, clock=clock, queue_kind="joint")

    @classmethod
    def from_environment(cls, spec, *, aliases=None, excluded_paths=()):
        value = os.environ.get("RISKOPS_JOINT_AI_CONFIG")
        if not value:
            return cls(spec)
        try:
            path = Path(value)
            if not isinstance(spec, JointRuntimeSpec):
                raise ValueError("joint_ai_configuration_unavailable")
            _validate_paths(path, spec, excluded_paths)
            info = path.stat()
            if (not path.is_absolute() or path.is_symlink() or not stat.S_ISREG(info.st_mode)
                    or info.st_mode & 0o077 or info.st_size > 16 * 1024):
                raise ValueError
            settings = Settings.model_validate_json(path.read_bytes())
            return cls(spec, settings, aliases=aliases, excluded_paths=(*excluded_paths, path))
        except Exception:
            # Optional configuration must not disable collection or existing AI.
            return cls(spec, error="joint_ai_configuration_unavailable")

    @property
    def enabled(self):
        return self.jobs is not None

    def status(self):
        mode = self.settings.mode if self.enabled else "disabled"
        return {"enabled": self.enabled, "mode": mode,
                "external_calls": False, "model": mode + "-review" if self.enabled else None,
                "summary_version": VERSION, "error": self.error}

    def _require(self):
        if not self.enabled:
            raise RuntimeError("joint_ai_disabled")

    def _bundle(self, case_id, revision):
        self._require()
        if (type(case_id) is not str or not re.fullmatch(r"JOINT-[0-9a-f]{32}", case_id)
                or type(revision) is not int or not 1 <= revision <= 2**31 - 1):
            raise ValueError("joint_ai_invalid_request")
        result = saved_preview(self.spec, case_id, revision, self.aliases,
                               now=datetime.fromtimestamp(self.clock(), timezone.utc))
        if result is None:
            raise KeyError("joint_ai_record_not_found")
        # The dossier revision already binds the complete saved projection,
        # scope, epochs and freshness context. Capture time is deliberately out.
        result["meta"].update(execution_mode=self.settings.mode, envelope_version=ENVELOPE_VERSION)
        if self.recording is not None:
            result["meta"]["recording_sha256"] = self.recording.digest
        result["preview_key"] = hashlib.sha256(canonical([result["case"], self.config_sha]).encode()).hexdigest()
        return result

    def preview(self, case_id, revision):
        return {**self._bundle(case_id, revision), "execution": self.status()}

    def enqueue(self, case_id, revision, preview_key, actor):
        bundle = self._bundle(case_id, revision)
        if preview_key != bundle["preview_key"]:
            raise ValueError("joint_ai_request_changed")
        if not isinstance(actor, str) or not 1 <= len(actor) <= 256:
            raise ValueError("joint_ai_invalid_request")
        request_sha = self._request_sha(bundle["case"])
        job_id = self.jobs.enqueue(case_id, bundle, self.config_sha, request_sha, actor,
                                   queue_limit=self.settings.queue_limit)
        return self.job(job_id)

    def _request_sha(self, case):
        request_kind = "joint-" + self.settings.mode + "-request-v1"
        return hashlib.sha256(canonical([request_kind, self.config_sha, case]).encode()).hexdigest()

    def _current(self, case_id, revision, cache=None):
        key = (case_id, revision)
        if cache is not None and key in cache:
            return cache[key]
        try:
            value = self._bundle(case_id, revision)
        except Exception:
            value = None
        if cache is not None:
            cache[key] = value
        return value

    def _freshness(self, job, revision, cache=None):
        current = self._current(job["incident_id"], revision, cache)
        return {"stale": (job.get("state") == "stale" or current is None or current["preview_key"] != job["cache_key"]
                           or job["config_sha"] != self.config_sha
                           or current["case"]["review_state"] != "current"),
                "current_review_state": current["case"]["review_state"] if current else "unavailable"}

    def job(self, job_id):
        self._require()
        job = self.jobs.get(job_id)
        if job is None:
            raise KeyError("joint_ai_record_not_found")
        revision = job["local"]["meta"]["case_revision"]
        return {**job, "case_id": job["incident_id"], "case_revision": revision,
                "execution_mode": job["local"]["meta"].get("execution_mode", "offline"),
                **self._freshness(job, revision)}

    def history(self, case_id):
        self._require()
        if type(case_id) is not str or not re.fullmatch(r"JOINT-[0-9a-f]{32}", case_id):
            raise ValueError("joint_ai_invalid_request")
        # Fetch bounded scalar fields, not 20 full dossiers/reference envelopes.
        with self.jobs.connection() as db:
            rows = db.execute("""SELECT id,incident_id,cache_key,config_sha,state,created,updated,error_code,
                json_extract(local_json,'$.meta.case_revision') AS case_revision,
                coalesce(json_extract(local_json,'$.meta.execution_mode'),'offline') AS execution_mode,
                json_extract(result_json,'$.verdict') AS verdict,
                json_extract(result_json,'$.confidence') AS confidence
                FROM ai_jobs WHERE incident_id=? ORDER BY created DESC,id DESC LIMIT 20""", (case_id,)).fetchall()
        cache, result = {}, []
        current_revision = None
        if rows:
            try:
                query = open_query(self.spec.database_path, self.spec.scope, self.spec.limits,
                                   catalog_min_seq=self.spec.catalog_min_seq)
                # One bounded projection read finds the current revision. Only
                # that revision needs a complete preview; old history is stale.
                detail = query.case_detail(case_id, rows[0]["case_revision"])
                if detail is not None:
                    current_revision = detail["current"]["revision"]
            except Exception:
                pass
        for row in rows:
            item = dict(row)
            freshness = {"stale": True, "current_review_state": "unavailable"}
            if current_revision is not None and item["case_revision"] < current_revision:
                freshness["current_review_state"] = "historical"
            elif item["case_revision"] == current_revision:
                freshness = self._freshness(item, item["case_revision"], cache)
            result.append({key: item[key] for key in ("id", "case_revision", "state", "created", "updated", "error_code")}
                          | {"case_id": case_id, "execution_mode": item["execution_mode"],
                             "result": {"verdict": item["verdict"], "confidence": item["confidence"]}
                             if item["verdict"] is not None else None,
                             **freshness})
        return result

    def run_once(self):
        if not self.enabled:
            return False
        job = self.jobs.claim(lease_seconds=self.settings.lease_seconds,
                              max_attempts=self.settings.max_attempts)
        if job is None:
            return False
        try:
            case = json.loads(job["dossier_json"])
            joint_triage.parse_dossier(case)
            meta = json.loads(job["local_json"])["meta"]
            revision = meta["case_revision"]
            current = self._current(job["incident_id"], revision)
            if (current is None or current["preview_key"] != job["cache_key"]
                    or job["config_sha"] != self.config_sha
                    or canonical(case) != canonical(current["case"])
                    or job["request_sha"] != self._request_sha(case)
                    or meta.get("execution_mode", "offline") != self.settings.mode
                    or (self.recording is not None and meta.get("recording_sha256") != self.recording.digest)):
                self.jobs.finish(job, "stale", error="joint_ai_request_changed")
                return True
            proposal = {"verdict": "abstain", "confidence": "low", "revision": case["revision"],
                        "rationale": "Offline workflow check; no model was called. Human review is required.",
                        "evidence_ids": [], "attack_techniques": [], "claims": []}
            # Tests may inject a pure fake. No configuration can select a client;
            # it receives only the aliased case, never the private envelope.
            if self.recording is not None:
                text = self.recording.response(case)
            else:
                text = self.provider(json.loads(canonical(case))) if self.provider is not None else canonical(proposal)
            verdict, details = joint_triage.validate(text, case)
            freshness = self._freshness(job, revision)
            record = {**verdict, "metadata": {"evidence_validation": details, "offline": True,
                      "stale_at_completion": freshness["stale"]}, "usd": 0}
            if self.recording is not None:
                record["metadata"].update(execution_mode="recorded", recording_sha256=self.recording.digest,
                                          recorded_generation_cost="unknown", provenance_verified=False)
            if len(canonical(record).encode()) > 256 * 1024:
                raise ValueError("joint_ai_result_too_large")
            self.jobs.finish(job, "review" if verdict["verdict"] == "abstain" else "complete", record=record)
        except joint_ai_recorded.RecordedResponseMissing:
            self.jobs.finish(job, "failed", error="joint_ai_recording_missing")
        except joint_ai_recorded.RecordedResponseUnavailable:
            state = "queued" if job["attempt_count"] < self.settings.max_attempts else "failed"
            self.jobs.finish(job, state, error="joint_ai_recording_unavailable")
        except Exception:
            self.jobs.retry_unsubmitted(job, max_attempts=self.settings.max_attempts)
        return True

    def start(self):
        if not self.enabled or self.thread is not None:
            return
        def work():
            while not self.stop.is_set():
                try:
                    busy = self.run_once()
                except Exception:
                    busy = False
                self.stop.wait(0.1 if busy else 1)
        self.thread = threading.Thread(target=work, name="joint-offline-review", daemon=True)
        try:
            self.thread.start()
        except BaseException:
            self.thread = None
            raise

    def close(self):
        self.stop.set()
        if self.thread is not None and self.thread.ident is not None:
            self.thread.join(timeout=5)
