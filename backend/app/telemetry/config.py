"""Validated, fail-closed configuration for the live telemetry service."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from pathlib import Path

from pydantic import BaseModel, Field, field_validator, model_validator

from .joint_config import JointCasesConfig, compile_joint_config

_PASSWORD_ALGORITHM = "pbkdf2_sha256"
_PASSWORD_ITERATIONS = 600_000


def _password_parts(encoded: str) -> tuple[int, bytes, bytes]:
    try:
        algorithm, iterations_raw, salt_raw, digest_raw = encoded.split("$")
        iterations = int(iterations_raw)
        salt = base64.b64decode(salt_raw, validate=True)
        digest = base64.b64decode(digest_raw, validate=True)
        if algorithm != _PASSWORD_ALGORITHM or not 310_000 <= iterations <= 2_000_000:
            raise ValueError
        if not 16 <= len(salt) <= 64 or len(digest) != 32:
            raise ValueError
        return iterations, salt, digest
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid operator password hash") from exc


def hash_operator_password(password: str) -> str:
    """Create a salted standard-library PBKDF2 hash for deployment configuration."""
    if not 16 <= len(password) <= 1024:
        raise ValueError("Operator password must contain 16 to 1024 characters")
    salt = secrets.token_bytes(24)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PASSWORD_ITERATIONS)
    return "$".join((_PASSWORD_ALGORITHM, str(_PASSWORD_ITERATIONS),
                     base64.b64encode(salt).decode("ascii"),
                     base64.b64encode(digest).decode("ascii")))


def verify_operator_password(password: str, encoded: str) -> bool:
    iterations, salt, expected = _password_parts(encoded)
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(candidate, expected)


class SourceConfig(BaseModel):
    model_config = {"extra": "forbid", "frozen": True}

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    hostname: str = Field(min_length=1, max_length=253)
    token_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, value: str) -> str:
        if not value.strip() or any(ord(char) < 33 or ord(char) == 127 for char in value):
            raise ValueError("Invalid source hostname")
        return value


class HttpSourceConfig(SourceConfig):
    services: tuple[str, ...] = Field(min_length=1, max_length=32)

    @field_validator("services")
    @classmethod
    def valid_services(cls, values):
        import re
        if len(set(values)) != len(values) or any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", v) for v in values):
            raise ValueError("Invalid or duplicate HTTP service identity")
        return values


class HttpIngestConfig(BaseModel):
    model_config = {"extra": "forbid", "frozen": True}
    database_path: str = Field(min_length=1)
    sources: tuple[HttpSourceConfig, ...] = Field(min_length=1, max_length=200)
    retention_days: int = Field(default=14, ge=1, le=365)

    @field_validator("database_path")
    @classmethod
    def absolute_database(cls, value):
        if not Path(value).is_absolute():
            raise ValueError("HTTP database must be an absolute persistent path")
        return value


class NetworkSourceConfig(SourceConfig):
    # Preserve historical enrolled profiles while pending batches can replay.
    profiles: tuple[dict, ...] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def valid_profiles(self):
        from .network_protocol import profile_from_dict
        profiles = [profile_from_dict(value) for value in self.profiles]
        if (any(profile.source_id != self.id for profile in profiles)
                or len({profile.revision for profile in profiles}) != len(profiles)):
            raise ValueError("Invalid or duplicate network profile")
        return self

    def profile_for(self, revision):
        from .network_protocol import profile_from_dict
        for value in self.profiles:
            profile = profile_from_dict(value)
            if profile.revision == revision:
                return profile
        raise ValueError("Network profile is not enrolled")


class NetworkIngestConfig(BaseModel):
    model_config = {"extra": "forbid", "frozen": True}
    database_path: str = Field(min_length=1)
    sources: tuple[NetworkSourceConfig, ...] = Field(min_length=1, max_length=16)
    retention_days: int = Field(default=14, ge=1, le=365, strict=True)
    max_receipts: int = Field(default=100_000, ge=1, le=1_000_000, strict=True)
    max_batches: int = Field(default=10_000, ge=1, le=100_000, strict=True)
    max_storage_bytes: int = Field(default=256 * 1024 * 1024, ge=1024 * 1024,
                                   le=2 * 1024**3, strict=True)

    @field_validator("database_path")
    @classmethod
    def absolute_database(cls, value):
        if not Path(value).is_absolute():
            raise ValueError("Network database must be an absolute persistent path")
        return value


class LiveConfig(BaseModel):
    model_config = {"extra": "forbid", "frozen": True}

    database_path: str = Field(min_length=1)
    sources: tuple[SourceConfig, ...] = Field(min_length=1, max_length=200)
    operator_username: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    operator_password_pbkdf2: str = Field(min_length=1, max_length=512, repr=False)
    retention_days: int = Field(default=14, ge=1, le=365)
    heartbeat_timeout_seconds: int = Field(default=300, ge=60, le=3600)
    notifications_enabled: bool = True
    console_cache_enabled: bool = False
    http_ingest: HttpIngestConfig | None = None
    network_ingest: NetworkIngestConfig | None = None
    joint_cases: JointCasesConfig | None = None
    notification_backup_directories: tuple[str, ...] = Field(default=(), max_length=8)

    @field_validator("notification_backup_directories")
    @classmethod
    def backup_directories(cls, values):
        if any(not Path(value).is_absolute() for value in values):
            raise ValueError("backup directories must be absolute paths")
        return values

    @field_validator("database_path")
    @classmethod
    def persistent_database(cls, value: str) -> str:
        if not Path(value).is_absolute() or value == ":memory:":
            raise ValueError("database_path must be an absolute persistent path")
        return value

    @field_validator("operator_password_pbkdf2")
    @classmethod
    def password_hash(cls, value: str) -> str:
        _password_parts(value)
        return value

    @model_validator(mode="after")
    def unique_sources(self) -> "LiveConfig":
        if len({source.id for source in self.sources}) != len(self.sources):
            raise ValueError("Duplicate source id")
        if len({source.token_sha256 for source in self.sources}) != len(self.sources):
            raise ValueError("Each source must have an independent token")
        if self.http_ingest:
            http_sources = self.http_ingest.sources
            if len({s.id for s in http_sources}) != len(http_sources):
                raise ValueError("Duplicate HTTP source identity")
            all_sources = (*self.sources, *http_sources)
            if len({s.token_sha256 for s in all_sources}) != len(all_sources):
                raise ValueError("HTTP sources require independent tokens")
            if Path(self.http_ingest.database_path).resolve() == Path(self.database_path).resolve():
                raise ValueError("HTTP storage must be separate from SSH storage")
        if self.network_ingest:
            network_sources = self.network_ingest.sources
            if len({s.id for s in network_sources}) != len(network_sources):
                raise ValueError("Duplicate network source identity")
            all_sources = (*self.sources, *(self.http_ingest.sources if self.http_ingest else ()),
                           *network_sources)
            if len({s.token_sha256 for s in all_sources}) != len(all_sources):
                raise ValueError("Network sources require independent tokens")
            other_paths = [Path(self.database_path).resolve()]
            if self.http_ingest:
                other_paths.append(Path(self.http_ingest.database_path).resolve())
            if Path(self.network_ingest.database_path).resolve() in other_paths:
                raise ValueError("Network storage must be separate from SSH and HTTP storage")
        compile_joint_config(self)
        return self


def load_config(path: str | None = None) -> LiveConfig:
    config_path = path or os.environ.get("RISKOPS_CONFIG")
    if not config_path:
        raise RuntimeError("RISKOPS_CONFIG must point to the live service configuration")
    try:
        content = Path(config_path).read_bytes()
        if len(content) > 128 * 1024:
            raise ValueError("Configuration too large")
        return LiveConfig.model_validate_json(content)
    except (OSError, ValueError):
        # Do not echo the configuration, password hash, tokens, or validation input.
        raise RuntimeError("Live service configuration is missing or invalid") from None
