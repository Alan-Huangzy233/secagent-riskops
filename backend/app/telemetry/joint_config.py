"""Pure, default-off configuration for explicit retained-evidence observations.

Compilation does not stat/resolve paths or open a store. Filesystem alias and
source identity checks belong to the explicitly invoked CLI preflight.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import PurePath

from pydantic import BaseModel, Field, field_validator, model_validator

from .joint_case_contract import CaseScope, CaseStoreError, StoreLimits


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def _path(value):
    if (type(value) is not str or not 1 <= len(value) <= 4096 or '\x00' in value
            or not PurePath(value).is_absolute()):
        raise ValueError('invalid_joint_configuration')
    try:
        value.encode('utf-8', errors='strict')
    except UnicodeError:
        raise ValueError('invalid_joint_configuration') from None
    return os.path.normpath(value)


class JointCasesConfig(BaseModel):
    model_config = {'extra': 'forbid', 'frozen': True}
    database_path: str = Field(strict=True, min_length=1, max_length=4096)
    scope: dict
    catalog_min_seq: int = Field(default=1, ge=1, le=2**63-1, strict=True)
    store_limits: dict = Field(default_factory=dict)

    @field_validator('database_path')
    @classmethod
    def absolute_path(cls, value):
        return _path(value)

    @model_validator(mode='after')
    def valid_contract(self):
        try:
            CaseScope.from_json(_json(self.scope))
            StoreLimits(**self.store_limits)
        except (CaseStoreError, ValueError, TypeError, OverflowError):
            raise ValueError('invalid_joint_configuration') from None
        return self


@dataclass(frozen=True)
class JointRuntimeSpec:
    database_path: str
    scope: CaseScope
    limits: StoreLimits
    catalog_min_seq: int
    network_database_path: str
    ssh_database_path: str
    http_database_path: str | None
    config_sha256: str


def compile_joint_config(live_config) -> JointRuntimeSpec | None:
    """Bind declared mappings to enrolled source/profile configuration only.

    Paths are normalized lexically; symlink/hardlink checks require explicit I/O.
    Neither the scope digest nor config digest is proof of source authenticity.
    """
    config = getattr(live_config, 'joint_cases', None)
    if config is None:
        return None
    try:
        if not isinstance(config, JointCasesConfig) or live_config.network_ingest is None:
            raise ValueError
        scope = CaseScope.from_json(_json(config.scope))
        limits = StoreLimits(**config.store_limits)
        ssh_ids = {source.id for source in live_config.sources}
        network = {source.id: source for source in live_config.network_ingest.sources}
        for mapping in scope.mappings:
            if not set(mapping.ssh_source_ids) <= ssh_ids:
                raise ValueError
            for binding in mapping.network_bindings:
                source = network.get(binding.source_id)
                if source is None:
                    raise ValueError
                for revision in binding.profile_revisions:
                    profile = source.profile_for(revision)
                    if not profile.local_input_labels or not profile.local_input_interfaces:
                        raise ValueError
                    if any(ipaddress.ip_address(address).version not in profile.ip_families
                           for address in binding.destination_ips):
                        raise ValueError
        derived = _path(config.database_path)
        ssh = _path(live_config.database_path)
        net = _path(live_config.network_ingest.database_path)
        http = _path(live_config.http_ingest.database_path) if live_config.http_ingest else None
        if derived in (ssh, net, http):
            raise ValueError
        digest = hashlib.sha256(_json({'database_path': derived, 'ssh_database_path': ssh,
            'network_database_path': net, 'http_database_path': http,
            'scope': scope.to_dict(), 'limits': json.loads(limits.to_json()),
            'catalog_min_seq': config.catalog_min_seq}).encode('ascii')).hexdigest()
        return JointRuntimeSpec(derived, scope, limits, config.catalog_min_seq, net, ssh, http, digest)
    except (AttributeError, CaseStoreError, ValueError, TypeError, OverflowError):
        raise ValueError('invalid_joint_configuration') from None
