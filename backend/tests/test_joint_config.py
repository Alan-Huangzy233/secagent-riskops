"""Pure enrolled mapping validation; only synthetic configuration is used."""
from dataclasses import asdict, replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.telemetry.config import NetworkSourceConfig
from app.telemetry.joint_case_contract import CaseScope
from app.telemetry.joint_config import JointCasesConfig, compile_joint_config
from app.telemetry.joint_evidence import AssetMapping, NetworkBinding
from test_network_detection import profile, DESTINATION


def config_for(tmp_path, *, mapping=None, producer='fixture-producer', source_profile=None):
    prof = source_profile or profile()
    mapping = mapping or AssetMapping('asset-a', ('auth-a',),
        (NetworkBinding(prof.source_id, (DESTINATION,), (prof.revision,)),))
    scope = CaseScope((mapping,), producer)
    return SimpleNamespace(database_path=str(tmp_path/'ssh.sqlite'),
        sources=(SimpleNamespace(id='auth-a'),), http_ingest=None,
        network_ingest=SimpleNamespace(database_path=str(tmp_path/'network.sqlite'), sources=(
            NetworkSourceConfig(id=prof.source_id,hostname='synthetic.invalid',token_sha256='a'*64,
                                profiles=(asdict(prof),)),)),
        joint_cases=JointCasesConfig(database_path=str(tmp_path/'joint.sqlite'),
                                    scope=json.loads(scope.to_json())))


def test_default_off_has_no_filesystem_access(monkeypatch):
    monkeypatch.setattr(Path, 'stat', lambda *a,**k: pytest.fail('pure compilation stat'))
    monkeypatch.setattr(Path, 'resolve', lambda *a,**k: pytest.fail('pure compilation resolve'))
    assert compile_joint_config(SimpleNamespace(joint_cases=None)) is None


def test_config_compiles_without_io_and_ignores_credentials(tmp_path, monkeypatch):
    config = config_for(tmp_path)
    monkeypatch.setattr(Path, 'stat', lambda *a,**k: pytest.fail('pure compilation stat'))
    monkeypatch.setattr(Path, 'resolve', lambda *a,**k: pytest.fail('pure compilation resolve'))
    spec = compile_joint_config(config)
    assert spec.catalog_min_seq == 1 and spec.scope.mappings[0].asset_id == 'asset-a'
    assert spec.limits.registration_limit == 1000
    assert len(spec.config_sha256) == 64


@pytest.mark.parametrize('change', ['ssh','source','profile','nonlocal','family','alias','network_missing'])
def test_unenrolled_or_ineligible_configuration_rejected(tmp_path, change):
    config = config_for(tmp_path)
    if change == 'ssh':
        config.sources = ()
    elif change == 'source':
        config.network_ingest.sources = ()
    elif change == 'profile':
        scope = config.joint_cases.scope
        scope['mappings'][0]['network_bindings'][0]['profile_revisions'] = ['b'*64]
    elif change == 'nonlocal':
        config = config_for(tmp_path, source_profile=profile(local_input_labels=(), local_input_interfaces=()))
    elif change == 'family':
        prof = profile(ip_families=(6,))
        config = config_for(tmp_path, source_profile=prof)
    elif change == 'alias':
        config.joint_cases = config.joint_cases.model_copy(update={'database_path':str(tmp_path/'x/../ssh.sqlite')})
    else:
        config.network_ingest = None
    with pytest.raises(ValueError,match='^invalid_joint_configuration$'):
        compile_joint_config(config)


@pytest.mark.parametrize('field,value', [('catalog_min_seq',True),('catalog_min_seq',0),
    ('catalog_min_seq',2**63),('database_path','relative.sqlite'),('database_path','/bad\x00name'),
    ('database_path','/bad\ud800name'),('store_limits',{'registration_limit':True}),
    ('store_limits',{'unknown':1}),('enabled',True)])
def test_strict_configuration_fields(tmp_path, field, value):
    fields = config_for(tmp_path).joint_cases.model_dump()
    fields[field] = value
    with pytest.raises(ValidationError):
        JointCasesConfig(**fields)


def test_scope_ownership_cannot_be_inferred_from_shared_ip(tmp_path):
    fields = config_for(tmp_path).joint_cases.model_dump()
    other = json.loads(json.dumps(fields['scope']['mappings'][0]))
    other['asset_id'] = 'another'
    fields['scope']['mappings'].append(other)
    with pytest.raises(ValidationError):
        JointCasesConfig(**fields)


def test_low_limits_and_explicit_catalog_floor_are_immutable_values(tmp_path):
    config = config_for(tmp_path)
    fields = config.joint_cases.model_dump()
    fields.update(catalog_min_seq=42, store_limits={'registration_limit':3})
    config.joint_cases = JointCasesConfig(**fields)
    spec = compile_joint_config(config)
    assert spec.catalog_min_seq == 42 and spec.limits.registration_limit == 3
    assert replace(spec, catalog_min_seq=43).catalog_min_seq == 43
