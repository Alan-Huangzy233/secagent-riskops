"""Finite catalog barriers over temporary real source schemas."""
from contextlib import closing
from dataclasses import replace
import json
import sqlite3

import pytest

from app.telemetry.joint_case_contract import CaseStoreError
from app.telemetry.joint_catalog import catalog_target, read_catalog_page, preflight_sources
from app.telemetry.joint_config import compile_joint_config
from app.telemetry.joint_reader_io import EvidenceReadError, ReadBudget, ReadLimits
from test_joint_reader import sources as sources, read, store_digest
from test_joint_config import config_for


@pytest.fixture
def configured(sources, tmp_path):
    net, ssh, mapping, _, _ = sources
    producer = read(sources).projection.to_dict()['anchor']['producer_id']
    config = config_for(tmp_path, mapping=mapping, producer=producer)
    config.database_path, config.network_ingest.database_path = str(ssh.path), str(net.path)
    return config, compile_joint_config(config)


def clone_heads(path, count, *, start=100, **changes):
    with closing(sqlite3.connect(path)) as db:
        db.row_factory = sqlite3.Row
        original = dict(db.execute('SELECT * FROM network_incidents ORDER BY seq LIMIT 1').fetchone())
        for number in range(count):
            values = dict(original)
            values.pop('seq')
            values['incident_id'] = 'NET-'+format(number+start, '032x')
            values.update(changes)
            payload = json.loads(values['payload_json'])
            for key in ('incident_id','source_id','source_profile_revision','src_ip','dst_ip','revision'):
                payload[key] = values[key]
            values['payload_json'] = json.dumps(payload)
            columns = ','.join(values)
            db.execute('INSERT INTO network_incidents('+columns+') VALUES('+','.join('?' for _ in values)+')', tuple(values.values()))
        db.commit()


def test_finite_barrier_skips_new_rows_and_revisits_old_heads(configured, sources):
    _, spec = configured
    net = sources[0]
    clone_heads(net.path, 2)
    before = store_digest(net.path)
    target = catalog_target(net.path, spec)
    page = read_catalog_page(net.path,spec,after_seq=0,target_seq=target,limit=2)
    assert page.scanned_count == 2 and not page.complete
    assert store_digest(net.path) == before
    clone_heads(net.path,1,start=300,source_id='other')
    with closing(sqlite3.connect(net.path)) as db:
        db.execute('UPDATE network_incidents SET active=0,surfaced=0,stale=1')
        db.commit()
    tail = read_catalog_page(net.path,spec,after_seq=page.next_seq,target_seq=target,limit=2)
    assert tail.complete and tail.scanned_count == 1
    assert len(tail.eligible_requests) == 1
    assert read_catalog_page(net.path,spec,after_seq=0,target_seq=target).scanned_count == 3
    assert catalog_target(net.path,spec) > target


@pytest.mark.parametrize('change,reason', [({'source_id':'unmapped'},'source_unmapped'),
    ({'dst_ip':'192.0.2.99'},'destination_unmapped'),({'source_profile_revision':'f'*64},'profile_unmapped')])
def test_unmapped_heads_counted_not_claimed_complete_coverage(configured,sources,change,reason):
    _, spec = configured
    clone_heads(sources[0].path,1,**change)
    page = read_catalog_page(sources[0].path,spec,after_seq=0,target_seq=catalog_target(sources[0].path,spec))
    assert page.complete and page.scanned_count == 2
    assert len(page.eligible_requests)==1 and page.skipped_counts=={reason:1}


@pytest.mark.parametrize('sql', ["UPDATE network_incidents SET source_id='x'||printf('%1000000s','')",
    "UPDATE network_incidents SET payload_json='{'", "UPDATE network_incidents SET revision=0",
    "UPDATE network_incidents SET payload_json=json_object('giant',printf('%5000000s',''))",
    "UPDATE network_incidents SET src_ip='not-an-ip'", "UPDATE network_incidents SET source_profile_revision='bad'"])
def test_malformed_or_oversized_rows_fail_entire_page(configured,sources,sql):
    _,spec=configured
    with closing(sqlite3.connect(sources[0].path)) as db:
        db.execute(sql)
        db.commit()
    with pytest.raises(EvidenceReadError,match='evidence_invalid'):
        read_catalog_page(sources[0].path,spec,after_seq=0,target_seq=1)


def test_bad_producer_and_regressed_catalog_do_not_advance(configured,sources):
    _,spec=configured
    wrong=replace(spec,scope=replace(spec.scope,producer_id='different'))
    with pytest.raises(CaseStoreError,match='joint_anchor_mismatch'):
        catalog_target(sources[0].path,wrong)
    with pytest.raises(CaseStoreError,match='joint_revision_regression'):
        read_catalog_page(sources[0].path,spec,after_seq=0,target_seq=2)


def test_empty_ssh_still_requires_full_schema(configured,sources):
    _,spec=configured
    with closing(sqlite3.connect(sources[1].path)) as db:
        db.execute('DROP TABLE incident_evidence')
        db.commit()
    with pytest.raises(EvidenceReadError,match='source_schema_unavailable'):
        preflight_sources(spec)


def test_shared_deadline_and_byte_budget(configured,sources):
    _,spec=configured
    now=[0.0]
    budget=ReadBudget(clock=lambda:now[0])
    target=catalog_target(sources[0].path,spec,budget=budget)
    now[0]=6
    with pytest.raises(EvidenceReadError,match='query_deadline_exceeded'):
        read_catalog_page(sources[0].path,spec,after_seq=0,target_seq=target,budget=budget)
    with pytest.raises(EvidenceReadError,match='adapter_limit_exceeded'):
        read_catalog_page(sources[0].path,spec,after_seq=0,target_seq=1,limits=ReadLimits(byte_limit=100))


def test_schema_missing_rejected_even_empty_catalog(configured,sources):
    _,spec=configured
    with closing(sqlite3.connect(sources[0].path)) as db:
        db.execute('DELETE FROM network_incidents')
        db.execute('DROP TABLE network_evidence_membership')
        db.commit()
    with pytest.raises(EvidenceReadError,match='source_schema_unavailable'):
        catalog_target(sources[0].path,spec)


@pytest.mark.parametrize('options',[{'limit':51},{'limit':True},{'after_seq':-1},{'target_seq':True}])
def test_bounded_requests_rejected(configured,sources,options):
    values={'after_seq':0,'target_seq':1,**options}
    with pytest.raises(EvidenceReadError,match='adapter_invalid_request'):
        read_catalog_page(sources[0].path,configured[1],**values)


def test_busy_source_has_bounded_wait_and_fixed_error(configured,sources):
    import time
    _,spec=configured
    with closing(sqlite3.connect(sources[0].path)) as writer:
        writer.execute('PRAGMA journal_mode=DELETE')
        writer.execute('BEGIN EXCLUSIVE')
        started=time.monotonic()
        with pytest.raises(EvidenceReadError,match='source_busy'):
            catalog_target(sources[0].path,spec)
        assert time.monotonic()-started<1.5
        writer.rollback()


def test_unrelated_payload_text_is_not_copied_to_python(configured,sources):
    _,spec=configured
    with closing(sqlite3.connect(sources[0].path)) as db:
        db.execute("UPDATE network_incidents SET payload_json=json_set(payload_json,'$.unused',?)",('x'*500_000,))
        db.commit()
    budget=ReadBudget()
    page=read_catalog_page(sources[0].path,spec,after_seq=0,target_seq=1,budget=budget)
    assert page.complete and len(page.eligible_requests)==1
    assert budget.bytes_read<1024
