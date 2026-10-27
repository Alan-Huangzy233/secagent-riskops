"""Synthetic immutable generations and bounded read-only console views."""
import json
import sqlite3
from types import SimpleNamespace

import pytest

from app.telemetry import joint_case_query as module
from app.telemetry.joint_case_contract import AnchorRequest, CaseStoreError, validate_read
from app.telemetry.joint_case_store import JointCaseStore
from app.telemetry.joint_case_query import open_query
from test_joint_case_contract import authored, NET


@pytest.fixture
def populated(tmp_path,monkeypatch):
    scope,_,_ = authored(monkeypatch)
    store = JointCaseStore.create(tmp_path/'joint.sqlite',scope)
    values = {}
    for index in range(4):
        _,request,result = authored(monkeypatch,changes={'incident_id':'NET-'+f'{index:032x}'})
        values[request.incident_id] = validate_read(scope,request,result)
        store.register((request,))
    store.begin_cycle()
    while item:=store.next_item():
        store.publish(item,values[item.incident_id])
    return store,values


def query(store):
    return open_query(store.path,store.scope,store.limits,catalog_min_seq=store.catalog_min_seq)


def revise(store,values,monkeypatch,index,*,records=()):
    scope,request,result = authored(monkeypatch,changes={'incident_id':'NET-'+f'{index:032x}'},records=records)
    values[request.incident_id] = validate_read(scope,request,result)
    store.begin_cycle()
    while item:=store.next_item():
        store.publish(item,values[item.incident_id])


def change_saved(store,table,sql,params=()):
    with sqlite3.connect(store.path) as db:
        triggers = db.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name=?",(table,)).fetchall()
        for name,_ in triggers:
            db.execute('DROP TRIGGER '+name)
        db.execute(sql,params)
        for _,ddl in triggers:
            db.execute(ddl)


def test_fixed_generation_paging_and_filters_do_not_drift_on_new_revisions(populated,monkeypatch):
    store,values = populated
    q = query(store)
    initial = q.list_cases(limit=1)
    assert initial['total']==4 and initial['total_pages']==4
    first = initial['items'][0]
    revise(store,values,monkeypatch,3)
    pages = [q.list_cases(limit=1,page=i,snapshot=initial['snapshot']) for i in range(1,5)]
    assert len({p['items'][0]['case_id'] for p in pages})==4
    assert all(p['items'][0]['revision']==1 and p['current_generation']==5 for p in pages)
    assert pages[0]['items'][0]==first
    assert q.list_cases({'state':'linked'})['total']==3
    assert q.list_cases({'state':'unmatched'})['total']==1
    old = q.case_detail(first['case_id'],1)
    assert old['projection']['state']=='linked' and old['current']['revision']==2
    assert q.case_detail(first['case_id'],2)['projection']['state']=='unmatched'
    assert q.list_cases({'ip':'198.51.100.99'})['total']==0
    assert q.list_cases({'start':'2026-01-01T00:00:00Z','end':'2026-01-01T00:00:00+00:00'})['total']==4
    assert q.list_cases({'start':'2027-01-01T00:00:00Z'})['total']==0


def test_snapshot_bound_to_scope_filters_generation_and_epoch(populated):
    store,_ = populated
    q = query(store)
    token = q.list_cases()['snapshot']
    for value in ('bad',token+' ',{},'x'*8193):
        with pytest.raises(CaseStoreError,match='joint_refresh_required'):
            q.list_cases(snapshot=value)
    with pytest.raises(CaseStoreError,match='joint_refresh_required'):
        q.list_cases({'state':'linked'},snapshot=token)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE joint_runtime SET query_epoch=?",('a'*32,))
    with pytest.raises(CaseStoreError,match='joint_refresh_required'):
        q.list_cases(snapshot=token)


@pytest.mark.parametrize('filters',[{'ip':'198.51.100.0/24'},{'ip':'fe80::1%eth0'},{'state':[]},{'asset_id':'/'},
    {'start':'not-a-date'},{'start':'2026-01-01T00:00:00+01:00'},
    {'start':'2026-01-02T00:00:00Z','end':'2026-01-01T00:00:00Z'},{'unknown':'private'}])
def test_query_filters_are_strict(populated,filters):
    with pytest.raises(CaseStoreError,match='joint_invalid_request'):
        query(populated[0]).list_cases(filters)


def test_saved_timeline_pagination_never_reconstructs_hidden_evidence(tmp_path,monkeypatch):
    scope,request,result = authored(monkeypatch,cap=2)
    store = JointCaseStore.create(tmp_path/'joint.sqlite',scope)
    store.register((request,))
    store.begin_cycle()
    value = validate_read(scope,request,result)
    store.publish(store.next_item(),value)
    q = query(store)
    row, = q.list_cases()['items']
    assert row['saved_count']==2 and row['observed_count']==4 and not row['timeline_complete']
    part = q.timeline(row['case_id'],1,limit=1,page=2)
    assert len(part['items'])==1 and part['total_saved']==2 and part['observed_count']==4
    assert q.timeline(row['case_id'],99) is None


def test_get_uses_only_readonly_connections_and_leaves_all_bytes(populated,monkeypatch):
    store,_ = populated
    with sqlite3.connect(store.path) as db:
        before = tuple(db.iterdump())
    monkeypatch.setattr(JointCaseStore,'_connection',lambda *a,**k: pytest.fail('GET used writer object'))
    q = open_query(store.path,store.scope,store.limits)
    assert q.status()['state']=='ready'
    page = q.list_cases()
    q.case_detail(page['items'][0]['case_id'],1)
    q.timeline(page['items'][0]['case_id'],1)
    with sqlite3.connect(store.path) as db:
        assert tuple(db.iterdump())==before


def test_query_deadline_and_cleanup(populated,monkeypatch):
    store,_ = populated
    q = query(store)
    monkeypatch.setattr(module,'QUERY_SECONDS',0)
    with pytest.raises(CaseStoreError,match='joint_store_busy'):
        q.list_cases()
    monkeypatch.setattr(module,'QUERY_SECONDS',5)
    assert q.list_cases()['total']==4


@pytest.mark.parametrize('field,value',[('peer_ip','1'*500000),('peer_ip','not-ip'),('window_start_us',-1),
    ('window_end_us',None),('temporal_available',4),('network_count',999),('saved_count',10000)])
def test_invalid_typed_summary_is_not_returned(populated,field,value):
    store,_ = populated
    change_saved(store,'joint_revision_summaries','UPDATE joint_revision_summaries SET '+field+'=?',(value,))
    with pytest.raises(CaseStoreError,match='joint_store_corrupt'):
        query(store).list_cases()


@pytest.mark.parametrize('kind',['payload_hash','payload_extra','metadata_extra','runtime_large','current_error'])
def test_invalid_stored_history_and_large_metadata_fail_closed(populated,kind):
    store,_ = populated
    q = query(store)
    identity = q.list_cases()['items'][0]['case_id']
    with sqlite3.connect(store.path) as db:
        raw,metadata = db.execute('SELECT projection_json,first_read_metadata_json FROM joint_case_revisions WHERE case_id=?',
                                 (identity,)).fetchone()
    if kind.startswith('payload'):
        value = json.loads(raw)
        value['raw_message' if kind=='payload_extra' else 'observed_evidence_count'] = 'private'
        change_saved(store,'joint_case_revisions','UPDATE joint_case_revisions SET projection_json=? WHERE case_id=?',
                     (json.dumps(value),identity))
    elif kind=='metadata_extra':
        value = json.loads(metadata)
        value['private_path'] = '/private'
        change_saved(store,'joint_case_revisions','UPDATE joint_case_revisions SET first_read_metadata_json=? WHERE case_id=?',
                     (json.dumps(value),identity))
    elif kind=='runtime_large':
        with sqlite3.connect(store.path) as db:
            db.execute('UPDATE joint_runtime SET query_epoch=?',('x'*500000,))
    else:
        with sqlite3.connect(store.path) as db:
            db.execute('UPDATE joint_registrations SET fixed_error_code=?',('/private/path'*100000,))
    with pytest.raises(CaseStoreError,match='joint_store_corrupt'):
        q.case_detail(identity,1)


def test_discovery_atomic_checkpoint_replay_failures_and_fixed_barrier(tmp_path,monkeypatch):
    scope,_,_ = authored(monkeypatch)
    store = JointCaseStore.create(tmp_path/'joint.sqlite',scope,catalog_min_seq=10)
    cycle = store.begin_discovery(20,scope.producer_id)
    page = SimpleNamespace(producer_id=scope.producer_id,after_seq=9,target_seq=20,next_seq=12,
        scanned_count=2,eligible_requests=(AnchorRequest(NET,1),),skipped_counts={'source_unmapped':1},complete=False)
    assert store.apply_discovery_page(cycle['cycle_id'],9,page)=='applied'
    assert store.apply_discovery_page(cycle['cycle_id'],9,page)=='superseded'
    assert store.begin_discovery(99,scope.producer_id)['target_seq']==20
    assert store.get_discovery()['cursor_seq']==12
    assert store.fail_discovery(cycle['cycle_id'],12,'source_unavailable')=='recorded'
    assert store.get_discovery()['error']=='source_unavailable'
    rollback = SimpleNamespace(**(vars(page)|{'after_seq':12,'next_seq':20,'complete':True,
        'eligible_requests':(AnchorRequest(NET,2),AnchorRequest('NET-'+'b'*32,1)),'skipped_counts':{}}))
    store.register((AnchorRequest(NET,3),))
    with pytest.raises(CaseStoreError,match='joint_revision_regression'):
        store.apply_discovery_page(cycle['cycle_id'],12,rollback)
    assert store.get_registration('NET-'+'b'*32) is None and store.get_discovery()['cursor_seq']==12
    rollback.eligible_requests = (AnchorRequest(NET,3),AnchorRequest('NET-'+'b'*32,1))
    assert store.apply_discovery_page(cycle['cycle_id'],12,rollback)=='applied'
    assert store.get_discovery()['complete'] and store.get_discovery()['error'] is None
    with pytest.raises(CaseStoreError,match='joint_revision_regression'):
        store.begin_discovery(19,scope.producer_id)
    assert store.begin_discovery(22,scope.producer_id)['cursor_seq']==9
