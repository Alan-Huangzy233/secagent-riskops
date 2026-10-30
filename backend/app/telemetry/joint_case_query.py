"""Bounded read-only views of saved joint observations; never read source stores."""
from __future__ import annotations

import base64
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import json
import math
import re
import sqlite3
import time

from .joint_case_contract import (
    AnchorRequest, CaseScope, CaseStoreError, StoreLimits, SCOPE_BYTES, ERROR_CODES, ValidatedRead, validate_read,
)
from .joint_evidence import JointProjection, MAX_TIME_US
from .joint_reader import JointRead
from .joint_case_store import (
    APPLICATION_ID, SCHEMA_VERSION, SCOPE, JointCaseStore, _CASE, _connect, _discovery,
    _expected_schema, _identity, _path, _schema, _storage_error,
)

QUERY_SECONDS = 5.0
LIST_BYTES = 128*1024
_STATES = {'linked','unmatched','partial','stale','retracted'}
_FIELDS = ('case_id','revision','publish_generation','asset_id','peer_ip','association_state',
           'window_start_us','window_end_us','temporal_available','network_count','ssh_count',
           'saved_count','observed_count','timeline_complete')
_TEXT = {'case_id','asset_id','peer_ip','association_state'}


def _error(code='joint_invalid_request'):
    raise CaseStoreError(code)


def _json(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)


def _int(value,minimum=1,maximum=2**63-1):
    if type(value) is not int or not minimum<=value<=maximum:
        _error()


def _timestamp(value):
    if value is None:
        return None,None
    if type(value) is not str or len(value)>40:
        _error()
    try:
        parsed = datetime.fromisoformat(value.replace('Z','+00:00'))
        if parsed.tzinfo is None or parsed.utcoffset().total_seconds()!=0:
            _error()
        delta = parsed-datetime(1970,1,1,tzinfo=timezone.utc)
        micros = (delta.days*86400+delta.seconds)*1_000_000+delta.microseconds
        if micros<0:
            _error()
        return parsed.isoformat(timespec='microseconds').replace('+00:00','Z'),micros
    except (ValueError,OverflowError):
        _error()


def normalize_filters(filters=None):
    if filters is None:
        filters = {}
    if type(filters) is not dict or set(filters)-{'ip','asset_id','state','start','end'}:
        _error()
    result = {name:filters.get(name) for name in ('ip','asset_id','state','start','end')}
    if result['ip'] is not None:
        raw = result['ip']
        if type(raw) is not str or not 1<=len(raw)<=64 or '%' in raw:
            _error()
        try:
            result['ip'] = str(ipaddress.ip_address(raw))
        except ValueError:
            _error()
    if result['asset_id'] is not None and (type(result['asset_id']) is not str or
            not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',result['asset_id'])):
        _error()
    if result['state'] is not None and (type(result['state']) is not str or result['state'] not in _STATES):
        _error()
    result['start'],start = _timestamp(result['start'])
    result['end'],end = _timestamp(result['end'])
    if start is not None and end is not None and start>end:
        _error()
    return result,start,end


@dataclass(frozen=True)
class SavedCaseSnapshot:
    """Full saved observation and query context from one read transaction."""

    observation: ValidatedRead
    detail: dict
    status: dict


class JointCaseQuery:
    def __init__(self,path,scope,limits,catalog_min_seq):
        self.path,self.scope,self.limits = _path(path),scope,limits
        self.catalog_min_seq = catalog_min_seq

    @contextmanager
    def _connection(self):
        db = None
        deadline = time.monotonic()+QUERY_SECONDS
        try:
            _identity(self.path)
            db = _connect(self.path,write=False)
            db.set_progress_handler(lambda: int(time.monotonic()>=deadline),1000)
            db.execute('BEGIN')
            if (db.execute('PRAGMA application_id').fetchone()[0]!=APPLICATION_ID or
                    db.execute('PRAGMA user_version').fetchone()[0]!=SCHEMA_VERSION):
                _error('joint_store_schema_mismatch')
            if db.execute("SELECT 1 FROM sqlite_master WHERE sql IS NOT NULL AND length(CAST(sql AS BLOB))>16384 LIMIT 1").fetchone():
                _error('joint_store_schema_mismatch')
            if db.execute('SELECT count(*) FROM sqlite_master').fetchone()[0]>64 or _schema(db)!=_expected_schema():
                _error('joint_store_schema_mismatch')
            valid = db.execute("SELECT 1 FROM joint_meta WHERE singleton=1 AND length(CAST(scope_json AS BLOB))<=? "
                "AND length(CAST(limits_json AS BLOB))<=1024 AND length(CAST(store_id AS BLOB))=32 "
                "AND length(CAST(scope_sha256 AS BLOB))=64 AND typeof(scope_json)='text' AND typeof(limits_json)='text' "
                "AND typeof(store_id)='text' AND typeof(scope_sha256)='text' AND typeof(schema_version)='integer' "
                "AND typeof(revision_count)='integer' AND typeof(payload_bytes)='integer' "
                "AND typeof(committed_generation)='integer'",(SCOPE_BYTES,)).fetchone()
            if valid is None:
                _error('joint_store_corrupt')
            meta = dict(db.execute('SELECT * FROM joint_meta WHERE singleton=1').fetchone())
            runtime = db.execute("SELECT singleton,CASE WHEN typeof(query_epoch)='text' AND "
                'length(CAST(query_epoch AS BLOB))=32 THEN query_epoch END AS query_epoch,'
                "CASE WHEN typeof(catalog_min_seq)='integer' THEN catalog_min_seq END AS catalog_min_seq,"
                'CASE WHEN revalidation_pending IN (0,1) THEN revalidation_pending END AS revalidation_pending,'
                'CASE WHEN length(CAST(discovery_error AS BLOB))<=64 THEN discovery_error '
                "WHEN discovery_error IS NULL THEN NULL ELSE '!' END AS discovery_error "
                'FROM joint_runtime WHERE singleton=1').fetchone()
            if (runtime is None or meta['schema_version']!=SCHEMA_VERSION or
                    meta['scope_sha256']!=self.scope.sha256 or meta['scope_json']!=self.scope.to_json() or
                    meta['limits_json']!=self.limits.to_json() or runtime['catalog_min_seq']!=self.catalog_min_seq):
                _error('joint_scope_mismatch')
            if (not re.fullmatch('[0-9a-f]{32}',meta['store_id']) or
                    type(runtime['query_epoch']) is not str or not re.fullmatch('[0-9a-f]{32}',runtime['query_epoch']) or
                    any(type(meta[k]) is not int or meta[k]<0 for k in ('revision_count','payload_bytes','committed_generation')) or
                    meta['revision_count']>self.limits.revision_limit or meta['payload_bytes']>self.limits.payload_byte_limit or
                    meta['committed_generation']!=meta['revision_count'] or
                    type(runtime['revalidation_pending']) is not int or runtime['revalidation_pending'] not in (0,1)):
                _error('joint_store_corrupt')
            yield db,meta,dict(runtime)
            if time.monotonic()>=deadline:
                _error('joint_store_busy')
        except sqlite3.Error as error:
            if getattr(error,'sqlite_errorcode',0)==sqlite3.SQLITE_INTERRUPT:
                raise CaseStoreError('joint_store_busy') from None
            raise _storage_error(error) from None
        except OSError:
            raise CaseStoreError('joint_store_unavailable') from None
        finally:
            if db is not None:
                db.set_progress_handler(None,0)
                with suppress(sqlite3.Error):
                    db.rollback()
                db.close()

    def status(self):
        with self._connection() as (db,meta,runtime):
            return self._status(db,meta,runtime)

    def _status(self,db,meta,runtime):
        discovery = cycle = None
        registrations = db.execute('SELECT count(*) FROM joint_registrations').fetchone()[0]
        if registrations>self.limits.registration_limit:
            _error('joint_store_corrupt')
        if db.execute("SELECT 1 FROM joint_registrations WHERE fixed_error_code IS NOT NULL AND "
            "(typeof(fixed_error_code)!='text' OR length(CAST(fixed_error_code AS BLOB))>64) LIMIT 1").fetchone():
            _error('joint_store_corrupt')
        if db.execute("SELECT 1 FROM joint_discovery WHERE length(CAST(skipped_json AS BLOB))>2048 OR "
            "length(CAST(cycle_id AS BLOB))>128 OR length(CAST(producer_id AS BLOB))>128 OR "
            "length(CAST(fixed_error_code AS BLOB))>64 OR length(CAST(started_at AS BLOB))>40 OR "
            "length(CAST(finished_at AS BLOB))>40 OR length(CAST(state AS BLOB))>16 LIMIT 1").fetchone():
            _error('joint_store_corrupt')
        latest_error = db.execute('SELECT fixed_error_code FROM joint_registrations '
            'WHERE fixed_error_code IS NOT NULL ORDER BY registration_seq LIMIT 1').fetchone()
        if db.execute("SELECT 1 FROM joint_cycle WHERE length(CAST(cycle_id AS BLOB))>128 OR "
            "length(CAST(started_at AS BLOB))>40 OR length(CAST(finished_at AS BLOB))>40 OR "
            "state NOT IN ('active','completed') OR typeof(item_count)!='integer' OR "
            "item_count<0 OR item_count>1000 OR typeof(published)!='integer' OR typeof(unchanged)!='integer' OR "
            "typeof(failed)!='integer' OR typeof(not_eligible)!='integer' OR typeof(superseded)!='integer' OR "
            "typeof(cursor_seq)!='integer' OR typeof(target_registration_seq)!='integer' LIMIT 1").fetchone():
            _error('joint_store_corrupt')
        try:
            discovery,cycle = _discovery(db),JointCaseStore._cycle(db)
            if discovery:
                if (type(discovery['skipped_counts']) is not dict or
                        set(discovery['skipped_counts'])-{'source_unmapped','destination_unmapped','profile_unmapped'} or
                        any(type(value) is not int or value<0 for value in discovery['skipped_counts'].values()) or
                        discovery['producer_id']!=self.scope.producer_id or
                        discovery['state'] not in ('active','completed') or
                        any(type(discovery[key]) is not int or discovery[key]<0 for key in
                            ('target_seq','cursor_seq','scanned_count','registered_count'))):
                    _error('joint_store_corrupt')
            for state in (discovery,cycle):
                if state:
                    if not re.fullmatch('[0-9a-f]{32}',state['cycle_id']):
                        _error('joint_store_corrupt')
                    _timestamp(state['started_at'])
                    if state['finished_at'] is not None:
                        _timestamp(state['finished_at'])
            if cycle and any(value<0 or value>1000 for value in cycle['counts'].values()):
                _error('joint_store_corrupt')
        except (TypeError,ValueError,KeyError,CaseStoreError):
            _error('joint_store_corrupt')
        error = runtime['discovery_error'] or (discovery or {}).get('error') or (latest_error[0] if latest_error else None)
        if error is not None and error not in ERROR_CODES | {'network_source_unmapped','network_destination_unmapped',
                'network_profile_unmapped','network_observation_not_local_tcp'}:
            _error('joint_store_corrupt')
        state = ('revalidation_pending' if runtime['revalidation_pending'] else 'unavailable' if error else
                 'processing' if (discovery and not discovery['complete']) or (cycle and not cycle['attempted_complete']) else
                 'ready' if meta['revision_count'] else 'empty')
        return {'enabled':True,'state':state,'store_id':meta['store_id'],'query_epoch':runtime['query_epoch'],
            'generation':meta['committed_generation'],'catalog_min_seq':runtime['catalog_min_seq'],
            'assets':[{'asset_id':asset.asset_id} for asset in self.scope.mappings],
            'discovery':discovery,'cycle':cycle,'capacity':{'registrations':registrations,
                'registration_limit':self.limits.registration_limit,'revisions':meta['revision_count'],
                'revision_limit':self.limits.revision_limit,'payload_bytes':meta['payload_bytes'],
                'payload_byte_limit':self.limits.payload_byte_limit},'error':error,
            'revalidation_pending':bool(runtime['revalidation_pending']),
            'scope':SCOPE,'evidence_scope':'retained_incident_evidence_only'}

    def _snapshot(self,snapshot,meta,runtime,filters):
        fixed = {'version':1,'schema':SCHEMA_VERSION,'store_id':meta['store_id'],
                 'query_epoch':runtime['query_epoch'],'scope':self.scope.sha256,'filters':filters}
        if snapshot is None:
            value = dict(fixed,generation=meta['committed_generation'])
        else:
            if type(snapshot) is not str or len(snapshot)>4096:
                _error('joint_refresh_required')
            try:
                raw = base64.b64decode(snapshot.encode('ascii'),altchars=b'-_',validate=True).decode('ascii')
                value = json.loads(raw)
                if (type(value) is not dict or set(value)!=set(fixed)|{'generation'} or
                        any(value[key]!=expected for key,expected in fixed.items()) or
                        type(value['generation']) is not int or not 0<=value['generation']<=meta['committed_generation'] or
                        _json(value)!=raw):
                    _error('joint_refresh_required')
            except (ValueError,TypeError,UnicodeError,RecursionError):
                _error('joint_refresh_required')
        return base64.urlsafe_b64encode(_json(value).encode('ascii')).decode('ascii'),value['generation']

    def list_cases(self,filters=None,*,page=1,limit=20,snapshot=None):
        _int(page,1,1000)
        _int(limit,1,50)
        filters,start,end = normalize_filters(filters)
        with self._connection() as (db,meta,runtime):
            token,generation = self._snapshot(snapshot,meta,runtime,filters)
            clauses,params = [],[generation]
            for key,column in (('ip','peer_ip'),('asset_id','asset_id'),('state','association_state')):
                if filters[key] is not None:
                    clauses.append('s.'+column+'=?')
                    params.append(filters[key])
            if start is not None:
                clauses.append('s.temporal_available=1 AND s.window_end_us>=?')
                params.append(start)
            if end is not None:
                clauses.append('s.temporal_available=1 AND s.window_start_us<=?')
                params.append(end)
            selected = ('WITH selected AS (SELECT case_id,max(publish_generation) AS g FROM joint_revision_summaries '
                        'WHERE publish_generation<=? GROUP BY case_id) ')
            relation = ' FROM selected p JOIN joint_revision_summaries s ON s.case_id=p.case_id AND s.publish_generation=p.g'
            where = ' WHERE '+' AND '.join(clauses) if clauses else ''
            total = db.execute(selected+'SELECT count(*)'+relation+where,params).fetchone()[0]
            if total>self.limits.registration_limit:
                _error('joint_store_corrupt')
            columns = ','.join(('CASE WHEN typeof(s.'+name+")='text' AND length(CAST(s."+name+
                               ' AS BLOB))<=128 THEN s.'+name+' ELSE NULL END AS '+name) if name in _TEXT else
                              ('CASE WHEN typeof(s.'+name+") IN ('integer','null') THEN s."+name+' ELSE -1 END AS '+name)
                              for name in _FIELDS)
            rows = db.execute(selected+'SELECT '+columns+relation+where+
                ' ORDER BY s.publish_generation DESC,s.case_id LIMIT ? OFFSET ?',params+[limit,(page-1)*limit]).fetchall()
            items = []
            for row in rows:
                item = dict(row)
                if (any(type(item[key]) is not str for key in _TEXT) or not _CASE.fullmatch(item['case_id']) or
                        item['association_state'] not in _STATES or
                        any(type(item[key]) is not int or item[key]<0 for key in set(_FIELDS)-_TEXT-{'window_start_us','window_end_us'}) or
                        item['temporal_available'] not in (0,1) or item['timeline_complete'] not in (0,1)):
                    _error('joint_store_corrupt')
                try:
                    if '%' in item['peer_ip'] or len(item['peer_ip'])>64 or str(ipaddress.ip_address(item['peer_ip']))!=item['peer_ip']:
                        _error('joint_store_corrupt')
                except ValueError:
                    _error('joint_store_corrupt')
                if (item['revision']<1 or item['publish_generation']<1 or
                        item['network_count']>5000 or item['ssh_count']>5000 or item['saved_count']>1000 or item['saved_count']>item['observed_count'] or
                        item['network_count']+item['ssh_count']!=item['observed_count'] or
                        bool(item['timeline_complete'])!=(item['saved_count']==item['observed_count'])):
                    _error('joint_store_corrupt')
                if item['temporal_available']:
                    if any(type(item[key]) is not int or not 0<=item[key]<=MAX_TIME_US
                           for key in ('window_start_us','window_end_us')) or item['window_start_us']>item['window_end_us']:
                        _error('joint_store_corrupt')
                elif item['window_start_us'] is not None or item['window_end_us'] is not None:
                    _error('joint_store_corrupt')
                item['temporal_available'] = bool(item['temporal_available'])
                item['timeline_complete'] = bool(item['timeline_complete'])
                items.append(item)
            result = {'items':items,'page':page,'total_pages':max(1,math.ceil(total/limit)),
                      'total':total,'snapshot':token,'current_generation':meta['committed_generation']}
            if len(_json(result))>LIST_BYTES:
                _error('joint_capacity_exceeded')
            return result

    def case_detail(self,case_id,revision):
        if type(case_id) is not str or not _CASE.fullmatch(case_id):
            _error()
        _int(revision)
        with self._connection() as (db,_,__):
            saved = self._case_detail(db,case_id,revision)
            return saved[1] if saved is not None else None

    def ai_snapshot(self,case_id,revision):
        """Pin complete saved evidence, registration and runtime in one transaction."""
        if type(case_id) is not str or not _CASE.fullmatch(case_id):
            _error()
        _int(revision)
        with self._connection() as (db,meta,runtime):
            saved = self._case_detail(db,case_id,revision)
            if saved is None:
                return None
            observation,detail = saved
            return SavedCaseSnapshot(observation,detail,self._status(db,meta,runtime))

    def _case_detail(self,db,case_id,revision):
        row = db.execute('SELECT v.case_id,v.revision,CASE WHEN length(CAST(v.projection_json AS BLOB))<=? '
            'THEN v.projection_json END AS projection_json,CASE WHEN length(CAST(v.first_read_metadata_json AS BLOB))<=? '
            'THEN v.first_read_metadata_json END AS metadata_json,CASE WHEN length(CAST(v.projection_sha256 AS BLOB))=64 '
            'THEN v.projection_sha256 END AS projection_sha256,c.current_revision,'
            "CASE WHEN length(CAST(r.refresh_state AS BLOB))<=32 THEN r.refresh_state ELSE '!' END AS refresh_state,"
            "CASE WHEN length(CAST(r.last_success AS BLOB))<=40 THEN r.last_success WHEN r.last_success IS NULL THEN NULL ELSE '!' END AS last_success,"
            "CASE WHEN length(CAST(r.fixed_error_code AS BLOB))<=64 THEN r.fixed_error_code WHEN r.fixed_error_code IS NULL THEN NULL ELSE '!' END AS fixed_error_code "
            'FROM joint_case_revisions v JOIN joint_cases c USING(case_id) JOIN joint_registrations r USING(registration_seq) '
            'WHERE v.case_id=? AND v.revision=?',
            (self.limits.projection_byte_limit,self.limits.metadata_byte_limit,case_id,revision)).fetchone()
        if row is None:
            return None
        try:
            projection,metadata = json.loads(row['projection_json']),json.loads(row['metadata_json'])
            checked = validate_read(self.scope,AnchorRequest(projection['anchor']['incident_id'],projection['anchor']['revision']),
                JointRead(JointProjection(projection['case_id'],projection['state'],row['projection_sha256'],row['projection_json']),
                          row['metadata_json']),limits=self.limits)
            _int(row['current_revision'],revision)
            if checked.case_id!=case_id or row['refresh_state'] not in ('fresh','pending','unavailable','needs_review','not_eligible'):
                _error('joint_store_corrupt')
            if row['last_success'] is not None:
                if len(row['last_success'])>40:
                    _error('joint_store_corrupt')
                _timestamp(row['last_success'])
            if row['fixed_error_code'] is not None and row['fixed_error_code'] not in ERROR_CODES | {
                    'network_source_unmapped','network_destination_unmapped','network_profile_unmapped','network_observation_not_local_tcp'}:
                _error('joint_store_corrupt')
        except (KeyError,TypeError,ValueError,RecursionError,CaseStoreError):
            _error('joint_store_corrupt')
        return checked,{'case_id':case_id,'revision':revision,'projection':projection,'first_read_metadata':metadata,
                'current':{'revision':row['current_revision'],'refresh_state':row['refresh_state'],
                           'last_success':row['last_success'],'error':row['fixed_error_code']}}

    def timeline(self,case_id,revision,*,page=1,limit=50):
        _int(page,1,1000)
        _int(limit,1,50)
        detail = self.case_detail(case_id,revision)
        if detail is None:
            return None
        payload = detail['projection']
        total = len(payload['timeline'])
        return {'case_id':case_id,'revision':revision,'items':payload['timeline'][(page-1)*limit:page*limit],
                'page':page,'total_pages':max(1,math.ceil(total/limit)),'total_saved':total,
                'observed_count':payload['observed_evidence_count'],'timeline_complete':payload['timeline_complete']}


def open_query(path,expected_scope,expected_limits,*,catalog_min_seq=1):
    if type(expected_scope) is not CaseScope or type(expected_limits) is not StoreLimits:
        _error()
    _int(catalog_min_seq)
    query = JointCaseQuery(path,expected_scope,expected_limits,catalog_min_seq)
    with query._connection():
        pass
    return query
