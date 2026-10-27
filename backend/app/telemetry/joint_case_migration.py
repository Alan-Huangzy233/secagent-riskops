"""Explicit offline copy/upgrade/snapshot/restore, always into a new private file.

Operators stop writers first. SQLite backup captures one derived database, never
an atomic SSH/network/derived cohort. Source databases are opened read-only.
"""
from __future__ import annotations

from contextlib import contextmanager, suppress
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import time
import uuid

from .joint_case_contract import (
    AnchorRequest, CaseScope, CaseStoreError, SCOPE_BYTES, StoreLimits, validate_read,
)
from .joint_evidence import JointProjection
from .joint_reader import JointRead
from .joint_case_store import (
    APPLICATION_ID, SCHEMA_VERSION, JointCaseStore, _SCHEMA_V1, _V2_SCHEMA,
    _connect, _expected_schema, _identity, _initialize_runtime, _path, _positive,
    _schema, _storage_error, _summary, _summary_values,
)

OFFLINE_SECONDS = 60.0
MAX_DATABASE_BYTES = 1024*1024*1024
_MANIFEST_KEYS = {'version','schema_version','store_id','query_epoch','scope_sha256','scope_json',
                  'limits_json','generation','catalog_min_seq','revalidation_pending','sha256','bytes',
                  'evidence_scope','cross_store_atomic'}


def _error(code='joint_store_corrupt'):
    raise CaseStoreError(code)


def _json(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)


def _check_deadline(deadline):
    if time.monotonic()>=deadline:
        _error('joint_store_busy')


def _expected_v1():
    db = sqlite3.connect(':memory:')
    try:
        for statement in _SCHEMA_V1:
            db.execute(statement)
        return _schema(db)
    finally:
        db.close()


def _source_meta(db,version):
    if (db.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]>64 or
            db.execute("SELECT 1 FROM sqlite_master WHERE length(CAST(sql AS BLOB))>16384 LIMIT 1").fetchone() is not None):
        _error('joint_store_schema_mismatch')
    if (db.execute('PRAGMA application_id').fetchone()[0]!=APPLICATION_ID or
            db.execute('PRAGMA user_version').fetchone()[0]!=version or
            _schema(db)!=(_expected_v1() if version==1 else _expected_schema())):
        _error('joint_store_schema_mismatch')
    valid = db.execute("SELECT 1 FROM joint_meta WHERE singleton=1 AND typeof(scope_json)='text' "
        "AND length(CAST(scope_json AS BLOB))<=? AND typeof(limits_json)='text' "
        "AND length(CAST(limits_json AS BLOB))<=1024 AND typeof(store_id)='text' "
        "AND length(CAST(store_id AS BLOB))=32 AND typeof(scope_sha256)='text' "
        "AND length(CAST(scope_sha256 AS BLOB))=64 AND typeof(schema_version)='integer' "
        "AND typeof(revision_count)='integer' AND typeof(payload_bytes)='integer' "
        "AND typeof(committed_generation)='integer'",(SCOPE_BYTES,)).fetchone()
    if not valid:
        _error()
    meta = dict(db.execute('SELECT * FROM joint_meta WHERE singleton=1').fetchone())
    try:
        scope,limits = CaseScope.from_json(meta['scope_json']),StoreLimits.from_json(meta['limits_json'])
        if meta['schema_version']!=version or scope.sha256!=meta['scope_sha256']:
            _error()
    except (ValueError,TypeError,CaseStoreError):
        _error()
    return meta,scope,limits


@contextmanager
def _copy(source_path,output_path,version):
    """Yield a private SQLite-backup copy; caller publishes only after validation."""
    source,output = _path(source_path),_path(output_path)
    deadline = time.monotonic()+OFFLINE_SECONDS
    temporary,src,dst,created,completed = None,None,None,None,False
    try:
        _identity(source)
        if output.exists() or output.is_symlink():
            _error('joint_store_exists')
        if source==output:
            _error('joint_source_alias')
        output.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        src = _connect(source,write=False)
        src.set_progress_handler(lambda:int(time.monotonic()>=deadline),1000)
        src.execute('BEGIN')
        _source_meta(src,version)
        size = src.execute('PRAGMA page_count').fetchone()[0]*src.execute('PRAGMA page_size').fetchone()[0]
        if size>MAX_DATABASE_BYTES or shutil.disk_usage(output.parent).free<size*2+8*1024*1024:
            _error('joint_capacity_exceeded')
        temporary = output.parent/('.joint-'+uuid.uuid4().hex+'.sqlite')
        fd = os.open(temporary,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        created = os.fstat(fd).st_dev,os.fstat(fd).st_ino
        os.close(fd)
        dst = sqlite3.connect(temporary,isolation_level=None,timeout=.25)
        dst.row_factory = sqlite3.Row
        def progress(status,remaining,total):
            _check_deadline(deadline)
        src.backup(dst,pages=128,progress=progress,sleep=.01)
        src.rollback()
        src.close()
        src = None
        dst.execute('PRAGMA journal_mode=DELETE')
        dst.execute('PRAGMA foreign_keys=ON')
        dst.execute('PRAGMA trusted_schema=OFF')
        dst.set_progress_handler(lambda:int(time.monotonic()>=deadline),1000)
        yield temporary,output,dst,deadline
        _check_deadline(deadline)
        completed = True
    except sqlite3.Error as error:
        if getattr(error,'sqlite_errorcode',0)==sqlite3.SQLITE_INTERRUPT:
            raise CaseStoreError('joint_store_busy') from None
        raise _storage_error(error) from None
    except OSError:
        raise CaseStoreError('joint_store_unavailable') from None
    finally:
        for db in (src,dst):
            if db is not None:
                with suppress(sqlite3.Error):
                    db.rollback()
                db.close()
        if not completed and created is not None:
            with suppress(FileNotFoundError):
                current = output.lstat()
                if (current.st_dev,current.st_ino)==created:
                    output.unlink()
        if temporary is not None:
            for suffix in ('','-wal','-shm','-journal'):
                with suppress(FileNotFoundError):
                    Path(str(temporary)+suffix).unlink()


def _publish(temporary,output):
    with open(temporary,'rb') as file:
        os.fsync(file.fileno())
    try:
        os.link(temporary,output)
    except FileExistsError:
        _error('joint_store_exists')
    temporary.unlink()
    descriptor = os.open(output.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validated_revisions(db,scope,limits,deadline,*,summaries=False):
    total = size = generation = 0
    rows = db.execute('SELECT CASE WHEN length(CAST(v.case_id AS BLOB))<=38 THEN v.case_id END AS case_id,'
        "CASE WHEN typeof(v.revision)='integer' THEN v.revision END AS revision,"
        "CASE WHEN typeof(v.publish_generation)='integer' THEN v.publish_generation END AS publish_generation,"
        'CASE WHEN length(CAST(v.projection_sha256 AS BLOB))=64 THEN v.projection_sha256 END AS projection_sha256,'
        "CASE WHEN typeof(v.payload_bytes)='integer' THEN v.payload_bytes END AS payload_bytes,"
        'CASE WHEN length(CAST(v.projection_json AS BLOB))<=? THEN v.projection_json END AS projection_json,'
        'CASE WHEN length(CAST(v.first_read_metadata_json AS BLOB))<=? THEN v.first_read_metadata_json END AS first_read_metadata_json,'
        'CASE WHEN length(CAST(r.anchor_fingerprint AS BLOB))=64 THEN r.anchor_fingerprint END AS anchor_fingerprint '
        'FROM joint_case_revisions v '
        'JOIN joint_cases c USING(case_id) JOIN joint_registrations r USING(registration_seq) '
        'ORDER BY publish_generation',(limits.projection_byte_limit,limits.metadata_byte_limit))
    for row in rows:
        _check_deadline(deadline)
        if (type(row['projection_json']) is not str or type(row['first_read_metadata_json']) is not str or
                len(row['projection_json'])>limits.projection_byte_limit or
                len(row['first_read_metadata_json'])>limits.metadata_byte_limit):
            _error()
        try:
            payload = json.loads(row['projection_json'])
            request = AnchorRequest(payload['anchor']['incident_id'],payload['anchor']['revision'])
            result = JointRead(JointProjection(payload['case_id'],payload['state'],row['projection_sha256'],row['projection_json']),
                               row['first_read_metadata_json'])
            checked = validate_read(scope,request,result,limits=limits)
            if (checked.case_id!=row['case_id'] or checked.anchor_fingerprint!=row['anchor_fingerprint'] or
                    row['payload_bytes']!=len(row['projection_json']) or row['publish_generation']!=generation+1):
                _error()
        except (KeyError,TypeError,ValueError,RecursionError,CaseStoreError):
            _error()
        if summaries:
            _summary(db,row['case_id'],row['revision'],row['publish_generation'],payload)
        else:
            saved = db.execute('SELECT * FROM joint_revision_summaries WHERE case_id=? AND revision=?',
                               (row['case_id'],row['revision'])).fetchone()
            if saved is None or tuple(saved)!=_summary_values(row['case_id'],row['revision'],row['publish_generation'],payload):
                _error()
        total += 1
        size += row['payload_bytes']
        generation = row['publish_generation']
        if total>limits.revision_limit or size>limits.payload_byte_limit:
            _error('joint_capacity_exceeded')
    meta = db.execute('SELECT * FROM joint_meta WHERE singleton=1').fetchone()
    if (total!=meta['revision_count'] or size!=meta['payload_bytes'] or generation!=meta['committed_generation'] or
            db.execute('PRAGMA foreign_key_check').fetchone() is not None):
        _error()


def _identity_update(db,*,version=None):
    db.execute('DROP TRIGGER joint_scope_no_update')
    if version is None:
        db.execute('UPDATE joint_meta SET store_id=? WHERE singleton=1',(uuid.uuid4().hex,))
    else:
        db.execute('UPDATE joint_meta SET schema_version=?,store_id=? WHERE singleton=1',(version,uuid.uuid4().hex))
    db.execute(next(sql for sql in _SCHEMA_V1 if 'CREATE TRIGGER joint_scope_no_update' in sql))


def migrate_v1(source_path,output_path,*,catalog_min_seq=1,expected_scope=None,expected_limits=None):
    if ((expected_scope is not None and type(expected_scope) is not CaseScope) or
            (expected_limits is not None and type(expected_limits) is not StoreLimits)):
        _error('joint_invalid_request')
    _positive(catalog_min_seq)
    with _copy(source_path,output_path,1) as (temporary,output,db,deadline):
        _,scope,limits = _source_meta(db,1)
        if ((expected_scope is not None and scope!=expected_scope) or
                (expected_limits is not None and limits!=expected_limits)):
            _error('joint_scope_mismatch')
        db.execute('BEGIN IMMEDIATE')
        for statement in _V2_SCHEMA:
            db.execute(statement)
        _initialize_runtime(db,catalog_min_seq)
        _validated_revisions(db,scope,limits,deadline,summaries=True)
        _identity_update(db,version=SCHEMA_VERSION)
        db.execute(f'PRAGMA user_version={SCHEMA_VERSION}')
        db.commit()
        JointCaseStore.open(temporary)
        _publish(temporary,output)
    return JointCaseStore.open(output)


def _hash_file(path,deadline):
    digest = hashlib.sha256()
    with open(path,'rb') as file:
        while block:=file.read(1024*1024):
            _check_deadline(deadline)
            digest.update(block)
    return digest.hexdigest()


def _manifest(db,path,deadline):
    meta = db.execute('SELECT * FROM joint_meta WHERE singleton=1').fetchone()
    runtime = db.execute('SELECT * FROM joint_runtime WHERE singleton=1').fetchone()
    return {'version':'joint-derived-snapshot-v1','schema_version':SCHEMA_VERSION,'store_id':meta['store_id'],
        'query_epoch':runtime['query_epoch'],'scope_sha256':meta['scope_sha256'],'scope_json':meta['scope_json'],
        'limits_json':meta['limits_json'],'generation':meta['committed_generation'],
        'catalog_min_seq':runtime['catalog_min_seq'],'revalidation_pending':bool(runtime['revalidation_pending']),
        'sha256':_hash_file(path,deadline),'bytes':path.stat().st_size,
        'evidence_scope':'retained_incident_evidence_only','cross_store_atomic':False}


def snapshot_store(source_path,output_path):
    manifest_output = _path(str(output_path)+'.manifest.json')
    if manifest_output.exists():
        _error('joint_store_exists')
    manifest_created = False
    published = None
    try:
        with _copy(source_path,output_path,SCHEMA_VERSION) as (temporary,output,db,deadline):
            _,scope,limits = _source_meta(db,SCHEMA_VERSION)
            _validated_revisions(db,scope,limits,deadline)
            JointCaseStore.open(temporary)
            manifest = _manifest(db,temporary,deadline)
            descriptor = os.open(manifest_output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            manifest_created = True
            with os.fdopen(descriptor,'w') as file:
                file.write(_json(manifest))
                file.flush()
                os.fsync(file.fileno())
            _publish(temporary,output)
            published = output
        return manifest
    except BaseException:
        if manifest_created:
            with suppress(FileNotFoundError):
                manifest_output.unlink()
        if published is not None:
            with suppress(FileNotFoundError):
                published.unlink()
        raise


def restore_store(snapshot_path,output_path,*,expected_scope,expected_limits,catalog_min_seq=1):
    if type(expected_scope) is not CaseScope or type(expected_limits) is not StoreLimits:
        _error('joint_invalid_request')
    _positive(catalog_min_seq)
    snapshot = _path(snapshot_path)
    manifest_path = _path(str(snapshot)+'.manifest.json')
    try:
        _identity(manifest_path)
        if manifest_path.stat().st_size>SCOPE_BYTES+8192:
            _error()
        raw = manifest_path.read_text(encoding='ascii')
        manifest = json.loads(raw)
        if type(manifest) is not dict or set(manifest)!=_MANIFEST_KEYS or _json(manifest)!=raw:
            _error()
    except (UnicodeError,ValueError,TypeError,RecursionError):
        _error()
    except OSError:
        raise CaseStoreError('joint_store_unavailable') from None
    with _copy(snapshot,output_path,SCHEMA_VERSION) as (temporary,output,db,deadline):
        actual = _manifest(db,snapshot,deadline)
        if manifest!=actual or _json(actual)!=raw:
            _error()
        _,scope,limits = _source_meta(db,SCHEMA_VERSION)
        if scope!=expected_scope or limits!=expected_limits or manifest['catalog_min_seq']!=catalog_min_seq:
            _error('joint_scope_mismatch')
        _validated_revisions(db,scope,limits,deadline)
        db.execute('BEGIN IMMEDIATE')
        _identity_update(db)
        db.execute('UPDATE joint_runtime SET query_epoch=?,revalidation_pending=1,recovery_discovery_done=0,'
                   'recovery_refresh_cycle=NULL,recovery_discovery_cycle=NULL WHERE singleton=1',(uuid.uuid4().hex,))
        db.execute('DELETE FROM joint_discovery')
        db.commit()
        JointCaseStore.open(temporary)
        _publish(temporary,output)
    return JointCaseStore.open(output)
