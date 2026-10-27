"""Explicit derived-case storage; no source I/O, workers or activation.

Only this database is written. Logical payload limits exclude SQLite pages,
indexes, bounded observation metadata and WAL overhead; they are not disk caps.
One finite cycle worklist is retained, while published revisions are immutable.
"""
from __future__ import annotations

from contextlib import contextmanager, suppress
from datetime import datetime, timezone
from functools import lru_cache
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import uuid

from .joint_case_contract import (
    AnchorRequest, CaseScope, CaseStoreError, StoreLimits, ValidatedRead, WorkItem,
    validate_read,
)

APPLICATION_ID = 0x4A4E5431
SCHEMA_VERSION = 2
SCOPE = 'explicit_registered_anchors_only'
_INCIDENT = re.compile(r'NET-[0-9a-f]{32}\Z')
_CASE = re.compile(r'JOINT-[0-9a-f]{32}\Z')
_OUTCOMES = ('published', 'unchanged', 'failed', 'not_eligible', 'superseded')
_UNSET = object()
_SCHEMA_V1 = (
    """CREATE TABLE joint_meta (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL,
        store_id TEXT NOT NULL, scope_json TEXT NOT NULL, scope_sha256 TEXT NOT NULL,
        limits_json TEXT NOT NULL, committed_generation INTEGER NOT NULL CHECK(committed_generation>=0),
        revision_count INTEGER NOT NULL CHECK(revision_count>=0),
        payload_bytes INTEGER NOT NULL CHECK(payload_bytes>=0))""",
    """CREATE TABLE joint_registrations (
        registration_seq INTEGER PRIMARY KEY, incident_id TEXT NOT NULL UNIQUE,
        requested_network_revision INTEGER NOT NULL CHECK(requested_network_revision>=1),
        request_generation INTEGER NOT NULL CHECK(request_generation>=1),
        case_id TEXT UNIQUE, anchor_fingerprint TEXT, last_success TEXT,
        latest_read_metadata_json TEXT, refresh_state TEXT NOT NULL, fixed_error_code TEXT,
        last_attempt_cycle TEXT, last_attempt_at TEXT)""",
    """CREATE TABLE joint_cases (
        case_id TEXT PRIMARY KEY, registration_seq INTEGER NOT NULL UNIQUE
            REFERENCES joint_registrations(registration_seq),
        created_generation INTEGER NOT NULL, current_revision INTEGER NOT NULL CHECK(current_revision>=1))""",
    """CREATE TABLE joint_case_revisions (
        case_id TEXT NOT NULL REFERENCES joint_cases(case_id), revision INTEGER NOT NULL CHECK(revision>=1),
        publish_generation INTEGER NOT NULL UNIQUE, projection_sha256 TEXT NOT NULL,
        projection_json TEXT NOT NULL, first_read_metadata_json TEXT NOT NULL,
        payload_bytes INTEGER NOT NULL CHECK(payload_bytes>=0), observed_at TEXT NOT NULL,
        PRIMARY KEY(case_id,revision))""",
    """CREATE TABLE joint_cycle (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), cycle_id TEXT NOT NULL UNIQUE,
        target_registration_seq INTEGER NOT NULL, item_count INTEGER NOT NULL,
        cursor_seq INTEGER NOT NULL, state TEXT NOT NULL,
        published INTEGER NOT NULL, unchanged INTEGER NOT NULL, failed INTEGER NOT NULL,
        not_eligible INTEGER NOT NULL, superseded INTEGER NOT NULL,
        started_at TEXT NOT NULL, finished_at TEXT)""",
    """CREATE TABLE joint_cycle_items (
        cycle_id TEXT NOT NULL REFERENCES joint_cycle(cycle_id),
        registration_seq INTEGER NOT NULL REFERENCES joint_registrations(registration_seq),
        captured_request_generation INTEGER NOT NULL, captured_network_revision INTEGER NOT NULL,
        state TEXT NOT NULL, fixed_error_code TEXT, PRIMARY KEY(cycle_id,registration_seq))""",
    """CREATE TRIGGER joint_revision_no_update BEFORE UPDATE ON joint_case_revisions
        BEGIN SELECT RAISE(ABORT,'immutable_joint_revision'); END""",
    """CREATE TRIGGER joint_revision_no_delete BEFORE DELETE ON joint_case_revisions
        BEGIN SELECT RAISE(ABORT,'immutable_joint_revision'); END""",
    """CREATE TRIGGER joint_scope_no_update BEFORE UPDATE OF schema_version,store_id,
        scope_json,scope_sha256,limits_json ON joint_meta
        BEGIN SELECT RAISE(ABORT,'immutable_joint_scope'); END""",
    """CREATE TRIGGER joint_scope_no_delete BEFORE DELETE ON joint_meta
        BEGIN SELECT RAISE(ABORT,'immutable_joint_scope'); END""",
)


_V2_SCHEMA = (
    """CREATE TABLE joint_runtime (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), query_epoch TEXT NOT NULL,
        catalog_min_seq INTEGER NOT NULL CHECK(catalog_min_seq>=1),
        revalidation_pending INTEGER NOT NULL CHECK(revalidation_pending IN (0,1)),
        recovery_discovery_done INTEGER NOT NULL CHECK(recovery_discovery_done IN (0,1)),
        recovery_refresh_cycle TEXT, discovery_error TEXT, recovery_discovery_cycle TEXT)""",
    """CREATE TABLE joint_discovery (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), cycle_id TEXT NOT NULL,
        producer_id TEXT NOT NULL, target_seq INTEGER NOT NULL, cursor_seq INTEGER NOT NULL,
        state TEXT NOT NULL, scanned_count INTEGER NOT NULL, registered_count INTEGER NOT NULL,
        skipped_json TEXT NOT NULL, fixed_error_code TEXT, started_at TEXT NOT NULL, finished_at TEXT)""",
    """CREATE TABLE joint_revision_summaries (
        case_id TEXT NOT NULL, revision INTEGER NOT NULL, publish_generation INTEGER NOT NULL UNIQUE,
        asset_id TEXT NOT NULL, peer_ip TEXT NOT NULL, association_state TEXT NOT NULL,
        network_incident_id TEXT NOT NULL, network_revision INTEGER NOT NULL, network_source_id TEXT NOT NULL,
        window_start_us INTEGER, window_end_us INTEGER, temporal_available INTEGER NOT NULL,
        network_count INTEGER NOT NULL, ssh_count INTEGER NOT NULL, saved_count INTEGER NOT NULL,
        observed_count INTEGER NOT NULL, timeline_complete INTEGER NOT NULL,
        PRIMARY KEY(case_id,revision), FOREIGN KEY(case_id,revision) REFERENCES joint_case_revisions(case_id,revision))""",
    'CREATE INDEX joint_summary_history ON joint_revision_summaries(case_id,publish_generation DESC)',
    'CREATE INDEX joint_summary_generation ON joint_revision_summaries(publish_generation DESC,case_id)',
    """CREATE TRIGGER joint_summary_no_update BEFORE UPDATE ON joint_revision_summaries
        BEGIN SELECT RAISE(ABORT,'immutable_joint_summary'); END""",
    """CREATE TRIGGER joint_summary_no_delete BEFORE DELETE ON joint_revision_summaries
        BEGIN SELECT RAISE(ABORT,'immutable_joint_summary'); END""",
)
_SCHEMA = _SCHEMA_V1 + _V2_SCHEMA


def _summary_values(case_id, revision, generation, payload):
    anchor, counts = payload['anchor'], payload['counts']
    return (case_id, revision, generation, payload['asset_id'], anchor['src_ip'], payload['state'],
         anchor['incident_id'], anchor['revision'], anchor['source_id'], payload['window']['start_us'],
         payload['window']['end_us'], int(payload['temporal_association_available']),
         sum(counts['network'].values()), sum(item['evidence'] for item in counts['ssh'].values()),
         len(payload['timeline']), payload['observed_evidence_count'], int(payload['timeline_complete']))


def _summary(db, case_id, revision, generation, payload):
    db.execute('INSERT INTO joint_revision_summaries VALUES('+','.join('?' for _ in range(17))+')',
               _summary_values(case_id,revision,generation,payload))


def _initialize_runtime(db, catalog_min_seq, *, pending=False):
    db.execute('INSERT INTO joint_runtime VALUES(1,?,?,?,0,NULL,NULL,NULL)',
               (uuid.uuid4().hex, catalog_min_seq, int(pending)))


def _positive(value, *, zero=False):
    if type(value) is not int or not (0 if zero else 1) <= value <= 2**63-1:
        _error('joint_invalid_request')


def _discovery(db):
    row = db.execute('SELECT d.*,r.catalog_min_seq FROM joint_discovery d JOIN joint_runtime r USING(singleton)').fetchone()
    if row is None:
        return None
    result = dict(row)
    result.pop('singleton')
    result['skipped_counts'] = json.loads(result.pop('skipped_json'))
    result['error'] = result.pop('fixed_error_code')
    result['complete'] = result['state']=='completed'
    return result


def _recover_if_complete(db):
    runtime = db.execute('SELECT * FROM joint_runtime WHERE singleton=1').fetchone()
    discovery = _discovery(db)
    if (runtime['revalidation_pending'] and runtime['recovery_discovery_done'] and not runtime['discovery_error']
            and discovery and discovery['complete'] and not discovery['error']
            and runtime['recovery_discovery_cycle']==discovery['cycle_id']):
        cycle = JointCaseStore._cycle(db)
        if (cycle and runtime['recovery_refresh_cycle']==cycle['cycle_id'] and cycle['all_items_refreshed']
                and db.execute("SELECT 1 FROM joint_registrations WHERE refresh_state!='fresh' LIMIT 1").fetchone() is None):
            db.execute('UPDATE joint_runtime SET revalidation_pending=0 WHERE singleton=1')


def _now():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _error(code):
    raise CaseStoreError(code)


def _storage_error(error):
    code = getattr(error, 'sqlite_errorcode', 0) & 255
    if code in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
        return CaseStoreError('joint_store_busy')
    if code == sqlite3.SQLITE_FULL:
        return CaseStoreError('joint_capacity_exceeded')
    return CaseStoreError('joint_store_unavailable')


def _path(value):
    if not isinstance(value, (str, Path)) or not str(value) or str(value) == ':memory:':
        _error('joint_invalid_request')
    try:
        str(value).encode('utf-8', errors='strict')
        if '\x00' in str(value):
            _error('joint_invalid_request')
        raw = Path(value).expanduser().absolute()
        if raw.is_symlink():
            _error('joint_invalid_request')
        return raw.parent.resolve()/raw.name
    except (UnicodeError, ValueError):
        raise CaseStoreError('joint_invalid_request') from None
    except (OSError, RuntimeError) as error:
        if isinstance(error, CaseStoreError):
            raise
        raise CaseStoreError('joint_store_unavailable') from None


def _identity(path):
    entry = path.lstat()
    if (not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1
            or entry.st_uid != os.geteuid() or stat.S_IMODE(entry.st_mode) & 0o077):
        _error('joint_store_unavailable')
    return entry.st_dev, entry.st_ino


def _connect(path, *, write):
    db = sqlite3.connect(path.as_uri()+('?mode=rw' if write else '?mode=ro'),
                         uri=True, timeout=.25, isolation_level=None)
    try:
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA trusted_schema=OFF')
        if write:
            db.execute('PRAGMA synchronous=FULL')
        else:
            db.execute('PRAGMA query_only=ON')
        return db
    except BaseException:
        db.close()
        raise


def _commit(db):
    db.commit()


def _schema(db):
    return {(row[0], row[1]): re.sub(r'\s+', ' ', row[2].strip()) for row in db.execute(
        "SELECT type,name,sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'")}


@lru_cache(maxsize=1)
def _expected_schema():
    db = sqlite3.connect(':memory:')
    try:
        for sql in _SCHEMA:
            db.execute(sql)
        return _schema(db)
    finally:
        db.close()


class JointCaseStore:
    """A single immutable scope and lowered limits, opened only explicitly."""

    def __init__(self, path, scope, limits, store_id, identity):
        self._path, self._scope, self._limits = str(path), scope, limits
        self._store_id, self._identity = store_id, identity

    @property
    def path(self):
        return self._path

    @property
    def scope(self):
        return self._scope

    @property
    def limits(self):
        return self._limits

    @classmethod
    def create(cls, path, scope, *, limits=None, catalog_min_seq=1):
        _positive(catalog_min_seq)
        if type(scope) is not CaseScope or (limits is not None and type(limits) is not StoreLimits):
            _error('joint_invalid_request')
        limits = limits or StoreLimits()
        path = _path(path)
        created, db = None, None
        try:
            missing, directory = [], path.parent
            while not directory.exists():
                missing.append(directory)
                directory = directory.parent
            for directory in reversed(missing):
                directory.mkdir(mode=0o700)
            try:
                descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                raise CaseStoreError('joint_store_exists') from None
            with os.fdopen(descriptor, 'rb') as file:
                entry = os.fstat(file.fileno())
                created = entry.st_dev, entry.st_ino
            db = _connect(path, write=True)
            if db.execute('PRAGMA journal_mode=WAL').fetchone()[0] != 'wal':
                _error('joint_store_unavailable')
            db.execute('BEGIN IMMEDIATE')
            for sql in _SCHEMA:
                db.execute(sql)
            db.execute(f'PRAGMA application_id={APPLICATION_ID}')
            db.execute(f'PRAGMA user_version={SCHEMA_VERSION}')
            db.execute('INSERT INTO joint_meta VALUES(1,?,?,?,?,?,0,0,0)',
                       (SCHEMA_VERSION, uuid.uuid4().hex, scope.to_json(), scope.sha256, limits.to_json()))
            _initialize_runtime(db, catalog_min_seq)
            _commit(db)
        except BaseException as error:
            if db is not None:
                with suppress(sqlite3.Error):
                    db.rollback()
                db.close()
                db = None
            if created is not None:
                with suppress(OSError):
                    current = path.lstat()
                    if (current.st_dev, current.st_ino) == created:
                        path.unlink()
            if isinstance(error, sqlite3.Error):
                raise _storage_error(error) from None
            if isinstance(error, OSError):
                raise CaseStoreError('joint_store_unavailable') from None
            raise
        finally:
            if db is not None:
                db.close()
        return cls.open(path)

    @classmethod
    def open(cls, path):
        path, db = _path(path), None
        try:
            identity = _identity(path)
            db = _connect(path, write=False)
            db.execute('BEGIN')
            if (db.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID
                    or db.execute('PRAGMA user_version').fetchone()[0] != SCHEMA_VERSION
                    or _schema(db) != _expected_schema()):
                _error('joint_store_schema_mismatch')
            row = db.execute('SELECT * FROM joint_meta WHERE singleton=1').fetchone()
            if row is None or row['schema_version'] != SCHEMA_VERSION:
                _error('joint_store_corrupt')
            try:
                scope, limits = CaseScope.from_json(row['scope_json']), StoreLimits.from_json(row['limits_json'])
                if (scope.sha256 != row['scope_sha256'] or scope.to_json() != row['scope_json']
                        or limits.to_json() != row['limits_json']
                        or not re.fullmatch('[0-9a-f]{32}', row['store_id'])):
                    _error('joint_store_corrupt')
            except (CaseStoreError, TypeError, ValueError):
                raise CaseStoreError('joint_store_corrupt') from None
            count, size, generation = db.execute('SELECT count(*),coalesce(sum(payload_bytes),0),'
                'coalesce(max(publish_generation),0) FROM joint_case_revisions').fetchone()
            registrations = db.execute('SELECT count(*) FROM joint_registrations').fetchone()[0]
            runtime = db.execute('SELECT * FROM joint_runtime WHERE singleton=1').fetchone()
            if (runtime is None or not re.fullmatch('[0-9a-f]{32}', runtime['query_epoch'])
                    or type(runtime['catalog_min_seq']) is not int or runtime['catalog_min_seq'] < 1
                    or db.execute('SELECT count(*) FROM joint_revision_summaries').fetchone()[0] != count):
                _error('joint_store_corrupt')
            if (count != row['revision_count'] or size != row['payload_bytes']
                    or generation != row['committed_generation'] or count > limits.revision_limit
                    or size > limits.payload_byte_limit or registrations > limits.registration_limit
                    or db.execute('PRAGMA foreign_key_check').fetchone() is not None):
                _error('joint_store_corrupt')
            return cls(path, scope, limits, row['store_id'], identity)
        except sqlite3.Error as error:
            raise _storage_error(error) from None
        except OSError:
            raise CaseStoreError('joint_store_unavailable') from None
        finally:
            if db is not None:
                with suppress(sqlite3.Error):
                    db.rollback()
                db.close()

    @contextmanager
    def _connection(self, *, write=False):
        db = None
        try:
            path = Path(self.path)
            if _identity(path) != self._identity:
                _error('joint_store_unavailable')
            db = _connect(path, write=write)
            db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
            row = db.execute('SELECT store_id,scope_sha256 FROM joint_meta WHERE singleton=1').fetchone()
            if (row is None or row['store_id'] != self._store_id or row['scope_sha256'] != self.scope.sha256
                    or db.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID
                    or db.execute('PRAGMA user_version').fetchone()[0] != SCHEMA_VERSION):
                _error('joint_store_schema_mismatch')
            yield db
            if write:
                _commit(db)
        except sqlite3.Error as error:
            raise _storage_error(error) from None
        except OSError:
            raise CaseStoreError('joint_store_unavailable') from None
        finally:
            if db is not None:
                with suppress(sqlite3.Error):
                    db.rollback()
                db.close()

    def register(self, requests):
        if (type(requests) is not tuple or not 1 <= len(requests) <= 50
                or any(type(item) is not AnchorRequest for item in requests)
                or len({item.incident_id for item in requests}) != len(requests)):
            _error('joint_invalid_request')
        with self._connection(write=True) as db:
            return self._register(db, requests)

    def _register(self, db, requests):
        summary = dict(registered=0, updated=0, unchanged=0)
        total, last = db.execute('SELECT count(*),coalesce(max(registration_seq),0) FROM joint_registrations').fetchone()
        for item in requests:
            row = db.execute('SELECT * FROM joint_registrations WHERE incident_id=?', (item.incident_id,)).fetchone()
            if row is None:
                if total >= self.limits.registration_limit:
                    _error('joint_capacity_exceeded')
                last += 1
                db.execute("INSERT INTO joint_registrations(registration_seq,incident_id,requested_network_revision,"
                    "request_generation,refresh_state) VALUES(?,?,?,1,'pending')", (last, item.incident_id, item.revision))
                total += 1
                summary['registered'] += 1
            elif item.revision < row['requested_network_revision']:
                _error('joint_revision_regression')
            elif item.revision == row['requested_network_revision']:
                summary['unchanged'] += 1
            else:
                db.execute("UPDATE joint_registrations SET requested_network_revision=?,request_generation=request_generation+1,"
                           "refresh_state='pending',fixed_error_code=NULL WHERE registration_seq=?",
                           (item.revision, row['registration_seq']))
                summary['updated'] += 1
        summary['total'] = total
        return summary

    @property
    def catalog_min_seq(self):
        with self._connection() as db:
            return db.execute('SELECT catalog_min_seq FROM joint_runtime WHERE singleton=1').fetchone()[0]

    def get_discovery(self):
        with self._connection() as db:
            return _discovery(db)

    def begin_discovery(self, target_seq, producer_id):
        _positive(target_seq, zero=True)
        if type(producer_id) is not str or producer_id != self.scope.producer_id:
            _error('joint_anchor_mismatch')
        with self._connection(write=True) as db:
            previous = _discovery(db)
            if previous and not previous['complete']:
                return previous
            if previous and target_seq < previous['target_seq']:
                _error('joint_revision_regression')
            minimum = db.execute('SELECT catalog_min_seq FROM joint_runtime WHERE singleton=1').fetchone()[0]
            complete, at, identity = target_seq < minimum, _now(), uuid.uuid4().hex
            db.execute('DELETE FROM joint_discovery')
            db.execute('INSERT INTO joint_discovery VALUES(1,?,?,?,?,?,0,0,?,NULL,?,?)',
                (identity, producer_id, target_seq, minimum-1,
                 'completed' if complete else 'active', '{}', at, at if complete else None))
            db.execute('UPDATE joint_runtime SET recovery_discovery_done=?,recovery_refresh_cycle=NULL,'
                       'recovery_discovery_cycle=? WHERE singleton=1', (int(complete),identity))
            if complete:
                db.execute('UPDATE joint_runtime SET discovery_error=NULL WHERE singleton=1')
            return _discovery(db)

    def apply_discovery_page(self, cycle_id, expected_cursor, page):
        _positive(expected_cursor, zero=True)
        try:
            requests, skips = page.eligible_requests, page.skipped_counts
            for number in (page.after_seq, page.target_seq, page.next_seq, page.scanned_count):
                _positive(number, zero=True)
            if (type(requests) is not tuple or len(requests)>50
                    or any(type(item) is not AnchorRequest for item in requests)
                    or len({item.incident_id for item in requests})!=len(requests)
                    or type(skips) is not dict or len(skips)>8
                    or any(key not in ('source_unmapped','destination_unmapped','profile_unmapped')
                           or type(value) is not int or value<0 for key,value in skips.items())
                    or type(page.complete) is not bool or page.scanned_count>50
                    or page.scanned_count != len(requests)+sum(skips.values())
                    or page.after_seq != expected_cursor or not expected_cursor<=page.next_seq<=page.target_seq
                    or (page.scanned_count and page.next_seq<=expected_cursor)
                    or (not page.complete and (page.scanned_count==0 or page.next_seq>=page.target_seq))
                    or (page.complete and page.next_seq != page.target_seq)):
                _error('joint_invalid_request')
        except AttributeError:
            raise CaseStoreError('joint_invalid_request') from None
        with self._connection(write=True) as db:
            current = _discovery(db)
            if (not current or current['cycle_id'] != cycle_id or current['cursor_seq'] != expected_cursor
                    or current['complete']):
                return 'superseded'
            if page.producer_id != self.scope.producer_id:
                _error('joint_anchor_mismatch')
            if page.target_seq != current['target_seq']:
                _error('joint_invalid_request')
            summary = self._register(db, requests)
            totals = current['skipped_counts']
            for key,value in skips.items():
                totals[key] = totals.get(key,0)+value
            db.execute('UPDATE joint_discovery SET cursor_seq=?,state=?,scanned_count=scanned_count+?,'
                'registered_count=registered_count+?,skipped_json=?,fixed_error_code=NULL,finished_at=? WHERE singleton=1',
                (page.next_seq,'completed' if page.complete else 'active',page.scanned_count,
                 summary['registered']+summary['updated'],json.dumps(totals,sort_keys=True),_now() if page.complete else None))
            if page.complete:
                db.execute('UPDATE joint_runtime SET recovery_discovery_done=1,discovery_error=NULL WHERE singleton=1 '
                           'AND (revalidation_pending=0 OR recovery_discovery_cycle=?)',(cycle_id,))
            return 'applied'

    def fail_discovery(self, cycle_id, expected_cursor, code):
        _positive(expected_cursor, zero=True)
        try:
            CaseStoreError(code)
        except (TypeError,ValueError):
            _error('joint_invalid_request')
        with self._connection(write=True) as db:
            current = _discovery(db)
            if not current or current['cycle_id']!=cycle_id or current['cursor_seq']!=expected_cursor or current['complete']:
                return 'superseded'
            db.execute('UPDATE joint_discovery SET fixed_error_code=? WHERE singleton=1',(code,))
            self._record_discovery_failure(db,code)
            return 'recorded'

    @staticmethod
    def _record_discovery_failure(db,code):
        db.execute('UPDATE joint_runtime SET discovery_error=?,revalidation_pending=1,'
                   'recovery_discovery_done=0,recovery_refresh_cycle=NULL,recovery_discovery_cycle=NULL WHERE singleton=1',(code,))

    def record_discovery_failure(self,code,*,expected_cycle_id=_UNSET,expected_cursor=None,
                                 expected_revalidation_pending=_UNSET,expected_refresh_cycle_id=_UNSET):
        try:
            CaseStoreError(code)
        except (TypeError,ValueError):
            _error('joint_invalid_request')
        with self._connection(write=True) as db:
            if expected_cycle_id is not _UNSET:
                current = _discovery(db)
                if ((current is None and expected_cycle_id is not None) or
                        (current is not None and (current['cycle_id']!=expected_cycle_id or
                                                  current['cursor_seq']!=expected_cursor))):
                    return 'superseded'
            if expected_revalidation_pending is not _UNSET:
                if type(expected_revalidation_pending) is not bool:
                    _error('joint_invalid_request')
                pending = db.execute('SELECT revalidation_pending FROM joint_runtime WHERE singleton=1').fetchone()[0]
                if bool(pending)!=expected_revalidation_pending:
                    return 'superseded'
            if expected_refresh_cycle_id is not _UNSET:
                cycle = self._cycle(db)
                if (cycle['cycle_id'] if cycle else None)!=expected_refresh_cycle_id:
                    return 'superseded'
            self._record_discovery_failure(db,code)
        return 'recorded'

    @staticmethod
    def _cycle(db):
        row = db.execute('SELECT * FROM joint_cycle WHERE singleton=1').fetchone()
        if row is None:
            return None
        result = dict(row)
        result.pop('singleton')
        counts = {name: result.pop(name) for name in _OUTCOMES}
        counts['pending'] = result['item_count']-sum(counts.values())
        result.update(counts=counts, attempted_complete=counts['pending'] == 0,
                      all_items_refreshed=counts['pending'] == 0 and not any(
                          counts[name] for name in ('failed', 'superseded', 'not_eligible')), scope=SCOPE)
        return result

    def begin_cycle(self):
        with self._connection(write=True) as db:
            current = self._cycle(db)
            if current is not None and not current['attempted_complete']:
                return current
            total, target = db.execute('SELECT count(*),coalesce(max(registration_seq),0) FROM joint_registrations').fetchone()
            if total > self.limits.registration_limit:
                _error('joint_capacity_exceeded')
            db.execute('DELETE FROM joint_cycle_items')
            db.execute('DELETE FROM joint_cycle')
            identity, at = uuid.uuid4().hex, _now()
            db.execute('INSERT INTO joint_cycle VALUES(1,?,?,?,?,?,0,0,0,0,0,?,?)',
                       (identity, target, total, 0, 'active' if total else 'completed', at, None if total else at))
            db.execute("INSERT INTO joint_cycle_items SELECT ?,registration_seq,request_generation,"
                       "requested_network_revision,'pending',NULL FROM joint_registrations WHERE registration_seq<=?",
                       (identity, target))
            db.execute('UPDATE joint_runtime SET recovery_refresh_cycle=? WHERE singleton=1 AND '
                       'revalidation_pending=1 AND recovery_discovery_done=1', (identity,))
            _recover_if_complete(db)
            return self._cycle(db)

    def get_cycle(self):
        with self._connection() as db:
            return self._cycle(db)

    def next_item(self):
        with self._connection() as db:
            row = db.execute("SELECT i.cycle_id,i.registration_seq,i.captured_request_generation,"
                "i.captured_network_revision,r.incident_id FROM joint_cycle_items i "
                "JOIN joint_registrations r USING(registration_seq) WHERE i.state='pending' "
                'ORDER BY i.registration_seq LIMIT 1').fetchone()
            return WorkItem(*row) if row is not None else None

    @staticmethod
    def _finish(db, item, outcome, error=None):
        db.execute('UPDATE joint_cycle_items SET state=?,fixed_error_code=? WHERE cycle_id=? AND registration_seq=?',
                   (outcome, error, item.cycle_id, item.registration_seq))
        remaining = db.execute("SELECT min(registration_seq) FROM joint_cycle_items WHERE state='pending'").fetchone()[0]
        target = db.execute('SELECT target_registration_seq FROM joint_cycle WHERE singleton=1').fetchone()[0]
        db.execute(f'UPDATE joint_cycle SET {outcome}={outcome}+1,cursor_seq=?,state=?,finished_at=? WHERE singleton=1',
                   (target if remaining is None else remaining-1, 'completed' if remaining is None else 'active',
                    _now() if remaining is None else None))
        _recover_if_complete(db)

    def _pending(self, db, item):
        row = db.execute('SELECT i.*,r.incident_id,r.request_generation,r.requested_network_revision,'
            'r.case_id,r.anchor_fingerprint FROM joint_cycle_items i JOIN joint_registrations r USING(registration_seq) '
            'WHERE i.cycle_id=? AND i.registration_seq=?', (item.cycle_id, item.registration_seq)).fetchone()
        if (row is None or row['state'] != 'pending' or row['incident_id'] != item.incident_id
                or row['captured_request_generation'] != item.request_generation
                or row['captured_network_revision'] != item.network_revision):
            return None, 'already_processed'
        if row['request_generation'] != item.request_generation or row['requested_network_revision'] != item.network_revision:
            self._finish(db, item, 'superseded')
            return None, 'superseded'
        return row, None

    def publish(self, item, value):
        if type(item) is not WorkItem or type(value) is not ValidatedRead:
            _error('joint_invalid_request')
        value = validate_read(self.scope, AnchorRequest(item.incident_id, item.network_revision),
                              value.to_joint_read(), limits=self.limits)
        with self._connection(write=True) as db:
            registration, outcome = self._pending(db, item)
            if outcome:
                return outcome
            if (registration['anchor_fingerprint'] is not None
                    and registration['anchor_fingerprint'] != value.anchor_fingerprint):
                _error('joint_anchor_mismatch')
            at = _now()
            if value.state == 'rejected':
                db.execute('UPDATE joint_registrations SET anchor_fingerprint=?,latest_read_metadata_json=?,last_success=?, '
                    'refresh_state=?,fixed_error_code=?,last_attempt_cycle=?,last_attempt_at=? WHERE registration_seq=?',
                    (value.anchor_fingerprint, value.metadata_json, at,
                     'needs_review' if registration['case_id'] else 'not_eligible', value.rejection_code,
                     item.cycle_id, at, item.registration_seq))
                self._finish(db, item, 'not_eligible', value.rejection_code)
                return 'not_eligible'
            if registration['case_id'] is not None and registration['case_id'] != value.case_id:
                _error('joint_anchor_mismatch')
            current = db.execute('SELECT c.current_revision,v.projection_sha256 FROM joint_cases c '
                'JOIN joint_case_revisions v ON v.case_id=c.case_id AND v.revision=c.current_revision '
                'WHERE c.case_id=?', (value.case_id,)).fetchone()
            outcome = 'unchanged'
            if current is None or current['projection_sha256'] != value.projection_sha256:
                meta = db.execute('SELECT * FROM joint_meta WHERE singleton=1').fetchone()
                size = len(value.projection_json.encode('ascii'))
                if meta['revision_count'] >= self.limits.revision_limit or meta['payload_bytes']+size > self.limits.payload_byte_limit:
                    _error('joint_capacity_exceeded')
                revision = current['current_revision']+1 if current else 1
                generation = meta['committed_generation']+1
                if current is None:
                    db.execute('INSERT INTO joint_cases VALUES(?,?,?,?)',
                               (value.case_id, item.registration_seq, generation, revision))
                db.execute('INSERT INTO joint_case_revisions VALUES(?,?,?,?,?,?,?,?)',
                    (value.case_id, revision, generation, value.projection_sha256, value.projection_json,
                     value.metadata_json, size, at))
                _summary(db,value.case_id,revision,generation,json.loads(value.projection_json))
                db.execute('UPDATE joint_cases SET current_revision=? WHERE case_id=?', (revision, value.case_id))
                db.execute('UPDATE joint_meta SET committed_generation=?,revision_count=revision_count+1,'
                           'payload_bytes=payload_bytes+? WHERE singleton=1', (generation, size))
                outcome = 'published'
            db.execute("UPDATE joint_registrations SET case_id=?,anchor_fingerprint=?,last_success=?,latest_read_metadata_json=?,"
                       "refresh_state='fresh',fixed_error_code=NULL,last_attempt_cycle=?,last_attempt_at=? WHERE registration_seq=?",
                       (value.case_id, value.anchor_fingerprint, at, value.metadata_json, item.cycle_id, at, item.registration_seq))
            self._finish(db, item, outcome)
            return outcome

    def fail(self, item, fixed_code):
        if type(item) is not WorkItem:
            _error('joint_invalid_request')
        # Constructor validates the fixed allowlist; never persist exception text.
        try:
            error = CaseStoreError(fixed_code)
        except (TypeError, ValueError):
            raise CaseStoreError('joint_invalid_request') from None
        with self._connection(write=True) as db:
            _, outcome = self._pending(db, item)
            if outcome:
                return outcome
            db.execute('UPDATE joint_registrations SET refresh_state=?,fixed_error_code=?,last_attempt_cycle=?,'
                       'last_attempt_at=? WHERE registration_seq=?',
                       ('needs_review' if error.code in ('joint_anchor_mismatch', 'joint_scope_mismatch') else 'unavailable',
                        error.code, item.cycle_id, _now(), item.registration_seq))
            self._finish(db, item, 'failed', error.code)
            return 'failed'

    def get_registration(self, incident_id):
        if type(incident_id) is not str or not _INCIDENT.fullmatch(incident_id):
            _error('joint_invalid_request')
        with self._connection() as db:
            row = db.execute('SELECT * FROM joint_registrations WHERE incident_id=?', (incident_id,)).fetchone()
            if row is None:
                return None
            result = dict(row)
            raw = result.pop('latest_read_metadata_json')
            result['latest_read_metadata'] = json.loads(raw) if raw is not None else None
            return result

    def get_case(self, case_id, revision=None):
        if (type(case_id) is not str or not _CASE.fullmatch(case_id)
                or (revision is not None and (type(revision) is not int or not 1 <= revision <= 2**63-1))):
            _error('joint_invalid_request')
        with self._connection() as db:
            row = db.execute('SELECT v.*,c.current_revision,c.created_generation,c.registration_seq,'
                'r.refresh_state,r.fixed_error_code,r.last_success FROM joint_cases c '
                'JOIN joint_case_revisions v ON v.case_id=c.case_id AND v.revision=coalesce(?,c.current_revision) '
                'JOIN joint_registrations r ON r.registration_seq=c.registration_seq WHERE c.case_id=?',
                (revision, case_id)).fetchone()
            if row is None:
                return None
            result = dict(row)
            result['projection'] = json.loads(result.pop('projection_json'))
            result['first_read_metadata'] = json.loads(result.pop('first_read_metadata_json'))
            result['is_current'] = result['revision'] == result['current_revision']
            result['scope'] = SCOPE
            return result
