"""Real SQLite error/lock/snapshot behavior; no production source access."""
from contextlib import closing
import sqlite3

import pytest

from app.telemetry.joint_reader_io import EvidenceReadError, ReadBudget, ReadLimits, snapshot


def database(tmp_path):
    path = tmp_path/'source.sqlite'
    with closing(sqlite3.connect(path)) as db:
        db.execute('CREATE TABLE evidence(id INTEGER PRIMARY KEY,value TEXT)')
        db.execute("INSERT INTO evidence VALUES(1,'before')")
        db.commit()
    return path


def test_missing_file_is_not_created_and_error_does_not_leak_path(tmp_path):
    path = tmp_path/'private-location'/'source.sqlite'
    with pytest.raises(EvidenceReadError) as error:
        with snapshot(path, ReadBudget()):
            pytest.fail('missing source opened')
    assert str(error.value) == 'source_unavailable'
    assert not path.parent.exists()


def test_query_only_rejects_accidental_writes_and_cleanup_releases_connection(tmp_path):
    path = database(tmp_path)
    with pytest.raises(EvidenceReadError, match='source_unavailable'):
        with snapshot(path, ReadBudget()) as db:
            assert db.execute('PRAGMA query_only').fetchone()[0] == 1
            db.execute("UPDATE evidence SET value='changed'")
    with closing(sqlite3.connect(path, timeout=.1)) as writer:
        assert writer.execute('SELECT value FROM evidence').fetchone()[0] == 'before'
        writer.execute('BEGIN EXCLUSIVE')
        writer.execute("UPDATE evidence SET value='after'")
        writer.commit()


def test_busy_error_is_distinct_and_does_not_leak_sql(tmp_path):
    path = database(tmp_path)
    with closing(sqlite3.connect(path)) as writer:
        writer.execute('BEGIN EXCLUSIVE')
        with pytest.raises(EvidenceReadError, match='^source_busy$'):
            with snapshot(path, ReadBudget(ReadLimits(lock_wait_seconds=.01))) as reader:
                reader.execute('SELECT * FROM evidence').fetchall()
        writer.rollback()
    with snapshot(path, ReadBudget()) as reader:
        assert reader.execute('SELECT count(*) FROM evidence').fetchone()[0] == 1


def test_one_wal_snapshot_is_stable_and_next_read_observes_writer(tmp_path):
    path = database(tmp_path)
    with closing(sqlite3.connect(path)) as writer:
        writer.execute('PRAGMA journal_mode=WAL')
        with snapshot(path, ReadBudget()) as reader:
            assert reader.execute('SELECT value FROM evidence').fetchone()[0] == 'before'
            writer.execute("UPDATE evidence SET value='after'")
            writer.commit()
            assert reader.execute('SELECT value FROM evidence').fetchone()[0] == 'before'
        with snapshot(path, ReadBudget()) as reader:
            assert reader.execute('SELECT value FROM evidence').fetchone()[0] == 'after'


def test_cooperative_progress_interrupt_and_cleanup(tmp_path):
    path = database(tmp_path)
    elapsed = [0.0]
    budget = ReadBudget(clock=lambda: elapsed[0])
    with pytest.raises(EvidenceReadError, match='^query_deadline_exceeded$'):
        with snapshot(path, budget) as reader:
            elapsed[0] = 6
            reader.execute('WITH RECURSIVE x(n) AS (VALUES(0) UNION ALL SELECT n+1 FROM x WHERE n<100000) SELECT sum(n) FROM x').fetchone()
    assert budget.progress_calls > 0
    with snapshot(path, ReadBudget()) as reader:
        assert reader.execute('SELECT count(*) FROM evidence').fetchone()[0] == 1


def test_budget_is_shared_across_sequential_sources_and_python_work(tmp_path):
    path = database(tmp_path)
    elapsed = [0.0]
    budget = ReadBudget(clock=lambda: elapsed[0])
    with snapshot(path, budget) as reader:
        reader.execute('SELECT * FROM evidence').fetchall()
        elapsed[0] = 4
    elapsed[0] = 6
    with pytest.raises(EvidenceReadError, match='query_deadline_exceeded'):
        with snapshot(path, budget):
            pytest.fail('budget reset for second source')
    budget = ReadBudget(ReadLimits(byte_limit=10))
    budget.consume_bytes(6)
    with pytest.raises(EvidenceReadError, match='adapter_limit_exceeded'):
        budget.consume_bytes(5)


@pytest.mark.parametrize('sql,code', [('SELECT * FROM absent', 'source_schema_unavailable'),
                                    ("SELECT json_extract('bad-json','$.field')", 'evidence_invalid')])
def test_schema_and_json_errors_are_fixed_codes(tmp_path, sql, code):
    with pytest.raises(EvidenceReadError, match='^'+code+'$'):
        with snapshot(database(tmp_path), ReadBudget()) as reader:
            reader.execute(sql).fetchall()


@pytest.mark.parametrize('options', [{'record_limit':5001}, {'candidate_limit':201},
    {'deadline_seconds':float('nan')}, {'deadline_seconds':6}, {'deadline_seconds':True},
    {'lock_wait_seconds':1}, {'batch_size':201}, {'byte_limit':0},
    {'deadline_seconds':10**1000}, {'lock_wait_seconds':10**1000}])
def test_callers_can_only_lower_resource_limits(options):
    with pytest.raises(EvidenceReadError, match='adapter_invalid_request'):
        ReadLimits(**options)


def test_malformed_unicode_path_uses_fixed_code():
    with pytest.raises(EvidenceReadError, match='^adapter_invalid_request$'):
        with snapshot('/private/\ud800.sqlite', ReadBudget()):
            pytest.fail('invalid path opened')


def test_busy_after_budget_expires_is_deadline_not_false_available_result(tmp_path):
    path = database(tmp_path)
    elapsed = [0.0]
    budget = ReadBudget(ReadLimits(lock_wait_seconds=.01), clock=lambda: elapsed[0])
    with closing(sqlite3.connect(path)) as writer:
        writer.execute('BEGIN EXCLUSIVE')
        with pytest.raises(EvidenceReadError, match='^query_deadline_exceeded$'):
            with snapshot(path, budget) as reader:
                elapsed[0] = 6
                reader.execute('SELECT * FROM evidence').fetchall()
        writer.rollback()
