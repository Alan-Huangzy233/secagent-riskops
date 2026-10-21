"""Continuous network analysis: durable bounds, provenance and exact history."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager

import pytest

from app.telemetry import network_incidents as analysis, network_store
from app.telemetry.network_protocol import event_to_dict, journal_entry
from app.telemetry.network_store import NetworkStore, NetworkStoreError
from test_network_detection import event, journal, profile, REALTIME_US


NOW = REALTIME_US / 1_000_000 + 100
DAY = 86400


def payload(index, events, *, before=None, source_profile=None, reports=None, caught_up=True):
    current = source_profile or profile()
    entries = [{"event": event_to_dict(item)} for item in events]
    return {"version": 1, "source_id": current.source_id, "profile_revision": current.revision,
            "batch_id": f"analysis-batch-{index}", "collected_at_us": int(NOW * 1_000_000),
            "cursor_before": before,
            "cursor_after": entries[-1]["event"]["journal_cursor"] if entries else before,
            "entries": entries, "reports": reports or [], "caught_up": caught_up}


def deliver(store, index, events, **kwargs):
    previous = next((row for row in store.sources() if row["source_id"] == kwargs.get("source_profile", profile()).source_id), None)
    batch = payload(index, events, before=previous["checkpoint"] if previous else None, **kwargs)
    store.ingest(batch, kwargs.get("source_profile", profile()), now_us=int(NOW * 1_000_000))
    return batch


def drain(store, now=NOW, **kwargs):
    for _ in range(30):
        result = analysis.process(store, now, **kwargs)
        if result["caught_up"]:
            return result
    raise AssertionError("bounded analysis did not catch up")


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(network_store, "_now_us", lambda: int(NOW * 1_000_000))
    return NetworkStore(tmp_path / "network.sqlite3")


def test_split_threshold_late_arrival_keeps_identity_and_historical_evidence(store):
    first = deliver(store, 1, [event(index) for index in range(6)])
    drain(store)
    assert store.incidents()["total"] == 0
    deliver(store, 2, [event(index) for index in range(6, 10)])
    drain(store)
    original, = store.incidents()["items"]
    assert original["revision"] == 1 and original["assessment"]["score"] == 35
    assert original["stale"] is False
    assert "logging_rate_limited" in original["coverage"]
    assert "offline_context_only" not in original["coverage"]
    original_evidence = store.evidence(original["incident_id"], revision=1)["items"]
    assert len(original_evidence) == 10
    deliver(store, 3, [event(20, offset_us=5_500_000)])
    drain(store)
    updated = store.incident(original["incident_id"])
    assert updated["revision"] == 2 and updated["evidence_count"] == 11
    assert updated["assessment"]["score"] == 35
    assert store.incident(original["incident_id"], 1) == original
    assert store.evidence(original["incident_id"], revision=1)["items"] == original_evidence
    assert store.evidence(original["incident_id"], revision=2, limit=4)["total_pages"] == 3
    reopened = NetworkStore(store.path)
    reopened.ingest(first, profile(), now_us=int(NOW * 1_000_000))
    drain(reopened)
    assert reopened.incident(original["incident_id"]) == updated
    assert reopened.analysis_status()["analyzed_input_records"] == 11
    with reopened.connection() as db:
        notice, = db.execute("SELECT * FROM network_notice_outbox").fetchall()
        assert notice["revision"] == 2 and notice["cancelled"] == 0


@pytest.mark.parametrize("change", ["boot", "profile", "source", "destination", "peer"])
def test_different_provenance_never_supplies_missing_threshold(store, change):
    deliver(store, 1, [event(index) for index in range(6)])
    custom = profile()
    options = {}
    if change == "boot":
        options["boot_id"] = "2" * 32
    elif change == "profile":
        custom = profile(ruleset_sha256="b" * 64)
    elif change == "source":
        custom = profile(source_id="sensor-b")
    elif change == "destination":
        options["dst_ip"] = "192.0.2.11"
    else:
        options["src_ip"] = "198.51.100.43"
    deliver(store, 2, [event(index, source_profile=custom, **options) for index in range(6, 10)],
            source_profile=custom)
    drain(store)
    assert store.incidents()["total"] == 0


def test_monotonic_hour_boundary_and_wall_clock_jump_keep_threshold(store):
    records = [event(index, offset_us=3_595_000_000 + index * 1_000_000,
                     realtime_offset_us=index * 1_000_000 if index < 5 else -600_000_000 + index * 1_000_000)
               for index in range(10)]
    deliver(store, 1, records)
    drain(store)
    cases = store.incidents()["items"]
    assert len(cases) == 2  # Review buckets can share boundary evidence.
    assert {case["window_start_monotonic_us"] for case in cases} == {0, analysis.HOUR_US}
    assert all(case["evidence_count"] == 10 and "journal_clock_discontinuity" in case["coverage"] for case in cases)
    assert all(case["assessment"]["score"] == 35 for case in cases)


def test_low_monotonic_boundary_creates_no_negative_bucket_and_udp_does_not_alert(store):
    deliver(store, 1, [event(index, protocol="UDP") for index in range(12)])
    drain(store)
    assert store.incidents()["total"] == 0
    with store.connection() as db:
        assert [row[0] for row in db.execute("SELECT monotonic_hour_us FROM network_windows")] == [0]


def test_partial_intake_never_recomputes_from_incomplete_new_batch(store):
    deliver(store, 1, [event(index) for index in range(10)])
    result = analysis.process(store, NOW, intake_limit=5)
    assert result["caught_up"] is False and result["windows_processed"] == 0
    assert store.incidents()["total"] == 0 and store.analysis_status()["pending"]
    drain(store, intake_limit=5)
    assert store.incidents()["items"][0]["evidence_count"] == 10


def test_overflow_preserves_old_score_and_evidence_visibly_stale(store, monkeypatch):
    deliver(store, 1, [event(index) for index in range(10)])
    drain(store)
    old = store.incidents()["items"][0]
    deliver(store, 2, [event(11)])
    monkeypatch.setattr(analysis, "MAX_CONTEXT_RECORDS", 10)
    drain(store)
    current = store.incident(old["incident_id"])
    assert current["stale"] and current["assessment"] == old["assessment"]
    assert current["evidence_sha256"] == old["evidence_sha256"]
    assert current["revision"] == 2 and "context_limit" in current["coverage"]
    assert store.evidence(old["incident_id"])["total"] == 10
    assert store.incidents(focus="stale")["total"] == 1
    assert store.analysis_status()["coverage_issues"][0]["coverage"]
    with store.connection() as db:
        assert db.execute("SELECT cancelled FROM network_notice_outbox").fetchone()[0] == 1
    monkeypatch.setattr(analysis, "MAX_CONTEXT_RECORDS", 5000)
    deliver(store, 3, [event(12)])
    drain(store)
    assert store.incident(old["incident_id"])["stale"] is False
    assert store.incident(old["incident_id"])["evidence_count"] == 12


def test_new_overflow_reports_unknown_without_empty_safe_case(store, monkeypatch):
    deliver(store, 1, [event(index) for index in range(10)])
    monkeypatch.setattr(analysis, "MAX_CONTEXT_BYTES", 1)
    drain(store)
    assert store.incidents()["total"] == 0
    assert "context_limit" in store.analysis_status()["coverage_issues"][0]["coverage"]


def test_empty_gap_report_and_rejection_persist_after_clean_heartbeat_and_restart(store):
    deliver(store, 1, [], reports=["journal_cursor_unavailable"], caught_up=False)
    rejected = journal_entry({**journal(7), "MESSAGE": "authored invalid record"}, profile())
    batch = payload(2, [])
    batch.update(entries=[rejected], cursor_after=rejected["rejection"]["journal_cursor"])
    store.ingest(batch, profile(), now_us=int(NOW * 1_000_000))
    deliver(store, 3, [])
    drain(store)
    reopened = NetworkStore(store.path)
    source, = reopened.analysis_status()["source_coverage"]
    assert {"journal_cursor_unavailable", "collection_backlog_observed", "rejected_records", "invalid_record"} <= set(source["coverage"])
    assert source["last_report"]["caught_up"] and source["last_report"]["reports"] == []
    assert reopened.incidents()["total"] == 0


def test_missing_raw_before_analysis_is_scoped_to_boot_and_retains_uncertainty(store):
    deliver(store, 1, [event(index) for index in range(10)])
    missing = event(0)
    with store.write_connection() as db:
        db.execute("DELETE FROM network_events WHERE event_id=?", (missing.event_id,))
    deliver(store, 2, [event(index, boot_id="2" * 32) for index in range(10)])
    drain(store)
    cases = store.incidents()["items"]
    assert len(cases) == 1 and cases[0]["boot_id"] == "2" * 32
    assert store.analysis_status()["missing_raw_records"] == 1
    issue, = store.analysis_status()["coverage_issues"]
    assert issue["boot_id"] == "1" * 32 and "raw_history_expired_before_analysis" in issue["coverage"]


def test_expired_context_does_not_delete_exact_case_history_or_reset_score(store):
    deliver(store, 1, [event(index) for index in range(10)])
    drain(store)
    original = store.incidents()["items"][0]
    original_evidence = store.evidence(original["incident_id"])["items"]
    drain(store, NOW + 15 * DAY)
    current = store.incident(original["incident_id"])
    assert current["stale"] and current["assessment"] == original["assessment"]
    assert "expired_context" in current["coverage"]
    assert store.incident(original["incident_id"], 1) == original
    assert store.evidence(original["incident_id"], revision=1)["items"] == original_evidence
    assert store.evidence(original["incident_id"])["items"] == original_evidence
    with store.connection() as db:
        assert db.execute("SELECT count(*) FROM network_context").fetchone()[0] == 0


def test_failure_rolls_back_cursor_context_and_analysis_state(store, monkeypatch):
    deliver(store, 1, [event(index) for index in range(10)])
    original = analysis._dirty
    def fail(*args):
        original(*args)
        raise RuntimeError("injected interruption")
    monkeypatch.setattr(analysis, "_dirty", fail)
    with pytest.raises(RuntimeError, match="injected interruption"):
        analysis.process(store, NOW)
    assert store.analysis_status()["analyzed_input_records"] == 0
    with store.connection() as db:
        assert db.execute("SELECT count(*) FROM network_context").fetchone()[0] == 0
    monkeypatch.setattr(analysis, "_dirty", original)
    drain(NetworkStore(store.path))
    assert store.incidents()["total"] == 1


def test_revision_and_outbox_rollback_with_analysis_failure(store, monkeypatch):
    deliver(store, 1, [event(index) for index in range(10)])
    original = analysis._save_case
    def fail(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("injected after revision")
    monkeypatch.setattr(analysis, "_save_case", fail)
    with pytest.raises(RuntimeError, match="injected after revision"):
        analysis.process(store, NOW)
    with store.connection() as db:
        for table in ("network_incidents", "network_incident_revisions", "network_evidence", "network_notice_outbox"):
            assert db.execute("SELECT count(*) FROM " + table).fetchone()[0] == 0
    monkeypatch.setattr(analysis, "_save_case", original)
    drain(store)
    assert store.incidents()["items"][0]["revision"] == 1


def test_physical_quota_failure_leaves_no_partial_analysis_and_receipt_replay_works(store, monkeypatch):
    batch = deliver(store, 1, [event(index) for index in range(10)])
    ack = store.ingest(batch, profile(), now_us=int(NOW * 1_000_000))
    def full(_):
        raise NetworkStoreError("storage_capacity_exceeded")
    monkeypatch.setattr(store, "_page_limit", full)
    with pytest.raises(NetworkStoreError, match="storage_capacity_exceeded"):
        analysis.process(store, NOW)
    assert store.analysis_status()["analyzed_input_records"] == 0
    assert store.ingest(batch, profile(), now_us=0) == ack


def v1_database(path):
    db = sqlite3.connect(path)
    db.executescript(network_store._SCHEMA)
    db.execute("INSERT INTO network_meta VALUES('schema_version','1')")
    db.execute(f"PRAGMA application_id={network_store.APPLICATION_ID}")
    db.execute("PRAGMA user_version=1")
    db.commit()
    db.close()


def test_strict_v1_migration_is_atomic_and_preserves_existing_tables(tmp_path, monkeypatch):
    path = tmp_path / "v1.sqlite3"
    v1_database(path)
    original = analysis.initialize
    def fail(db):
        original(db)
        raise RuntimeError("injected during migration")
    monkeypatch.setattr(analysis, "initialize", fail)
    with pytest.raises(RuntimeError, match="during migration"):
        NetworkStore(path)
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
        assert db.execute("SELECT value FROM network_meta WHERE key='schema_version'").fetchone()[0] == "1"
        assert db.execute("SELECT count(*) FROM sqlite_master WHERE name='network_context'").fetchone()[0] == 0
    monkeypatch.setattr(analysis, "initialize", original)
    store = NetworkStore(path)
    assert store.status()["schema_version"] == 2 and store.healthcheck()
    assert NetworkStore(path).analysis_status()["analyzed_input_records"] == 0


def test_modified_v1_schema_is_rejected_without_partial_upgrade(tmp_path):
    path = tmp_path / "v1.sqlite3"
    v1_database(path)
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE unexpected(value)")
    with pytest.raises(NetworkStoreError, match="network_store_schema_mismatch"):
        NetworkStore(path)
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM sqlite_master WHERE name='network_context'").fetchone()[0] == 0


def test_extreme_monotonic_and_realtime_values_do_not_crash_processing(store):
    records = [event(index, offset_us=2**63 - 1 - 1_000_000 - 9 + index,
                     realtime_offset_us=253402300799999999 - REALTIME_US - 9 + index)
               for index in range(10)]
    deliver(store, 1, records)
    drain(store)
    case, = store.incidents()["items"]
    assert case["last_seen"] == "9999-12-31T23:59:59.999999Z"
    assert case["window_end_monotonic_us"] == 2**63 - 1


@pytest.mark.parametrize("kwargs", [{"page": 0}, {"page": True}, {"limit": 201}, {"focus": "invalid"}])
def test_invalid_case_pagination_is_rejected(store, kwargs):
    with pytest.raises(ValueError):
        store.incidents(**kwargs)


@pytest.mark.parametrize('change', ['index', 'primary_key'])
def test_same_named_foreign_schema_is_not_migration_eligible(tmp_path, change):
    path = tmp_path / 'foreign.sqlite3'
    if change == 'index':
        v1_database(path)
        with sqlite3.connect(path) as db:
            db.execute('DROP INDEX network_events_source')
            db.execute('CREATE INDEX network_events_source ON network_events(event_id,seq)')
    else:
        with sqlite3.connect(path) as db:
            db.executescript(network_store._SCHEMA.replace('key TEXT PRIMARY KEY, value TEXT NOT NULL',
                                                          'key TEXT, value TEXT NOT NULL'))
            db.execute("INSERT INTO network_meta VALUES('schema_version','1')")
            db.execute(f'PRAGMA application_id={network_store.APPLICATION_ID}')
            db.execute('PRAGMA user_version=1')
    with pytest.raises(NetworkStoreError, match='network_store_schema_mismatch'):
        NetworkStore(path)
    with sqlite3.connect(path) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM sqlite_master WHERE name='network_context'").fetchone()[0] == 0


def test_migration_refuses_second_wal_transaction_after_checkpoint_race(tmp_path, monkeypatch):
    path = tmp_path / 'v1.sqlite3'
    v1_database(path)
    original = NetworkStore._disk_usage
    calls = 0
    def competing_writer(store):
        nonlocal calls
        calls += 1
        usage = original(store)
        return {**usage, 'wal': 64} if calls == 2 else usage
    monkeypatch.setattr(NetworkStore, '_disk_usage', competing_writer)
    with pytest.raises(NetworkStoreError, match='network_storage_busy'):
        NetworkStore(path)
    with sqlite3.connect(path) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM sqlite_master WHERE name='network_context'").fetchone()[0] == 0


def test_pinned_wal_reader_stops_analysis_then_resumes_without_duplicate_cases(store, monkeypatch):
    checkpoint = store._checkpoint
    def bounded_checkpoint(db):
        db.execute('PRAGMA busy_timeout=20')
        return checkpoint(db)
    monkeypatch.setattr(store, '_checkpoint', bounded_checkpoint)
    reader = sqlite3.connect(store.path, isolation_level=None)
    try:
        reader.execute('BEGIN')
        reader.execute('SELECT count(*) FROM network_events').fetchone()
        batch = deliver(store, 1, [event(index) for index in range(10)])
        ack = store.ingest(batch, profile(), now_us=int(NOW * 1_000_000))
        assert store.status()['wal_bytes'] > 0
        with pytest.raises(NetworkStoreError, match='network_storage_busy'):
            analysis.process(store, NOW)
        assert store.analysis_status()['analyzed_input_records'] == 0
        assert store.ingest(batch, profile(), now_us=0) == ack
        reader.rollback()
        drain(store)
        case, = store.incidents()['items']
        assert case['revision'] == 1 and case['evidence_count'] == 10
    finally:
        reader.close()


def test_finite_barrier_analyzes_accepted_snapshot_despite_new_arrivals_and_restart(store):
    deliver(store, 1, [event(index) for index in range(10)])
    result = analysis.process(store, NOW, intake_limit=3, window_limit=1)
    assert not result['caught_up'] and result['windows_processed'] == 0
    with store.connection() as db:
        assert analysis.meta(db, 'intake_targets') == [10, 1]
    for batch_index in range(2, 5):
        deliver(store, batch_index, [event(20 + batch_index)])
        store = NetworkStore(store.path)
        result = analysis.process(store, NOW, intake_limit=3, window_limit=1)
        assert not result['caught_up'] and store.analysis_status()['pending']
        with store.connection() as db:
            assert analysis.meta(db, 'intake_targets') == [10, 1]
    case, = store.incidents()['items']
    assert case['evidence_count'] == 10 and case['revision'] == 1
    assert store.analysis_status()['analyzed_input_records'] == 10
    drain(store, intake_limit=3, window_limit=1)
    current = store.incident(case['incident_id'])
    assert current['evidence_count'] == 13 and current['revision'] == 2
    assert store.evidence(case['incident_id'], revision=1)['total'] == 10
    assert store.analysis_status()['pending'] is False
    with store.connection() as db:
        assert analysis.meta(db, 'intake_targets') == [13, 4]


def test_finite_barrier_drains_bounded_windows_before_starting_next_snapshot(store):
    deliver(store, 1, [event(index) for index in range(10)] +
            [event(index + 20, src_ip='198.51.100.43') for index in range(10)])
    result = analysis.process(store, NOW, window_limit=1)
    assert result == {'caught_up': False, 'windows_processed': 1}
    assert store.incidents()['total'] == 1
    deliver(store, 2, [event(40)])
    reopened = NetworkStore(store.path)
    result = analysis.process(reopened, NOW, window_limit=1)
    assert result == {'caught_up': False, 'windows_processed': 1}
    assert reopened.incidents()['total'] == 2
    assert reopened.analysis_status()['analyzed_input_records'] == 20
    assert reopened.analysis_status()['pending']
    with reopened.connection() as db:
        assert analysis.meta(db, 'intake_targets') == [20, 1]
    drain(reopened, window_limit=1)
    assert reopened.analysis_status()['analyzed_input_records'] == 21
    assert reopened.analysis_status()['pending'] is False


def test_other_process_starting_partial_cycle_cannot_be_analyzed_by_old_loop(store, monkeypatch):
    deliver(store, 1, [event(index) for index in range(10)])
    connection = store.write_connection
    committed = 0
    @contextmanager
    def interleave():
        nonlocal committed
        with connection() as db:
            yield db
        committed += 1
        if committed == 2:
            other = NetworkStore(store.path)
            deliver(other, 2, [event(index) for index in range(20, 30)])
            result = analysis.process(other, NOW, intake_limit=3, window_limit=1)
            assert result['caught_up'] is False and result['windows_processed'] == 0
    monkeypatch.setattr(store, 'write_connection', interleave)
    result = analysis.process(store, NOW, window_limit=5)
    assert result == {'caught_up': False, 'windows_processed': 1}
    case, = store.incidents()['items']
    assert case['revision'] == 1 and case['evidence_count'] == 10
    assert store.analysis_status()['analyzed_input_records'] == 13
    drain(store)
    current = store.incident(case['incident_id'])
    assert current['revision'] == 2 and current['evidence_count'] == 20
