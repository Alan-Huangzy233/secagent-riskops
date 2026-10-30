"""Queue identity checks use only disposable SQLite stores and fake records."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
import sqlite3

import pytest

from app.telemetry.ai_jobs import Jobs


def contents(path):
    # Read-only WAL opens may create normal SHM bookkeeping. Compare logical
    # schema and rows: neither foreign data nor an AI table may change.
    with closing(sqlite3.connect(path)) as db:
        tables = db.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        return {
            name: (schema, db.execute('SELECT * FROM "' + name + '"').fetchall())
            for name, schema in tables
        }


def logical(path):
    with sqlite3.connect(path) as db:
        return {
            table: db.execute(
                "SELECT * FROM "
                + table
                + (" WHERE name!='queue_kind'" if table == "ai_meta" else "")
            ).fetchall()
            for table in ("ai_meta", "ai_jobs", "ai_attempts", "ai_calls", "ai_audit")
        }


def legacy(path, *, version=3):
    jobs = Jobs(path)
    bundle = {
        "case": {
            "dossier_version": version,
            "incident_id": "I-synthetic",
            "revision": "R-synthetic",
        },
        "meta": {"execution_mode": "offline"},
        "local_refs": {},
    }
    jobs.enqueue("synthetic", bundle, "config", "request", "operator")
    jobs.set_budget(100, 20)
    with jobs.connection(write=True) as db:
        db.execute(
            "INSERT INTO ai_calls VALUES('uncertain','2026-01-01',10,NULL,'uncertain',NULL,'timeout')"
        )
        db.execute("DELETE FROM ai_meta WHERE name='queue_kind'")
    return path


@pytest.mark.parametrize("kind", ["ssh", "joint"])
def test_wrong_queue_kind_rejected_without_file_or_data_changes(tmp_path, kind):
    path = tmp_path / "queue.sqlite"
    Jobs(path, queue_kind=kind)
    before = contents(path)
    with pytest.raises(ValueError, match="analysis_queue_kind_mismatch"):
        Jobs(path, queue_kind="joint" if kind == "ssh" else "ssh")
    assert contents(path) == before


def test_legacy_ssh_adoption_preserves_secret_budget_uncertain_call_and_history(
    tmp_path,
):
    path = legacy(tmp_path / "legacy.sqlite")
    before = logical(path)
    jobs = Jobs(path)
    assert logical(path) == before
    assert jobs.budget()["unresolved_calls"] == 1
    assert jobs.budget()["reserved_usd"] == 0.000010
    assert jobs.history(["synthetic"])


def test_joint_never_adopts_unmarked_ssh_even_if_empty(tmp_path):
    path = tmp_path / "legacy.sqlite"
    jobs = Jobs(path)
    with jobs.connection(write=True) as db:
        db.execute("DELETE FROM ai_meta WHERE name='queue_kind'")
    before = contents(path)
    with pytest.raises(ValueError, match="analysis_queue_kind_mismatch"):
        Jobs(path, queue_kind="joint")
    assert contents(path) == before


def test_unknown_legacy_protocol_is_not_assumed_ssh(tmp_path):
    path = legacy(tmp_path / "legacy.sqlite", version="joint-v1")
    before = contents(path)
    with pytest.raises(ValueError, match="analysis_queue_kind_mismatch"):
        Jobs(path)
    assert contents(path) == before


def test_unknown_database_rejected_before_schema_or_wal(tmp_path):
    path = tmp_path / "foreign.sqlite"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE unrelated(secret TEXT)")
        db.execute("INSERT INTO unrelated VALUES('synthetic')")
    path.chmod(0o600)
    before = contents(path)
    with pytest.raises(ValueError, match="analysis_queue_kind_mismatch"):
        Jobs(path, queue_kind="joint")
    assert contents(path) == before


def test_live_handle_checks_kind_before_next_write(tmp_path):
    jobs = Jobs(tmp_path / "queue.sqlite", queue_kind="joint")
    with sqlite3.connect(jobs.path) as db:
        db.execute("UPDATE ai_meta SET value='ssh' WHERE name='queue_kind'")
    before = contents(jobs.path)
    with pytest.raises(ValueError, match="analysis_queue_kind_mismatch"):
        jobs.claim()
    assert contents(jobs.path) == before


def test_competing_queue_initializers_cannot_share_one_file(tmp_path):
    path = tmp_path / "queue.sqlite"

    def create(kind):
        try:
            return Jobs(path, queue_kind=kind).queue_kind
        except (ValueError, sqlite3.OperationalError):
            return None

    with ThreadPoolExecutor(2) as pool:
        outcomes = list(pool.map(create, ("ssh", "joint")))
    assert len([kind for kind in outcomes if kind is not None]) == 1
    with sqlite3.connect(path) as db:
        (kind,) = db.execute(
            "SELECT value FROM ai_meta WHERE name='queue_kind'"
        ).fetchone()
    assert kind in outcomes


def test_legacy_missing_dossier_version_remains_compatible(tmp_path):
    path = legacy(tmp_path / "queue.sqlite")
    with sqlite3.connect(path) as db:
        row = db.execute("SELECT id,dossier_json FROM ai_jobs").fetchone()
        case = json.loads(row[1])
        case.pop("dossier_version")
        db.execute(
            "UPDATE ai_jobs SET dossier_json=? WHERE id=?", (json.dumps(case), row[0])
        )
    assert Jobs(path).history(["synthetic"])


def test_legacy_sqlite_statistics_do_not_disable_existing_ssh_queue(tmp_path):
    path = legacy(tmp_path / "legacy.sqlite")
    with closing(sqlite3.connect(path)) as db:
        db.execute("ANALYZE")
        db.commit()
    before = logical(path)
    restored = Jobs(path)
    assert logical(path) == before and restored.budget()["unresolved_calls"] == 1


@pytest.mark.parametrize("foreign", ["view", "application_id", "user_version"])
@pytest.mark.parametrize("kind", ["ssh", "joint"])
def test_foreign_empty_or_view_only_database_is_not_adopted(tmp_path, foreign, kind):
    path = tmp_path / "foreign.sqlite"
    with closing(sqlite3.connect(path)) as db:
        if foreign == "view":
            db.execute("CREATE VIEW foreign_report AS SELECT 1 AS value")
        else:
            db.execute("PRAGMA " + foreign + "=73")
        db.commit()
    path.chmod(0o600)

    def identity():
        with closing(sqlite3.connect(path)) as db:
            return (
                db.execute(
                    "SELECT type,name,sql FROM sqlite_master ORDER BY type,name"
                ).fetchall(),
                db.execute("PRAGMA application_id").fetchone()[0],
                db.execute("PRAGMA user_version").fetchone()[0],
            )

    before = identity()
    with pytest.raises(ValueError, match="analysis_queue_kind_mismatch"):
        Jobs(path, queue_kind=kind)
    assert identity() == before
