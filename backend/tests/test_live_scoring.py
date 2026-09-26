"""Live scores use retained evidence and never suppress operator work."""
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path

import pytest

from app.reduction.score import assess
from app.telemetry import scoring
from app.telemetry import store as module
from app.telemetry.store import TelemetryStore
from test_dashboard_control import run_dashboard
from test_live_api import client, config, password_hash, PASSWORD  # noqa: F401

NOW = datetime(2026, 9, 20, 12, tzinfo=timezone.utc)


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "_now", lambda: NOW)
    return TelemetryStore(tmp_path / "live.sqlite")


def activity(store, *, source="source-a", peer="198.51.100.7", offset=0, count=4,
             user="amara", success=True, invalid=False):
    start = NOW - timedelta(hours=2) + timedelta(seconds=offset)
    rows = [{"event_id": f"{offset}-{n}", "timestamp": (start + timedelta(seconds=n * 10)).isoformat(),
             "identifier": "sshd", "message": f"Failed password for {'invalid user ' if invalid else ''}{user} from {peer} port 42000 ssh2"}
            for n in range(count)]
    if success:
        rows.append({"event_id": f"{offset}-success", "timestamp": (start + timedelta(seconds=count * 10)).isoformat(),
                     "identifier": "sshd", "message": f"Accepted publickey for {user} from {peer} port 42000 ssh2"})
    return rows, store.ingest(source, source, f"batch-{offset}", rows)


def test_scores_full_evidence_and_replay_does_not_inflate_it(store, monkeypatch):
    rows, ack = activity(store, count=60)
    item, = store.list_incidents()
    assessment = item["assessment"]
    assert assessment["score"] == 67 and assessment["priority"] == "P1"
    assert item["evidence_count"] == 61 and len(item["evidence_snapshots"]) == 20
    assert any("succeeded" in reason for reason in assessment["reasons"])
    assert store.ingest("source-a", "source-a", "batch-0", rows)["accepted"] == 0
    assert store.ingest("source-a", "source-a", "another-batch", rows)["accepted"] == 0
    assert store.get_incident(ack["incident_ids"][0])["assessment"] == assessment
    assert store.triage_counts()["pending"] == 1
    monkeypatch.setattr(module, "_now", lambda: NOW + timedelta(days=15))
    store.cleanup()
    assert not store.list_events()
    assert TelemetryStore(store.path).list_incidents()[0]["assessment"] == assessment
    # Scoring from retained evidence also survives an explicit projection rebuild.
    with store._connection(write=True) as db:
        db.execute("DELETE FROM incident_scores")
    assert store.backfill_scores()["scored"] == 1
    assert store.list_incidents()[0]["assessment"] == assessment


def test_invalid_user_messages_do_not_invent_existing_accounts(store):
    activity(store, invalid=True, success=False)
    assert store.list_incidents()[0]["assessment"]["score"] == 0
    assert store.paginate_incidents(focus="low")["total"] == 1
    assert store.paginate_incidents(focus="attention")["total"] == 0
    assert store.triage_counts()["pending"] == 1


def test_known_login_never_discounts_production_success(store):
    at = NOW - timedelta(hours=5)
    store.ingest("source-a", "source-a", "prior", [{"event_id": "prior", "timestamp": at.isoformat(),
        "identifier": "sshd", "message": "Accepted publickey for amara from 198.51.100.7 port 42000 ssh2"}])
    activity(store)
    item, = store.list_incidents()
    assert item["assessment"]["score"] == 62
    assert item["assessment"]["known_source_discount"] is False


def test_cross_source_duplicate_ids_have_distinct_evidence_and_shared_score(store):
    activity(store, source="source-a", count=3, success=False)
    activity(store, source="source-b", count=3, success=False)
    item, = store.list_incidents()
    assert item["evidence_count"] == 6
    assert item["assessment"]["score"] == 22  # existing account + two hosts
    for source in ("source-a", "source-b"):
        assert store.paginate_incidents(source)["items"][0]["assessment"] == item["assessment"]
        assert store.paginate_incidents(source)["score_counts"]["total"] == 1


def test_scoring_matches_shared_model_on_complete_valid_evidence(store):
    activity(store, count=60)
    item, = store.list_incidents()
    evidence = store.paginate_incident_evidence(item["incident_id"])["items"]
    expected = assess(evidence, {})
    assert item["assessment"]["score"] == expected.score
    assert item["assessment"]["reasons"] == list(expected.reasons)


def test_legacy_scores_backfill_bounded_and_unknown_stays_visible(store, monkeypatch):
    activity(store, peer="198.51.100.7", offset=0)
    activity(store, peer="198.51.100.8", offset=1000, success=False, invalid=True)
    before = store.list_incidents()
    with store._connection(write=True) as db:
        db.execute("DROP TABLE incident_scores")
    restarted = TelemetryStore(store.path)
    assert all(x["assessment"]["status"] == "unscored" for x in restarted.list_incidents())
    assert restarted.paginate_incidents(focus="attention")["total"] == 2
    assert restarted.backfill_scores(1)["scored"] == 1
    assert restarted.paginate_incidents(focus="unscored")["total"] == 1
    assert restarted.backfill_scores(1)["scored"] == 1
    assert restarted.backfill_scores(1)["scored"] == 0
    assert restarted.list_incidents() == before
    # Read APIs must not compute scores or scan evidence to construct scores.
    monkeypatch.setattr(scoring, "refresh", lambda *a: pytest.fail("GET scored evidence"))
    page = restarted.paginate_incidents(limit=1, sort="score")
    assert page["items"][0]["assessment"]["score"] == 62
    assert page["score_counts"] == {"attention": 1, "low": 1, "unscored": 0, "total": 2}
    assert restarted.paginate_incidents(limit=1, sort="score", page=2)["items"][0]["assessment"]["score"] == 0
    with pytest.raises(ValueError):
        restarted.paginate_incidents(sort="score; DROP TABLE incidents")
    with pytest.raises(ValueError):
        restarted.paginate_incidents(focus="bad")


def test_stale_projection_is_unknown_after_old_writer_changes_evidence(store):
    activity(store)
    with store._connection(write=True) as db:
        db.execute("UPDATE incident_scores SET evidence_count=evidence_count-1")
    assert store.list_incidents()[0]["assessment"]["status"] == "unscored"
    assert store.paginate_incidents(focus="attention")["total"] == 1
    assert store.backfill_scores()["scored"] == 1
    assert store.list_incidents()[0]["assessment"]["score"] == 62


def test_score_failure_rolls_back_batch_evidence_and_receipts(store, monkeypatch):
    def fail(*args):
        raise RuntimeError("scoring failure")
    monkeypatch.setattr(scoring, "refresh", fail)
    with pytest.raises(RuntimeError):
        activity(store)
    assert store.count_incidents() == 0 and store.list_events() == []
    with store._connection() as db:
        assert db.execute("SELECT count(*) FROM batches").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM event_receipts").fetchone()[0] == 0


def test_score_filters_on_api_and_dashboard_keep_authentication(client):  # noqa: F811
    activity(client.app.state.store, source="server-a")
    auth = ("operator", PASSWORD)
    for path in ("/api/incidents?page=1&sort=score&focus=attention",
                 "/api/dashboard?incident_sort=score&incident_focus=attention"):
        assert client.get(path).status_code == 401
        result = client.get(path, auth=auth)
        assert result.status_code == 200
        page = result.json().get("incidents", result.json())
        assert page["items"][0]["assessment"]["score"] == 62
        assert page["focus"] == "attention" and page["sort"] == "score"
    for path in ("/api/incidents?sort=bad", "/api/incidents?focus=bad", "/api/dashboard?incident_focus=bad"):
        assert client.get(path, auth=auth).status_code == 422


def test_backfill_command_is_read_only_by_default(store):
    path = Path(__file__).resolve().parents[2] / "scripts" / "backfill_incident_scores.py"
    spec = importlib.util.spec_from_file_location("backfill_incident_scores", path)
    command = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(command)
    activity(store)
    with store._connection(write=True) as db:
        db.execute("DROP TABLE incident_scores")
    assert command.run(Path(store.path))["unscored"] == 1
    with store._connection() as db:
        assert not db.execute("SELECT 1 FROM sqlite_master WHERE name='incident_scores'").fetchone()
    result = command.run(Path(store.path), apply=True, limit=1)
    assert result["batch"]["scored"] == 1
    assert command.run(Path(store.path))["unscored"] == 0


def test_dashboard_renders_reasons_and_maintains_filter_identity():
    run_dashboard(r"""
const incident={incident_id:'test',src_ip:'198.51.100.7',assessment:{status:'scored',score:62,priority:'P1',surfaced:true,reasons:['+50 login succeeded after failed attempts','+12 attempts against 1 existing non-root account(s)','<img onerror=alert(1)>']}};
renderIncidents([incident]);
const cell=$('incidents').children[0].children[4];
assert.match(cell.textContent,/62 分 · P1/);assert.match(cell.textContent,/多次失败后登录成功/);assert.match(cell.textContent,/1 个非 root 有效账号/);
assert.match(cell.textContent,/<img onerror=alert\(1\)>/);
assert.equal(incidentSort,'score');assert.equal(incidentFocus,'all');
const before=listKey('incident');incidentFocus='attention';assert.notEqual(listKey('incident'),before);
assert.equal(sourceQuery(1,'source-a').get('focus'),'attention');assert.equal(sourceQuery(1,'source-a').get('sort'),'score');
renderScoreCounts({attention:2,low:9,unscored:1,total:12});assert.match($('incident-score-counts').textContent,/低分 9 · 未评分 1/);
renderIncidents([{...incident,assessment:{status:'unscored'}}]);assert.match($('incidents').textContent,/尚未评分/);
""")


def test_new_success_promotes_low_score_without_resetting_operator_decision(store):
    _, ack = activity(store, success=False)
    identity = ack['incident_ids'][0]
    store.set_triage([identity], 'acknowledged', actor='operator')
    assert store.get_incident(identity)['assessment']['score'] == 12
    store.ingest('source-a', 'source-a', 'new-success', [{
        'event_id': 'success', 'timestamp': (NOW - timedelta(hours=2) + timedelta(seconds=50)).isoformat(),
        'identifier': 'sshd', 'message': 'Accepted publickey for amara from 198.51.100.7 port 42000 ssh2'}])
    item = store.get_incident(identity)
    assert item['assessment']['score'] == 62 and item['triage_status'] == 'acknowledged'
    assert store.paginate_incidents(focus='low')['total'] == 0
    assert store.paginate_incidents(triage='pending')['score_counts']['total'] == 0


def test_merged_alias_uses_combined_score_and_counts_once(store):
    from test_incident_triage import bridge, two_incidents_one_peer
    from unittest.mock import patch
    # Their source timestamps are before this fixture's clock; deterministic and valid.
    survivor, absorbed = two_incidents_one_peer(store)
    with patch.object(module, '_now', lambda: NOW):
        bridge(store)
    canonical = store.get_incident(survivor)
    assert store.get_incident(absorbed)['assessment'] == canonical['assessment']
    assert store.paginate_incidents()['score_counts']['total'] == 1


def test_unknown_version_is_never_filtered_as_low(store):
    activity(store, success=False)
    with store._connection(write=True) as db:
        db.execute("UPDATE incident_scores SET version='previous-version'")
    assert store.paginate_incidents(focus='low')['total'] == 0
    page = store.paginate_incidents(focus='attention')
    assert page['total'] == 1 and page['items'][0]['assessment']['score'] is None
    assert store.backfill_scores()['scored'] == 1


def test_old_parser_edit_invalidates_same_count_projection(store):
    import json
    activity(store, success=False)
    item, = store.list_incidents()
    assert item['assessment']['score'] == 12
    with store._connection(write=True) as db:
        row = db.execute('SELECT source_id,event_id,snapshot_json FROM incident_evidence LIMIT 1').fetchone()
        value = json.loads(row['snapshot_json'])
        value['event_type'] = 'invalid_user'
        db.execute('UPDATE incident_evidence SET snapshot_json=? WHERE source_id=? AND event_id=?',
                   (json.dumps(value), row['source_id'], row['event_id']))
    assert store.paginate_incidents(focus='unscored')['total'] == 1
    assert store.get_incident(item['incident_id'])['assessment']['score'] is None
    assert store.backfill_scores()['scored'] == 1
    assert store.get_incident(item['incident_id'])['assessment']['score'] == 0
