"""The existing private management list is visible without granting blanket trust."""
from app.telemetry.control import ControlService
from test_dashboard_control import run_dashboard
from test_live_scoring import activity
from test_manual_control import (
    AUTH, client as client, config as config, control_config as control_config,
    password_hash as password_hash, service as service, transport as transport,
    clock as clock,
)


def test_protected_network_membership_canonicalizes_ipv4_mapped_ipv6_and_keeps_bounds(service):
    for ip in ("192.0.2.1", "192.0.2.15", "::ffff:192.0.2.1", "2001:db8:1::a"):
        assert service.source_context(ip) == {"management_protected": True}
    for ip in ("192.0.2.16", "2001:db8:2::a", "bad", "2001:db8:1::a%eth0", None):
        assert service.source_context(ip) == {"management_protected": False}
    assert ControlService(None, []).source_context("192.0.2.1") == {"management_protected": False}


def test_authenticated_lists_detail_dashboard_cache_and_ip_share_current_protection(client):
    store = client.app.state.store
    _, ack = activity(store, source="server-a", peer="192.0.2.7")
    activity(store, source="server-a", peer="192.0.2.70", offset=1000)
    identity = ack["incident_ids"][0]
    for path in ("/api/incidents", "/api/incidents?page=1", "/api/dashboard"):
        assert client.get(path).status_code == 401
        response = client.get(path, auth=AUTH).json()
        if path == "/api/dashboard":
            response = response["incidents"]
        items = response if isinstance(response, list) else response["items"]
        by_ip = {i["src_ip"]: i for i in items}
        assert by_ip["192.0.2.7"]["source_context"]["management_protected"] is True
        assert by_ip["192.0.2.70"]["source_context"]["management_protected"] is False
        assert by_ip["192.0.2.7"]["assessment"]["score"] == 62, "Real failures are still scored"
        assert "protected_networks" not in str(response)
    detail = client.get("/api/incidents/" + identity, auth=AUTH).json()
    assert detail["source_context"]["management_protected"] is True
    assert detail["severity"] == "high"
    cache = client.app.state.console_cache
    cache.enabled = True
    assert cache.refresh_once()
    result = client.get("/api/console/bootstrap", auth=AUTH).json()
    item = next(i for i in result["data"]["incidents"]["items"] if i["incident_id"] == identity)
    assert item["source_context"] == detail["source_context"]
    for ip in ("192.0.2.7", "::ffff:192.0.2.7"):
        assert client.get("/api/ip-info", params={"ip": ip}).status_code == 401
        value = client.get("/api/ip-info", params={"ip": ip}, auth=AUTH).json()
        assert value["source_context"]["management_protected"] is True


def test_protection_badge_is_consistent_without_changing_scores_or_external_reputation():
    run_dashboard(r"""
const incident={incident_id:'protected',src_ip:'192.0.2.7',source_context:{management_protected:true},assessment:{status:'scored',score:62,priority:'P1',surfaced:true,reasons:[]}};
renderIncidents([incident]);assert.match($('incidents').children[0].children[2].textContent,/管理白名单 · 禁止封禁/);
assert.match($('incidents').textContent,/62 分 · P1/);
renderRecordOverview(incident);assert.match($('detail-fields').textContent,/管理白名单/);
renderIp({ip:'192.0.2.7',source_context:incident.source_context});assert.match($('ip-protection').textContent,/管理白名单/);
renderIp({ip:'192.0.2.70'});assert.equal($('ip-protection').textContent,'');
renderIncidents([{...incident,source_context:{management_protected:false}}]);assert.doesNotMatch($('incidents').textContent,/管理白名单/);
assert.equal(calls.length,0);
""")
