from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
from html.parser import HTMLParser

import pytest

from app.telemetry.dashboard import CONTENT_SECURITY_POLICY, DASHBOARD_HTML, _SCRIPT


class IncidentTable(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_section = False
        self.in_header = False
        self.headers: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "section" and dict(attrs).get("id") == "incident-section":
            self.in_section = True
        if self.in_section and tag == "th":
            self.in_header = True

    def handle_endtag(self, tag):
        if tag == "section":
            self.in_section = False
        if tag == "th":
            self.in_header = False

    def handle_data(self, data):
        if self.in_header:
            self.headers.append(data)


def test_detection_table_has_rules_sources_and_record_count_explanation():
    table = IncidentTable()
    table.feed(DASHBOARD_HTML)
    assert table.headers == ["最近发生", "关联服务器 / 来源", "来源 IP", "日志 / 账号统计", "命中规则", "状态"]
    assert "不等于独立连接或攻击次数" in DASHBOARD_HTML
    assert "不会自动封禁" in DASHBOARD_HTML
    for field in ("source_ids", "hostnames", "rules", "success_count", "username_count", "usernames"):
        assert f"incident.{field}" in _SCRIPT
    for rule in ("burst", "slow_scan", "multi_account", "cross_source", "success_after_failures"):
        assert rule in _SCRIPT


def test_detection_dashboard_preserves_text_only_rendering_and_csp():
    assert "innerHTML" not in _SCRIPT
    assert "outerHTML" not in _SCRIPT
    assert "insertAdjacentHTML" not in _SCRIPT
    assert "document.write" not in _SCRIPT
    assert "td.textContent=String(value??'—')" in _SCRIPT
    digest = base64.b64encode(hashlib.sha256(_SCRIPT.encode()).digest()).decode()
    assert f"'sha256-{digest}'" in CONTENT_SECURITY_POLICY


@pytest.mark.skipif(shutil.which("node") is None, reason="Node is optional for the dashboard rendering check")
def test_rendered_incidents_keep_all_sources_legacy_rows_and_untrusted_text():
    # Execute the actual shipped script with a minimal inert DOM. No browser,
    # network request, or collector credentials are needed for this regression.
    hostile_name = '<img src=x onerror="throw new Error(1)">'
    records = [
        {
            "source_id": "source-a", "hostname": "relay-a", "peer_ip": "192.0.2.7",
            "source_ids": ["source-a", "source-b"], "hostnames": ["relay-a", hostile_name],
            "failure_count": 12, "success_count": 1, "username_count": 3,
            "usernames": ["operator", "service", hostile_name], "status": "open",
            "rules": [
                {"rule_id": "cross_source", "rule_version": "1", "window_seconds": 1800, "reason": hostile_name},
                {"rule_id": "slow_scan", "rule_version": "1", "window_seconds": 7200, "reason": "12 records"},
            ],
        },
        {"source_id": "source-c", "hostname": "host-c", "failure_count": 3, "status": "open"},
    ]
    runner = r"""
const vm=require('node:vm'),fs=require('node:fs');
const input=JSON.parse(fs.readFileSync(0,'utf8'));
class Element{
 constructor(tag){this.tag=tag;this.children=[];this.textContent='';this.title='';}
 append(...nodes){this.children.push(...nodes);}
 replaceChildren(...nodes){this.children=nodes;}
 setAttribute(){} removeAttribute(){} addEventListener(){} scrollIntoView(){}
}
const nodes=new Map();
const document={getElementById(id){if(!nodes.has(id))nodes.set(id,new Element('node'));return nodes.get(id);},createElement(tag){return new Element(tag);}};
const context={document,localStorage:{getItem(){return null;}},records:input.records};
vm.createContext(context);
const script=input.script.replace(/refresh\(\);\s*$/,'');
vm.runInContext(script,context);
vm.runInContext('renderIncidents(records)',context);
const rows=nodes.get('incidents').children;
const output={rows:rows.map(row=>row.children.map(cell=>({text:cell.textContent,title:cell.title,tags:cell.children.map(child=>child.tag)})))};
vm.runInContext('renderIncidents([])',context);
output.emptyColumns=nodes.get('incidents').children[0].children[0].colSpan;
process.stdout.write(JSON.stringify(output));
"""
    result = subprocess.run(
        [shutil.which("node"), "-e", runner],
        input=json.dumps({"script": _SCRIPT, "records": records}),
        capture_output=True, text=True, encoding="utf-8", check=True, timeout=10,
    )
    rendered = json.loads(result.stdout)
    rows = rendered["rows"]
    assert len(rows) == 2
    assert all(len(row) == 6 for row in rows)
    assert all(source in rows[0][1]["text"] for source in ("source-a", "source-b", "relay-a", hostile_name))
    assert rows[0][1]["tags"] == []
    assert "失败日志：12 条\n成功日志：1 条\n非空账号：3 个" == rows[0][3]["text"]
    assert hostile_name in rows[0][3]["title"]
    assert rows[0][4]["text"] == "跨服务器尝试、慢速扫描"
    assert hostile_name in rows[0][4]["title"]
    assert rows[0][4]["tags"] == []
    assert "host-c" in rows[1][1]["text"] and "source-c" in rows[1][1]["text"]
    assert rows[1][3]["text"] == "失败日志：3 条"
    assert rows[1][4]["text"] == "登录失败（旧版记录）"
    assert rendered["emptyColumns"] == 6
