"""Explicit operator actions, durable jobs and a fixed SSH control protocol.

This module is independent of the detector and model agents. Only an operator's
confirmed, expiring plan creates jobs. No log text becomes a command.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import threading
import time
import uuid

DURATIONS = (300, 900, 1800, 3600, 86400, None)
CHANNELS = ("ssh", "tcp", "udp")
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def address(value):
    if not isinstance(value, str) or len(value) > 64 or "%" in value:
        raise ValueError("IP 地址格式无效")
    try:
        ip = ipaddress.ip_address(value)
        ip = getattr(ip, "ipv4_mapped", None) or ip
    except ValueError:
        raise ValueError("IP 地址格式无效") from None
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local:
        raise ValueError("此类地址不可封禁")
    return str(ip)


class SSHTransport:
    def __init__(self, config_path):
        self.config_path = str(config_path)

    def __call__(self, source, payload):
        # Alias and config path are administrator-owned configuration, never
        # values from an HTTP request. No remote command or shell is accepted.
        command = ["/usr/bin/ssh", "-T", "-F", self.config_path,
                   "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                   "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=5",
                   "-o", "ServerAliveCountMax=2", source["ssh_host"]]
        result = subprocess.run(command, input=encoded(payload).encode(),
                                capture_output=True, timeout=35, check=False)
        if result.returncode not in (0, 1) or len(result.stdout) > 512 * 1024:
            raise RuntimeError("控制通道暂不可用")
        try:
            response = json.loads(result.stdout)
        except (ValueError, UnicodeError):
            raise RuntimeError("控制通道返回异常") from None
        if not isinstance(response, dict) or response.get("source_id") != source["source_id"] or response.get("request_id") != payload["request_id"]:
            raise RuntimeError("控制通道身份不匹配")
        return response


class ControlService:
    def __init__(self, config, live_sources, *, transport=None, block_listener=None):
        self.enabled = config is not None
        self.csrf_token = secrets.token_urlsafe(32)
        # Called after a ban is verified on a source with the sources that now
        # hold an SSH-covering block for that IP. It never influences the job.
        self.block_listener = block_listener
        self._stop = threading.Event()
        self._thread = None
        self._last_reconcile = 0
        self.sources = {}
        if config is None:
            return
        allowed = {s.id: s.hostname for s in live_sources}
        if set(config) != {"database_path", "ssh_config", "sources", "protected_networks"}:
            raise ValueError("Invalid control configuration")
        self.path = config["database_path"]
        if not isinstance(self.path, str) or not Path(self.path).is_absolute():
            raise ValueError("Control database must be absolute")
        if not Path(config["ssh_config"]).is_absolute():
            raise ValueError("Control SSH configuration must be absolute")
        self.protected = tuple(ipaddress.ip_network(n) for n in config["protected_networks"])
        if not self.protected:
            raise ValueError("Management protection must be configured")
        for source in config["sources"]:
            if set(source) != {"source_id", "ssh_host", "ssh_ports"}:
                raise ValueError("Invalid control source")
            sid = source["source_id"]
            if sid not in allowed or sid in self.sources or not ID.fullmatch(source["ssh_host"]):
                raise ValueError("Invalid control source")
            ports = source["ssh_ports"]
            if not isinstance(ports, list) or not ports or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
                raise ValueError("Invalid SSH ports")
            self.sources[sid] = {**source, "hostname": allowed[sid]}
        if not self.sources:
            raise ValueError("No control sources configured")
        self.transport = transport or SSHTransport(config["ssh_config"])
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS plans (
                    id TEXT PRIMARY KEY, actor TEXT NOT NULL, created REAL NOT NULL,
                    expires REAL NOT NULL, payload TEXT NOT NULL, job_id TEXT);
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, actor TEXT NOT NULL, created REAL NOT NULL,
                    updated REAL NOT NULL, status TEXT NOT NULL, items TEXT NOT NULL,
                    reason TEXT NOT NULL, lease_until REAL NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS audit (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL NOT NULL,
                    actor TEXT NOT NULL, event TEXT NOT NULL, body TEXT NOT NULL,
                    previous_hash TEXT NOT NULL, hash TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS blocks (
                    source_id TEXT NOT NULL, ip TEXT NOT NULL, channel TEXT NOT NULL,
                    expires_at REAL, verified_at REAL NOT NULL,
                    PRIMARY KEY (source_id,ip,channel));
                CREATE TABLE IF NOT EXISTS source_checks (
                    source_id TEXT PRIMARY KEY, checked_at REAL NOT NULL, error TEXT);
            """)

    @classmethod
    def from_environment(cls, live_sources, *, block_listener=None):
        path = os.environ.get("RISKOPS_CONTROL_CONFIG")
        if not path:
            return cls(None, live_sources, block_listener=block_listener)
        try:
            raw = Path(path).read_bytes()
            if len(raw) > 65536:
                raise ValueError
            return cls(json.loads(raw), live_sources, block_listener=block_listener)
        except Exception:
            raise RuntimeError("Control configuration is missing or invalid") from None

    @contextmanager
    def connection(self, write=False):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            if write:
                db.execute("BEGIN IMMEDIATE")
            yield db
            if write:
                db.commit()
        except BaseException:
            if write:
                db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def audit(db, actor, event, body):
        previous = db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        previous = previous[0] if previous else "0" * 64
        now, payload = time.time(), encoded(body)
        digest = hashlib.sha256(encoded([previous, now, actor, event, payload]).encode()).hexdigest()
        db.execute("INSERT INTO audit(timestamp,actor,event,body,previous_hash,hash) VALUES(?,?,?,?,?,?)",
                   (now, actor, event, payload, previous, digest))

    def require_enabled(self):
        if not self.enabled:
            raise ValueError("手动控制尚未配置")

    def capabilities(self):
        result = {"enabled": self.enabled, "csrf_token": self.csrf_token,
                  "channels": CHANNELS, "durations": DURATIONS,
                  "sources": [{k: v for k, v in source.items() if k != "ssh_host"} for source in self.sources.values()],
                  "jobs": [], "blocks": [], "source_checks": []}
        if self.enabled:
            with self.connection() as db:
                result["jobs"] = [self.job_value(row) for row in db.execute("SELECT * FROM jobs ORDER BY created DESC LIMIT 30")]
                result["blocks"] = [dict(row) for row in db.execute("SELECT * FROM blocks WHERE expires_at IS NULL OR expires_at>? ORDER BY source_id,ip,channel LIMIT 2000", (time.time(),))]
                result["source_checks"] = [dict(row) for row in db.execute("SELECT * FROM source_checks ORDER BY source_id")]
        return result

    def preview(self, actor, body, *, operator_ip=None):
        self.require_enabled()
        try:
            operator_ip = address(operator_ip) if operator_ip else None
        except ValueError:
            operator_ip = None
        if not isinstance(body, dict) or set(body) != {"action", "targets", "channels", "duration_seconds", "reason"}:
            raise ValueError("请求字段无效")
        if body["action"] not in ("ban", "unban"):
            raise ValueError("不支持此操作")
        duration = body["duration_seconds"]
        if duration is not None and (type(duration) is not int or duration not in DURATIONS):
            raise ValueError("封禁时间无效")
        if not isinstance(body["reason"], str) or not 1 <= len(body["reason"].strip()) <= 300:
            raise ValueError("请填写 1–300 字的操作原因")
        channels = body["channels"]
        if not isinstance(channels, list) or not channels or len(channels) > 3 or any(c not in CHANNELS for c in channels):
            raise ValueError("请选择有效的封禁范围")
        channels = set(channels)
        if "tcp" in channels and body["action"] == "ban":
            channels.discard("ssh")
        targets = body["targets"]
        if not isinstance(targets, list) or not 1 <= len(targets) <= 100:
            raise ValueError("每次可操作 1–100 个明确目标")
        items = {}
        for target in targets:
            if not isinstance(target, dict) or set(target) != {"source_id", "ip"} or target["source_id"] not in self.sources:
                raise ValueError("目标服务器无效")
            ip = address(target["ip"])
            if body["action"] == "ban" and (any(ipaddress.ip_address(ip) in net for net in self.protected)
                                              or ip == operator_ip):
                raise ValueError("目标包含受保护的管理地址，请从选择中移除")
            for channel in sorted(channels):
                key = (target["source_id"], ip, channel)
                items[key] = {"source_id": key[0], "ip": ip, "channel": channel,
                              "action": body["action"], "duration_seconds": duration}
        if len(items) > 100:
            raise ValueError("目标与范围的组合最多 100 项，请分批操作")
        now, pid = time.time(), str(uuid.uuid4())
        payload = {"items": list(items.values()), "reason": body["reason"].strip()}
        with self.connection(write=True) as db:
            db.execute("INSERT INTO plans VALUES(?,?,?,?,?,NULL)", (pid, actor, now, now + 300, encoded(payload)))
            self.audit(db, actor, "preview", {"plan_id": pid, **payload})
        return {"plan_id": pid, "expires_at": now + 300, **payload}

    @staticmethod
    def job_value(row):
        return {"id": row["id"], "actor": row["actor"], "status": row["status"],
                "created_at": row["created"], "updated_at": row["updated"],
                "reason": row["reason"], "items": json.loads(row["items"])}

    def job(self, job_id):
        self.require_enabled()
        with self.connection() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            return self.job_value(row) if row else None

    def execute(self, actor, plan_id):
        self.require_enabled()
        now = time.time()
        with self.connection(write=True) as db:
            plan = db.execute("SELECT * FROM plans WHERE id=? AND actor=?", (plan_id, actor)).fetchone()
            if not plan:
                raise ValueError("预览计划不存在")
            if plan["job_id"]:
                return self.job_value(db.execute("SELECT * FROM jobs WHERE id=?", (plan["job_id"],)).fetchone())
            if plan["expires"] < now:
                raise ValueError("预览已过期，请重新预览")
            payload = json.loads(plan["payload"])
            job_id = str(uuid.uuid4())
            items = [{**item, "request_id": str(uuid.uuid4()), "status": "pending", "attempts": 0,
                      "expires_at": int(now) + item["duration_seconds"] if item["action"] == "ban" and item["duration_seconds"] is not None else None}
                     for item in payload["items"]]
            db.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?)", (job_id, actor, now, now, "queued", encoded(items), payload["reason"], 0))
            db.execute("UPDATE plans SET job_id=? WHERE id=?", (job_id, plan_id))
            self.audit(db, actor, "confirmed", {"plan_id": plan_id, "job_id": job_id, "items": items})
            return self.job_value(db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())

    def start(self):
        if self.enabled and self._thread is None:
            self._thread = threading.Thread(target=self._loop, name="riskops-control", daemon=True)
            self._thread.start()

    def close(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=40)

    def _loop(self):
        while not self._stop.is_set():
            try:
                if not self.run_once() and time.time() - self._last_reconcile > 60:
                    self._last_reconcile = time.time()
                    self.reconcile()
            except Exception:
                # Inputs and remote stderr may contain private data. Persistent
                # job state survives unexpected failures and lease expiry.
                pass
            self._stop.wait(2)

    def run_once(self):
        now = time.time()
        with self.connection(write=True) as db:
            # Serialize jobs globally: an uncertain old add cannot race a
            # newer unban. Remote request receipts make retries idempotent.
            row = db.execute("SELECT * FROM jobs WHERE status IN ('queued','running') ORDER BY created LIMIT 1").fetchone()
            if row is None or row["lease_until"] > now:
                return False
            job_id, actor = row["id"], row["actor"]
            items = json.loads(row["items"])
            index = next((i for i, item in enumerate(items) if item["status"] in ("pending", "running")), None)
            if index is None:
                return False
            item = items[index]
            item["status"] = "running"
            item["attempts"] += 1
            db.execute("UPDATE jobs SET status='running',items=?,lease_until=?,updated=? WHERE id=?", (encoded(items), now + 90, now, job_id))
        payload = {"version": 1, "request_id": item["request_id"], "source_id": item["source_id"],
                   "action": "add" if item["action"] == "ban" else "delete", "ip": item["ip"], "channel": item["channel"]}
        if item["action"] == "ban":
            payload["expires_at"] = item["expires_at"]
        try:
            response = self.transport(self.sources[item["source_id"]], payload)
            if (response.get("version") != 1 or response.get("source_id") != item["source_id"]
                    or response.get("request_id") != item["request_id"]):
                raise RuntimeError
            if response.get("status") == "rejected":
                item.update(status="rejected", error="目标服务器拒绝此操作（保护规则或配置检查）")
            elif (response.get("status") == "ok" and response.get("source_id") == item["source_id"]
                  and response.get("request_id") == item["request_id"]
                  and response.get("ip") == item["ip"] and response.get("channel") == item["channel"]
                  and response.get("blocked") is (item["action"] == "ban")
                  and (item["action"] != "ban" or response.get("expires_at") == item["expires_at"])):
                item.update(status="ok", verified_at=time.time())
                item.pop("error", None)
            else:
                raise RuntimeError
        except Exception:
            item.update(status="pending" if item["attempts"] < 3 else "uncertain",
                        error="尚未确认目标状态，请检查控制通道并刷新；不要将其视为操作成功")
        now = time.time()
        with self.connection(write=True) as db:
            if item["status"] == "ok":
                if item["action"] == "ban":
                    db.execute("INSERT OR REPLACE INTO blocks VALUES(?,?,?,?,?)", (item["source_id"], item["ip"], item["channel"], item["expires_at"], now))
                else:
                    db.execute("DELETE FROM blocks WHERE source_id=? AND ip=? AND channel=?", (item["source_id"], item["ip"], item["channel"]))
            states = {i["status"] for i in items}
            status = "running" if states & {"pending", "running"} else ("done" if states == {"ok"} else ("partial" if "ok" in states else "failed"))
            db.execute("UPDATE jobs SET status=?,items=?,updated=?,lease_until=? WHERE id=?",
                       (status, encoded(items), now, now + 10 if item["status"] == "pending" else 0, job_id))
            self.audit(db, actor, "result", {"job_id": job_id, "item": item})
        if item["status"] == "ok" and item["action"] == "ban" and item["channel"] in ("ssh", "tcp"):
            self._notify_block(job_id, actor, row["reason"], item)
        return True

    def _notify_block(self, job_id, actor, reason, item):
        if self.block_listener is None:
            return
        with self.connection() as db:
            covered = sorted({row[0] for row in db.execute(
                "SELECT source_id FROM blocks WHERE ip=? AND channel IN ('ssh','tcp') AND (expires_at IS NULL OR expires_at>?)",
                (item["ip"], time.time()))})
        try:
            self.block_listener({"ip": item["ip"], "source_ids": covered, "job_id": job_id,
                                 "actor": actor, "reason": reason})
        except Exception:
            # The firewall change is already verified and recorded; only the
            # incident bookkeeping failed, which the audit trail must show.
            with self.connection(write=True) as db:
                self.audit(db, actor, "incident_update_failed", {"job_id": job_id, "ip": item["ip"], "source_ids": covered})

    def reconcile(self):
        for source in self.sources.values():
            if self._stop.is_set():
                return
            payload = {"version": 1, "action": "status", "source_id": source["source_id"], "request_id": str(uuid.uuid4())}
            now, error = time.time(), None
            try:
                response = self.transport(source, payload)
                if (response.get("version") != 1 or response.get("source_id") != source["source_id"]
                        or response.get("request_id") != payload["request_id"]
                        or response.get("status") != "ok" or not isinstance(response.get("blocks"), list)
                        or len(response["blocks"]) > 4096):
                    raise ValueError
                if response.get("ready") is not True or response.get("table_present") is not True:
                    error = "目标控制防火墙尚未就绪；列表保留上次确认结果"
                    raise ValueError
                blocks = []
                for item in response["blocks"]:
                    ip = address(item["ip"])
                    if item["channel"] not in CHANNELS or (item.get("expires_at") is not None and type(item["expires_at"]) is not int):
                        raise ValueError
                    blocks.append((source["source_id"], ip, item["channel"], item.get("expires_at"), now))
                with self.connection(write=True) as db:
                    db.execute("DELETE FROM blocks WHERE source_id=?", (source["source_id"],))
                    db.executemany("INSERT INTO blocks VALUES(?,?,?,?,?)", blocks)
            except Exception:
                error = error or "暂时无法核实目标状态；列表保留上次确认结果"
            with self.connection(write=True) as db:
                db.execute("INSERT OR REPLACE INTO source_checks VALUES(?,?,?)", (source["source_id"], now, error))
