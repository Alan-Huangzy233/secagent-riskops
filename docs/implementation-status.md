# Implementation Status

The other documents in this repository describe the **target design**. This
page records what is **actually implemented in code** so the two are never
confused.

Last updated for: `v0.2` — MVP walking skeleton plus an independent SSH/auth telemetry pilot.

## Implemented (runnable, tested)

A single end-to-end vertical slice that satisfies the eight *Initial Success
Criteria* in the [Project Charter](../PROJECT_CHARTER.md):

| Capability | Where |
|---|---|
| Content-addressed evidence vault + integrity check | `backend/app/storage/evidence_store.py` |
| Ingest: Suricata EVE + Linux auth parsers, normalize, dedup, group, risk score | `backend/app/pipeline/ingest.py` |
| Flow / Task / Step / ToolCall / Artifact runtime + state machine | `backend/app/runtime/workflow.py` |
| Append-only, hash-chained, tamper-evident audit log | `backend/app/storage/audit_log.py` |
| Agent boundary (contract / registry / provider seam) | `backend/app/agents/contract.py` |
| Deterministic, evidence-grounded triage agent + skeptic gate | `backend/app/agents/triage.py`, `backend/app/pipeline/soc.py` |
| Incident creation with ATT&CK techniques | `backend/app/pipeline/soc.py` |
| GRC control mapping (NIST 800-53 subset) + risk candidate | `backend/app/pipeline/grc.py` |
| Typed action catalog + ActionPlan (created, never executed) | `backend/app/tools/registry.py`, `backend/app/pipeline/remediation.py` |
| **Deterministic, fail-closed policy engine + stable reason codes** | `backend/app/policy/engine.py` |
| Immutable, hash-bound assessment scope | `backend/app/authorization.py` |
| Replay from retained evidence | `backend/app/replay.py` |
| FastAPI surface + SQLite persistence | `backend/app/api/app.py`, `backend/app/storage/repository.py` |
| Test suite incl. adversarial scope enforcement | `backend/tests/` |
| CI: run tests + demo smoke | `.github/workflows/ci.yml` |

Run it: `make install && make test && make demo`.

## 独立真实日志试点（代码已实现）

试点入口为 `app.live_api:app`，与上面的样例流程分开。它使用部署者提供的
来源身份和持久化 SQLite，提供中文只读页面，并通过定时 collector 读取
受限 SSH journal 导出。部署时请根据目标环境自行准备凭证、地址和 systemd
参数；此处只记录代码能力，不保存或代替任何特定环境的验收记录。

| 能力 | 实现位置 |
|---|---|
| Basic 读取认证、每来源 Bearer、身份绑定、体积/时间/字段校验 | `backend/app/live_api.py`, `backend/app/telemetry/config.py` |
| 独立 SQLite 事务、批次/event 去重、来源心跳、SSH 成功/失败分类与事件 | `backend/app/telemetry/store.py` |
| 中文只读来源、日志和事件页面；无 CDN，日志按文本渲染 | `backend/app/telemetry/dashboard.py` |
| 固定命令 journal 导出与受限 relay | `scripts/journal_export.py` |
| 最早未读前缀轮询、本地 spool、持久化确认后推进游标 | `scripts/telemetry_collector.py` |
| localhost API、VPN socket proxy、采集/备份定时单元 | `deploy/systemd/` |
| SQLite 一致恢复副本与完整性检查 | `scripts/backup_telemetry.py` |
| IPv4 / IPv6 离线属地、ASN 查询；DB-IP 月度库原子更新 | `backend/app/telemetry/geoip.py`, `scripts/update_geoip.py` |
| 总页数、数字跳页、独立列表请求与匹配排序索引 | `backend/app/telemetry/store.py`, `backend/app/telemetry/dashboard.py` |
| 成功认证摘要单项缓存，60 秒到期，保留 PBKDF2 强度 | `backend/app/telemetry/operator_auth.py` |
| sshd 完整对端解析、认证前断开/协议探测、受保护的历史派生字段回填 | `backend/app/telemetry/sshd_parse.py`, `scripts/reparse_ssh_telemetry.py` |
| 默认手动刷新、可选 1/5/15 分钟，刷新保留记录与详情、合并请求 | `backend/app/telemetry/dashboard.py`, `backend/app/live_api.py` |
| 主动触发 AbuseIPDB 风险分、5 分钟缓存、服务端 Key 与限额处理 | `backend/app/telemetry/abuseipdb.py` |
| SSH 短时/慢速、多账号、跨来源、失败后成功关联；共享证据合并、按参与来源筛选 | `backend/app/telemetry/detection.py`, `backend/app/telemetry/store.py` |
| 历史告警预览、独立备份后重评估、原始记录与回执完整性校验 | `scripts/rebuild_ssh_detections.py`, `docs/ssh-detection.md` |

试点仅覆盖进入部署者指定 journal 过滤范围的 SSH/auth 日志，不提供全网络活动可见性，
也不调用模型或自动修复。raw events 默认保留 14 天，receipts 和事件证据不会自动
随之清除；首次覆盖窗口、日志轮转、每来源每轮 200 条、消息截断、最新错误覆盖
历史缺口等限制请结合部署环境自行记录。来源状态“在线”只表示近期收到心跳。
本仓库不保存任何特定环境的地址、凭证、日志或部署交接记录。

## Not yet implemented (design only)

These are documented in `docs/` but have **no code** yet:

- External intelligence ingestion (connectors, crawlers) — `external-intelligence-ingestion.md`
- Authorized security validation scanners — `authorized-security-validation.md`
- Curated knowledge intake (upload/parse/review) — `curated-knowledge-intake.md`
- Full Rules-of-Engagement UI and natural-language scope parsing — `assessment-authorization-and-rules-of-engagement.md`
- Knowledge lifecycle (candidate → reviewed → active) — `grc-workflow.md`, product docs
- Approval service and full product identity/role management — `v0.2.4`, `remediation-workflow.md`; the isolated telemetry pilot has Basic/source-token authentication only
- Real typed executors (GitHub/SSH), verification, rollback — `v0.4`, `remediation-workflow.md`
- Full product frontend UI — `v0.2.5`, `frontend/README.md`; the isolated telemetry pilot has a read-only page
- Real model-provider integration behind the agent seam
- PostgreSQL + Alembic migrations (SQLite is the current stand-in) — `v0.2.4`

## Known limitations of the skeleton

- The triage "agent" is deterministic rule logic standing in for a model, so the
  pipeline is reproducible without a provider. The `ModelProvider` seam exists
  for the real integration.
- The evidence vault keeps blobs in memory for the process lifetime; durable
  blob storage is a follow-up. Replay therefore runs within a live `Services`.
- The control library, ATT&CK map, and asset registry are small hard-coded
  reference sets in `backend/app/reference.py`.
