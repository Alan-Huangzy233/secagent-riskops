# Implementation Status

The other documents in this repository describe the **target design**. This
page records what is **actually implemented in code** so the two are never
confused.

Last updated for: `v0.2` — MVP walking skeleton plus an independent SSH/auth telemetry pilot.

## Implemented (runnable, tested)

A single end-to-end vertical slice that satisfies the eight *Initial Success
Criteria* in the [Project Charter](./project-charter.md):

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
| Seeded, labelled synthetic sshd dataset (ground truth kept apart) and scheduled log-to-alert conversion through the production parser and rules | `backend/app/evaluation/` |
| Alert reduction: dedup (re-raised detections), correlate (shared evidence, one source close in time), explainable score and surface decision | `backend/app/reduction/` |

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
| 日志组合检索（来源 / IP / 账号 / 类型 / 关键字 / 时间范围）、按回执 rowid 固定的分页快照、告警详情与完整证据分页 | `backend/app/telemetry/store.py`, `backend/app/live_api.py`, `backend/app/telemetry/dashboard.py` |
| 单 IP / 批量手动封禁与解封：预览 → 勾选确认 → 异步任务 → 逐项核实；SSH / TCP / UDP 范围，5 分钟至 24 小时或永久；CSRF 与 Origin 校验、hash 链审计、目标状态定期核实 | `backend/app/telemetry/control.py`, `backend/app/live_api.py`, `docs/manual-blocking.md` |
| 目标端固定 helper 只改自有 nft 表的本机入站规则，保护地址检查、到期自动解除、永久与未到期条目开机恢复；普通账号固定 relay 网关 | `scripts/ssh_block_control.py`, `scripts/control_gateway.py`, `deploy/systemd/secagent-riskops-control-restore.service` |
| 告警处置状态（待处理 / 已知晓 / 已处理）：受限的人工转换、封禁核实后自动标为已处理、新证据自动回到待处理、合并保留较低状态、处置记录与按状态筛选计数 | `backend/app/telemetry/store.py`, `backend/app/live_api.py`, `backend/app/telemetry/dashboard.py`, `docs/ssh-detection.md` |
| 恢复包：先游标后快照的一致捕获、SHA-256 与 schema 指纹清单、zstd 压缩、gpg 指纹加密与清单签名、原子发布、摘要校验 / 深度校验 / 隔离目录恢复演练 | `scripts/recovery_package.py`, `deploy/recovery-package.example.json` |
| 备份节点主动拉取：固定命令只允许列出 / 取用清单内文件 / 按自身节点名回执，不接受路径、不开 shell；拉取端逐文件校验后才发布副本并回执；本地轮换只删除"已有独立副本确认且超出保留代数"的包 | `scripts/backup_export.py`, `scripts/pull_recovery_packages.py`, `scripts/recovery_package.py` |

试点仅覆盖进入部署者指定 journal 过滤范围的 SSH/auth 日志，不提供全网络活动可见性，
也不调用模型。封禁只在单个操作员预览并勾选确认后执行，规则命中不会自动封禁；
封禁只作用于目标本机入站（不过滤转发流量），是单操作员手动控制，不是完整的角色 / 审批体系。raw events 默认保留 14 天，receipts 和事件证据不会自动
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
- Real typed executors (GitHub/SSH), verification, rollback — `v0.4`, `remediation-workflow.md`; the pilot's fixed nft block helper is a single-purpose operator control, not the typed executor / verification / rollback chain
- Full product frontend UI — `v0.2.5`, `frontend/README.md`; the isolated telemetry pilot has a self-contained page with read views, search and single-operator manual blocking
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
