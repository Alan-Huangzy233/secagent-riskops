# Implementation Status

The other documents in this repository describe the **target design**. This
page records what is **actually implemented in code** so the two are never
confused.

Last reviewed: 2026-10-03; HTTP acceptance/network detection sections updated
2026-10-19; network ingestion/analysis updated 2026-10-20; enrollment preparation updated 2026-10-23. The walking skeleton and measured
demo baseline are preserved; further demo work is paused. Active development targets the independent
SSH/auth telemetry pilot. The [production plan](./production-plan.md) tracks
model comparison and broader detection; planned capabilities are not claims of
implementation or deployment.

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
| Typed action catalog + ActionPlan | `backend/app/tools/registry.py`, `backend/app/pipeline/remediation.py` |
| **Deterministic, fail-closed policy engine + stable reason codes**; blank scope (`SCOPE_EMPTY`) and ambiguous entries or windows (`SCOPE_AMBIGUOUS`) refused before any request is compared; times compared as instants | `backend/app/policy/engine.py` |
| Approval recorded by one permitted operator, bound to the plan hash and the scope's policy hash; a later rejection or any edit to the plan withdraws it; no second-approver rule yet | `backend/app/pipeline/remediation.py` |
| Typed `harden_ssh_access` executor confined to marked lab copies: smallest in-place edit, byte-for-byte backup, atomic write; verification re-reads the host with sshd's precedence (first value, includes in place, `Match` overrides); a failed check rolls back automatically and the rollback is verified | `backend/app/tools/harden_ssh.py`, `backend/app/tools/sshd_config.py` |
| Audit timeline export: agent call, tool calls, plans, policy decisions, approvals, execution, verification and rollback as one hash-chained JSON Lines file, verified from the file alone | `backend/app/audit_timeline.py`, `backend/app/storage/audit_log.py` |
| Safety demo on two recorded model escalations; its exported timeline reproduces byte for byte in CI | `backend/app/safety_demo.py`, `examples/safety-demo/`, [safety-demo.md](./safety-demo.md) |
| Read-only web demo at `/demo`: a replay of the synthetic week, built from a snapshot that CI rebuilds byte for byte. It shows incident detail, the score breakdown and the recorded model verdicts, and its response buttons run the real policy engine and executor on lab copies. A headless-browser check runs in CI | `backend/app/webdemo/`, `docs/eval/web-demo-synthetic-7d.json`, [web-demo.md](./web-demo.md) |
| Configurable model triage: Responses and Chat Completions APIs; shared durable budget; validated synthetic calls and historical Claude replay | `backend/app/agents/triage_api.py`, `backend/app/agents/triage_budget.py`, [usage](model-triage.md) |
| Versioned SSH/HTTP advisory dossiers, deterministic typed-claim and dismissal validation, 72 built-in synthetic development/holdout scenarios plus a separate 36-case three-model pilot suite; model proposals and effective advice reported separately | `backend/app/agents/triage_evidence.py`, `backend/app/evaluation/triage_benchmark.py`, [scope](triage-evidence.md) |
| Immutable, hash-bound assessment scope | `backend/app/authorization.py` |
| Replay from retained evidence | `backend/app/replay.py` |
| FastAPI surface + SQLite persistence | `backend/app/api/app.py`, `backend/app/storage/repository.py` |
| Test suite incl. adversarial scope enforcement | `backend/tests/` |
| CI: run tests + demo smoke | `.github/workflows/ci.yml` |
| Seeded, labelled synthetic sshd dataset (ground truth kept apart) and scheduled log-to-alert conversion through the production parser and rules | `backend/app/evaluation/` |
| Alert reduction: dedup (re-raised detections), correlate (shared evidence, one source close in time), explainable score and surface decision | `backend/app/reduction/` |
| Evaluation harness: baselines B0–B2, episode matching at τ = 0 / 0.5, miss rate with bootstrap CI, clustering quality, permutation control, sweeps; byte-identical `results.json` checked in CI; numbers rendered into EVALUATION.md and README; LANL slicer; five-minute demo | `backend/app/evaluation/`, `docs/eval/` |

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
| 可选 HTTP 结构化日志本地采集、独立来源凭据/数据库、批次与事件回执、轮转/拒收报告、持久化 ACK 后推进文件游标；持续关联、版本证据、评分、独立表格与站内通知；真实来源尚需验收 | `scripts/http_collector.py`, `backend/app/telemetry/http_store.py`, `http_api.py`, [范围与验证](http-ingestion.md) |
| localhost API、VPN socket proxy、采集/备份定时单元 | `deploy/systemd/` |
| SQLite 一致恢复副本与完整性检查 | `scripts/backup_telemetry.py` |
| IPv4 / IPv6 离线属地、ASN 查询；DB-IP 月度库原子更新 | `backend/app/telemetry/geoip.py`, `scripts/update_geoip.py` |
| 总页数、数字跳页、独立列表请求与匹配排序索引 | `backend/app/telemetry/store.py`, `backend/app/telemetry/dashboard.py` |
| 成功认证摘要单项缓存，60 秒到期，保留 PBKDF2 强度 | `backend/app/telemetry/operator_auth.py` |
| sshd 完整对端解析、认证前断开/协议探测、受保护的历史派生字段回填 | `backend/app/telemetry/sshd_parse.py`, `scripts/reparse_ssh_telemetry.py` |
| 分视图表格与详情抽屉、按需查询及可选 1/5/15 分钟刷新；可选服务器首屏预载与后台同步，显示更新时间，保留分页查询边界 | `backend/app/telemetry/dashboard.py`, `console_workspace.py`, `console_cache.py`, [说明](console-workspace.md) |
| 主动触发 AbuseIPDB 风险分、5 分钟缓存、服务端 Key 与限额处理 | `backend/app/telemetry/abuseipdb.py` |
| SSH 短时/慢速、多账号、跨来源、失败后成功关联；共享证据合并、按参与来源筛选 | `backend/app/telemetry/detection.py`, `backend/app/telemetry/store.py` |
| 历史告警预览、独立备份后重评估、原始记录与回执完整性校验 | `scripts/rebuild_ssh_detections.py`, `docs/ssh-detection.md` |
| 日志组合检索（来源 / IP / 账号 / 类型 / 关键字 / 时间范围）、按回执 rowid 固定的分页快照、告警详情与完整证据分页 | `backend/app/telemetry/store.py`, `backend/app/live_api.py`, `backend/app/telemetry/dashboard.py` |
| 单 IP / 批量手动封禁与解封：预览 → 勾选确认 → 异步任务 → 逐项核实；SSH / TCP / UDP 范围，5 分钟至 24 小时或永久；CSRF 与 Origin 校验、hash 链审计、目标状态定期核实 | `backend/app/telemetry/control.py`, `backend/app/live_api.py`, `docs/manual-blocking.md` |
| 目标端固定 helper 只改自有 nft 表的本机入站规则，保护地址检查、到期自动解除、永久与未到期条目开机恢复；普通账号固定 relay 网关 | `scripts/ssh_block_control.py`, `scripts/control_gateway.py`, `deploy/systemd/secagent-riskops-control-restore.service` |
| 告警处置状态（待处理 / 已知晓 / 已处理）：受限的人工转换、封禁核实后自动标为已处理、新证据自动回到待处理、合并保留较低状态、处置记录与按状态筛选计数 | `backend/app/telemetry/store.py`, `backend/app/live_api.py`, `backend/app/telemetry/dashboard.py`, `docs/ssh-detection.md` |
| 恢复包：先游标后快照的一致捕获、SHA-256 与 schema 指纹清单、zstd 压缩、gpg 指纹加密与清单签名、原子发布、摘要校验 / 深度校验 / 隔离目录恢复演练 | `scripts/recovery_package.py`, `deploy/recovery-package.example.json` |
| HTTP 同机恢复：锁定全部本地 collector 至两库 WAL 读快照固定，复制前释放写锁；保存通知修订检查点与游标/spool，校验加密恢复和真实 Nginx 请求/轮转重试 | `scripts/recovery_package.py`, `scripts/simulate_http_recovery.py`, [边界与演练](http-recovery.md) |
| 备份节点主动拉取：固定命令只允许列出 / 取用清单内文件 / 按自身节点名回执，不接受路径、不开 shell；拉取端逐文件校验后才发布副本并回执；本地轮换只删除"已有独立副本确认且超出保留代数"的包 | `scripts/backup_export.py`, `scripts/pull_recovery_packages.py`, `scripts/recovery_package.py` |
| 采集完整性：按来源持久记录缺口（覆盖起点、游标丢失、来源日志轮转；区间只算到恢复窗口起点，窗口与已收日志重叠时不算缺口）和延迟（来源读取失败、5 分钟无批次、批次在本地排队、积压追赶），缺口永不覆盖；满页时同一轮有界多页追赶；控制台把在线、采集完整性、延迟 / 追赶分列显示，另有采集记录；恢复包还原后可写入恢复点 | `backend/app/telemetry/collection.py`, `scripts/telemetry_collector.py`, `backend/app/telemetry/dashboard.py`, `scripts/recovery_package.py` |
| 可选人工 AI 复核：有界别名化摘要预览、可信私有上下文、持久队列 / 租约 / 总额与每日预算、缓存和未知调用恢复、证据版本历史与人工反馈；默认禁用，离线验收 | `backend/app/telemetry/ai_summary.py`, `ai_jobs.py`, `ai_triage.py`, `ai_dashboard.py`, [说明](manual-ai-triage.md) |

试点默认覆盖部署者指定 journal 过滤范围的 SSH/auth 日志；可选 HTTP 需单独配置和验收，不提供全网络活动可见性，
默认不调用模型；可选 AI 模式与外发边界见上表，开发完成不代表已上线。封禁只在单个操作员预览并勾选确认后执行，规则命中不会自动封禁；
封禁只作用于目标本机入站（不过滤转发流量），是单操作员手动控制，不是完整的角色 / 审批体系。raw events 默认保留 14 天，receipts 和事件证据不会自动
随之清除。首次覆盖窗口、日志轮转、积压追赶和消息截断会作为缺口、延迟或提示写入采集记录，
不会被后续批次覆盖；来源状态“在线”只表示近期收到心跳，完整性与延迟分列显示。
本仓库不保存任何特定环境的地址、凭证、日志或部署交接记录。

## Not yet implemented (design only)

These are documented in `docs/` but have **no code** yet:

- External intelligence ingestion (connectors, crawlers) — `external-intelligence-ingestion.md`
- Authorized security validation scanners — `authorized-security-validation.md`
- Curated knowledge intake (upload/parse/review) — `curated-knowledge-intake.md`
- Full Rules-of-Engagement UI and natural-language scope parsing — `assessment-authorization-and-rules-of-engagement.md`
- Knowledge lifecycle (candidate → reviewed → active) — `grc-workflow.md`, product docs
- Approval requests, approver authentication, a second-approver rule and full product identity/role management — `v0.2.4`, `remediation-workflow.md`; today one operator's approval is recorded and bound to the plan hash, and the isolated telemetry pilot has Basic/source-token authentication only
- Typed executors on real hosts (GitHub/SSH) — `v0.4`, `remediation-workflow.md`; the one typed executor runs on lab copies only, and the pilot's fixed nft block helper is a single-purpose operator control, not the typed executor / verification / rollback chain
- Full product frontend UI — `v0.2.5`, `frontend/README.md`; today there is the read-only web demo, and the isolated telemetry pilot has a self-contained page with read views, search and single-operator manual blocking
- Model triage inside the walking-skeleton flow; it runs on the evaluation's surfaced incidents and in the safety demo (replayed), not behind the `AgentContract` seam
- PostgreSQL + Alembic migrations (SQLite is the current stand-in) — `v0.2.4`

## Live incident scoring (implemented; deployment is separate)

The telemetry pilot now persists an explainable score for changed incidents,
reusing the shared reduction weights while retaining its existing evidence-based
correlation and stable incident IDs. The Chinese console supports score ordering,
attention/low/unscored filters and counts. Historical scores are filled by an
explicit bounded maintenance command, not at startup. Scores never dismiss or
block an incident. See [live-incident-scoring.md](./live-incident-scoring.md) for
production differences, API parameters and deployment/backfill instructions.

## Console notifications (implemented; deployment is separate)

The live pilot has a persistent shared inbox, unread state, coalesced incident
notifications, collection/capacity/optional local-backup monitoring and UTC daily
briefings. Background work runs without a browser, resumes after restart and
retries failed local delivery. Historical log aggregation uses bounded pages
outside write transactions. The console reports queue/worker status and whether
backup monitoring is configured. External push and per-user inboxes remain
future work. See [console-notifications.md](./console-notifications.md).

## HTTP detection (opt-in; real-source acceptance pending)

Structured HTTP access records feed three versioned rules: sensitive-resource
probes, path-traversal attempts and multi-path scans. The local collector and
authenticated API persist receipts before advancing cursors. Bounded workers
correlate records across batches, retain case/evidence revisions, score request
patterns and publish to the console's separate HTTP table and notification inbox.
Separate UTC HTTP daily briefings resume bounded aggregation after restart and
preserve the input cutoff and historical case assessments. Findings never claim
an exploit or login succeeded. See
[web-detection.md](web-detection.md) and [http-ingestion.md](http-ingestion.md).

The explicit same-host recovery mapping pins the HTTP and console databases
with their collector cursor/spool state. CI exercises real loopback Nginx
requests, rename/reopen, lost ACKs, encrypted/signed restoration, historical
evidence and idempotent replay. The [recovery runbook](http-recovery.md) documents
retained log inodes, lock contention and the exact guarantee. Isolated
[real Nginx HTTPS acceptance](http-https-acceptance.md) and
[bounded workload/resource exercises](http-workload-acceptance.md) now run in CI.
Real-source TLS/workload acceptance and remote/whole-host recovery remain
follow-up work.
After an offline restore, an explicit command verifies both database files against
the same package before recording a restart-safe marker. The HTTP workspace has
separate incident and paginated restore-history tabs. History describes paired
database snapshots and operator marking time, not collector catch-up or log completeness. None of these fixtures
claims production coverage or measures detection accuracy.

## Network detection and ingestion (live acceptance pending)

The versioned UFW kernel-journal parser and source profile are implemented in
`backend/app/telemetry/network_parse.py`. The bounded offline detector in
`network_detection.py` retains exact evidence for an observed inbound TCP
multi-port pattern, deduplicates journal identities, separates boots/profiles
and reports coverage and clock uncertainty. Authored IPv4/IPv6 scenarios cover
positive cases, retries, UDP port hopping and malformed/provenance boundaries.
Run `PYTHONPATH=backend python scripts/simulate_network_detection.py` for a
self-checking synthetic exercise; see [usage and limits](network-detection.md).

The [durable ingestion foundation](network-ingestion.md) is merged: `network_protocol.py`, `network_store.py` and
`network_api.py` add dedicated source/profile validation, immutable transactional
receipts, a separate bounded SQLite store and operator read APIs. Dedicated
`scripts/network_export.py` and `scripts/network_collector.py` provide bounded
UFW journal reads, durable pending-batch retry and ACK-gated cursor commits.
`network_ingest` defaults to `null`; no network store or collector is enabled by
existing configuration. The synthetic `scripts/simulate_network_ingest.py`
exercises the disposable delivery path without live source access.

The legacy exporter guards only iptables/ip6tables snapshots. New sources
explicitly select the [full guard](network-source-guard.md), with native prefixes
restricted to unknown-direction observations. Local-input provenance, absence of
unrelated producers and profile validity still require operator review. Normalized events have bounded retention; compact event identities and
batch receipts remain until configured capacity stops writes. Expiry remains
visible after cleanup, and no unsafe receipt pruning is implemented.

[Continuous analysis](network-analysis.md) is merged: bounded receipt/batch checkpoints, monotonic-hour cases, versioned scores
and evidence, a paginated network table/detail view and console notices. Late
observations revise cases; incomplete context preserves prior evidence visibly
stale. The strict network schema migration preserves existing delivery ACKs.
Passive real-source acceptance, resource measurements, long-term capacity and
network store/spool/cursor backup/restore acceptance remain separate gates in
the [network source plan](network-source-plan.md).
This change enables no production network detector; synthetic cases do not
establish accuracy or live coverage. The demo Suricata parser and SSH exporter
do not supply this network source. HTTP #119 awaits a real business service;
continue network #120 before Linux host behavior #121.

## Known limitations of the skeleton

- The walking skeleton's triage agent is deterministic rule logic, so that flow
  is reproducible without a provider. Model triage is measured separately on
  the reduction pipeline's incidents and replayed from recordings.
- The typed executor edits only the file it owns and never reloads a daemon; a
  drop-in that overrides it is caught by verification and rolled back, not
  fixed. Verification does not evaluate `Match` criteria: any conditional
  value that weakens a planned setting fails the check.
- The evidence vault keeps blobs in memory for the process lifetime; durable
  blob storage is a follow-up. Replay therefore runs within a live `Services`.
- The control library, ATT&CK map, and asset registry are small hard-coded
  reference sets in `backend/app/reference.py`.


### Network enrollment preparation (review pending)

The [enrollment guide](network-enrollment.md) covers opt-in full-firewall guards,
restricted native-prefix observations, explicit network/console/collector paired
recovery, independent capacity warnings and a three-source synthetic workload.
Existing v1 profile revisions remain compatible; new profiles bind their guard
and reviewed validity time. Native observations cannot assert local-input or
rejection meaning and do not create TCP probe findings. Collector service/timer
templates remain opt-in. No source account, firewall policy or production
configuration is enabled by these code changes. Per-source passive acceptance,
sustained capacity and a safe long-term compaction policy remain outstanding.
