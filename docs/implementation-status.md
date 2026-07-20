# Implementation Status

The other documents in this repository describe the **target design**. This
page records what is **actually implemented in code** so the two are never
confused.

Last updated for: `v0.2` — MVP walking skeleton.

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

## Not yet implemented (design only)

These are documented in `docs/` but have **no code** yet:

- External intelligence ingestion (connectors, crawlers) — `external-intelligence-ingestion.md`
- Authorized security validation scanners — `authorized-security-validation.md`
- Curated knowledge intake (upload/parse/review) — `curated-knowledge-intake.md`
- Full Rules-of-Engagement UI and natural-language scope parsing — `assessment-authorization-and-rules-of-engagement.md`
- Knowledge lifecycle (candidate → reviewed → active) — `grc-workflow.md`, product docs
- Approval service, real typed executors (GitHub/SSH), verification, rollback — `remediation-workflow.md`
- Frontend UI — `frontend/README.md`
- Real model-provider integration behind the agent seam
- PostgreSQL + Alembic migrations (SQLite is the current stand-in)

## Known limitations of the skeleton

- The triage "agent" is deterministic rule logic standing in for a model, so the
  pipeline is reproducible without a provider. The `ModelProvider` seam exists
  for the real integration.
- The evidence vault keeps blobs in memory for the process lifetime; durable
  blob storage is a follow-up. Replay therefore runs within a live `Services`.
- The control library, ATT&CK map, and asset registry are small hard-coded
  reference sets in `backend/app/reference.py`.
