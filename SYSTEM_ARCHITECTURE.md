# SecAgent RiskOps System Architecture

## High-Level Architecture

```text
Data Sources
├── Code Scanner
├── Linux / Windows Logs
├── Suricata / Zeek / Packetbeat
├── Cloud Logs
├── GitHub Security Alerts
├── SIEM Connectors
└── Manual Findings

Ingestion Layer
├── Parser
├── Normalizer
├── Deduplicator
├── Event Store
└── Evidence Store

Context Layer
├── Asset Inventory
├── Identity Graph
├── Entity Risk Graph
├── Control Library
├── Threat Intel
└── Historical Baseline

Detection & Triage Layer
├── Deterministic Rules
├── Sigma / Custom Rules
├── Correlation Engine
├── Risk Scoring Engine
├── AI Triage Agent
├── Skeptic Agent
└── Disposition Engine

SOC Layer
├── SOC Inbox
├── Incident Timeline
├── Attack Story Graph
├── MITRE ATT&CK Mapping
├── Suppression Rules
└── Daily Briefing

GRC Layer
├── Control Mapping
├── Evidence-as-Code
├── Risk Register
├── Control Status
├── Audit Package
└── OSCAL-like Export

Remediation Layer
├── Action Planner
├── Policy Engine
├── Approval Queue
├── Typed Executor
├── Verifier
├── Rollback Manager
└── Remediation Report

Knowledge Layer
├── Detection Knowledge
├── Suppression Knowledge
├── Remediation Knowledge
├── Control Knowledge
├── Feedback Loop
└── Versioning / TTL

Observability & Governance
├── Agent Trace
├── Tool Call Logs
├── Approval Logs
├── Model Evaluation
├── Prompt Injection Tests
└── Admin Policies
```

## Core Design Principles

1. Evidence first: every conclusion must link back to evidence.
2. Deterministic detection first: LLMs triage, enrich, and explain; they do not replace deterministic detection.
3. AI proposes; policy decides; executor acts.
4. High-risk actions require human approval.
5. Suppression must be explainable, scoped, reversible, and time-limited.
6. Knowledge promotion requires validation.
7. All agent decisions, tool calls, approvals, and remediation actions must be auditable.

## First Technical Stack Proposal

- Backend: FastAPI
- Storage: PostgreSQL
- Live updates: WebSocket or SSE
- Frontend: React + TypeScript
- Agent orchestration: internal orchestrator first; optional future integration with agent frameworks
- Search/event store: PostgreSQL first; OpenSearch/ClickHouse later
- Executor adapters: GitHub first, Linux SSH lab second
