# Project Charter: SecAgent RiskOps

## Mission

Build an AI-assisted SOC, GRC, and controlled remediation platform that reduces alert fatigue, turns technical security findings into risk-based incidents and compliance evidence, and executes approved remediation with verification and rollback.

## Problem

Small security teams often lack enough analysts to continuously monitor alerts, investigate incidents, maintain compliance evidence, and safely remediate issues. Traditional dashboards show more data but do not sufficiently reduce the operational burden.

## Product Direction

SecAgent RiskOps focuses on:

1. Reducing alert noise through normalization, deduplication, grouping, scoring, and AI triage.
2. Turning alert groups into evidence-grounded incidents.
3. Mapping confirmed findings and incidents to GRC controls and risk register entries.
4. Producing remediation plans that require policy checks, approval, verification, rollback, and audit.
5. Learning from analyst feedback through a controlled knowledge base.

## Target Users

- SOC analysts
- Security engineers
- GRC analysts
- DevSecOps engineers
- Small security teams
- Students or researchers building AI-assisted security operations workflows

## Core Modules

- SOC Inbox
- Alert Reduction Engine
- AI Triage Agent
- Skeptic Agent
- Incident Investigation
- GRC Bridge
- Risk Register
- Controlled Remediation Executor
- Knowledge Core
- Evidence Vault
- Policy Engine
- Agent Observability

## Non-Goals

- No unauthorized scanning.
- No unrestricted autonomous shell access.
- No unapproved destructive remediation.
- No automatic suppression without audit trail.
- No claims without evidence grounding.
- No direct production remediation without explicit policy and approval.

## Autonomy Levels

| Level | Name | Description |
|---|---|---|
| 0 | Report Only | The system only analyzes and reports. |
| 1 | Suggest Only | The system suggests fixes but does not apply changes. |
| 2 | Create Patch / PR | The system creates patches or pull requests but does not merge. |
| 3 | Execute After Approval | The system executes approved actions only. |
| 4 | Auto-Fix Low Risk | The system may auto-fix low-risk issues; medium/high risk requires approval. |
| 5 | Lab-Only Full Autonomy | Full autonomy is allowed only in controlled lab environments. |
