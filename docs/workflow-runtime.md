# Agent Workflow Runtime

## Purpose

The Agent Workflow Runtime provides a reusable execution model for SOC investigations, GRC mapping, remediation workflows, and knowledge review.

The goal is to avoid one-off agent calls and instead represent every investigation or remediation process as a traceable workflow.

## Core Objects

```text
Flow
  ↓
Task
  ↓
Step
  ↓
ToolCall
  ↓
Evidence / Artifact
```

## Flow

A Flow represents a complete workflow instance.

Examples:

- Investigate repeated SSH alerts on web-01
- Map a confirmed incident to GRC controls
- Generate a remediation plan for missing security headers
- Review a suppression rule candidate

Suggested fields:

```json
{
  "flow_id": "FLOW-2026-0001",
  "flow_type": "soc_investigation",
  "title": "Investigate repeated SSH alerts on web-01",
  "status": "running",
  "created_at": "2026-07-06T21:00:00Z",
  "updated_at": "2026-07-06T21:10:00Z",
  "related_alert_group_ids": ["AG-001"],
  "related_incident_id": "INC-001",
  "created_by": "system"
}
```

## Task

A Task is a logical unit of work inside a Flow.

Examples:

- Normalize related alerts
- Enrich with asset context
- Run AI triage
- Run skeptic validation
- Generate control mapping
- Create remediation ActionPlan

## Step

A Step is a concrete action taken by an agent or deterministic component.

Examples:

- Query related alerts
- Read asset profile
- Run risk scoring
- Call AI triage agent
- Validate suppression safety

## ToolCall

A ToolCall records an invocation of an internal tool.

Examples:

- `alerts.query_related`
- `assets.get_profile`
- `risk.score_alert_group`
- `grc.map_controls`
- `policy.evaluate_action`

Tool calls should always record:

- input
- output
- status
- duration
- error
- evidence references
- agent run reference

## Artifact

Artifacts are workflow outputs such as:

- normalized alert exports
- incident timeline
- evidence package
- remediation diff
- approval record
- verification result
- SOC/GRC report

## State Machine

Recommended states:

```text
created
queued
running
waiting_for_approval
completed
failed
cancelled
```

## Design Rules

1. Every Flow must be auditable.
2. Every AI decision must link to evidence.
3. Every tool call must be structured and logged.
4. Every state transition must be recorded.
5. High-risk actions should move the Flow into `waiting_for_approval`.
6. Failed verification should stop the Flow or trigger rollback.
