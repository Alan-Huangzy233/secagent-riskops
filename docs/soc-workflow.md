# SOC Workflow

## Alert Triage

```text
Raw Alert
  ↓
Normalize
  ↓
Deduplicate
  ↓
Group
  ↓
Enrich
  ↓
Risk Score
  ↓
AI Triage
  ↓
Skeptic Validation
  ↓
Disposition
```

## Dispositions

- P0 Escalate
- P1 Needs Review
- P2 Auto-Triaged
- P3 Suppressed

## SOC Inbox Goal

The SOC Inbox should answer:

- What needs human attention now?
- What was auto-triaged?
- What was suppressed?
- Why was it suppressed?
- What tuning suggestions are available?
