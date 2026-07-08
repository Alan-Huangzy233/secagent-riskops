# Evaluation and Replay Framework

## Purpose

The Evaluation and Replay Framework is used to measure whether SecAgent RiskOps makes reliable triage, suppression, GRC mapping, and remediation decisions.

This is critical because automatic alert reduction can create hidden risk if the system suppresses a real attack.

## Core Questions

- Did the system correctly escalate important alerts?
- Did the system incorrectly suppress risky alerts?
- Did AI triage use sufficient evidence?
- Did the GRC mapping match the finding?
- Did the remediation plan succeed?
- Did regression results improve or degrade after a prompt/model/rule change?

## Replay Workflow

```text
Historical Alert Dataset
  ↓
Normalize
  ↓
Group
  ↓
Score
  ↓
AI Triage
  ↓
Skeptic Validation
  ↓
Disposition
  ↓
Compare with Expected Labels
  ↓
Metrics Report
```

## Dataset Format

Each replay dataset should include:

```json
{
  "dataset_id": "DATASET-001",
  "name": "SSH brute force and benign scanner sample",
  "alerts": [],
  "expected_groups": [],
  "expected_dispositions": [],
  "expected_incidents": []
}
```

## Key Metrics

### SOC Metrics

- Triage accuracy
- False suppression rate
- Missed escalation rate
- P0/P1 precision
- P0/P1 recall
- Duplicate reduction rate
- Alert-to-incident compression ratio

### AI Quality Metrics

- Evidence grounding rate
- Hallucinated claim rate
- Low-confidence decision rate
- Skeptic disagreement rate

### GRC Metrics

- Control mapping accuracy
- Evidence sufficiency
- Risk statement quality

### Remediation Metrics

- Preflight success rate
- Verification pass rate
- Rollback success rate
- Failed execution rate

## Safety Thresholds

Suggested initial thresholds:

```text
False suppression of P0/P1 expected alert: unacceptable
Missed escalation of confirmed incident: unacceptable
AI triage without evidence references: fail
Suppression rule without TTL: fail
Remediation plan without rollback: fail
```

## Regression Testing

Every prompt, model, scoring, or rule change should be tested against replay datasets.

Recommended command shape:

```bash
python -m backend.app.evaluation.replay --dataset examples/replay/ssh_bruteforce.json
```

## Design Rule

If the system cannot measure whether its triage is safe, it should not auto-suppress alerts beyond low-risk, scoped, time-limited cases.
