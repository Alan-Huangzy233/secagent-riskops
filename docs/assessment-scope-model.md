# Assessment Scope Model

## Purpose

The Assessment Scope Model defines what SecAgent RiskOps is allowed to validate.

This prevents accidental scanning of unauthorized systems and gives every validation job a clear authorization boundary.

## AssessmentTarget

Represents a system that may be checked.

Suggested fields:

```json
{
  "target_id": "TGT-001",
  "asset_id": "ASSET-001",
  "target_type": "host",
  "hostname": "web-01.example.internal",
  "ip_address": "192.0.2.10",
  "environment": "lab",
  "owner": "security",
  "criticality": "medium"
}
```

## AssessmentScope

Represents an approved boundary for validation.

Suggested fields:

```json
{
  "scope_id": "SCOPE-001",
  "title": "Lab web validation",
  "status": "active",
  "authorized_by": "alan",
  "valid_from": "2026-07-09T00:00:00Z",
  "valid_until": "2026-07-16T00:00:00Z",
  "allowed_targets": ["TGT-001"],
  "allowed_ports": [80, 443, 22],
  "allowed_protocols": ["tcp", "http", "https", "tls"],
  "safety_level": "level_2_baseline_configuration",
  "rate_limit": "low",
  "notes": "Read-only validation only."
}
```

## ValidationJob

Represents one validation run.

Suggested fields:

```json
{
  "validation_job_id": "VJOB-001",
  "scope_id": "SCOPE-001",
  "flow_id": "FLOW-001",
  "status": "running",
  "requested_by": "alan",
  "started_at": "2026-07-09T01:00:00Z",
  "completed_at": null
}
```

## ValidationCheck

Represents one concrete check inside a job.

Suggested fields:

```json
{
  "validation_check_id": "VCHECK-001",
  "validation_job_id": "VJOB-001",
  "check_type": "http_security_headers",
  "target_id": "TGT-001",
  "tool_name": "web.headers_check",
  "status": "completed",
  "risk_level": "low",
  "evidence_ids": ["EVID-001"],
  "finding_ids": ["FIND-001"]
}
```

## Relationship Summary

```text
AssessmentScope contains AssessmentTargets
AssessmentScope authorizes ValidationJobs
ValidationJob contains ValidationChecks
ValidationCheck produces Evidence
ValidationCheck may create Findings
Findings may map to Controls and Risks
Findings may produce ActionPlans
```
