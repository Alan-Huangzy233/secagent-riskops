# Assessment Scope Model

## Purpose

The Assessment Scope Model defines what SecAgent RiskOps is allowed to validate.

This prevents accidental scanning of unauthorized systems and gives every validation job a clear authorization boundary.

## Model Boundaries

Scope is not the same as authorization. The model uses separate records so the platform can prove who authorized the work, compile natural-language instructions into deterministic rules, and bind approvals to an immutable policy version.

```text
AssessmentAuthorization
  -> AssessmentScopeDraft
  -> AssessmentScopeVersion
  -> ScopeApproval
  -> ValidationJob
  -> ValidationCheck
```

See [Assessment Authorization and Rules of Engagement](./assessment-authorization-and-rules-of-engagement.md) for the product workflow and enforcement contract.

## AssessmentAuthorization

Represents the accountable authorization for an assessment.

Suggested fields:

```json
{
  "authorization_id": "AUTH-001",
  "tenant_id": "TENANT-001",
  "requestor_id": "USER-001",
  "authorized_by": "security-owner",
  "purpose": "Read-only validation of the approved lab web tier",
  "evidence_reference": "AUTHDOC-001",
  "status": "verified",
  "valid_from": "2026-07-18T07:00:00Z",
  "valid_until": "2026-07-18T13:00:00Z"
}
```

Authorization evidence is access-controlled and referenced from audit records rather than copied into them.

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

## AssessmentScopeDraft

Represents user-provided structured fields, optional natural-language instructions, and the AI interpretation before approval.

Drafts may be incomplete or ambiguous. They cannot authorize target-facing tool calls.

Suggested fields:

```json
{
  "scope_draft_id": "SCOPEDRAFT-001",
  "authorization_id": "AUTH-001",
  "instructions": "Read-only checks for *.example.test; exclude payments.example.test.",
  "structured_input": {},
  "ai_interpretation": {},
  "unresolved_questions": [],
  "status": "ready_for_review"
}
```

## AssessmentScopeVersion

Represents an immutable, approved, canonical boundary for validation. Material changes create a new version.

Suggested fields:

```json
{
  "scope_id": "SCOPE-001",
  "version": 1,
  "title": "Lab web validation",
  "status": "active",
  "authorization_id": "AUTH-001",
  "valid_from": "2026-07-18T07:00:00Z",
  "valid_until": "2026-07-18T13:00:00Z",
  "timezone": "America/Los_Angeles",
  "allowed_targets": [
    {"type": "domain_suffix", "value": "example.test", "include_apex": true}
  ],
  "excluded_targets": [
    {"type": "exact_host", "value": "payments.example.test"}
  ],
  "allowed_ports": [80, 443, 22],
  "allowed_protocols": ["tcp", "http", "https", "tls"],
  "allowed_check_types": ["http_headers", "tls_configuration"],
  "safety_level": "level_2_baseline_configuration",
  "rate_limits": {
    "requests_per_second": 2,
    "max_concurrency": 3
  },
  "prohibited_actions": ["exploit_execution", "brute_force", "payload_upload"],
  "stop_conditions": [{"type": "manual_stop", "contact_role": "operations"}],
  "policy_hash": "sha256:REDACTED_EXAMPLE"
}
```

## ScopeApproval

Represents a decision bound to one exact policy version.

Suggested fields:

```json
{
  "approval_id": "APPROVAL-001",
  "scope_id": "SCOPE-001",
  "scope_version": 1,
  "policy_hash": "sha256:REDACTED_EXAMPLE",
  "approved_by": "security-owner",
  "decision": "approved",
  "approved_at": "2026-07-18T06:55:00Z",
  "expires_at": "2026-07-18T13:00:00Z"
}
```

## ValidationJob

Represents one validation run.

Suggested fields:

```json
{
  "validation_job_id": "VJOB-001",
  "scope_id": "SCOPE-001",
  "scope_version": 1,
  "policy_hash": "sha256:REDACTED_EXAMPLE",
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
AssessmentAuthorization supports AssessmentScopeDrafts
AssessmentScopeDraft compiles into an immutable AssessmentScopeVersion
ScopeApproval binds to an exact scope version and policy hash
AssessmentScopeVersion contains typed target rules and Rules of Engagement
AssessmentScopeVersion authorizes ValidationJobs
ValidationJob contains ValidationChecks
ValidationCheck produces Evidence
ValidationCheck may create Findings
Findings may map to Controls and Risks
Findings may produce ActionPlans
```

An empty or unapproved scope authorizes only Level 0 passive import. It never means unrestricted validation.
