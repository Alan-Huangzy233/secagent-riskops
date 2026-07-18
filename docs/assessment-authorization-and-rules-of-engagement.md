# Assessment Authorization and Rules of Engagement

## Purpose

This document defines the product and control-plane contract for collecting, interpreting, approving, and enforcing authorization, assessment scope, and rules of engagement (RoE) before SecAgent RiskOps performs target-facing security validation.

The workflow is designed for authorized defensive assessment and controlled pentest-style validation. It does not treat model output, network reachability, credentials, or a blank form as permission.

## Core Decision

```text
No explicit scope means no active validation.
Ambiguous scope means review is required.
Approved scope becomes a versioned policy.
Every target-facing action is checked against that policy at runtime.
```

A blank scope must never mean “unrestricted.” When the user does not provide an approved target boundary, the platform may only save a draft or run Level 0 passive import. Level 1 or higher checks remain blocked.

## Concepts

The platform separates four related concerns:

1. **Authorization evidence** proves who approved the work, for what purpose, and for what period.
2. **Assessment scope** defines which assets, addresses, services, and environments may be tested and which are excluded.
3. **Rules of engagement** define when and how testing may occur, including techniques, rate limits, credentials, data handling, stop conditions, and contacts.
4. **Compiled enforcement policy** is the deterministic, versioned policy evaluated by the control plane before and during execution.

Natural-language input is a convenience for drafting these objects. It is not itself the enforcement boundary.

## User Experience

### 1. Authorization Attestation

Before scope entry, the user must confirm that they own the target or have explicit permission to assess it.

Required inputs:

- responsible requestor identity
- authorizing party identity or reference
- business purpose
- authorization validity period
- authorization evidence reference, when required by tenant policy
- acknowledgement that third-party and shared-service assets require separate authorization

The UI must not imply that checking a box creates legal authorization. The attestation records accountability; tenant policy decides what supporting evidence is required.

### 2. Scope and RoE Entry

The user may provide:

- structured targets and exclusions
- structured limits and allowed techniques
- optional natural-language instructions
- a reusable, already-approved scope template

Example natural-language input:

> Validate `*.example.test` and `192.0.2.0/28` during the approved maintenance window. Exclude `payments.example.test`, third-party services, and ports other than 80 and 443. Read-only web and TLS checks only. Stop if error rate exceeds 2% or the operations contact requests it.

Structured fields remain available so users can correct or complete the interpretation.

### 3. AI-Assisted Parsing

AI may extract a draft containing:

- exact hosts, domain suffixes, URLs, IP addresses, and CIDR ranges
- explicit exclusions
- ports and protocols
- environments and asset tags
- validity and execution windows
- safety level and allowed check types
- prohibited techniques
- request, concurrency, and crawl limits
- credential-use restrictions
- data handling rules
- stop conditions and contacts

AI must also return:

- confidence for each interpreted field
- source text span or rationale for each interpretation
- unresolved questions
- conflicts between user text, structured fields, tenant policy, and platform policy

AI must not infer ownership, add targets, weaken platform prohibitions, or convert silence into permission.

### 4. Review and Confirmation

The UI presents a human-readable diff between the submitted input and the compiled draft.

The user must be able to see:

- allowed targets and exclusions
- effective time window
- allowed and prohibited actions
- rate and crawl limits
- unresolved or low-confidence fields
- the result of policy checks
- the exact policy version that will govern the job

Active validation cannot start while required fields are missing, scope terms conflict, or unresolved ambiguity could broaden access.

### 5. Approval and Activation

On approval, the platform creates an immutable `AssessmentScopeVersion`. Any material edit creates a new version and invalidates approvals tied to the old version.

Approval must bind to:

- scope identifier and version
- canonical policy hash
- requestor and approver
- safety level
- validity period
- authorization evidence reference
- approval timestamp and expiry

### 6. Execution and Monitoring

The policy engine evaluates every target-facing tool call. Long-running jobs also revalidate scope at checkpoints and when target identity changes through DNS, redirects, discovered services, or cloud-resource resolution.

The UI exposes current scope, remaining validity, active stop conditions, blocked actions, and an emergency stop control throughout the job.

## Scope Semantics

### Allow Rules

Allow rules should use typed matchers rather than free text:

- exact host or FQDN
- domain suffix with explicit subdomain semantics
- exact URL origin or approved path prefix
- exact IP address
- CIDR range
- cloud account, subscription, project, resource, or tag selector
- inventory asset identifier

Wildcards are normalized into explicit matcher types. A rule such as `*.example.test` does not automatically include `example.test`, unrelated look-alike domains, delegated third-party zones, or external services referenced by the application.

### Deny Rules

Explicit exclusions always win over allow rules. Tenant and platform denials always win over user-provided permissions.

```text
platform deny > tenant deny > scope deny > scope allow > default deny
```

### Target Identity Changes

Before dispatch and after identity-changing events, the platform must evaluate:

- submitted hostname and normalized hostname
- resolved IP addresses
- redirect destination
- proxy or service endpoint when known
- port and protocol
- cloud resource identity when applicable

DNS rebinding, resolution into private/link-local/loopback ranges, cross-origin redirects, and newly discovered targets must fail closed unless explicitly authorized by policy. Discovery does not expand scope.

## Rules of Engagement

At minimum, an RoE policy defines:

- allowed safety level and check types
- prohibited actions
- maximum request rate, concurrency, and crawl depth
- approved execution windows and timezone
- credential profile references and permitted use
- sensitive-data collection, redaction, retention, and export rules
- evidence requirements
- operational and emergency contacts
- automated and manual stop conditions
- incident-escalation procedure

Platform-wide prohibitions cannot be overridden by a project RoE. Future Level 4 active validation requires a separate feature gate, role, approval policy, and technique-specific controls.

## Canonical Policy Shape

```json
{
  "scope_id": "SCOPE-001",
  "version": 1,
  "status": "active",
  "authorization_id": "AUTH-001",
  "purpose": "Read-only validation of the approved lab web tier",
  "valid_from": "2026-07-18T07:00:00Z",
  "valid_until": "2026-07-18T13:00:00Z",
  "timezone": "America/Los_Angeles",
  "allow": {
    "targets": [
      {"type": "domain_suffix", "value": "example.test", "include_apex": true},
      {"type": "cidr", "value": "192.0.2.0/28"}
    ],
    "ports": [80, 443],
    "protocols": ["http", "https", "tls"],
    "check_types": ["http_headers", "tls_configuration", "redirect_behavior"]
  },
  "deny": {
    "targets": [
      {"type": "exact_host", "value": "payments.example.test"}
    ],
    "actions": ["exploit_execution", "brute_force", "payload_upload", "lateral_movement"]
  },
  "limits": {
    "requests_per_second": 2,
    "max_concurrency": 3,
    "max_crawl_depth": 2,
    "max_redirects": 3
  },
  "stop_conditions": [
    {"type": "target_error_rate", "operator": ">", "value": 0.02},
    {"type": "manual_stop", "contact_role": "operations"}
  ],
  "safety_level": "level_2_baseline_configuration",
  "policy_hash": "sha256:REDACTED_EXAMPLE"
}
```

The canonical representation must be normalized before hashing so semantically identical policies produce stable approval bindings.

## Policy Compilation

Policy compilation is deterministic and separate from AI parsing:

```text
Structured input + AI draft
  -> schema validation
  -> normalization
  -> ambiguity and conflict checks
  -> platform and tenant policy overlay
  -> effective-policy preview
  -> human approval
  -> canonicalization and hash
  -> immutable active version
```

Compilation must reject:

- empty allow rules for active validation
- invalid, overly broad, or non-normalizable target expressions
- expired or missing authorization
- an end time earlier than the start time
- absent rate limits
- safety levels unsupported by platform policy
- allowed actions that conflict with a deny rule
- unresolved targets or exclusions whose ambiguity may broaden scope

## Runtime Enforcement

The Tool Gateway receives an immutable evaluation context containing:

- actor and tenant
- scope and version
- policy hash
- validation job and check identifiers
- typed tool and parameters
- normalized target identity
- current time
- accumulated rate and stop-condition state

The policy engine returns `allow`, `deny`, or `review_required` with reason codes. The Tool Gateway must not dispatch on timeout, evaluator error, missing context, or `review_required`.

Scope checks occur:

1. when a validation plan is proposed
2. before a job is queued
3. before every target-facing tool call
4. after DNS resolution and before connection
5. before following a redirect or discovered link
6. before using credentials
7. at scheduled checkpoints during long-running jobs

## Change and Extension Workflow

A running job cannot silently expand its own scope. When a new target or technique appears useful:

1. pause the affected check
2. record the proposed extension and evidence
3. create a new scope draft version
4. repeat policy validation and required approval
5. resume only under the newly approved policy version

Shrinking scope or invoking emergency stop takes effect immediately. Already queued actions are re-evaluated and cancelled when no longer allowed.

## Audit Events

The platform records at least:

- authorization attested, verified, expired, or revoked
- scope draft created and AI interpretation generated
- ambiguity or conflict detected
- scope approved, rejected, activated, superseded, expired, or revoked
- policy evaluation allowed, denied, or requested review
- redirect, DNS, or discovered-target boundary decision
- rate limit or stop condition triggered
- emergency stop requested and completed
- scope extension proposed and decided

Audit records reference the canonical policy hash without copying credentials or sensitive evidence into logs.

## Minimum Acceptance Criteria

- Blank scope cannot start Level 1 or higher validation.
- A scope must contain at least one typed allow target and an expiry.
- AI output remains a draft until deterministic compilation and human confirmation complete.
- Explicit exclusions and higher-level policy denials override allow rules.
- Every target-facing tool call carries and validates scope version and policy hash.
- DNS results, redirects, and discovered targets are rechecked before access.
- Scope expansion requires a new version and approval.
- Emergency stop prevents new dispatches and cancels queued work.
- Allowed and blocked decisions are auditable with stable reason codes.
- No credential values, raw authorization documents, or sensitive target data are copied into general audit logs.
