# Validation Safety Policy

## Purpose

This policy defines the safety boundaries for SecAgent RiskOps' Authorized Security Validation Layer.

The goal is to support useful security checks against authorized systems while preventing the system from becoming an uncontrolled offensive automation platform.

## Core Principle

```text
Validate authorized scope.
Collect evidence.
Do not exploit by default.
Do not exceed policy.
Record everything.
```

## Required Controls

Every validation job must have:

- explicit user request or approval
- assessment scope
- target allowlist
- allowed protocols and ports
- rate limits
- expiration time
- safety level
- audit log
- evidence storage

## Safety Levels

### Level 0: Passive Import

Only import existing scan results or security findings.

Examples:
- uploaded scanner output
- GitHub security alerts
- cloud security events

### Level 1: Read-Only Discovery

Perform low-impact read-only checks.

Examples:
- DNS resolution
- TCP connect checks
- banner capture
- HTTP GET / HEAD
- TLS certificate inspection

### Level 2: Baseline Configuration Checks

Perform non-destructive configuration validation.

Examples:
- HTTP security headers
- CORS configuration
- TLS protocol/cipher checks
- allowed HTTP methods
- redirect behavior

### Level 3: Authenticated Read-Only Checks

Use approved credentials or API tokens to inspect configuration without changing state.

Examples:
- GitHub branch protection checks
- cloud posture checks
- package advisory checks

### Level 4: Active Validation

Reserved for future work. Requires explicit policy, approval, and strong guardrails.

Not enabled by default.

## Prohibited by Default

- exploit execution
- brute force
- password spraying
- credential theft
- payload upload
- persistence installation
- lateral movement
- privilege escalation
- destructive proof-of-concept execution
- unsafe fuzzing
- unbounded crawling
- scanning unauthorized public targets

## Scope Rules

A validation job must not run unless all of the following are true:

- target is in allowlist
- target is inside active assessment scope
- current time is within scope validity window
- check type is allowed by safety level
- rate limit is configured
- tool is registered
- policy engine approves the tool call

## Evidence Requirements

Every validation check should produce:

- raw output reference
- normalized result
- target reference
- scope reference
- tool name and version
- timestamp
- content hash when applicable
- severity and confidence if a finding is generated

## Failure Behavior

If policy validation fails:

```text
Do not run the check.
Create audit log.
Mark validation check as blocked.
Surface reason to user.
```

If verification or parsing fails:

```text
Store raw evidence.
Mark check as failed or inconclusive.
Do not create high-confidence finding.
```
