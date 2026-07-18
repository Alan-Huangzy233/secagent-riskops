# Core Data Model

## Core Objects

- Asset
- Identity
- Event
- Alert
- AlertGroup
- Finding
- Evidence
- Incident
- Control
- Risk
- ActionPlan
- KnowledgeItem
- AgentRun
- ToolCall
- Approval
- AssessmentAuthorization
- AssessmentScopeDraft
- AssessmentScopeVersion
- ScopeApproval
- ValidationJob
- ValidationCheck

## Key Relationships

```text
Asset -> Alert -> AlertGroup -> Incident -> Evidence
Incident -> Control -> Risk -> ActionPlan
ActionPlan -> Approval -> Execution -> Verification -> RemediationReport
Incident -> KnowledgeCandidate -> KnowledgeItem
AssessmentAuthorization -> AssessmentScopeDraft -> AssessmentScopeVersion
AssessmentScopeVersion -> ScopeApproval -> ValidationJob -> ValidationCheck
```

An active target-facing `ValidationJob` must preserve `scope_id`, `scope_version`, and the canonical `policy_hash`. Scope drafts and AI interpretations cannot authorize execution.

## Initial Schema Requirements

Every security conclusion should link to evidence.

Every AI output should include:
- confidence
- evidence_ids
- model/agent name
- timestamp
- structured output
