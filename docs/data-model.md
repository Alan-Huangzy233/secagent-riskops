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

## Key Relationships

```text
Asset -> Alert -> AlertGroup -> Incident -> Evidence
Incident -> Control -> Risk -> ActionPlan
ActionPlan -> Approval -> Execution -> Verification -> RemediationReport
Incident -> KnowledgeCandidate -> KnowledgeItem
```

## Initial Schema Requirements

Every security conclusion should link to evidence.

Every AI output should include:
- confidence
- evidence_ids
- model/agent name
- timestamp
- structured output
