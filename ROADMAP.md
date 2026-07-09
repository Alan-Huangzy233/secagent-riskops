# SecAgent RiskOps Roadmap

## v0.1 Foundation

Goal: Establish the project structure, architecture, core schemas, evidence model, and audit trail.

Deliverables:
- Project charter
- System architecture
- Threat model
- Core data schemas
- PostgreSQL persistence
- Evidence and audit trace model

## v0.1.5 Agent Workflow Runtime

Goal: Build the Flow / Task / Step / ToolCall / Artifact runtime that powers SOC investigations, GRC mapping, remediation workflows, and knowledge review.

Deliverables:
- Flow / Task / Step / ToolCall / Artifact model
- Workflow state machine
- Agent activity timeline
- Memory model for SOC, GRC, and remediation
- Supervisor agent and stuck-state detection
- Evaluation and replay framework design

## v0.2 AI SOC Inbox

Goal: Reduce alert fatigue by normalizing, grouping, scoring, and triaging alerts.

Deliverables:
- Alert ingestion
- Deduplication and grouping
- Risk scoring
- AI triage agent
- Skeptic agent
- SOC Inbox UI
- Daily SOC briefing

## v0.3 GRC Bridge

Goal: Convert confirmed findings and incidents into compliance evidence and risk register entries.

Deliverables:
- Control library
- Finding-to-control mapping
- Evidence package
- Risk register
- GRC report export

## v0.4 Controlled Remediation

Goal: Propose and execute approved remediation actions with verification and rollback.

Deliverables:
- ActionPlan schema
- Policy engine
- Approval queue
- GitHub adapter
- Linux SSH lab adapter
- Verifier and rollback manager

## v0.5 Knowledge Loop

Goal: Store validated detection, suppression, control mapping, and remediation knowledge for future reuse.

Deliverables:
- Knowledge item schema
- Candidate to reviewed to active workflow
- TTL and versioning
- Human feedback loop
- Detection tuning suggestions

## v1.0 End-to-End Demo

Goal: Demonstrate the full workflow from raw alerts to incident, GRC evidence, remediation, verification, and knowledge update.

## v0.1.6 External Intelligence Ingestion

Goal: Build the source registry, connector, crawler-safety, raw document, extracted entity, and knowledge candidate foundation for external security intelligence enrichment.

Deliverables:
- External intelligence ingestion architecture
- Source Registry
- Raw Intelligence Document schema
- Extracted Entity schema
- Knowledge Candidate schema
- NVD and CISA KEV connector skeletons
- EPSS enrichment design
- ATT&CK enrichment design
- Crawler safety and governance policy
- External intelligence integration into risk scoring design

## v0.1.7 Authorized Security Validation

Goal: Build a safe, scoped, read-only validation layer that checks authorized targets and converts results into findings, evidence, risks, controls, and remediation plans.

Deliverables:
- Authorized Security Validation architecture
- AssessmentTarget schema
- AssessmentScope schema
- ValidationJob schema
- ValidationCheck schema
- Scanner orchestrator skeleton
- Safe service discovery checks
- Web security baseline checks
- External intelligence enrichment for validation findings
- No-exploit default policy
