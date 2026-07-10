# Curated Knowledge Intake

## Purpose

Curated Knowledge Intake allows authorized users to manually submit security knowledge that may not be available through structured feeds or automated collection.

Supported sources include authorized lab writeups, vulnerability advisories, vendor remediation guides, incident notes, detection guidance, security rules, pasted text, and source URLs.

Manual submissions never become active knowledge immediately.

```text
External Connectors ──────┐
Manual Upload / Paste ────┼─> Raw Document
Internal Operational Data ┘
                                ↓
                         Parse / Extract
                                ↓
                           Deduplicate
                                ↓
                       Knowledge Candidate
                                ↓
                     Validation / Human Review
                                ↓
                       Active Knowledge Base
```

Core objects:

- UploadBatch
- UploadedDocument
- DocumentChunk
- ExtractedEntity
- KnowledgeCandidate
- ReviewDecision

Lab writeups should be transformed into defensive knowledge:

```text
Attack Step
  ↓
Detection Opportunity
  ↓
Affected Control
  ↓
Risk Statement
  ↓
Validation Check
  ↓
Remediation Guidance
```

Lab-derived records default to:

```text
lab_only = true
production_validated = false
```

Promotion requires provenance, rights metadata, duplicate checks, sensitive-data checks, conflict review, and explicit approval.
