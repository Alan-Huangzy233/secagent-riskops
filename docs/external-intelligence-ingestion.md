# External Intelligence Ingestion Layer

## Purpose

The External Intelligence Ingestion Layer expands SecAgent RiskOps with trusted external security knowledge.

It collects and normalizes external security intelligence such as CVEs, known exploited vulnerabilities, EPSS scores, ATT&CK techniques, vendor advisories, and security advisory metadata. The goal is to improve SOC triage, GRC mapping, risk scoring, and remediation planning.

This layer must not behave like an uncontrolled web crawler. External content should be treated as untrusted input until validated.

## Position in Architecture

```text
Data Sources
  ↓
Ingestion Layer
  ↓
External Intelligence Ingestion Layer
  ↓
Context Layer
  ↓
SOC Layer
  ↓
GRC Layer
  ↓
Remediation Layer
  ↓
Knowledge Layer
  ↓
Evaluation Layer
```

## Core Workflow

```text
External Source
  ↓
Connector / Fetcher
  ↓
Raw Intelligence Document
  ↓
Parser / Extractor
  ↓
Entity Resolver
  ↓
Deduplication
  ↓
Source Reputation Check
  ↓
Knowledge Candidate
  ↓
Validation / Human Review / TTL
  ↓
Active Knowledge Base
```

## Initial Source Priority

Start with structured, high-trust sources before building a general crawler.

Initial sources:

- NVD CVE API
- CISA Known Exploited Vulnerabilities catalog
- FIRST EPSS
- MITRE ATT&CK STIX/TAXII
- GitHub Security Advisories
- OSV.dev
- CWE / CAPEC
- Vendor security advisories

## Core Objects

### Source Registry Entry

Defines an approved external intelligence source.

Suggested fields:

```json
{
  "source_id": "SRC-CISA-KEV",
  "name": "CISA Known Exploited Vulnerabilities",
  "source_type": "structured_feed",
  "trust_level": "high",
  "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
  "update_frequency": "daily",
  "rate_limit": "respect_source_default",
  "robots_policy": "not_applicable",
  "enabled": true
}
```

### Raw Intelligence Document

Stores the raw response or document before extraction.

Suggested fields:

```json
{
  "raw_document_id": "RAW-0001",
  "source_id": "SRC-CISA-KEV",
  "retrieved_at": "2026-07-08T00:00:00Z",
  "content_hash": "sha256:...",
  "content_type": "application/json",
  "raw_storage_uri": "object://intelligence/raw/RAW-0001.json",
  "license_or_terms": "source-defined",
  "processing_status": "parsed"
}
```

### Extracted Entity

Stores structured entities extracted from raw documents.

Examples:

- CVE
- CWE
- product
- vendor
- affected version
- ATT&CK technique
- mitigation
- patch reference
- advisory URL

### Knowledge Candidate

External content should first become a candidate, not active knowledge.

Suggested statuses:

```text
candidate
validated
active
rejected
expired
superseded
```

## Design Rules

1. External intelligence is untrusted until validated.
2. Crawlers and connectors must use allowlisted sources.
3. Raw documents must be retained with provenance.
4. Extracted knowledge must include source, timestamp, confidence, and TTL.
5. Conflicting sources should create review tasks, not overwrite active knowledge silently.
6. AI may propose knowledge candidates but must not directly promote them to active knowledge.
7. General web crawling should come after structured source connectors.
8. No automatic exploit download or execution belongs in this layer.

## Value to SOC

External intelligence can enrich alerts with:

- known exploitation status
- EPSS probability
- public exploitability signal
- affected products
- ATT&CK techniques
- vendor mitigation
- patch priority

## Value to GRC

External intelligence can support:

- risk register severity justification
- control gap evidence
- vulnerability-to-control mapping
- audit-ready remediation rationale
- compensating control recommendations

## Value to Remediation

External intelligence can provide:

- patched versions
- vendor workarounds
- configuration mitigations
- temporary compensating controls
- remediation urgency signals
