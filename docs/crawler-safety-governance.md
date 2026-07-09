# Crawler Safety and Intelligence Governance

## Purpose

This document defines safety rules for external intelligence collection.

The goal is to prevent low-quality, stale, malicious, or legally problematic content from polluting SecAgent RiskOps' knowledge base.

## Core Principle

```text
External collection creates candidate knowledge.
Validated candidate knowledge may become active knowledge.
Raw crawler output never becomes active knowledge directly.
```

## Source Policy

Use an allowlist-first strategy.

Allowed initial source categories:

- Official vulnerability databases
- Government advisories
- Standards bodies
- Vendor security advisories
- Official security advisory APIs
- Curated open-source security rule repositories

Do not add broad web crawling until structured sources are implemented and evaluated.

## Prohibited Behaviors

The ingestion layer must not:

- execute exploit code
- automatically download exploit payloads
- actively scan third-party systems
- bypass robots.txt or source terms
- scrape authenticated content without permission
- ingest random SEO pages into active knowledge
- treat LLM summaries as verified facts
- overwrite active knowledge without versioning

## Source Reputation

Every source should have a trust level:

```text
high
medium
low
unknown
blocked
```

Suggested defaults:

- Official government / standards / vendor feeds: high
- Major package advisory databases: high
- Curated rule repositories: medium
- Blogs / reports: medium or low until reviewed
- Unknown websites: blocked by default

## Required Metadata

Every imported item must include:

- source_id
- source_url
- retrieval timestamp
- content hash
- parser version
- confidence
- TTL
- license or terms metadata when available
- validation status
- reviewer if promoted manually

## TTL and Freshness

External knowledge can become stale.

Suggested defaults:

```text
CVE metadata: refresh weekly
CISA KEV: refresh daily
EPSS score: refresh daily
ATT&CK techniques: refresh monthly
Vendor advisories: refresh weekly
Blog/report-derived knowledge: review before active use
```

## Conflict Handling

If sources disagree, create a review task.

Examples:

- different affected version ranges
- conflicting mitigation advice
- exploitability status disagreement
- patch availability disagreement

The system should not silently choose one source unless policy defines a deterministic priority.

## Promotion Workflow

```text
candidate
  ↓
source and schema validation
  ↓
deduplication
  ↓
confidence scoring
  ↓
optional human review
  ↓
active / rejected / expired
```

## Security Notes

Treat external content as hostile input.

Risks:

- prompt injection in advisories or web pages
- poisoned vulnerability descriptions
- malicious links
- stale exploit claims
- false vulnerability relationships
- SEO spam

Mitigations:

- strip active content
- store raw and extracted content separately
- never execute fetched content
- use allowlisted connectors
- require provenance and TTL
- isolate parser failures
- review low-trust sources
