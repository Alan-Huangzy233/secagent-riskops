# Source Registry

## Purpose

The Source Registry defines approved external intelligence sources and their ingestion policies.

Each connector or crawler must reference a Source Registry entry before fetching content.

## Suggested Schema

```json
{
  "source_id": "SRC-NVD-CVE",
  "name": "NVD CVE API",
  "source_type": "api",
  "trust_level": "high",
  "base_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
  "enabled": true,
  "update_frequency": "daily",
  "rate_limit_policy": "configured",
  "robots_policy": "not_applicable",
  "license_or_terms": "source-defined",
  "owner": "secagent-riskops",
  "notes": "Used for CVE metadata enrichment."
}
```

## Initial Sources

| Source | Type | Trust | Primary Use |
|---|---|---:|---|
| NVD CVE API | API | High | CVE metadata |
| CISA KEV | JSON/CSV feed | High | Known exploited vulnerability status |
| FIRST EPSS | API/CSV | High | Exploit probability scoring |
| MITRE ATT&CK | STIX/TAXII | High | Technique and tactic mapping |
| GitHub Security Advisories | API | High | Package vulnerability context |
| OSV.dev | API | High | Open source package vulnerabilities |
| CWE | Catalog | High | Weakness classification |
| CAPEC | Catalog | High | Attack pattern context |

## Design Rules

1. Connectors must refuse to fetch from unregistered sources.
2. Disabled sources must not be fetched.
3. Rate limits should be source-specific.
4. Terms and robots metadata should be tracked.
5. Low-trust sources can create candidates but should not auto-promote to active knowledge.
