# Public Repository Security and Privacy

This public repository should contain code, schemas, sanitized examples, documentation, and tests only.

Never commit:

- `.env` files
- passwords, tokens, API keys, or private keys
- cloud credentials or session cookies
- real uploaded documents
- raw investigation evidence
- customer or employee data
- internal infrastructure inventories
- private hostnames
- local tool configuration containing secrets

Public fixtures should use neutral placeholders:

```text
security-operator
example.internal
192.0.2.10
CVE-YYYY-NNNN
REPLACE_ME
```

Run before pushing:

```bash
bash scripts/check_public_repo.sh
```

Operational data stays outside Git under ignored directories:

```text
runtime-data/
uploads/
evidence/
artifacts/
.local-audit/
```
