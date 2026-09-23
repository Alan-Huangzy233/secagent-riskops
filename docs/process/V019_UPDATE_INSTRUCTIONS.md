# SecAgent RiskOps v0.1.9 GitHub Planning Update

This update adds the milestone and implementation issues for the Assessment Authorization and Rules of Engagement roadmap already defined in `ROADMAP.md`.

## What This Adds

- `github-milestones-v019.json`
- `github-issues-v019.json`
- `scripts/apply_v019_update.py`
- `scripts/create_v019_github_items.sh`

The apply script merges the version-specific metadata into `github-milestones.json` and `github-issues.json` without duplicating entries by title.

## Apply Locally

From the repository root:

```bash
python3 scripts/apply_v019_update.py
bash scripts/check_public_repo.sh
```

## Create GitHub Items

Before running the creation script, confirm that the milestone and issues do not already exist. The GitHub creation helpers are not intended to create duplicates.

```bash
bash scripts/create_v019_github_items.sh Alan-Huangzy233/secagent-riskops
```

## New Milestone

- `v0.1.9 Assessment Authorization and Rules of Engagement`

## New Issues

- Implement assessment authorization attestation and evidence references
- Implement scope draft and AI interpretation contract
- Build assessment scope and Rules of Engagement review UI
- Implement deterministic scope compiler and canonical policy hashing
- Implement immutable scope versioning and approval binding
- Implement typed target matchers and deny precedence
- Enforce scope at every target-facing runtime boundary
- Implement Rules of Engagement limits and emergency stop
- Add authorization and scope audit events with stable reason codes
- Add adversarial assessment scope enforcement test suite

Issue #38 remains the earlier v0.1.7 baseline assessment-scope model. The v0.1.9 issues refine it into product, policy-compilation, approval, runtime-enforcement, and evaluation work rather than replacing it.
