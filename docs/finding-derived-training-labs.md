# Finding-derived Training Labs

Status: exploratory long-term direction, **not implemented**, with no delivery
milestone or date. Revisit after authorized assessment/pentest, evidence handling
and remediation verification mature. It adds no work to the current production
scoring release and does not expand the validation layer's present scope.

## Intent

Turn selected, confirmed findings from authorized assessments into reproducible
training environments. Other users could learn to find the same class of flaw,
understand its evidence, detect the activity, apply a repair and verify it.

The unit of reuse is the underlying failure mechanism and learning objective,
not a copy of the assessed machine. Findings that depend on complex business
logic, proprietary systems or several interacting conditions may need manual
reconstruction or may not make suitable exercises. Not every finding should
become a lab, and a report alone is not sufficient to generate a faithful one.

## Relationship to the existing product

| Area | Contribution |
|---|---|
| Authorized validation / pentest | Confirmed finding, root cause, required conditions and private source provenance |
| Knowledge loop | Reviewed lesson, reusable scenario template, versioning and retirement |
| Training environment | Isolated learner instances, reset, guided tasks and grading |
| SOC | Exercise telemetry, detection and investigation practice |
| Remediation | A repaired variant and checks that distinguish a repair from a broken service |
| GRC | Map the lesson to a control gap, remediation rationale and training evidence |

GRC can retain evidence that a relevant exercise took place and what was
validated. Completing an exercise does not establish that the original
production finding is fixed or that an organisation meets a control. Production
remediation and its retest keep their own evidence and approval workflow.

## Proposed flow

```text
Confirmed, authorised finding
  -> review suitability and permission to reuse as training material
  -> reconstruct the mechanism using synthetic services, identities and data
  -> build vulnerable and repaired variants with explicit learning objectives
  -> independently verify reproducibility, grading and isolation
  -> approve a versioned lesson for the intended audience
  -> issue an isolated learner instance, then reset or destroy it
  -> retain permitted exercise results and feed reviewed lessons back to knowledge/GRC
```

Each lesson would describe its prerequisites, expected observable behaviour,
hints, expected evidence, repair task and grading criteria. A useful exercise
can support attacker, defender and maintainer perspectives. A flag alone does
not demonstrate that the learner understood the finding or repaired it.

An initial private provenance record would link a finding to its reconstructed
scenario, template version, reviewer, distribution permission and validation
results. Learner-facing material gets a separate sanitised identity and never
inherits access to the originating assessment evidence.

## Conditions for sharing with other users

Assessment permission and permission to reuse or distribute material must be
recorded separately. Rebuild with synthetic data; do not distribute production
VM images, customer logs, credentials, source code or identifying topology.
Check component redistribution terms and unresolved disclosure restrictions
before approving a lesson for its audience.

Treat learner instances as intentionally vulnerable and potentially hostile.
Keep them separate from production, the assessment targets, the management
plane and other learners. Choose an isolation boundary appropriate to the
exercise; host/kernel exercises require a stronger boundary than an application
container. A hosted service needs per-user access, restricted outbound network
access, resource/time limits, instance reset and teardown, and validated
separation before admitting external users.

AI may help draft a scenario, environment definition, hints and grading checks.
Human review and independent execution of those checks gate distribution;
a plausible generated environment is not evidence that the original failure
has been reproduced. Active lab testing stays inside its own approved lab
scope and does not grant additional permissions against the source system.

## Incremental validation

1. **One curated internal exercise.** Manually reconstruct a suitable finding in
   an isolated VM or container with synthetic data. Prove fresh builds and reset
   repeat the result; verify both the vulnerable and repaired variants, including
   service health after repair. Produce useful detection and investigation logs.
2. **A small reviewed template library.** Map suitable finding classes to
   templates, then add assisted drafting. Measure reproduction reliability,
   grading errors, reset success and preparation effort. Keep human review.
3. **Limited external training.** Only after content reuse, isolation and
   lifecycle controls are verified, offer authenticated users separate instances.
   Assess learning outcomes and running cost before expanding the audience.

The first validation question is whether one real finding can become a useful,
faithful, sanitised exercise that a fresh learner can complete and repair.
A universal report-to-VM generator or public training marketplace is not a
prerequisite for answering it.

## Reference

[OWASP WebGoat](https://owasp.org/projects/webgoat) is an example of deliberately
vulnerable software used to teach application security. It is a reference for
the teaching format, not evidence that arbitrary pentest findings can be
converted automatically into useful training environments.
