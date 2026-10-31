# Offline joint-AI response replay

The manual joint workflow has an offline contract-qualification harness. It
replays raw response text against built-in, authored synthetic SSH/network
dossiers. It reads no source databases, initializes no queue, imports no API
client and makes no model calls. Production workflow settings remain unchanged.

## Run locally

Use the project's Python environment with `backend` on `PYTHONPATH`:

```sh
PYTHONPATH=backend .venv/bin/python -m app.evaluation.joint_ai_replay \
  --make-fake-tape runtime-data/joint-ai-eval/example/tape.json
PYTHONPATH=backend .venv/bin/python -m app.evaluation.joint_ai_replay \
  --tape runtime-data/joint-ai-eval/example/tape.json \
  --out runtime-data/joint-ai-eval/example/report.json
```

The first command creates authored fake responses, including deliberately bad
ones. The second revalidates them and compares their handling with hand-written
expectations. Use a new output name for each run: existing files are never
replaced. Outputs are owner-only files. Keep tapes and reports in ignored local storage. Do not publish evaluation or
operating records to GitHub.

The CLI accepts only the built-in corpus and local response tapes. It has no
live mode, provider configuration, key file or custom-data argument. Without
`--out`, it prints the sanitized report. Incomplete replay exits unsuccessfully;
a completed replay is not an approval to use a model in production.

## What the replay binds

A tape contains an exact protocol and a bounded list of records. The protocol
binds the synthetic corpus (including its author labels and fake-response
expectations), dossier version, validator version, prompt, response schema and
full dossier for each request. It cannot silently replay a different evidence
revision under an old request identity.

Each record contains only `scenario_id`, `request_sha256`, `outcome` and
`response_text`. Responses are raw text, including malformed JSON used by the
negative cases. They are validated again on every replay. A saved verdict,
validation flag or summary is never accepted as a substitute. Duplicate JSON
keys, duplicate/unknown scenarios, duplicate request identities, protocol
mismatches and extra record fields are rejected. File and response sizes are
bounded; non-regular input files are refused.

`source: authored_fake` requires the exact built-in response for every supplied
record. `source: local_recording` allows another locally supplied response to the
same synthetic request; it does not authenticate a model, provider or provenance.
Such recordings have no fake-response oracle and do not qualify a live model.
An unavailable provider is represented by `outcome: unavailable` with a null
response; an absent record is missing. Neither is counted as a valid abstention.
No live recording tool is introduced by this increment.

## Reading the results

The report separates:

- **Proposed decisions**: the schema-valid response's decision, or invalid,
  unavailable or missing.
- **Accepted decisions**: the result after deterministic citation, revision and
  typed-claim checks. Rejected responses become a human-review abstention.
- **Validation dimensions**: schema validity, matching revisions, known cited
  IDs and supported typed claims (including required evidence/claims for escalation). These are counts over received responses,
  independent of decision agreement.
- **Contract oracle**: whether the authored fake responses received their
  expected acceptance/rejection. It applies only to the fake corpus.

The main decision-agreement figures use every expected decision-track scenario
as their denominator, including missing/unavailable results. Guardrail and
free-text boundary challenges have separate tables; they are not mixed into
those decision figures. It measures agreement with an authored investigation
policy, not whether a real attack occurred. Results are also separated into
ordinary decisions, guardrail challenges and explicit validation limitations.
Failures deliberately present in fake responses must not be reported as a
model's error rate or accuracy.

The corpus includes limited or stale evidence, unsupported authentication
success, unrelated port groups, wrong revisions, invented citations, forbidden
dismissal/action fields and malformed responses. Boundary cases intentionally
show that a structurally valid response can contain misleading or hostile prose.
The typed validator does not establish narrative truth, ATT&CK accuracy,
causation, identity or comprehensive prompt-injection resistance. Raw account and
event strings are excluded by the existing alias-summary boundary; this replay
receives already aliased dossiers. Free text always requires human review.

Reports include only built-in scenario names, fixed outcomes, reason codes and
counts. Raw responses, rationales, local paths and arbitrary provider errors are
not copied into them. A protocol hash is a reproducibility check, not a signature
or proof of where a recording came from.

## Subsequent gates

This completes a local fake/recorded-response qualification step for #148.
Connecting recorded or live providers to the durable workflow, independent
review of response explanations, approval of outgoing network fields, shared
budget accounting and an explicitly approved live pilot remain separate work.
Automatic analysis and automatic response still belong to #149 and #150.
