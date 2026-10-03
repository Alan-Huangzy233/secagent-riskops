# Evidence-aware advisory triage

A versioned SSH/HTTP dossier and deterministic validation contract extend the
configurable evaluator. This addresses unsupported noise recommendations, such
as dismissing a multi-account campaign because names look common and no login
succeeded. It does not connect a model to the live console or change an alert's
disposition.

## Evidence and proposal contracts

Dossier version 3 carries an incident ID, exact revision, event IDs, domain,
and evidence status: complete, gapped, truncated, stale or unknown. Typed
context distinguishes organisation/generic/unknown accounts and
familiar/unfamiliar/unknown source history within an explicit prior window.
Missing history is unknown; it is not evidence that a source never logged in.

Observed SSH/HTTP records and trusted context have different record types.
Inventory, prior-history, authorization and configured-route records must be
built by trusted adapters. A username, path, User-Agent or model-generated
statement cannot create these records. The synthetic runner authors these
records locally; **production adapters and their provenance binding are still
part of #118**. Do not populate trusted context from unauthenticated log text.

The model returns its verdict, confidence, rationale, evidence references,
ATT&CK suggestions, exact revision, typed factual claims and a dismissal basis.
Every reference must exist in this exact dossier. A definitive verdict must
cite observed events, not just context. Typed success claims require
authentication-success or application-side exploitation-confirmation evidence:
an HTTP 200/302 or a requested sensitive path is insufficient.

Noise recommendations additionally require medium/high confidence, complete
current evidence and one of these checked conditions:

| Basis | Required evidence |
| --- | --- |
| Generic scan | Only failed/invalid SSH events; every host/account has explicit generic classification and an observed invalid-user record; no successful login |
| Known user retry | One source/host/account, organisation ownership and familiar prior history; 1–3 failures followed by one success within five minutes |
| Authorized activity | Every observed event matches a typed approval's exact source, host, accounts or method/path and time window; no authentication success or confirmed exploitation |
| Expected HTTP operation | Every request matches a configured route's exact host, method, path and response status; no authentication success or confirmed exploitation |

Gaps, truncation or unknown coverage prohibit dismissal. Current positive
evidence can still support escalation. Stale evidence or a mismatched revision
requires review. Missing/malformed output, unsupported claims or contradictory
dismissal evidence become an effective `abstain`, with reason codes and
offending claim indices/references retained.

Recordings preserve the bounded original proposal, validator/dossier versions,
dossier hash and revision, and validation reasons. **Arbitrary prose and ATT&CK
suggestions are not semantically verified.** The accepted rationale is a local
advisory description; the model's original narrative remains explicitly
unverified in the proposal for human review. Passing typed checks is not proof
that an incident is benign or that a model's attack interpretation is correct.

The v3 request fingerprint includes the prompt, schema, complete dossier,
provider request and validator version. Existing v2 authentication requests
and historical Claude replay retain their original fingerprints and outputs.

## Synthetic comparison

The built-in `mixed-evidence-v1` suite has **72 authored scenarios**: 36
development and 36 holdout cases. Each split contains 18 SSH and 18 HTTP cases,
12 expected escalations, 12 possible-noise cases and 12 insufficient-evidence
cases. There are 12 scenario families per split and three variants per family;
the family sets do not overlap. Cases exercise cross-host guessing, common
names belonging to real organisation accounts, scoped approvals, ambiguous
login responses, encoded paths, missing evidence and instructions inside logs.

These are **dossier-level scenarios**, separate from the old generated
authentication week. They do not exercise collection, normalization or rule
recall. Related authored families and variants are not IID samples or
representative production traffic; 36 cases are not enough to bound a real
miss rate. Holdout labels are authored expected policy decisions, not model
consensus. A separate independent expert review and broader data remain #117.

The generator and `examples/model-triage/scenarios-v1.json` freeze the corpus
and thresholds. The new command has **no custom-data input path**; it verifies
the built-in corpus against that manifest before any network request. Case
IDs are opaque. Split names, family names and expected labels stay local.

Begin with the development split:

```sh
python -m app.evaluation.triage_benchmark \
  --split development \
  --config examples/model-triage/openai-luna-low.json \
  --tape runtime-data/model-eval/mixed-dev/luna.jsonl \
  --out runtime-data/model-eval/mixed-dev/luna-report.json \
  --live --keys-file /path/to/private/model-eval-keys.json \
  --ledger /path/to/private/model-eval-budget.sqlite3 \
  --budget-usd 10 --limit 3
```

All candidates, smoke runs and repeats must use the same original budget
ledger. See [API setup and budget behavior](model-triage.md). Remove
`--limit 3` to complete the same split using the same tape; completed calls
are reused without a second charge. A sibling `*.jsonl.protocol.json` freezes
all 36 requests, prices and gates before the first request. A changed protocol
is rejected. Keep the original files and select a clearly named new run when
intentionally changing a prompt/model or performing a paid repeat.

Finish development before running `--split holdout` with distinct tape/report
paths. Freeze prompt, validator, configuration and thresholds before viewing
holdout model results. Do not tune on those results and call a rerun a fresh
holdout. To replay, use the same split/configuration/tape and a report path,
omitting `--live`, keys, ledger and budget arguments.

Reports separate **model proposals** from **effective validated advice**,
including confusion matrices, unsupported/unsafe dismissals, abstention,
validation failures, discrepancies, latency and all billable token classes.
A model's wrong dismissal is still counted against the model when the guard
converts it to review. Results are also broken down by SSH/HTTP.

Predeclared scenario gates require a complete 36-case/12-family run, no
proposed or accepted unsafe dismissal (including insufficient-evidence cases),
at least 90% proposal and effective decision agreement, 75% benign dismissal,
90% attack escalation, 90% insufficient-evidence abstention, 98% validation
pass rate, P95 at most 15 seconds and estimated cost at most USD 0.01 per case.
Counts and gates are reported even when none of the candidates passes.
Passing these small-scenario gates **never sets production qualification**.

API/budget failures stop remaining calls, retain uncertain reservations and
exit nonzero. Quality-gate failure is a completed measurement, reported as
`passes_scenario_gates: false`, not a transport error. CI uses fake providers
and recorded replay, never real credentials or paid requests.

The eval design follows the [official OpenAI evaluation guidance](https://developers.openai.com/api/docs/guides/evaluation-best-practices)
on explicit success criteria, task-specific examples and adversarial cases.
Production jobs, provenance, console review states and current-revision
checks at display time remain #118; general semantic verification remains #10.
