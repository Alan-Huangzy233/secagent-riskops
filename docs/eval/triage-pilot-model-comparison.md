# Three-model manual-pilot comparison — 2026-10-03

**GPT-6 Luna low is the candidate for the next human-reviewed pilot.** It passed
the predeclared gates on this new synthetic suite. DeepSeek Flash low and
Z.AI GLM-5.3-Flash low did not. None is marked production-qualified.

## Frozen measurement

Each model received the same 36 new dossiers: 18 SSH and 18 HTTP, with 12
expected escalations, 12 possible-noise decisions and 12 abstentions. There are
12 authored families with three related variants each. They exercise scoped
authorization, multiple hosts/sources, unrelated context, credential guessing,
route/method mismatches, ambiguous application signals and misleading headers.

The `pilot-evidence-v1` holdout was frozen before calls at commit
`a3e34cf56e4d8bda500c613a55b31e7bd1f06df3`.
Its corpus SHA-256 is
`a04c3b86fe9c26ab812e6c185581b7628efc8bc47ef35600fb264d7e17cf0cb9`.
It retains dossier v3, validator v2 and the existing model profiles/prompt.
No prompt, validator, labels, thresholds or evaluation code changed after the
responses were inspected. The older 72-case suite and recordings remain intact.

Models used `gpt-6-luna`, `deepseek-flash` and `glm-5.3-flash`, each with low
reasoning and an 8192 output-token limit. Luna used Responses; DeepSeek and
Z.AI used Chat Completions with thinking enabled. Provider aliases can change,
so the report records the served model strings and profile configuration.

## Results

Agreement means matching the **authored expected policy decision**. Effective
advice includes the evidence validator's conversion of invalid suggestions to
human review; it is not the proportion of valid outputs.

| Candidate | Raw agreement | Effective agreement | Valid outputs | P95 latency | Estimated USD / 36 | Scenario gates |
| --- | --- | --- | --- | --- | --- | --- |
| GPT-6 Luna low | 36/36 (100%) | 36/36 (100%) | 36/36 | 6.274 s | 0.009787 | Pass |
| DeepSeek Flash low | 33/36 (91.67%) | 29/36 (80.56%) | 29/36 | 11.323 s | 0.056314 | Fail |
| GLM-5.3-Flash low | 24/36 (66.67%) | 24/36 (66.67%) | 22/36 | 14.489 s | 0.012175 | Fail |

All three proposed **zero dismissals among the 12 attack cases** and zero
dismissals among the 12 insufficient-evidence cases. This small count is not a
bound on production miss rate.

| Effective behavior | Luna | DeepSeek | GLM |
| --- | --- | --- | --- |
| Attack cases escalated | 12/12 | 8/12 | 5/12 |
| Benign cases suggested as noise | 12/12 | 11/12 | 8/12 |
| Insufficient-evidence cases left for review | 12/12 | 10/12 | 11/12 |
| Total abstentions | 12/36 | 15/36 | 21/36 |
| SSH agreement | 18/18 | 15/18 | 12/18 |
| HTTP agreement | 18/18 | 14/18 | 12/18 |

DeepSeek had five unknown-evidence-reference failures, one unsupported claim
and one schema failure. It missed the effective agreement, attack escalation,
insufficient-evidence abstention and validation-pass gates.

GLM had five invalid-JSON responses, three schema failures and six unsupported
claims. It missed raw/effective agreement, attack escalation, benign dismissal
and validation-pass gates. Its raw and effective agreement totals happen to be
equal: moving invalid answers to review helps some insufficient-evidence cases
while losing useful escalation/noise advice elsewhere.

Predeclared gates required zero raw/effective unsafe dismissals; at least 90%
raw/effective agreement, 90% attack escalation, 75% benign dismissal, 90%
insufficient-evidence abstention and 98% validation pass; P95 at most 15 seconds;
estimated USD 0.01 or less per case; and all 36 cases / 12 families completed.
See the [machine-readable aggregate](triage-pilot-model-comparison.json) for
matrices, profile settings, checks, protocol hashes and separate SSH/HTTP results.

## Cost and replay

All 108 calls completed without an API/budget stop. This round cost an estimated
USD **0.078276**. The original shared USD 10 evaluation ledger ended at 552
cumulative calls / USD **0.482821**, leaving **9.517179**, with no unresolved
reservations. All three recordings were replayed offline; results match the
live reports exactly apart from their historical shared-budget snapshots.

Prices were rechecked on October 3 against
[OpenAI](https://developers.openai.com/api/docs/models/gpt-6-luna),
[DeepSeek](https://api-docs.deepseek.com/quick_start/pricing/) and
[Z.AI](https://docs.z.ai/guides/overview/pricing).
The frozen profiles retain their October 2 price date; the comparison uses
conservative peak DeepSeek rates. Usage/caching and reasoning/output tokens
are included. These are local estimates, not invoices or wallet balances.

Private recordings and protocol files are retained outside Git; the public
artifact contains aggregates and hashes, not credentials or raw API responses.
With an original recording available, offline replay is:

```sh
python -m app.evaluation.triage_benchmark \
  --suite pilot-evidence-v1 --split holdout \
  --config examples/model-triage/openai-luna-low.json \
  --tape /path/to/original/openai-luna-low.jsonl \
  --out /path/to/replay-report.json
```

Use the matching profile and tape for the other candidates. This command omits
live mode and performs no paid calls. CI uses fake transports, not these private
recordings or credentials.

## Interpretation and next step

These dossiers are related authored variants with policy labels, not IID
production observations or independent expert adjudications. There was one
call per case/model, so this round does not establish repeatability. It tests
advice on supplied evidence, not collection, rule recall, the live summary
adapter or production HTTP coverage. It does not establish that Luna is better
on every workload; different prompts/settings may change the ordering.

Use Luna low as the current candidate for the
[manual review workflow](../manual-ai-triage.md). Before real-provider telemetry
use, review field disclosure, trusted context, deployment/recovery and a
separate approved production budget. Keep expert label review, untouched new
families and later repeatability checks in #117/#10. This result does not enable
a production model or automatic dismissal.
