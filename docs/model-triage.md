# Configurable model triage evaluation

The evaluator accepts an explicit API profile instead of a hard-coded Claude
client. It supports OpenAI Responses, OpenAI-compatible Chat Completions
(including DeepSeek and Z.AI). Changing a model, endpoint, thinking mode, output limit, or prices requires editing JSON rather
than Python. This is an offline evaluation tool; production AI routing is a
separate task.

The historical Claude recordings, published tables, safety demo, and
`make triage` still replay without credentials or network access. They keep
their original model attribution. New recordings use a different request
fingerprint and do not substitute for the old demo recordings.

## Profiles and secrets

Install `.[ai]` alongside the normal project dependencies. Four starter profiles
are in `examples/model-triage/`:

| Profile | Protocol | Reasoning |
| --- | --- | --- |
| `openai-luna-low.json` | OpenAI Responses | low |
| `deepseek-flash.json` | Chat Completions | disabled |
| `deepseek-flash-low.json` | Chat Completions | enabled, low |
| `zai-glm-flash-low.json` | Chat Completions | enabled, low |

These are candidate configurations, not measured recommendations. Availability
and account compatibility still require a live smoke test. Prices are explicit
USD per million tokens with an `as_of` date. The starter rates were checked October 2, 2026. DeepSeek uses peak rates
(including cache reads), so off-peak calls can cost less. Recheck prices before
a new paid comparison.
The resulting costs are estimates from usage and the configured rate card,
not provider invoices; discounts, later price changes, and account billing
currency can differ.

Put keys in a private JSON file **outside the repository**, readable only by
its owner (mode 0600), within a private directory (0700):

```json
{
  "OPENAI_API_KEY": "",
  "DEEPSEEK_API_KEY": "",
  "ZAI_API_KEY": ""
}
```

Populate it locally; do not put keys in a profile, command argument, recording,
PR, or chat. `--keys-file` selects the profile's `key_name`. A private
single-key file is also supported via `--api-key-file`. Environment variables
do not supply or redirect keys.

For a different service, copy a profile and set `provider`, `api_format`,
`endpoint`, `model`, `key_name`, reasoning settings and the complete rate
card. `api_format` is either `openai-responses` or `openai-chat`. Endpoints must
be explicit HTTPS URLs without credentials or query parameters. The key is sent to that configured endpoint:
use a destination you trust. Only the selected protocol's fields are sent;
remove `thinking`/`effort` if the service does not support them. Local HTTP
servers and arbitrary provider-specific extensions are outside this adapter.

Claude live API support has been removed. Historical Claude recordings are
retained solely for reproducible offline demo and evaluation replay.

## Run a small comparison

Run from a source checkout. First regenerate a published synthetic dataset:

```sh
python -m app.evaluation.synthetic --days 1 \
  --out runtime-data/eval/synthetic-1d \
  --verify examples/synthetic-sshd/manifest-1d.json
```

Start with three identical incidents per profile. Set the private key and
ledger paths to your local configuration directory. **All profiles, stages,
and repeats must use the same ledger and the same total ceiling of USD 10.**

```sh
python -m app.evaluation.triage \
  --data runtime-data/eval/synthetic-1d \
  --config examples/model-triage/openai-luna-low.json \
  --tape runtime-data/model-eval/luna-low.jsonl \
  --out runtime-data/model-eval/luna-low-report.json \
  --live --keys-file /path/to/private/model-eval-keys.json \
  --ledger /path/to/private/model-eval-budget.sqlite3 \
  --budget-usd 10 --limit 3
```

Change the profile, tape, and report paths for the other candidates. Reuse the
same `--data` and `--limit` so they see the same cases. A clean smoke test checks
API access, structured output, citations, latency and usage; three cases do
not establish model quality. Expand to the same full dataset only after
inspecting the smoke reports.

Offline replay needs only `--data`, `--config`, `--tape` and `--out` (and
the same `--limit` for a partial run). Omit `--live`, keys and budget flags.
A matching recorded request incurs no new charge. A different provider,
endpoint, model or generation setting cannot reuse that recording.

For an independent repeat, use a new tape path but **keep the same ledger**.
The ledger keys an attempt by the canonical tape path and request fingerprint.
Moving/deleting a tape or choosing a different path can initiate a new paid
repeat; deleting or replacing the ledger loses the cumulative budget record.
Back up the ledger together with the tapes.

## Budget and failure behavior

Before each request, SQLite atomically reserves a conservative maximum cost,
using `max_input_tokens`, `max_output_tokens` and the largest configured
input/cache rate. The serialized request is limited to half the input-token
allowance to leave room for tokenization and provider framing. Providers'
actual token usage settles the estimate, rounded up to a micro-dollar.
Ordinary input, cache reads, cache writes and reasoning tokens are normalized
without double counting. Responses requests explicitly select standard
processing; an unexpected returned tier has no implicit price.

This bounds spending according to the configured prices and token assumptions,
not an unknown provider's billing behavior. Keep the rate card current and set
a provider-side spending limit where available. A response costing more than
its reservation halts further spending across the ledger.

Reservations persist across restarts and concurrent processes. A changed
budget ceiling on an existing ledger is rejected. A timeout, HTTP error,
unpriced fallback model, invalid usage, or interruption retains the full
reservation and stops that run. There are no automatic retries or redirects.
The same uncertain attempt cannot be retried automatically; investigate its
provider billing first. Other profiles can use the remaining shared budget.
Do not delete reservations merely to get the next request through.

A completed result is saved in the ledger before it is appended and synced to
the tape. If the process stops between those writes, rerunning the same tape
recovers the result without another paid call. Both files contain synthetic
incident judgments and should remain local.

## Reading results and scope

Reports retain agreement, abstention, dangerous attack dismissals, cost and
latency. New reports also identify the complete configuration, validation
failures, API failures, and (for live runs) cumulative charged/reserved budget.
The per-report cost includes reused recordings; it is not the amount newly
spent by this invocation. `shared_budget` covers every attempt in the ledger,
including failed attempts whose costs remain uncertain. API/budget stops exit
with status 1 and leave incomplete cases unjudged.

Strict local validation checks output fields, enum values and cited event IDs.
Malformed output, refusals, truncated output, fabricated IDs and unsupported
decisions without evidence become recorded abstentions. These still cost money.
Citation membership does not prove that a rationale is semantically correct;
human review and broader safety evaluation remain necessary.

Live mode verifies the exact input bytes against the repository's published
1-day/7-day synthetic manifests, then evaluates an isolated snapshot. It
rejects `records.jsonl` and caller-declared synthetic manifests. Raw production
logs and LANL data cannot be sent through this command. Only bounded dossiers
are sent; ground-truth labels and pipeline scores stay local.

The original corpus and command above cover authentication incidents. A
separate [v3 evidence policy and synthetic SSH/HTTP benchmark](triage-evidence.md)
adds typed context, checked dismissal preconditions, development/holdout
families and separate proposal/validated metrics. The optional
[manual console workflow](manual-ai-triage.md) implements bounded SSH summaries,
private trusted inventory, persistent jobs/budgets, revision checks and review.
A [fresh three-model comparison](eval/triage-pilot-model-comparison.md) informs
the next pilot candidate. Real-provider rollout, broader independent evaluation
and final production model selection remain #118, #117 and #10. CI uses fake
HTTP responses and recordings, never paid APIs.

Protocol references:
[OpenAI structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs),
[OpenAI Luna](https://developers.openai.com/api/docs/models/gpt-6-luna),
[OpenAI caching usage](https://developers.openai.com/api/docs/guides/prompt-caching),
[DeepSeek thinking mode](https://api-docs.deepseek.com/guides/thinking_mode/),
[DeepSeek pricing](https://api-docs.deepseek.com/quick_start/pricing),
[Z.AI Chat Completions](https://docs.z.ai/api-reference/llm/chat-completion),
[Z.AI pricing](https://docs.z.ai/guides/overview/pricing).
