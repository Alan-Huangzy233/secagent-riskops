# Joint AI HTTP transport foundation

`app.agents.joint_triage_api` adds an independent provider adapter for the typed
joint dossier in [#148](https://github.com/Alan-Huangzy233/secagent-riskops/issues/148).
It connects the [evidence contract](joint-ai-contract.md) to the
[shared-budget ledger](joint-ai-budget.md) through an explicit code interface.
The [manual workflow](joint-ai-workflow.md) connects it to separately approved
API jobs and console results. Offline and recorded modes retain their behavior;
the workflow remains disabled by default. No repository example enables external
joint calls.

## Explicit inputs and request identity

A caller supplies a validated, aliased `joint-v1` dossier, a selected provider
profile and an existing job attempt's ledger bound to the shared SSH budget
owner. The adapter does not load source stores, generate aliases, construct a
queue, read a key file, allocate a new budget or accept a browser submission.
The manual service supplies credentials only for a new approved request;
receipt recovery requires no credential.
The existing SSH provider client and its accepted dossier versions remain
unchanged.

Only the envelope's `case` object is an outbound dossier. The local envelope,
`local_refs`, private metadata, raw logs and source identities are not transport
inputs. Typed validation, byte limits and exact profile/request binding precede
a new reservation or HTTP request. The binding includes the dossier and its
revision, the joint prompt/response protocol and the selected profile. A changed
dossier or profile cannot authorize a new HTTP request under an earlier request
fingerprint. Recovery checks the original receipt against its own saved bindings
and the original job.

Hash binding proves consistency between the supplied objects; it does not prove
that evidence is still current or that transmission has been approved. The
manual service rebuilds and checks the saved case before a new request and
after receiving a result, using the existing revision and freshness rules. Aliasing is pseudonymization, not anonymity. Destination ports,
relative timing and relationships still require an approved outgoing-field
policy.

## Provider protocols and request limits

The adapter supports the existing Responses and chat-completion protocol
families through a joint-specific request renderer. It uses the joint prompt
and response schema rather than passing joint inputs through the SSH renderer.
HTTP timeouts and a maximum response-body size constrain each request. Redirects
and environment proxy inheritance are disabled; unsupported response envelopes, usage or served
model/pricing combinations cannot be treated as a successful free response.

Protocol support does not qualify every provider or model using that format.
Provider selection still requires explicit review of model behavior, usage and
pricing semantics, error handling and explanation quality. Passing typed
citation checks does not establish narrative truth or model accuracy.

## Reservation, receipt and advisory result

For a new request, the adapter uses the bound attempt's original call ID and
reserves against the existing owner's total and daily limits. It does not create
a second allowance. The queue/owner lease and identity checks from the shared
ledger remain authoritative.

The response path keeps financial accounting separate from advisory acceptance:

1. Render and bind the exact typed dossier and profile to the claimed attempt.
2. Reserve the original call through its shared ledger before sending.
3. Receive a bounded response and normalize its served-model usage and cost.
4. Persist the original raw response receipt and settlement in the owner ledger.
5. Run the joint validator and return a checked advisory result with the original
   proposal kept separate for human review.

A malformed or unsupported recommendation can therefore produce an abstaining
review result while retaining the charge for the response that was received.
The validator does not erase a bill or turn a paid failure into a free retry.
Advice never changes incident disposition, closes evidence or blocks an address.
Only `escalate` and `abstain` are supported advisory decisions.

A completed receipt is recovered under the same call ID and its original
request/profile binding, then revalidated with the current joint validator
without another HTTP request. Recovery needs no credential and can retain the
paid receipt's old profile or prompt after the caller's profile changes. It
reports the original charge and zero additional cost; it does not describe the
original generation as free. If the provider outcome or receipt persistence is uncertain, the original reservation remains committed;
recovery cannot infer that no request was sent. An unavailable or incompatible
owner fails closed. Deterministically invalid paid receipts are distinguished
from temporary ledger access failures, so the manual service can retain the
charge and end invalid recovery in human review without starving later jobs. Existing total/daily limits, unresolved calls and halted
state remain shared with SSH.

## Integration and remaining approval

The manual service connects saved-case jobs, preview bindings, shared ownership
and transport results. Its console requires explicit confirmation, while paused
API mode retains history and receipt recovery. Live use still requires:
- Define permitted outgoing network/joint fields and handling of credentials;
  existing permission for SSH summaries does not authorize joint transmission.
- Qualify the chosen provider and model, request/receipt behavior and independent
  explanation review before making any accuracy claim.
- Obtain explicit approval for a bounded live pilot using the shared allowance,
  with clear failure, recovery and result-display behavior.

Automatic analysis (#149) and automatic response (#150) remain separate stages.
The local [synthetic replay](joint-ai-replay.md) and recording workflow keep their
existing formats and do not become live data collection or provider tools.
Only generic functionality and authored synthetic examples belong in the
repository; credentials, recordings, usage records and operating evidence stay
local.
