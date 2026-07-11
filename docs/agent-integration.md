# Agent Integration Boundary

## Purpose

SecAgent RiskOps must support deterministic components, a single AI agent, or multiple cooperating agents without coupling product workflows to one model provider or agent framework.

The Flow runtime remains the system of record. Agents are replaceable task executors inside a Flow; they do not own authorization, workflow state, tools, evidence, or audit history.

## Design Goals

- Use one execution contract for built-in, plugin, remote, and test agents.
- Treat single-agent execution as the simplest form of multi-task orchestration.
- Keep model-provider APIs outside domain workflows.
- Preserve structured evidence, handoffs, decisions, and versions for replay.
- Prevent agents and supervisors from bypassing policy or approval.
- Allow deterministic components to replace agents where probabilistic reasoning is unnecessary.

## Runtime Relationship

```text
Flow
  -> Task
    -> Step
      -> Executor
        |- Deterministic Component
        `- Registered Agent
      -> Proposed ToolCall
      -> Policy / Approval / Tool Gateway
      -> Evidence / Artifact / Audit Event
```

An agent is selected for a Task or Step by capability. The orchestrator controls scheduling and state transitions. The agent receives a bounded context and returns a structured result.

## Agent Contract

The implementation should expose an asynchronous protocol equivalent to:

```python
class Agent(Protocol):
    metadata: AgentMetadata

    async def run(self, context: AgentContext) -> AgentResult:
        ...
```

### AgentMetadata

Required metadata:

- stable `agent_id`
- semantic or immutable `version`
- supported capability names
- accepted input schema versions
- produced output schema versions
- required tool capabilities
- default timeout and resource budget
- publisher or ownership information
- enabled or disabled status

### AgentContext

The orchestrator constructs the context. It should contain only what the task is authorized to use:

- Flow, Task, Step, and correlation identifiers
- authenticated actor and tenant/project boundary
- effective autonomy level
- authorization and assessment-scope reference
- evidence and artifact references
- structured task input
- approved working-memory view
- policy-constrained Tool Gateway
- deadline, retry attempt, and resource budget
- trace and replay metadata

Credentials, unrestricted database sessions, raw executor clients, and mutable workflow state must not be exposed to the agent.

### AgentResult

The result must be schema-validated and should contain:

- terminal or non-terminal outcome
- structured decision or recommendation
- confidence and uncertainty
- evidence references supporting each material conclusion
- output artifacts
- proposed ToolCalls, never direct execution
- requested human review or approval
- optional structured handoff requests
- redacted diagnostics and error classification
- agent, prompt, model, policy, and schema versions required for audit and replay

A result with missing evidence, invalid schema, or unsupported capability fails validation and cannot advance a high-impact workflow automatically.

## Agent Registry

Agents are resolved through a registry rather than imported directly by product modules.

The registry owns:

- registration and discovery by capability
- version and schema compatibility checks
- enable/disable and environment policy
- required-tool declaration
- health and readiness metadata for remote agents
- selection constraints and deterministic fallback

Example capability names:

```text
soc.alert_group_triage
soc.skeptic_review
grc.control_mapping
remediation.action_plan_draft
knowledge.candidate_extraction
```

Product workflows request a capability, not a vendor-specific class name. Selection of an implementation must be recorded on the Task before execution.

## Model Provider Boundary

Agents use a provider-neutral model interface. Domain code must not call a model SDK directly.

The provider boundary should normalize:

- structured input and output schemas
- model and deployment identifiers
- timeout, retry, and cancellation
- token or cost accounting
- redaction and data-residency policy
- response metadata needed for audit
- test doubles and replay responses

Changing providers must not change authorization, evidence, ToolCall, or workflow semantics.

## Tool Gateway

Agents may propose typed ToolCalls only through a policy-constrained gateway.

```text
Agent proposal
  -> input-schema validation
  -> actor / target / scope validation
  -> autonomy and risk policy
  -> approval if required
  -> typed tool dispatch
  -> output validation and redaction
  -> evidence and audit records
```

The gateway exposes capability-scoped tools and opaque handles rather than raw credentials. Every dispatch is linked to the proposing agent and the authorizing policy decision.

## Structured Handoff

Agent-to-agent cooperation uses Flow artifacts and structured handoffs, not an unbounded shared chat transcript.

A handoff should include:

- source agent and version
- requested target capability, not a hard-coded agent identity
- reason and expected output schema
- evidence and artifact references
- explicit questions or tasks
- applicable constraints and deadline
- remaining resource budget
- handoff depth and lineage

The receiving agent must not inherit broader permissions than the originating Task. Handoff content is untrusted input and cannot grant tool access or change policy.

## Single-Agent Execution

A single-agent workflow contains one registered Agent executor and any number of deterministic Steps.

```text
Alert Group
  -> deterministic evidence collection
  -> deterministic risk score
  -> Triage Agent
  -> schema and evidence validation
  -> analyst review or disposition
```

This is the recommended first implementation because it exercises the same registry, context, result, Tool Gateway, audit, and replay boundaries needed later for multiple agents.

## Multi-Agent Orchestration

Multi-agent execution is represented as Tasks with explicit dependencies:

```text
Triage Agent
      |
      v
Skeptic Agent ---- insufficient evidence ----> Human Review
      |
      v
GRC Mapping Agent
      |
      v
Remediation Planning Agent
```

The orchestrator owns:

- dependency and readiness evaluation
- agent capability resolution
- timeout, retry, cancellation, and idempotency
- concurrency and resource budgets
- maximum handoff depth and total agent invocations
- stuck-state and cycle detection
- conflict routing and human-review gates
- aggregation of artifacts without rewriting source decisions

Agents do not call one another directly. They request a handoff, and the orchestrator creates or schedules the next Task after policy and budget checks.

## Supervisor Boundary

A Supervisor may schedule Tasks, request missing information, summarize outcomes, detect stuck workflows, and route conflicts. It is not a privileged bypass mechanism.

A Supervisor must not:

- approve its own or another agent's ActionPlan
- raise the effective autonomy level
- broaden target or tenant scope
- invoke tools outside the Tool Gateway
- alter or delete source evidence and prior decisions
- suppress policy failures or verification errors

Supervisor decisions are versioned, evidence-linked, and replayable like all other agent decisions.

## Conflict Handling

Conflicting agent results must remain separate records. The orchestrator may apply deterministic resolution rules or request human review, but it must not fabricate consensus.

Conflict records should preserve:

- each original result and confidence
- common and disputed evidence
- validation errors or missing evidence
- resolution policy and resolver identity
- final human or deterministic decision

## Safety and Resource Controls

Every agent Task must define:

- deadline and cancellation behavior
- maximum retries with retryable error classes
- token, cost, and tool-call budgets
- maximum handoff depth
- maximum artifacts and payload size
- allowed capabilities and tools
- low-confidence and invalid-output behavior

Budget exhaustion, recursion, repeated handoff, or unresolved conflict moves the Flow to review or a terminal failure state rather than silently continuing.

## Audit and Replay Requirements

For every Agent run, retain or reference:

- AgentMetadata and selected implementation
- input schema and redacted input snapshot
- evidence and artifact identifiers
- prompt/template and model/provider versions
- structured result and validation outcome
- proposed and executed ToolCalls
- policy and approval decisions
- handoff lineage
- timing, usage, errors, and final state

Replay may substitute a recorded or test provider, but replay output must be clearly separated from production decisions.

## Initial Implementation Sequence

1. Define Pydantic schemas for metadata, context, result, handoff, and errors.
2. Implement an in-process Agent protocol and registry.
3. Add a provider-neutral model client with a fake implementation for tests.
4. Implement one single-agent SOC triage Task without external write tools.
5. Record AgentRun, evidence references, and replay metadata.
6. Add the Skeptic Agent as the first multi-agent handoff.
7. Add Supervisor behavior only after timeout, budget, cycle, and conflict policies exist.

Remote agents, dynamic plugins, and third-party agent frameworks are later adapters to this contract, not replacements for it.

## Non-Goals for the Initial Runtime

- unrestricted peer-to-peer agent messaging
- a global mutable conversation shared by all agents
- agents selecting their own permissions or credentials
- framework-specific agent objects in domain schemas
- autonomous consensus as a substitute for evidence or human accountability
