# SecAgent RiskOps

[![CI](https://github.com/Alan-Huangzy233/secagent-riskops/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Alan-Huangzy233/secagent-riskops/actions/workflows/ci.yml) [![Public repository audit](https://github.com/Alan-Huangzy233/secagent-riskops/actions/workflows/public-repo-audit.yml/badge.svg?branch=main)](https://github.com/Alan-Huangzy233/secagent-riskops/actions/workflows/public-repo-audit.yml) [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

**What it is:** a pipeline that reduces a stream of raw security alerts to a much smaller set of incidents worth an analyst's time, and reports how many real attacks it misses.

**Why:** small security teams drown in duplicate, low-value alerts. Aggressive grouping cuts the noise but can hide an attack, and most tools never say how often that happens.

<!-- generated:readme-results -->
**Results:** on a labelled synthetic week (seed 20261115), 32,458 raw alerts become **50 incidents surfaced (99.85 % fewer)**; **41 of 60 attacks are caught, miss rate 31.7 % (95 % CI 21.7 %–43.3 %)**, precision 0.82. Tuple dedup keeps 28,716 incidents and misses 96.7 % at the same bar. On real LANL authentication data the rules see only 4 of 74 red-team episodes. Model triage (`claude-opus-5`) then dismisses 5 of 7 false alarms on the synthetic week and 23 of 29 false alarms on LANL without dismissing a single attack, at about $0.025 per incident. The method, baselines and limits are in [EVALUATION.md](./EVALUATION.md).
<!-- /generated:readme-results -->

**Run it** (Docker, no API key):

```bash
git clone https://github.com/Alan-Huangzy233/secagent-riskops && cd secagent-riskops
docker compose up
```

## What the demo shows today

`docker compose up` runs the demo once and then serves the API at
<http://127.0.0.1:8000/docs>. Without Docker, `make install && make demo` does the
same with Python 3.11+ in a project virtual environment.

The demo rebuilds one labelled synthetic day from its seed, checks it byte for
byte against the published manifest, raises alerts with the production rules,
reduces them, and ends with the before/after comparison against SIEM-style tuple
dedup, plus the reasons behind the highest-scoring incidents. It takes about ten
seconds. `make evaluate` runs the full seven-day evaluation behind the numbers
above.

`make flow` runs the walking skeleton past the incident: a remediation plan is
drafted and an **independent policy engine denies execution** because no
approval exists; the hash-chained audit log is verified and the run is replayed
from retained evidence.

## How it works

```text
raw logs ─► detection rules ─► alerts ─► dedup ─► correlate ─► score ─► triage ─► incidents
                                                                         │
                                                        remediation plan ─► policy gate (fails closed)
```

- **Deterministic before AI.** Fixed rules turn logs into alerts; grouping and
  scoring are deterministic. Triage is currently a rule-based, evidence-grounded
  agent behind a model-agnostic contract; model-backed triage is being added for
  the evaluation, with an offline fallback so nothing needs an API key.
- **AI proposes, policy decides, executors act.** The policy engine
  (`backend/app/policy/engine.py`) is a fixed sequence of deny-first gates:
  blank or ambiguous scope, an unbound policy hash, an expired window, an
  unlisted actor or target, or a medium/high-risk action without an approval
  record is refused with a stable reason code.
- **Everything is auditable and replayable.** Evidence is content-addressed, the
  audit log is hash-chained, and a run can be replayed from retained evidence.

## Scope

| Implemented and tested | Planned, not implemented |
|---|---|
| Alert reduction: dedup, correlation, explainable score, measured in [EVALUATION.md](./EVALUATION.md) | Model-backed triage (in progress for `v0.3.0-demo`) |
| SSH/auth detection rules: burst, slow scan, multiple accounts, cross-source, success after failures | Approval service with a second approver |
| Evidence-grounded triage agent and skeptic gate | Typed remediation executors with verification and rollback |
| Fail-closed policy engine, hash-bound assessment scope | Web console (SOC inbox); `frontend/` is a placeholder |
| Hash-chained audit log, evidence vault, replay | GRC evidence and risk register (only a fixed control mapping exists) |
| Field pilot: persistent ingestion, read-only console, manual block/unblock with verification, encrypted off-host recovery packages | Knowledge base, external intelligence ingestion, authorized scanning, PostgreSQL |

The planned items are described in [ROADMAP.md](./ROADMAP.md) and the design
documents under `docs/`; they are design only. Exactly what exists in code is
listed in [docs/implementation-status.md](./docs/implementation-status.md).

## Field deployment

The SSH/auth detection rules also run in a small live pilot
(`app.live_api:app`, `backend/app/telemetry/`, `scripts/telemetry_collector.py`)
that polls restricted journal exports from authorized hosts. Data from that
deployment is private and is **never** used for published numbers, because
nobody else could re-check them. See [SSH detection rules](./docs/ssh-detection.md),
[manual blocking](./docs/manual-blocking.md) and the
[deployment guide](./deploy/README.md). Deployment credentials, addresses, logs
and databases stay outside this repository.

## Safety boundaries

- Authorized environments only; it must not be used against systems without explicit permission.
- Blank or ambiguous scope fails closed; it never means unrestricted access.
- No unrestricted shell; actions are typed and policy-gated.
- Medium- and high-risk actions require an approval record.

See [SECURITY.md](./SECURITY.md), [capability boundaries](./docs/capability-boundaries.md),
[autonomy levels](./docs/autonomy-levels.md) and the [threat model](./docs/threat-model.md).

## Repository layout

```text
backend/    pipeline, agents, policy engine, storage, workflow runtime, telemetry pilot, tests
scripts/    collector, backup and recovery tools, public-repository audit
deploy/     container image, example systemd units and the deployment guide
docs/       design documents; docs/process/ keeps the historical GitHub seeding scripts
examples/   sanitized sample inputs
frontend/   placeholder: the web console is planned, not implemented
```

## Documentation

- [Evaluation](./EVALUATION.md) · [Implementation status](./docs/implementation-status.md) · [Roadmap](./ROADMAP.md)
- [Project charter](./docs/project-charter.md) · [System architecture](./docs/system-architecture.md) · [Threat model](./docs/threat-model.md)
- [Agent integration boundary](./docs/agent-integration.md) · [Security policy](./SECURITY.md)

## Contributing

This is a single-maintainer project and pull requests are not being merged yet;
issues and feedback are welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

[Apache-2.0](./LICENSE)
