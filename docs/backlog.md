# Known work and issue coverage

GitHub tracking index: [#170](https://github.com/Alan-Huangzy233/secagent-riskops/issues/170).

Reconciled 2026-10-24 against the current implementation, maintained-deployment
acceptance and prior roadmap decisions. This is the inventory of known unfinished
work, not a claim that every item is implemented or scheduled for immediate work.
The issue bodies carry deliverable checklists and dependencies. Private operating
inventories, credentials, addresses, raw logs and backup locations stay outside
public tracking.

## Delivery order

1. Delivered: visible exact-IP search in SSH alerts/logs and network→SSH pivots (#145).
2. Build SSH + network joint cases. The [offline foundation](joint-evidence.md)
   supplies typed association and bounded read-only source adapters with isolated
   acceptance. A separate derived store and explicit finite refresh of registered
   anchors are implemented. The [joint console](joint-console.md) adds optional
   mapping, explicit bounded discovery, recovery and a read-only paginated view.
   Optional bounded continuous refresh is implemented; scheduling remains opt-in.
   Search matches alone do not identify one actor or prove an attack chain.
3. Add manual AI review of those versioned joint dossiers. The saved-case adapter
   and local preview are implemented. The [local manual workflow](joint-ai-workflow.md)
   adds durable offline submission/history; recorded and approved live transport
   remain separate increments.
4. Continue Linux host evidence after the network foundation. Source inventory
   can run alongside investigation work; a pending AI data/budget decision need
   not block already-authorized Linux engineering.
5. Qualify optional automatic analysis separately from policy-controlled
   automatic response. Formal product identity, approvals and real executors
   remain distinct later increments.

Grouped network/HTTP IP lookup (#146) can ship alongside investigation work;
its raw cross-store search needs separate indexes/migrations and does not block
retained-evidence correlation.

Network sustained operation and storage/resource work run alongside these steps;
necessary reliability fixes take priority. HTTP real-source activation still
waits for a suitable business service. Demo and selected recovery/NAS work remain
paused. No date is promised for deferred product or exploratory work.

## Existing issue owners

| Issue | Delivered baseline | Remaining acceptance / status |
| --- | --- | --- |
| [#117](https://github.com/Alan-Huangzy233/secagent-riskops/issues/117) | Configurable evaluator and frozen three-model manual-pilot comparison | Broader independent/held-out and reviewed pilot qualification; synthetic agreement is not production accuracy |
| [#118](https://github.com/Alan-Huangzy233/secagent-riskops/issues/118) | Durable SSH manual AI summaries/jobs/budgets/results and limited pilot | Live HTTP adapter, new typed inputs, ongoing operational acceptance and formal AgentContract integration |
| [#10](https://github.com/Alan-Huangzy233/secagent-riskops/issues/10) | Typed schema/evidence and unsafe-dismissal validation | New network/joint types and independent semantic acceptance; no mandatory second paid model |
| [#119](https://github.com/Alan-Huangzy233/secagent-riskops/issues/119) | HTTP collection, cases, scoring, notifications/briefings and isolated HTTPS/workload/recovery | Blocked on real business source and source-specific format/proxy/TLS/resource/recovery acceptance |
| [#120](https://github.com/Alan-Huangzy233/secagent-riskops/issues/120) | Reviewed initial passive network enrollment, TCP findings and limited UDP observation path | Sustained operation, coverage, capacity/receipt governance and change-specific recovery checks |
| [#121](https://github.com/Alan-Huangzy233/secagent-riskops/issues/121) | Existing SSH authentication coverage only | Source-backed Linux actor/target/operation/outcome rules, evidence and staged source acceptance |
| [#73](https://github.com/Alan-Huangzy233/secagent-riskops/issues/73) | Limited demo approval and single-operator manual controls | Formal authenticated approval-service/policy integration; approval does not invoke an executor |
| [#105](https://github.com/Alan-Huangzy233/secagent-riskops/issues/105) | Runnable synthetic demo baseline | Paused: recording, release tag/notes and independent timed walkthrough |

## Next investigation increments

| Issue | Work | Stage |
| --- | --- | --- |
| [#145](https://github.com/Alan-Huangzy233/secagent-riskops/issues/145) | Make IP search visible and pivot from network findings to SSH evidence | deployed |
| [#146](https://github.com/Alan-Huangzy233/secagent-riskops/issues/146) | Add scoped IP lookup across network, HTTP and SSH records | planned |
| [#147](https://github.com/Alan-Huangzy233/secagent-riskops/issues/147) | Correlate SSH and network evidence into traceable investigation cases | foundation, readers, derived observations, explicit discovery/recovery, console and optional bounded refresh implemented |
| [#148](https://github.com/Alan-Huangzy233/secagent-riskops/issues/148) | Extend manual AI review to network and correlated SSH evidence | [dossier contract and local preview](joint-ai-contract.md), plus [offline manual jobs/history](joint-ai-workflow.md); recorded/live integration and field approval remain |

## Detection, AI and operational follow-ups

| Issue | Work | Stage |
| --- | --- | --- |
| [#151](https://github.com/Alan-Huangzy233/secagent-riskops/issues/151) | Expand network detections using verified source coverage and baselines | planned |
| [#149](https://github.com/Alan-Huangzy233/secagent-riskops/issues/149) | Qualify optional automatic AI analysis with bounded cost and throughput | later |
| [#152](https://github.com/Alan-Huangzy233/secagent-riskops/issues/152) | Bound telemetry receipt growth and validate long-term capacity | ongoing |
| [#153](https://github.com/Alan-Huangzy233/secagent-riskops/issues/153) | Complete deferred recovery, remote backup and key-lifecycle acceptance | deferred |
| [#154](https://github.com/Alan-Huangzy233/secagent-riskops/issues/154) | Add reviewed external notification transports and delivery operations | deferred |
| [#155](https://github.com/Alan-Huangzy233/secagent-riskops/issues/155) | Extend SOC briefings with priority groups, evidence links and export | later |
| [#169](https://github.com/Alan-Huangzy233/secagent-riskops/issues/169) | Maintain capability documentation, dependency health and repository hygiene | ongoing |

## Formal product foundations

| Issue | Work | Stage |
| --- | --- | --- |
| [#156](https://github.com/Alan-Huangzy233/secagent-riskops/issues/156) | Persist the product workflow, evidence and audit runtime | later |
| [#157](https://github.com/Alan-Huangzy233/secagent-riskops/issues/157) | Integrate live telemetry and agent contracts into the product SOC workflow | later |
| [#158](https://github.com/Alan-Huangzy233/secagent-riskops/issues/158) | Implement product sessions, roles and approval-service prerequisites | later |
| [#159](https://github.com/Alan-Huangzy233/secagent-riskops/issues/159) | Build the formal multi-user SOC and approval console | later |

## Later evidence, GRC and response workflows

| Issue | Work | Stage |
| --- | --- | --- |
| [#160](https://github.com/Alan-Huangzy233/secagent-riskops/issues/160) | Implement a managed GRC control library, risk register and evidence reports | later |
| [#161](https://github.com/Alan-Huangzy233/secagent-riskops/issues/161) | Implement reviewed knowledge lifecycle and feedback-driven tuning | later |
| [#162](https://github.com/Alan-Huangzy233/secagent-riskops/issues/162) | Implement governed external-intelligence ingestion and enrichment | later |
| [#163](https://github.com/Alan-Huangzy233/secagent-riskops/issues/163) | Implement secure document intake and reviewed defensive knowledge extraction | later |
| [#164](https://github.com/Alan-Huangzy233/secagent-riskops/issues/164) | Complete assessment authorization and Rules of Engagement service | later |
| [#165](https://github.com/Alan-Huangzy233/secagent-riskops/issues/165) | Implement authorized service discovery, web checks and scanner orchestration | later |
| [#166](https://github.com/Alan-Huangzy233/secagent-riskops/issues/166) | Implement real typed remediation adapters with verification and recovery | later |
| [#150](https://github.com/Alan-Huangzy233/secagent-riskops/issues/150) | Design and qualify policy-controlled automatic response | later |
| [#167](https://github.com/Alan-Huangzy233/secagent-riskops/issues/167) | Validate the full production evidence-to-remediation-and-knowledge workflow | later |

## Long-term exploration

| Issue | Work | Stage |
| --- | --- | --- |
| [#168](https://github.com/Alan-Huangzy233/secagent-riskops/issues/168) | Explore training labs reconstructed from reviewed pentest findings | exploration |

## Scope and completion rules

- Previously closed demo/design issues remain historical evidence. New production
  follow-ups link back to their original scope; closure of a narrowed demo task
  is not completion of the full product. Completed cache/layout, ingestion,
  scoring, notifications, backup serialization and demo evaluations are reused.
- The small joint-case pilot reads existing durable source stores and keeps
  derived observations in a separate, explicitly created store. This derived
  store is not a collector ACK participant; finite registration does not imply
  whole-deployment coverage. The pilot does not wait for a PostgreSQL migration,
  formal multi-user console or complete product rewrite.
- The formal identity/frontend scope still defers SSO, public self-registration,
  password-reset flows, multitenancy, realtime push and a dedicated mobile
  product. These remain design options, not new delivery promises.
- Operational recovery work explicitly preserves the decisions to defer NAS
  troubleshooting, replacement-host RPO/RTO exercises and an optional second
  offline encryption recipient. Old cleanup inventories are not current
  authorization to delete artifacts.
- A general model workflow does not automatically permit new outgoing fields,
  providers or spending. Automatic analysis, disposition and execution have
  separate activation boundaries; current advice never grants itself approval.
- Finding-derived labs start with reviewed synthetic internal reconstruction,
  then possibly reusable templates and isolated learner instances. Training is
  not production retest or compliance evidence by itself.
- Review implementation and deployment separately. Each code increment gets a
  focused PR, relevant local checks before upload and maintainer review before merge/release.
  This documentation sync changes no production service or model configuration.

See [production plan](production-plan.md), [implementation status](implementation-status.md)
and [roadmap](../ROADMAP.md). Refresh this inventory when a task completes, splits,
is explicitly deferred or gains a new verified prerequisite.
