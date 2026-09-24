# Safety demo inputs

Everything here is synthetic. It is read by `python -m app.safety_demo`
(`make safety`); see [docs/safety-demo.md](../../docs/safety-demo.md).

| Path | What it is |
|---|---|
| `incidents/INC-A0004561.json`, `incidents/INC-A0003598.json` | The dossiers of two incidents from the seven-day synthetic evaluation, exactly as they were sent to the model. Each hashes to a recorded call in `docs/eval/triage-tape-synthetic-7d.jsonl`; the demo refuses a dossier that does not. |
| `lab/bastion-01/` | A lab copy of bastion-01: a Debian-style `sshd_config` with root and password logins on, and an unrelated drop-in. |
| `lab/web-02/` | A lab copy of web-02 in the Ubuntu cloud-image layout, where cloud-init's `50-cloud-init.conf` turns password logins on before the main file is read. |
| `audit-timeline.jsonl` | The audit chain the demo exports. CI checks that a fresh run reproduces it byte for byte. |

The `.riskops-lab` file in each lab copy names the asset. The executor refuses
a directory without it, or one that names a different asset. The demo copies
the lab directories into a temporary directory before changing anything, so
the files here are never edited.

The dossiers were written from a rebuild of the seven-day dataset
(`python -m app.evaluation.synthetic --days 7 --verify examples/synthetic-sshd/manifest-7d.json`)
with `app.evaluation.triage.surfaced_cases`.
