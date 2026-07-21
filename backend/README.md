# Backend

FastAPI + Pydantic backend for SecAgent RiskOps. The `v0.2` walking skeleton is
implemented here; see [../docs/implementation-status.md](../docs/implementation-status.md).

## Layout

```text
app/
  core/         clock, deterministic IDs, content/canonical hashing
  schemas/      Pydantic domain contracts + enums
  storage/      Repository (in-memory / SQLite), evidence vault, audit log
  runtime/      Flow / Task / Step / ToolCall workflow runtime
  policy/       deterministic, fail-closed policy engine + reason codes
  agents/       AgentContract boundary + deterministic triage agent
  tools/        typed action/executor catalog
  pipeline/     ingest -> soc -> grc -> remediation stages
  api/          FastAPI application
  authorization.py  immutable, hash-bound assessment scope
  orchestrator.py   end-to-end flow assembly
  replay.py         replay from retained evidence
  demo.py           runnable end-to-end demo / CI smoke
tests/          pytest suite (incl. adversarial scope enforcement)
```

## Stack

- **Now:** FastAPI, Pydantic v2, SQLite (stdlib) behind the `Repository` interface.
- **Target:** PostgreSQL + Alembic migrations (swap the repository backend; the
  pipeline is unaffected).

## Run

```bash
pip install -e .[dev]     # from repo root
pytest                    # tests
python -m app.demo        # end-to-end demo (PYTHONPATH=backend, or run from backend/)
uvicorn app.api.app:app --app-dir backend --reload
```
