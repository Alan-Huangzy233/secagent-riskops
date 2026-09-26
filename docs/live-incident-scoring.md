# Live incident prioritisation

The SSH telemetry pilot retains its existing durable event/batch deduplication
and evidence-based, cross-source incident correlation. It now scores those
incidents with the shared deterministic weights in `app.reduction.score`.
It does **not** run the offline evaluation's whole-stream reducer on each batch
or introduce its one-hour proximity merge: existing incident IDs, evidence,
operator decisions and merged aliases retain their meaning.

## Console and API

The console defaults to **all pending incidents, ordered by score**. A filter
can show attention-worthy incidents plus unscored history, low-scoring incidents,
or unscored history alone. Unknown scores sort before known scores, then scores
descend, with recency and incident ID as stable tie-breakers. The counts beside
the filter cover the selected source and operator state, before score filtering.

Each incident's `assessment` contains the score, priority, threshold, reasons,
version and `scored` / `unscored` status. Low scores are retained, remain directly
addressable and never change operator state. This is prioritisation, not an
attack probability or an automatic dismissal/blocking decision.

- `GET /api/incidents`: `focus=all|attention|low|unscored`, `sort=recent|score`.
- `GET /api/dashboard`: corresponding `incident_focus` and `incident_sort`.
- Existing API callers default to all incidents sorted by recency.
- Both paginated and legacy offset lists accept the filters; detail and evidence
  endpoints remain available regardless of score.

## Signals and production differences

| Evidence signal | Points |
|---|---:|
| A successful login among correlated failures | +50 |
| Existing non-root accounts attempted | +12 each, up to three |
| Two or more monitored hosts | +10 |
| At least ten failures over two hours | +15 |
| At least fifty failure records | +5 |

Attention threshold: 25; P3: 25–39, P2: 40–59, P1: 60+.

Scores use **all retained incident evidence**, not the first 20 displayed rows.
Failure counts count log records, not distinct connections. Explicit `invalid
user` / `illegal user` messages disqualify an account even when the parser
classifies a `Failed password for invalid user ...` line as `auth_failure`.
Legacy failure kinds count toward volume but do not assert account existence.

Unlike the synthetic evaluation, live scoring does not subtract 40 points for
an earlier successful login. Prior success does not establish trust, source IPs
can be shared, and collection/retention gaps make an absent history inconclusive.
The API explicitly reports `known_source_discount: false`. Published demo
metrics do not measure this live adaptation; no production precision or miss
rate is claimed.

## Persistence, historical backfill and rollback

`incident_scores` is an additive, versioned derived table. Scores update in the
same transaction as changed incident evidence. Failed transactions are retried
through the existing collector spool/ACK protocol; replay never inflates scores.
Retained evidence preserves scores after raw logs expire and after restart.
Merges refresh the surviving identity; old aliases resolve to that identity.

Startup creates the empty table without scanning historical evidence. Existing
incidents remain visibly unscored until they change or an operator runs:

```bash
python scripts/backfill_incident_scores.py --database /absolute/path/live.sqlite
python scripts/backfill_incident_scores.py --database /absolute/path/live.sqlite --apply --limit 50
```

The first command is read-only. Each apply call fills at most 50 missing or
outdated projections in one transaction; repeat until `batch.scored` is zero.
Start with a limit of one on a large database and measure before raising it.
The limit bounds incidents, not evidence per incident or wall-clock time.
Rows with no retained evidence stay unscored and appear in `without_evidence`.
No API endpoint triggers backfill and GET requests do not score evidence.

Deploy as a new release with the existing backup/atomic-switch procedure.
Include `backend/app/reduction/{__init__,dedup,correlate,score}.py`, the new
telemetry scoring module, the updated store/API/dashboard and the backfill
script. No new Python dependency, credentials, source-host change or model call
is required. Backfill is separate from service activation.

An older release ignores the additive table. Small evidence triggers invalidate
scores on insert, update and delete, including edits made by an older release
after rollback. On re-upgrade those incidents stay visibly unscored until
refreshed or backfilled, even when a parser correction kept the same evidence
count. Unknown scoring versions are also treated as unscored. No raw evidence,
receipts, incident identity or triage history needs to be reverted.
