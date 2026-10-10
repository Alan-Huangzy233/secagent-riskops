# Console notifications and daily briefings

The live SSH console has a persistent, shared operator inbox. It shows
attention-worthy incidents, collection failures and recovery, recent collection
gaps, disk capacity warnings and UTC daily briefings. This is the first
production notification channel; no email, webhook, external API or model is
called. Reading a notification never acknowledges, resolves or blocks an
incident. A historical notification links to the incident's current detail.

## Delivery and noise control

A background worker runs while the API service is up, even with no browser
open. It normally checks every 30 seconds. Incident candidates enter the outbox
in the same transaction as their new evidence. A bounded, rotating scan of 200
scored incidents per cycle also covers existing history and score backfills.
Before delivery it checks the canonical incident is still pending and its
score is current and attention-worthy. Merged, handled or unscored pending
candidates are cancelled; delivered history stays available. The console labels
incident scores as their value when the notification was generated. Open the
incident for its current assessment after a score correction or new evidence.

The outbox coalesces updates by topic. Unchanged evidence never produces another
notification, including after replay or restart. New evidence of the same
priority has a one-hour cooldown; the pending payload contains the latest
summary. A priority increase bypasses the cooldown. Condition recovery and a
fresh failure after recovery are visible immediately. Collection alerts include
source read failure, a heartbeat timeout, a prolonged backlog and gaps recorded
in the last 24 hours. Older gaps remain in the existing collection timeline.

A cycle delivers at most 50 items. Inbox insertion and delivery acknowledgement
are one SQLite transaction, with a unique topic/revision pair. Failed local
writes roll back and retry from 30 seconds up to one hour; retries and errors
survive restart. This guarantee covers the local console channel. A future
external transport will need its own delivery semantics and authorization.

The console displays unread counts, pending/retrying counts, the worker's last
successful run and any error. An API health response alone does not prove that
the notification worker is current. Read state is shared by the existing single
operator identity; this does not implement per-user inboxes or multi-tenancy.

## Daily briefings

A report covers one completed UTC calendar day. It counts retained log records
by event time, new canonical incidents by creation time, their scores at report
generation, and recorded collection gaps. Counts describe collected data, not
attack counts or detection accuracy. Low and unscored incidents remain visible
in the totals.

The first run summarizes the previous day. After downtime it catches up one day
at a time within raw-log retention, explicitly reporting skipped older days.
Log aggregation reads 1,000 records per page using the existing time index,
without holding a write lock. A received-at cutoff excludes subsequent late
arrivals; a persisted keyset cursor and compare-and-set checkpoint allow restart
and concurrent workers without double counting. A worker with a report in
progress resumes after one second. Query failures do not stop urgent delivery.
The completed briefing is an immutable snapshot: late logs, deletion by retention
and collection gaps can affect completeness. The report states that limitation
and records its data cutoff and generation time.

## Configuration and operational monitoring

Existing configuration files remain valid:

```json
{
  "notifications_enabled": true,
  "notification_backup_directories": []
}
```

These are additional fields on the existing live configuration, not a complete
configuration file. `notifications_enabled=false` stops the worker while
preserving queued and delivered records. Evidence ingestion can still enqueue
candidates so re-enabling does not lose them.

Capacity monitoring checks the database filesystem and reports when free space
is below 10% or 1 GiB. Optional backup directories must be absolute paths and
readable/listable by the API service account. Configure each database's backup
directory separately. The monitor recognizes only nonempty, nonsymlink
`live-YYYYMMDDTHHMMSSffffff.sqlite` files, the verified names atomically published
by `backup_telemetry.py`; temporary copies do not qualify. No published snapshot
in 36 hours means stale. An inaccessible directory means unknown, not healthy.
The monitor does not read backup contents or prove offsite replication or a
successful restore. With no directories configured the UI explicitly shows that
backup monitoring is unconfigured. No filesystem permissions are changed by
this feature.

## API and rollout

- `GET /api/notifications?page=1&limit=20&unread=false&kind=briefing` lists the
  inbox. `kind` is optional and accepts incident, collection, health or briefing.
- `POST /api/notifications/read` takes `{"ids":[1,2]}` (1–100 IDs). It requires
  operator authentication, the existing CSRF header and same-origin checks.
- Both reading and writing require operator authentication; collector bearer
  tokens cannot access the inbox.

Use the existing new-release, backup and atomic-switch procedure after review.
Include the notification module, store, configuration, dashboard and live API.
The three notification tables and their indexes are additive. An older scoring
release ignores them and can continue collection. Re-upgrading resumes the
queue and scans current eligible history. No destructive migration or raw-log
rewrite is required. Production settings and data stay outside the public repo.

Validation covers restart/replay, parallel workers, cooldown and escalation,
handled/merged/stale-score cancellation, partial-write rollback and retries,
collection/health recovery, UTC totals, paged aggregation with late arrivals,
authentication/CSRF, and safe rendering/read actions.
