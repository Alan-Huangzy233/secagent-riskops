"""Read-only local previews of saved joint evidence; no provider or queue access."""
from __future__ import annotations

from .ai_summary import Aliases
from .joint_ai_summary import SnapshotContext, build
from .joint_case_query import open_query
from .joint_refresh_state import read_refresh_status, stamp, timestamp, utcnow


class JointPreviewError(ValueError):
    """Fixed retry instruction without private evidence or storage details."""

    code = 'joint_preview_changed'

    def __init__(self):
        super().__init__(self.code)


def _freshness(snapshot, refresh, now):
    status, current = snapshot.status, snapshot.detail['current']
    success = current['last_success']
    # Neither a recent row timestamp nor a running scheduler proves freshness.
    if (not refresh['enabled'] or refresh['error'] or
            refresh['state'] in ('not_started', 'disabled', 'unavailable') or
            not refresh['last_success_at'] or not success):
        return 'unknown'
    completed = timestamp(success)
    if completed > now:
        return 'unknown'
    if (refresh['stale'] or refresh['stalled'] or
            (now-completed).total_seconds() > refresh['stale_after_seconds'] or
            refresh['state'] != 'waiting' or refresh['phase'] != 'idle'):
        return 'stale'
    if (status['state'] == 'ready' and not status['error'] and
            not status['revalidation_pending'] and current['refresh_state'] == 'fresh' and
            not current['error']):
        return 'current'
    return 'unknown'


def preview(spec, case_id, revision, aliases: Aliases, *, now=None):
    """Build from one pinned DB read and reject changes detected by a second read.

    Refresh checkpoints are separate files, so this is an optimistic stability
    check, not a cross-store atomic snapshot. The result describes captured_at;
    a later submission or result display must independently revalidate it.
    """
    captured = now or utcnow()
    query = open_query(spec.database_path, spec.scope, spec.limits,
                       catalog_min_seq=spec.catalog_min_seq)
    first = query.ai_snapshot(case_id, revision)
    if first is None:
        return None
    refresh = read_refresh_status(spec, first.status, now=captured)
    current, status = first.detail['current'], first.status
    context = SnapshotContext(
        store_id=status['store_id'], query_epoch=status['query_epoch'],
        case_id=case_id, case_revision=revision, current_revision=current['revision'],
        refresh_state=current['refresh_state'],
        refresh_error=bool(current['error'] or status['error'] or refresh['error']),
        freshness=_freshness(first, refresh, captured),
        revalidation_pending=status['revalidation_pending'],
    )
    result = build(first.observation, spec.scope, context, aliases)
    second = query.ai_snapshot(case_id, revision)
    if second != first or read_refresh_status(spec, second.status, now=captured) != refresh:
        raise JointPreviewError()
    result['preview'] = {'version': 'joint-preview-v1', 'mode': 'local',
                         'external_calls': False, 'captured_at': stamp(captured)}
    return result
