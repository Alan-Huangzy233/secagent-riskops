"""One bounded local update step; no daemon, source writes or model calls."""
from __future__ import annotations

from datetime import timedelta
import time

from .joint_case_contract import CaseStoreError
from .joint_case_query import open_query
from .joint_catalog import preflight_sources
from .joint_reader_io import EvidenceReadError, ReadLimits
from .joint_reconcile import reconcile_step
from .joint_refresh_state import (binding, load_state, new_state, read_refresh_status,
                                  save_state, stamp, timestamp, utcnow, writer_lock)


def _status(spec):
    return open_query(spec.database_path, spec.scope, spec.limits,
                      catalog_min_seq=spec.catalog_min_seq).status()


def _id(value):
    return value['cycle_id'] if value else None


def _start(state, base):
    """Adopt unfinished manual work conservatively before starting a new round."""
    discovery, cycle = base['discovery'], base['cycle']
    state.update(phase='discover', discovery_id=None, refresh_id=None,
                 previous_discovery_id=_id(discovery), previous_refresh_id=_id(cycle),
                 qualified=True, resume_discovery=False)
    if cycle and not cycle['attempted_complete']:
        state.update(phase='refresh', refresh_id=_id(cycle), qualified=False)
    elif discovery and not discovery['complete']:
        state.update(discovery_id=_id(discovery), qualified=False)


def _realign(state, base):
    """Manual changes or interrupted metadata publication cannot invent success."""
    state.update(phase='idle', qualified=False, discovery_id=None, refresh_id=None,
                 resume_discovery=False, next_attempt_at=None)
    _start(state, base)


def _finish(state, spec, store, base, now):
    now = now or utcnow()
    cycle, discovery = base['cycle'], base['discovery']
    if not cycle or cycle['cycle_id'] != state['refresh_id']:
        raise CaseStoreError('joint_refresh_required')
    completed = timestamp(cycle['finished_at'])
    if completed > now:
        raise CaseStoreError('joint_refresh_required')
    state['last_complete_at'] = cycle['finished_at']
    state['previous_refresh_id'] = cycle['cycle_id']
    complete = (state['qualified'] and not state['resume_discovery'] and
                discovery is not None and _id(discovery) == state['discovery_id'] and
                discovery['complete'] and not discovery['error'] and
                completed >= timestamp(discovery['finished_at']) and
                cycle['all_items_refreshed'] and not base['revalidation_pending'])
    if complete:
        # A manual registration outside the frozen worklist must not be hidden.
        with store._connection() as db:
            complete = db.execute("SELECT 1 FROM joint_registrations WHERE refresh_state!='fresh' LIMIT 1").fetchone() is None
    if complete:
        state['last_success_at'] = cycle['finished_at']
    error = base.get('error')
    if not cycle['all_items_refreshed'] and error is None:
        error = 'joint_refresh_required'
    if error == 'joint_capacity_exceeded':
        state.update(state='blocked', error=error, qualified=False, next_attempt_at=None)
        return
    if state['resume_discovery']:
        # The failed catalog round remains finite and resumable. Re-check it on
        # the next step, without withholding old-anchor refresh indefinitely.
        state.update(phase='discover', refresh_id=None, qualified=False,
                     resume_discovery=False, state='backoff', error=error or state['error'],
                     next_attempt_at=stamp(now+timedelta(seconds=spec.refresh.retry_seconds)))
    else:
        state.update(phase='idle', qualified=False, refresh_id=None,
                     state='backoff' if error else 'waiting', error=error,
                     next_attempt_at=stamp((now if error else completed)+timedelta(seconds=(spec.refresh.retry_seconds if error
                                                                else spec.refresh.interval_seconds))))


def _capacity_failure(store):
    with store._connection() as db:
        if db.execute("SELECT 1 FROM joint_registrations WHERE fixed_error_code='joint_capacity_exceeded' LIMIT 1").fetchone():
            raise CaseStoreError('joint_capacity_exceeded')


def _discovery_step(spec, state, base):
    from .joint_cli import discover
    current = base['discovery']
    expected = state['discovery_id']
    if expected is not None and _id(current) != expected:
        _realign(state, base)
        return
    if expected is None and current and _id(current) != state['previous_discovery_id']:
        # The previous process committed begin_discovery/page but died before
        # checkpoint replacement. Resume its fixed barrier instead of reopening.
        state['discovery_id'] = _id(current)
    if current is not None and _id(current) == state['discovery_id'] and current['complete']:
        if current['error']:
            raise CaseStoreError(current['error'])
    else:
        current = discover(spec)['discovery']
        state['discovery_id'] = _id(current)
    if current['complete']:
        state.update(phase='refresh', refresh_id=None, previous_refresh_id=_id(base['cycle']))


def _refresh_step(spec, state, store, base, now):
    discovery, current = base['discovery'], base['cycle']
    if state['qualified'] and (not discovery or _id(discovery) != state['discovery_id'] or
                               not discovery['complete'] or discovery['error']):
        state['qualified'] = False
    if state['refresh_id'] is not None and _id(current) != state['refresh_id']:
        _realign(state, base)
        return
    if state['refresh_id'] is None:
        if current and _id(current) != state['previous_refresh_id']:
            state['refresh_id'] = _id(current)  # committed begin, checkpoint interrupted
        elif current and not current['attempted_complete']:
            state.update(refresh_id=_id(current), qualified=False)
        else:
            deadline = time.monotonic()+10.0
            # Even an empty recovered scope must validate both source schemas.
            if base['revalidation_pending'] or base['capacity']['registrations'] == 0:
                try:
                    preflight_sources(spec, limits=ReadLimits(deadline_seconds=5.0))
                except (CaseStoreError, EvidenceReadError) as error:
                    store.record_discovery_failure(error.code,
                        expected_cycle_id=_id(discovery),
                        expected_cursor=discovery['cursor_seq'] if discovery else None,
                        expected_revalidation_pending=base['revalidation_pending'],
                        expected_refresh_cycle_id=_id(current))
                    state['qualified'] = False
                    raise
            current = store.begin_cycle()
            state['refresh_id'] = _id(current)
            # Persist the cycle identity before any source read. A killed step
            # resumes exactly this frozen worklist; SQLite publishes with CAS.
            save_state(spec, state)
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                raise EvidenceReadError('query_deadline_exceeded')
            if not current['attempted_complete']:
                reconcile_step(store, spec.network_database_path, spec.ssh_database_path,
                               deadline_seconds=min(10.0, remaining))
            _capacity_failure(store)
            current = store.get_cycle()
            if current['attempted_complete']:
                _finish(state, spec, store, _status(spec), now)
            return
    if current['attempted_complete']:
        _finish(state, spec, store, base, now)
        return
    reconcile_step(store, spec.network_database_path, spec.ssh_database_path)
    _capacity_failure(store)
    current = store.get_cycle()
    if current and current['cycle_id'] == state['refresh_id'] and current['attempted_complete']:
        _finish(state, spec, store, _status(spec), now)


def _failure(state, spec, base, error, now):
    code = error.code
    next_attempt = (None if code == 'joint_capacity_exceeded' else
                    stamp(now+timedelta(seconds=spec.refresh.retry_seconds)))
    state.update(state='blocked' if code == 'joint_capacity_exceeded' else 'backoff', error=code,
                 qualified=False, next_attempt_at=next_attempt)
    if state['phase'] == 'discover' and base['capacity']['registrations'] and code != 'joint_capacity_exceeded':
        # A bad catalog page must not starve already registered anchors. This
        # degraded cycle cannot assert whole-round success or invent coverage.
        state.update(phase='refresh', resume_discovery=True, refresh_id=None,
                     discovery_id=_id(base['discovery']), previous_refresh_id=_id(base['cycle']))


def tick(spec, *, now=None):
    """Perform at most one discovery page or one refresh step, with a local lock.

    API reads never call this function. Disabled configurations do no I/O. A
    missing derived database must be explicitly initialized by the operator.
    """
    settings = getattr(spec, 'refresh', None) if spec is not None else None
    if settings is None or not settings.enabled:
        return {'enabled': False, 'state': 'disabled'}
    from .joint_cli import _open
    current_time = now or utcnow()
    _open(spec)  # no sidecar/lock creation for an absent or invalid derived store
    with writer_lock(spec):
        store = _open(spec)
        base = _status(spec)
        try:
            state = load_state(spec)
        except CaseStoreError:
            # Safe malformed JSON may be replaced, but save_state still rejects
            # unsafe permissions, symlinks, oversized files and foreign owners.
            state = None
        if state is None or state['binding'] != binding(spec, base):
            state = new_state(spec, base)
        if state['state'] == 'blocked':
            return read_refresh_status(spec, base, now=current_time)
        # A clock moving backwards cannot indefinitely postpone all work or
        # preserve a future success assertion.
        if any(state[key] and timestamp(state[key]) > current_time for key in
               ('last_attempt_at', 'last_complete_at', 'last_success_at')):
            state = new_state(spec, base)
        if state['next_attempt_at'] and timestamp(state['next_attempt_at']) > current_time:
            return read_refresh_status(spec, base, now=current_time)
        if state['phase'] == 'idle':
            _start(state, base)
        state.update(state='running', last_attempt_at=stamp(current_time), next_attempt_at=None)
        save_state(spec, state)  # no source work if checkpoint storage is unusable
        try:
            if state['phase'] == 'discover':
                _discovery_step(spec, state, base)
            else:
                _refresh_step(spec, state, store, base, now)
        except (CaseStoreError, EvidenceReadError) as error:
            _failure(state, spec, _status(spec), error, now or utcnow())
        else:
            if state['state'] == 'running':
                state.update(state='waiting', error=None)
        save_state(spec, state)
        return read_refresh_status(spec, _status(spec), now=now or utcnow())
