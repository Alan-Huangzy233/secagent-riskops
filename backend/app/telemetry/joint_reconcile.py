"""Explicit bounded refresh of registered anchors; no scheduling or activation.

Every cycle re-reads every registered anchor, including unchanged network
revisions, so retained SSH evidence arriving alone can change a joint case.
Source transactions finish before a short derived-store publication begins.
"""
from __future__ import annotations

from dataclasses import replace
import math
from pathlib import Path
import time

from .joint_case_contract import AnchorRequest, CaseStoreError, validate_read
from .joint_case_store import JointCaseStore
from .joint_reader import read_joint_evidence
from .joint_reader_io import EvidenceReadError, ReadLimits


def _separate_paths(store_path, *sources):
    """Reject resolved-path and hardlink aliases before any refresh write.

    These are trusted local paths, not a filesystem security boundary against an
    actor swapping files while the call runs. Store open validates database identity.
    """
    try:
        derived = Path(store_path).resolve(strict=True)
        identity = derived.stat()
        for source in sources:
            if not isinstance(source, (str, Path)) or not str(source) or '\x00' in str(source):
                raise CaseStoreError('joint_invalid_request')
            str(source).encode('utf-8', errors='strict')
            path = Path(source).expanduser().resolve(strict=False)
            if path == derived:
                raise CaseStoreError('joint_source_alias')
            try:
                current = path.stat()
            except FileNotFoundError:
                continue  # The source adapter records unavailable, never creates it.
            if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                raise CaseStoreError('joint_source_alias')
    except CaseStoreError:
        raise
    except UnicodeError:
        raise CaseStoreError('joint_invalid_request') from None
    except (OSError, RuntimeError, ValueError):
        raise CaseStoreError('joint_store_unavailable') from None


def reconcile_step(store: JointCaseStore, network_path: str | Path, ssh_path: str | Path, *,
                   max_items: int = 5, deadline_seconds: float = 10.0,
                   read_limits: ReadLimits | None = None) -> dict:
    """Attempt at most five frozen items; callers explicitly begin each cycle.

The cooperative deadline bounds admission and source reads, not filesystem I/O.
An in-flight read may finish with an error; its bounded outcome transaction is
still attempted so a bad source cannot permanently block the next anchor.
Derived-store write failures propagate and leave uncommitted work retryable.
Concurrent callers may duplicate a source read, but publication uses CAS.
cycle_id identifies the attempted cycle; current_cycle is the latest store
observation and may belong to a later cycle begun by another caller.
    """
    if (type(store) is not JointCaseStore or type(max_items) is not int or not 1 <= max_items <= 5
            or type(deadline_seconds) not in (int, float)
            or not 0 < deadline_seconds <= 10 or not math.isfinite(deadline_seconds)
            or (read_limits is not None and type(read_limits) is not ReadLimits)):
        raise CaseStoreError('joint_invalid_request')
    limits = read_limits or ReadLimits()
    _separate_paths(store.path, network_path, ssh_path)
    deadline = time.monotonic() + deadline_seconds
    outcomes = {key: 0 for key in ('published', 'unchanged', 'failed', 'not_eligible',
                                  'superseded', 'already_processed')}
    attempted = 0
    stopped_by_budget = False
    selected_cycle = None
    for _ in range(max_items):
        if time.monotonic() >= deadline:
            stopped_by_budget = True
            break
        item = store.next_item()
        if item is None:
            break
        if selected_cycle is None:
            selected_cycle = item.cycle_id
        elif item.cycle_id != selected_cycle:
            break  # Do not extend this step into a cycle begun by another caller.
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            stopped_by_budget = True
            break
        request = AnchorRequest(item.incident_id, item.network_revision)
        scope = store.scope
        try:
            result = read_joint_evidence(network_path, ssh_path, scope.mappings,
                item.incident_id, item.network_revision,
                limits=replace(limits, deadline_seconds=min(limits.deadline_seconds, remaining)),
                window_seconds=scope.window_seconds, max_timeline_records=scope.max_timeline_records,
                ssh_coverage=scope.ssh_coverage)
            validated = validate_read(scope, request, result, limits=store.limits)
        except EvidenceReadError as error:
            outcome = store.fail(item, error.code)
        except CaseStoreError as error:
            if error.code not in ('joint_result_invalid', 'joint_capacity_exceeded', 'joint_anchor_mismatch', 'joint_scope_mismatch'):
                raise
            outcome = store.fail(item, error.code)
        else:
            try:
                outcome = store.publish(item, validated)
            except CaseStoreError as error:
                if error.code not in ('joint_capacity_exceeded', 'joint_anchor_mismatch', 'joint_scope_mismatch', 'joint_result_invalid'):
                    raise
                outcome = store.fail(item, error.code)
        outcomes[outcome] += 1
        attempted += 1
    return {'scope': 'explicit_registered_anchors_only', 'cycle_id': selected_cycle,
            'attempted': attempted,
            'outcomes': outcomes, 'stopped_by_budget': stopped_by_budget,
            'current_cycle': store.get_cycle()}
