"""Explicit, bounded local joint observations; no daemon, scheduling or API calls."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .joint_case_contract import CaseStoreError
from .joint_case_store import JointCaseStore
from .joint_catalog import catalog_target, preflight_sources, read_catalog_page
from .joint_config import compile_joint_config
from .joint_reader_io import EvidenceReadError, ReadBudget
from .joint_reconcile import reconcile_step


def _separate(spec, *outputs):
    """Check lexical/symlink/hardlink aliases before any derived mutation."""
    try:
        sources = [Path(value).resolve(strict=False) for value in (
            spec.ssh_database_path, spec.network_database_path, spec.http_database_path) if value]
        identities = set()
        for source in sources:
            try:
                info = source.stat()
                identities.add((info.st_dev, info.st_ino))
            except FileNotFoundError:
                pass
        for value in (spec.database_path, *outputs):
            if not isinstance(value, (str, Path)) or not str(value) or '\x00' in str(value):
                raise CaseStoreError('joint_invalid_request')
            str(value).encode('utf-8', errors='strict')
            path = Path(value).resolve(strict=False)
            if path in sources:
                raise CaseStoreError('joint_source_alias')
            try:
                info = path.stat()
                if (info.st_dev, info.st_ino) in identities:
                    raise CaseStoreError('joint_source_alias')
            except FileNotFoundError:
                pass
    except CaseStoreError:
        raise
    except (OSError, RuntimeError, ValueError):
        raise CaseStoreError('joint_store_unavailable') from None


def _open(spec):
    store = JointCaseStore.open(spec.database_path)
    if (store.scope != spec.scope or store.limits != spec.limits or store.catalog_min_seq != spec.catalog_min_seq):
        raise CaseStoreError('joint_scope_mismatch')
    return store


def discover(spec, *, limit=50):
    """One page per invocation; source transaction closes before publication."""
    _separate(spec)
    store = _open(spec)
    budget = ReadBudget()
    current = store.get_discovery()
    if current is None or current['complete']:
        try:
            target = catalog_target(spec.network_database_path, spec, budget=budget)
            current = store.begin_discovery(target, spec.scope.producer_id)
        except (CaseStoreError, EvidenceReadError) as error:
            store.record_discovery_failure(error.code,
                expected_cycle_id=current['cycle_id'] if current else None,
                expected_cursor=current['cursor_seq'] if current else None)
            raise
    if current['complete']:
        return {'outcome': 'completed', 'discovery': current}
    try:
        page = read_catalog_page(spec.network_database_path, spec,
            after_seq=current['cursor_seq'], target_seq=current['target_seq'], limit=limit, budget=budget)
        outcome = store.apply_discovery_page(current['cycle_id'], current['cursor_seq'], page)
    except (CaseStoreError, EvidenceReadError) as error:
        store.fail_discovery(current['cycle_id'], current['cursor_seq'], error.code)
        raise
    return {'outcome': outcome, 'discovery': store.get_discovery()}


def run(config, command, *, output=None, input_path=None):
    """No source/store I/O when disabled. Returned summaries contain no paths."""
    spec = compile_joint_config(config)
    if spec is None:
        return {'enabled': False, 'state': 'disabled'}
    _separate(spec, *((output,) if output is not None else ()),
              *((input_path,) if input_path is not None else ()))
    base = {'enabled': True, 'command': command, 'scope': 'explicit_registered_anchors_only'}
    if command == 'check':
        result = preflight_sources(spec)
        if Path(spec.database_path).exists():
            _open(spec)
            result['store'] = 'available'
        else:
            result['store'] = 'not_initialized'
        return {**base, **result}
    if command == 'init':
        preflight_sources(spec)
        JointCaseStore.create(spec.database_path, spec.scope, limits=spec.limits,
                              catalog_min_seq=spec.catalog_min_seq)
        return {**base, 'state': 'initialized'}
    if command == 'discover':
        return {**base, **discover(spec)}
    if command == 'refresh':
        store = _open(spec)
        from .joint_case_query import open_query
        status = open_query(spec.database_path, spec.scope, spec.limits,
                            catalog_min_seq=spec.catalog_min_seq).status()
        if status['revalidation_pending']:
            observed_discovery = status['discovery']
            try:
                preflight_sources(spec)
            except (CaseStoreError, EvidenceReadError) as error:
                store.record_discovery_failure(error.code,
                    expected_cycle_id=observed_discovery['cycle_id'] if observed_discovery else None,
                    expected_cursor=observed_discovery['cursor_seq'] if observed_discovery else None,
                    expected_revalidation_pending=status['revalidation_pending'],
                    expected_refresh_cycle_id=status['cycle']['cycle_id'] if status['cycle'] else None)
                raise
        store.begin_cycle()
        return {**base, **reconcile_step(store, spec.network_database_path, spec.ssh_database_path)}
    if command in ('migrate-v1', 'snapshot', 'restore'):
        # Imported only for an explicit offline operation; normal reads do not
        # expose a writable migration constructor through the API.
        from .joint_case_migration import migrate_v1, restore_store, snapshot_store
        if output is None or (command == 'restore' and input_path is None):
            raise CaseStoreError('joint_invalid_request')
        if command == 'migrate-v1':
            migrate_v1(spec.database_path, output, catalog_min_seq=spec.catalog_min_seq,
                       expected_scope=spec.scope, expected_limits=spec.limits)
        elif command == 'snapshot':
            _open(spec)
            snapshot_store(spec.database_path, output)
        else:
            restore_store(input_path, output, expected_scope=spec.scope,
                          expected_limits=spec.limits, catalog_min_seq=spec.catalog_min_seq)
        return {**base, 'state': 'completed', 'activation': 'explicit_config_change_required'}
    raise CaseStoreError('joint_invalid_request')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('check', 'init', 'discover', 'refresh'):
        sub.add_parser(command)
    for command in ('migrate-v1', 'snapshot', 'restore'):
        option = sub.add_parser(command)
        option.add_argument('--output', required=True)
        if command == 'restore':
            option.add_argument('--input', required=True)
    args = parser.parse_args(argv)
    try:
        from .config import load_config
        config = load_config(args.config)
        result = run(config, args.command, output=getattr(args, 'output', None),
                     input_path=getattr(args, 'input', None))
    except (CaseStoreError, EvidenceReadError) as error:
        print(json.dumps({'ok': False, 'error': error.code}, sort_keys=True))
        return 2
    except (OSError, ValueError, RuntimeError):
        print(json.dumps({'ok': False, 'error': 'joint_invalid_request'}, sort_keys=True))
        return 2
    print(json.dumps({'ok': True, **result}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
