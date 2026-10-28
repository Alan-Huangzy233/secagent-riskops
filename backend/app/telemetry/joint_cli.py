"""Bounded local joint commands, including an opt-in update tick; no API calls."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .joint_case_contract import CaseStoreError
from .joint_case_store import JointCaseStore, _identity, _path
from .joint_catalog import catalog_target, preflight_sources, read_catalog_page
from .joint_config import compile_joint_config
from .joint_reader_io import EvidenceReadError, ReadBudget
from .joint_reconcile import reconcile_step


def _separate(spec, *outputs):
    """Check lexical/symlink/hardlink aliases before any derived mutation."""
    try:
        for value in (spec.database_path, *outputs):
            if not isinstance(value, (str, Path)) or not str(value) or '\x00' in str(value):
                raise CaseStoreError('joint_invalid_request')
            try:
                str(value).encode('utf-8', errors='strict')
            except UnicodeError:
                raise CaseStoreError('joint_invalid_request') from None
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
            path = Path(value).resolve(strict=False)
            if path in sources:
                raise CaseStoreError('joint_source_alias')
            try:
                info = path.stat()
                if (info.st_dev, info.st_ino) in identities:
                    raise CaseStoreError('joint_source_alias')
            except FileNotFoundError:
                pass
        from .joint_refresh_state import reserved_paths
        protected = [Path(value).resolve(strict=False) for value in (spec.database_path, *outputs)]
        for reserved in reserved_paths(spec):
            resolved = reserved.resolve(strict=False)
            if resolved in sources or resolved in protected:
                raise CaseStoreError('joint_source_alias')
            try:
                info = reserved.stat()
                reserved_identity = (info.st_dev, info.st_ino)
            except FileNotFoundError:
                reserved_identity = None
            if reserved_identity is not None:
                if reserved_identity in identities:
                    raise CaseStoreError('joint_source_alias')
                for path in protected:
                    try:
                        info = path.stat()
                        if (info.st_dev, info.st_ino) == reserved_identity:
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


def refresh(spec):
    """One explicitly admitted refresh step; callers own the writer lock."""
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
    return reconcile_step(store, spec.network_database_path, spec.ssh_database_path)


def _run_spec(spec, command, *, output=None, input_path=None):
    """Implementation entered with a writer lock for mutating commands."""
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
        return {**base, **refresh(spec)}
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


def _private_parent(path):
    missing, directory = [], path.parent
    while not directory.exists():
        missing.append(directory)
        directory = directory.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)


def run(config, command, *, output=None, input_path=None):
    """No file access when disabled; serialize explicit writes with update ticks."""
    spec = compile_joint_config(config)
    if spec is None:
        return {'enabled': False, 'state': 'disabled'}
    if command == 'tick':
        from .joint_refresh import tick
        return tick(spec)
    if command not in ('check', 'init', 'discover', 'refresh', 'migrate-v1', 'snapshot', 'restore'):
        raise CaseStoreError('joint_invalid_request')
    _separate(spec, *((output,) if output is not None else ()),
              *((input_path,) if input_path is not None else ()))
    if command == 'check':
        return _run_spec(spec, command)
    from .joint_refresh_state import writer_lock
    if command == 'init':
        preflight_sources(spec)  # A bad source must not create a derived directory.
        _private_parent(_path(spec.database_path))
    elif command == 'restore':
        # Recovery can be requested after loss of the original derived store.
        _private_parent(_path(spec.database_path))
    else:
        try:
            _identity(_path(spec.database_path))
        except OSError:
            raise CaseStoreError('joint_store_unavailable') from None
    with writer_lock(spec):
        return _run_spec(spec, command, output=output, input_path=input_path)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('check', 'init', 'discover', 'refresh', 'tick'):
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
