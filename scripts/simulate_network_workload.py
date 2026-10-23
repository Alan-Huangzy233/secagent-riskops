#!/usr/bin/env python3
"""Measure authored network backlog handling in temporary SQLite databases.

Three fictional sources exercise parser, paged durable ingestion, NetworkWorker,
console delivery and reopening/replay. No host commands, sockets, real logs,
production configuration or model calls are used. This measures an engineering
budget on the current machine; it is not a detection accuracy benchmark.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import resource
import sys
from tempfile import TemporaryDirectory
import threading
import time
from types import SimpleNamespace

from app.telemetry.network_parse import FULL_GUARD, SourceProfile
from app.telemetry.network_protocol import decode, encode, journal_entry
from app.telemetry.network_store import NetworkStore
from app.telemetry.network_worker import NetworkWorker
from app.telemetry.store import TelemetryStore

SAMPLE_SECONDS = .01
SOURCE_IDS = ('synthetic-tcp-v4', 'synthetic-tcp-v6', 'synthetic-udp-observation')


def profiles(now_us):
    result = []
    for index, identity in enumerate(SOURCE_IDS):
        tcp = index < 2
        result.append(SourceProfile(source_id=identity, ruleset_sha256=str(index + 1) * 64,
            log_labels=('[UFW BLOCK]',) if tcp else ('synthetic-observe:',),
            ip_families=(6,) if index == 1 else (4,),
            rejection_labels=('[UFW BLOCK]',) if tcp else (),
            local_input_labels=('[UFW BLOCK]',) if tcp else (),
            local_input_interfaces=('eth0',) if tcp else (),
            logging_limit='rate_limited' if tcp else 'unknown', retention='unknown',
            guard_version=FULL_GUARD, profile_valid_from_us=now_us - 7 * 86_400_000_000))
    return result


def record(source, index, total, now_us):
    """Ten authored distinct-port SYNs and fifty same-port SYNs per TCP hour."""
    group, position = divmod(index, 60)
    probe = source < 2 and position < 10
    peer = 9 if probe else 10
    if source == 1:
        address, destination = f'2001:db8:1::{peer}', '2001:db8:2::20'
    else:
        address, destination = f'198.51.100.{peer}', '192.0.2.20'
    label, protocol = ('[UFW BLOCK]', 'TCP') if source < 2 else ('synthetic-observe:', 'UDP')
    port = 8000 + position if probe else (443 if source < 2 else 9000 + index % 32)
    message = (f'{label} IN=eth0 OUT= SRC={address} DST={destination} '
               f'LEN=60 PROTO={protocol} SPT=45000 DPT={port}')
    if source < 2:
        message += ' WINDOW=1024 RES=0x00 SYN URGP=0'
    offset_us = (group * 3600 + position) * 1_000_000
    return {'_TRANSPORT': 'kernel', '_BOOT_ID': str(source + 1) * 32,
        '__CURSOR': f'authored-workload-{source}-{index}',
        '__REALTIME_TIMESTAMP': str(now_us - math.ceil(total / 60) * 3_600_000_000 + offset_us),
        '__MONOTONIC_TIMESTAMP': str(900_000_000 + offset_us), 'MESSAGE': message}


class FileSampler:
    """Sample simultaneous file usage; brief WAL peaks may fall between samples."""

    def __init__(self, root):
        self.paths = {name + suffix: root / (name + suffix)
                      for name in ('network.sqlite', 'console.sqlite')
                      for suffix in ('', '-wal', '-shm')}
        self.peaks = dict.fromkeys(self.paths, 0)
        self.simultaneous_peak = self.samples = 0
        self.failure = None
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def sample(self):
        with self.lock:
            current = {}
            for name, path in self.paths.items():
                try:
                    current[name] = path.stat().st_size
                except FileNotFoundError:
                    current[name] = 0
                self.peaks[name] = max(self.peaks[name], current[name])
            self.samples += 1
            self.simultaneous_peak = max(self.simultaneous_peak, sum(current.values()))

    def run(self):
        try:
            while not self.stop.wait(SAMPLE_SECONDS):
                self.sample()
        except Exception as exc:
            self.failure = exc

    def close(self):
        self.stop.set()
        self.thread.join(timeout=5)
        if self.thread.is_alive() or self.failure:
            raise AssertionError('Workload file sampler did not finish successfully')
        self.sample()


def budget_result(metrics, seconds, rss_mib):
    checks = {'elapsed_seconds': metrics['elapsed_seconds'] <= seconds,
              'process_peak_rss_bytes': metrics['process_peak_rss_bytes'] <= rss_mib * 1024 * 1024}
    return {'elapsed_seconds_limit': seconds, 'process_peak_rss_mib_limit': rss_mib,
            'checks': checks, 'passed': all(checks.values())}


def simulate(*, records=3000, page_size=100, backlog_pages=3,
             budget_seconds=60, budget_rss_mib=512):
    for name, value, low, high in (('records', records, 90, 10000),
            ('page_size', page_size, 1, 200), ('backlog_pages', backlog_pages, 1, 10000)):
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f'{name} must be an integer between {low} and {high}')
    for name, value in (('budget_seconds', budget_seconds), ('budget_rss_mib', budget_rss_mib)):
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise ValueError(f'{name} must be finite and positive')
    began, cpu_began = time.monotonic(), time.process_time()
    now_us = time.time_ns() // 1000
    now = now_us / 1_000_000
    selected = profiles(now_us)
    totals = [records // 3 + (index < records % 3) for index in range(3)]
    batch_count = tick_count = peak_backlog = 0
    first_batches, cursors, acknowledgements = {}, {}, {}
    with TemporaryDirectory(prefix='riskops-network-workload-') as directory:
        root = Path(directory)
        sampler = FileSampler(root)
        sampler.thread.start()
        worker = None
        try:
            store = NetworkStore(root / 'network.sqlite')
            console = TelemetryStore(str(root / 'console.sqlite'))
            worker = NetworkWorker(store, console,
                sources=tuple(SimpleNamespace(id=item.source_id) for item in selected))
            baseline = store.status()

            def observe():
                nonlocal peak_backlog
                state = store.analysis_status()
                peak_backlog = max(peak_backlog,
                    store.status()['counts']['receipts'] - state['analyzed_input_records'])
                sampler.sample()
                return state

            def tick():
                nonlocal tick_count
                tick_count += 1
                result = worker.tick(now=now)
                observe()
                return result

            for start in range(0, max(totals), page_size):
                for source, profile in enumerate(selected):
                    stop = min(totals[source], start + page_size)
                    if start >= stop:
                        continue
                    rows = [record(source, index, totals[source], now_us) for index in range(start, stop)]
                    caught_up = stop == totals[source]
                    body = {'version': 1, 'source_id': profile.source_id,
                        'profile_revision': profile.revision, 'batch_id': f'authored-{source}-{start}',
                        'collected_at_us': now_us, 'cursor_before': cursors.get(profile.source_id),
                        'cursor_after': rows[-1]['__CURSOR'],
                        'entries': [journal_entry(row, profile) for row in rows],
                        'reports': [] if caught_up else ['catching_up'], 'caught_up': caught_up}
                    # Exercise serialized boundaries while retaining only one replay page per source.
                    body = decode(encode(body))
                    assert all('event' in item for item in body['entries'])
                    ack = store.ingest(body, profile, now_us=now_us)
                    assert ack['accepted'] == len(rows) and ack['rejected'] == ack['duplicates'] == 0
                    if profile.source_id not in first_batches:
                        first_batches[profile.source_id] = body
                        acknowledgements[profile.source_id] = ack
                    cursors[profile.source_id] = body['cursor_after']
                    batch_count += 1
                    observe()
                    if batch_count % backlog_pages == 0:
                        tick()

            drain_started = time.monotonic()
            for _ in range(records * 2 + 100):
                if tick()['caught_up']:
                    break
            else:
                raise AssertionError('Bounded network worker failed to drain authored input')
            drain_seconds = time.monotonic() - drain_started
            state = observe()
            assert not state['pending'] and state['analyzed_input_records'] == records
            assert state['missing_raw_records'] == 0 and not state['coverage_issues']
            console.run_notifications([], now=now)

            cases, page = [], 1
            while True:
                result = store.incidents(page=page, limit=100)
                cases.extend(result['items'])
                if page == result['total_pages']:
                    break
                page += 1
            expected_cases = sum(total // 60 + (total % 60 >= 10) for total in totals[:2])
            assert len(cases) == expected_cases
            assert all(case['source_id'] != SOURCE_IDS[2] and case['active'] and not case['stale']
                       for case in cases)
            assert all(case['src_ip'] in ('198.51.100.9', '2001:db8:1::9') for case in cases)
            notices = console.list_notifications(kind='network_incident')['total']
            assert notices == len(cases)

            paged_counts = {}
            for profile, total in zip(selected, totals):
                after, snapshot, seen = 0, None, set()
                while True:
                    result = store.page(profile.source_id, after=after, snapshot=snapshot, limit=37)
                    for row in result['items']:
                        assert row['event_id'] not in seen
                        seen.add(row['event_id'])
                        if profile.source_id == SOURCE_IDS[2]:
                            assert row['direction'] == 'unknown' and not row['rejection_related']
                    if not result['has_more']:
                        break
                    assert result['next_after'] > after
                    after, snapshot = result['next_after'], result['snapshot']
                assert len(seen) == total
                paged_counts[profile.source_id] = len(seen)

            before_replay = store.status()
            source_before = store.sources()
            worker.close()
            store = NetworkStore(root / 'network.sqlite')
            console = TelemetryStore(str(root / 'console.sqlite'))
            worker = NetworkWorker(store, console,
                sources=tuple(SimpleNamespace(id=item.source_id) for item in selected))
            for profile in selected:
                assert store.ingest(first_batches[profile.source_id], profile, now_us=now_us + 1) == acknowledgements[profile.source_id]
            assert tick()['caught_up']
            console.run_notifications([], now=now + 1)
            assert store.status()['counts'] == before_replay['counts']
            assert store.sources() == source_before
            assert store.analysis_status()['analyzed_input_records'] == records
            assert [store.incident(case['incident_id']) for case in cases] == cases
            assert console.list_notifications(kind='network_incident')['total'] == notices
            assert console.list_events() == []
            final = store.status()
            assert final['counts']['events'] == final['counts']['receipts'] == records
            assert final['counts']['batches'] == batch_count
        finally:
            if worker is not None:
                worker.close()
            sampler.close()

        usage = resource.getrusage(resource.RUSAGE_SELF)
        metrics = {'elapsed_seconds': round(time.monotonic() - began, 4),
            'cpu_seconds': round(time.process_time() - cpu_began, 4),
            'process_peak_rss_bytes': int(usage.ru_maxrss * (1 if sys.platform == 'darwin' else 1024)),
            'final_drain_seconds': round(drain_seconds, 4), 'worker_ticks': tick_count,
            'peak_unanalyzed_receipts': peak_backlog, 'file_sample_interval_seconds': SAMPLE_SECONDS,
            'file_samples': sampler.samples, 'file_sampled_peaks_bytes': sampler.peaks,
            'managed_files_simultaneous_sampled_peak_bytes': sampler.simultaneous_peak,
            'network_database_bytes_before': baseline['database_bytes'],
            'network_database_bytes_after': final['database_bytes'],
            'network_wal_bytes_after': final['wal_bytes'],
            'network_pages_before': baseline['page_count'], 'network_pages_after': final['page_count'],
            'network_page_limit': final['page_limit'],
            'receipt_growth': final['counts']['receipts'] - baseline['counts']['receipts'],
            'batch_growth': final['counts']['batches'] - baseline['counts']['batches']}
        return {'mode': 'isolated_synthetic_network_workload', 'input_records': records,
            'source_records': paged_counts, 'page_size': page_size, 'backlog_pages': backlog_pages,
            'incidents': len(cases), 'console_incident_notifications': notices,
            'udp_observation_incidents': 0, 'analysis_drained': True,
            'reopened_store_replay_identical': True, 'replay_added_receipts': 0,
            'replay_added_batches': 0, 'replay_added_notifications': 0,
            'production_writes': False, 'model_calls': 0, 'metrics': metrics,
            'budget': budget_result(metrics, budget_seconds, budget_rss_mib),
            'limitations': [
                'Entirely authored records; no real records were relabeled or used as a fixture.',
                'This is a local engineering budget measurement, not a detection accuracy benchmark.',
                'Direct parser/store/worker calls do not measure remote export, SSH, TLS, journal provenance or source CPU.',
                'Reopening storage and replacing workers checks durable replay, not abrupt process death or restore.',
                'Peak RSS covers this whole process lifetime; invoke CLI in a fresh process for comparable measurements.',
                'File sizes are sampled and can miss brief WAL peaks; raw receipts and batches continue growing until capacity stop.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--records', type=int, default=3000)
    parser.add_argument('--page-size', type=int, default=100)
    parser.add_argument('--backlog-pages', type=int, default=3)
    parser.add_argument('--budget-seconds', type=float, default=60)
    parser.add_argument('--budget-rss-mib', type=float, default=512)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    result = simulate(records=args.records, page_size=args.page_size, backlog_pages=args.backlog_pages,
                      budget_seconds=args.budget_seconds, budget_rss_mib=args.budget_rss_mib)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['budget']['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
