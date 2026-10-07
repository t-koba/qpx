#!/usr/bin/env python3
"""Read complete process-tree descriptor data, including non-dumpable servers."""

import csv
import json
import os
from pathlib import Path
import sys
import time


def descriptors(root, include_targets=False):
    seen = set()
    pending = [root]
    records = []
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        base = Path('/proc') / pid
        try:
            for task in (base / 'task').iterdir():
                try:
                    pending.extend((task / 'children').read_text().split())
                except FileNotFoundError:
                    # A completed thread does not invalidate its live process.
                    continue
            for fd in (base / 'fd').iterdir():
                record = {'pid': int(pid), 'fd': int(fd.name)}
                if include_targets:
                    try:
                        record['target'] = os.readlink(fd)
                    except FileNotFoundError:
                        continue
                records.append(record)
        except FileNotFoundError:
            continue
    if not records:
        raise RuntimeError('process descriptor snapshot is empty')
    return records


def rss(root):
    pending = [root]
    seen = set()
    totals = {field: 0 for field in ("VmRSS", "RssAnon", "RssFile", "RssShmem")}
    measured = 0
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        base = Path('/proc') / pid
        try:
            for task in (base / 'task').iterdir():
                try:
                    pending.extend((task / 'children').read_text().split())
                except FileNotFoundError:
                    # A completed thread does not invalidate its live process.
                    continue
            fields = dict(line.split(':', 1) for line in (base / 'status').read_text().splitlines()
                          if ':' in line)
            if fields['State'].lstrip().startswith('Z'):
                continue
            for field in totals:
                totals[field] += int(fields[field].split()[0])
            measured += 1
        except FileNotFoundError:
            continue
    if not measured:
        raise RuntimeError('process RSS snapshot is empty')
    return totals


def memory_maps(root):
    pending, seen, processes = [root], set(), []
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        base = Path('/proc') / pid
        try:
            for task in (base / 'task').iterdir():
                try:
                    pending.extend((task / 'children').read_text().split())
                except FileNotFoundError:
                    continue
            fields = dict(line.split(':', 1) for line in (base / 'status').read_text().splitlines()
                          if ':' in line)
            if fields['State'].lstrip().startswith('Z'):
                continue
            text = (base / 'smaps').read_text()
        except FileNotFoundError:
            continue
        mappings, current = {}, None
        for line in text.splitlines():
            first = line.split()[0]
            if '-' in first and ':' not in first:
                header = line.split(None, 5)
                name = header[5] if len(header) == 6 else '[anonymous]'
                current = mappings.setdefault((name, header[1]), {})
            elif current is not None and ':' in line:
                field, value = line.split(':', 1)
                if field in ('Rss', 'Pss', 'Anonymous', 'Private_Clean', 'Private_Dirty',
                             'Shared_Clean', 'Shared_Dirty', 'Swap'):
                    current[field] = current.get(field, 0) + int(value.split()[0])
        if not mappings or any('Rss' not in values for values in mappings.values()):
            raise RuntimeError('process memory map snapshot is incomplete')
        processes.append({'pid': int(pid), 'mappings': [
            {'name': name, 'permissions': permissions, 'kilobytes': values}
            for (name, permissions), values in sorted(mappings.items())
        ]})
    if not processes:
        raise RuntimeError('process memory map snapshot is empty')
    return {'monotonic_ns': time.monotonic_ns(), 'processes': processes,
            'window': 'after_workload_sampler_shutdown'}


mode, root = sys.argv[1:3]
if mode == 'count':
    print(len(descriptors(root)))
elif mode == 'snapshot':
    Path(sys.argv[3]).write_text(json.dumps(descriptors(root, True), sort_keys=True) + '\n')
elif mode in ('monitor', 'rss-monitor'):
    output, stop = map(Path, sys.argv[3:5])
    peak = int(sys.argv[5])
    maps_enabled = sys.argv[6] if len(sys.argv) > 6 else '0'
    if maps_enabled not in ('0', '1'):
        raise SystemExit('memory map diagnostics must be 0 or 1')
    interval = 0.01 if mode == 'rss-monitor' else 0.05
    snapshot = (lambda: rss(root)) if mode == 'rss-monitor' else (lambda: len(descriptors(root)))
    started = time.monotonic()
    started_ns = time.monotonic_ns()
    started_cpu_ns = time.process_time_ns()
    count = 0
    maximum_gap = 0.0
    previous = started
    try:
        output.write_text(str(peak) + '\n')
        with Path(str(output) + '.samples.csv').open('w', newline='') as handle:
            writer = csv.writer(handle)
            columns = ['monotonic_ns', 'value']
            if mode == 'rss-monitor':
                columns.extend(['rss_anon_kb', 'rss_file_kb', 'rss_shmem_kb'])
            writer.writerow(columns)
            while not stop.exists() and (Path('/proc') / root).exists():
                observation = snapshot()
                value = observation["VmRSS"] if mode == "rss-monitor" else observation
                now = time.monotonic()
                maximum_gap = max(maximum_gap, now - previous)
                previous = now
                count += 1
                row = [time.monotonic_ns(), value]
                if mode == "rss-monitor":
                    row.extend(observation[field] for field in ("RssAnon", "RssFile", "RssShmem"))
                writer.writerow(row)
                if count == 1:
                    handle.flush()
                    Path(str(output) + '.ready').write_text('1\n')
                if value > peak:
                    peak = value
                    output.write_text(str(peak) + '\n')
                time.sleep(max(0.0, interval - (time.monotonic() - now)))
        if not count:
            raise RuntimeError('process peak sampler collected no observations')
        elapsed_ns = time.monotonic_ns() - started_ns
        cpu_time_ns = time.process_time_ns() - started_cpu_ns
        Path(str(output) + '.sampling.json').write_text(json.dumps({
            'mode': mode, 'pid': int(root), 'samples': count,
            'interval_seconds': interval, 'elapsed_seconds': time.monotonic() - started,
            'maximum_gap_seconds': maximum_gap,
            'elapsed_ns': elapsed_ns, 'cpu_time_ns': cpu_time_ns,
            'cpu_fraction_of_one_core': cpu_time_ns / elapsed_ns,
        }, sort_keys=True) + '\n')
        if mode == 'rss-monitor' and maps_enabled == '1':
            # Procfs map walks happen after all workload observations and
            # sampler CPU accounting, never inside the measured polling loop.
            Path(str(output) + '.memory-maps.json').write_text(
                json.dumps(memory_maps(root), sort_keys=True) + '\n')
    except Exception as error:
        Path(str(output) + '.error').write_text(str(error) + '\n')
        raise
else:
    raise SystemExit('unsupported descriptor measurement mode')
