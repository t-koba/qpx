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
    total = 0
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
            total += int(fields['VmRSS'].split()[0])
            measured += 1
        except FileNotFoundError:
            continue
    if not measured:
        raise RuntimeError('process RSS snapshot is empty')
    return total


mode, root = sys.argv[1:3]
if mode == 'count':
    print(len(descriptors(root)))
elif mode == 'snapshot':
    Path(sys.argv[3]).write_text(json.dumps(descriptors(root, True), sort_keys=True) + '\n')
elif mode in ('monitor', 'rss-monitor'):
    output, stop = map(Path, sys.argv[3:5])
    peak = int(sys.argv[5])
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
            writer.writerow(['monotonic_ns', 'value'])
            while not stop.exists() and (Path('/proc') / root).exists():
                value = snapshot()
                now = time.monotonic()
                maximum_gap = max(maximum_gap, now - previous)
                previous = now
                count += 1
                writer.writerow([time.monotonic_ns(), value])
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
    except Exception as error:
        Path(str(output) + '.error').write_text(str(error) + '\n')
        raise
else:
    raise SystemExit('unsupported descriptor measurement mode')
