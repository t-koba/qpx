#!/usr/bin/env python3
"""Snapshot Linux process CPU clocks without losing completed thread time."""

import ctypes
import json
import os
from pathlib import Path
import sys
import time


def snapshot(root):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.clock_getcpuclockid.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_int)]
    libc.clock_getcpuclockid.restype = ctypes.c_int
    pending = [root]
    seen = set()
    records = []
    started = time.monotonic_ns()
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        base = Path('/proc') / str(pid)
        for task in (base / 'task').iterdir():
            try:
                pending.extend(int(child) for child in (task / 'children').read_text().split())
            except FileNotFoundError:
                # Finished threads remain accounted for by the process CPU clock.
                continue
        status = (base / 'status').read_text()
        if any(line.startswith('State:') and line.split()[1] == 'Z' for line in status.splitlines()):
            raise RuntimeError(f'measured process has terminated: {pid}')
        stat = (base / 'stat').read_text()
        start_ticks = int(stat[stat.rindex(') ') + 2:].split()[19])
        clock = ctypes.c_int()
        error = libc.clock_getcpuclockid(pid, ctypes.byref(clock))
        if error:
            raise OSError(error, os.strerror(error), str(pid))
        resolution_ns = round(time.clock_getres(clock.value) * 1_000_000_000)
        if not 0 < resolution_ns <= 1_000_000:
            raise RuntimeError(f'process CPU clock resolution is inadequate: {resolution_ns} ns')
        records.append({'pid': pid, 'cpu_ns': time.clock_gettime_ns(clock.value),
                        'resolution_ns': resolution_ns, 'start_ticks': start_ticks})
    if not records:
        raise RuntimeError('process CPU clock snapshot is empty')
    return {'measurement': 'linux_process_cpu_clock_ns_v1', 'root_pid': root,
            'started_monotonic_ns': started, 'finished_monotonic_ns': time.monotonic_ns(),
            'processes': records, 'total_cpu_ns': sum(row['cpu_ns'] for row in records)}


def delta(before_path, after_path):
    before = json.loads(Path(before_path).read_text())
    after = json.loads(Path(after_path).read_text())
    if (before['measurement'] != 'linux_process_cpu_clock_ns_v1'
            or after['measurement'] != before['measurement']
            or before['root_pid'] != after['root_pid']
            or before['finished_monotonic_ns'] > after['started_monotonic_ns']):
        raise RuntimeError('process CPU clock snapshots do not describe the same measurement')
    previous = {row['pid']: row for row in before['processes']}
    current = {row['pid']: row for row in after['processes']}
    if not previous.keys() <= current.keys():
        raise RuntimeError('measured process exited before its final CPU snapshot')
    for pid, row in previous.items():
        if (current[pid]['start_ticks'] != row['start_ticks']
                or current[pid]['cpu_ns'] < row['cpu_ns']):
            raise RuntimeError(f'measured process identity or CPU clock changed: {pid}')
    for record in (before, after):
        if record['total_cpu_ns'] != sum(row['cpu_ns'] for row in record['processes']):
            raise RuntimeError('process CPU clock snapshot total is inconsistent')
    return after['total_cpu_ns'] - before['total_cpu_ns']


if __name__ == '__main__':
    if sys.argv[1] == 'delta':
        print(f"{delta(sys.argv[2], sys.argv[3]) / 1_000_000:.6f}")
    else:
        if sys.platform != 'linux':
            raise SystemExit('high-resolution process CPU measurement requires Linux')
        record = snapshot(int(sys.argv[1]))
        if len(sys.argv) > 2:
            Path(sys.argv[2]).write_text(json.dumps(record, sort_keys=True) + '\n')
        print(f"{record['total_cpu_ns'] / 1_000_000:.6f}")
