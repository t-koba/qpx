#!/usr/bin/env python3
"""Opt-in Linux diagnostic, not an acceptance metric.

Deltas cover consecutive observations of the same (PID/starttime, TID/starttime).
New, vanished or unreadable tasks have no invented zero baseline. Polling can
miss short-lived tasks and exit tails; counts and errors retain that limitation.
"""

import argparse
import json
import math
import os
from pathlib import Path
import signal
import threading
import time


def stat_identity(path):
    text = path.read_text()
    # comm may contain spaces and parentheses; fields after it begin at field 3.
    fields = text[text.rindex(")") + 2:].split()
    return int(fields[1]), int(fields[19])  # ppid, starttime (field 22)


def snapshot(proc, roots, previous):
    tasks, counts, errors = [], {}, []
    current = {}
    for role, root in roots.items():
        pending, seen = [root], set()
        listed = 0
        while pending:
            pid = pending.pop()
            if pid in seen:
                continue
            seen.add(pid)
            try:
                _, process_start = stat_identity(proc / str(pid) / "stat")
                task_dirs = sorted((proc / str(pid) / "task").iterdir())
                listed += len(task_dirs)
                for task in task_dirs:
                    try:
                        _, start = stat_identity(task / "stat")
                        raw = task.joinpath("schedstat").read_text().strip()
                        delay = int(raw.split()[1])
                        name = task.joinpath("comm").read_text().strip()
                        if stat_identity(task / "stat")[1] != start:
                            raise ValueError("task identity changed during read")
                        key = (role, pid, process_start, int(task.name), start)
                        before = previous.get(key)
                        delta = None if before is None else delay - before
                        if delta is not None and delta < 0:
                            raise ValueError("schedstat counter decreased")
                        current[key] = delay
                        tasks.append(dict(role=role, pid=pid, process_start=process_start,
                                          tid=int(task.name), task_start=start, name=name,
                                          schedstat=raw, delay_ns=delay,
                                          previous_delay_ns=before, delta_ns=delta))
                        # Children may belong to any thread, not just the leader.
                        pending.extend(map(int, task.joinpath("children").read_text().split()))
                    except (OSError, ValueError, IndexError) as exc:
                        errors.append(dict(role=role, pid=pid, task=task.name, error=str(exc)))
                if stat_identity(proc / str(pid) / "stat")[1] != process_start:
                    tasks = [t for t in tasks if (t["role"], t["pid"]) != (role, pid)]
                    current = {k: v for k, v in current.items() if k[:2] != (role, pid)}
                    raise ValueError("process identity changed during read")
            except (OSError, ValueError, IndexError) as exc:
                errors.append(dict(role=role, pid=pid, error=str(exc)))
        counts[role] = dict(process_count=len(seen), listed_task_count=listed,
                            read_task_count=sum(t["role"] == role for t in tasks))
    vanished = [list(key) for key in previous.keys() - current.keys()]
    return dict(monotonic_ns=time.monotonic_ns(), counts=counts, tasks=tasks,
                vanished=vanished, errors=errors), current


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", action="append", required=True, help="role=PID")
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--sample", required=True, help="proxy/mode/round/attempt identity")
    parser.add_argument("--interval", required=True, type=float)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--ready", required=True, type=Path)
    parser.add_argument("--stop", required=True, type=Path)
    args = parser.parse_args()
    if not math.isfinite(args.interval) or args.interval <= 0:
        parser.error("interval must be finite and positive")
    roots = {role: int(pid) for role, pid in (r.split("=", 1) for r in args.root)}
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    proc = Path("/proc")
    # Pin roots against PID reuse between observations, as well as each task.
    root_starts = {role: stat_identity(proc / str(pid) / "stat")[1]
                   for role, pid in roots.items()}
    with args.output.open("x") as output:
        def emit(record):
            output.write(json.dumps(record, sort_keys=True) + "\n")
            output.flush()

        emit(dict(type="identity", source_sha=args.source_sha, sample=args.sample,
                  boot_id=(proc / "sys/kernel/random/boot_id").read_text().strip(),
                  roots=roots, root_starttimes=root_starts, interval_seconds=args.interval,
                  clock_ticks_per_second=os.sysconf("SC_CLK_TCK"),
                  sched_schedstats=(proc / "sys/kernel/sched_schedstats").read_text().strip()))
        previous = {}
        failed = False
        while True:
            for role, pid in roots.items():
                if stat_identity(proc / str(pid) / "stat")[1] != root_starts[role]:
                    raise RuntimeError("root PID reused")
            record, previous = snapshot(proc, roots, previous)
            failed |= bool(record["errors"])
            emit(dict(type="snapshot", **record))
            args.ready.touch()
            if stopped.is_set() or args.stop.exists():
                break
            stopped.wait(args.interval)
        emit(dict(type="end", monotonic_ns=time.monotonic_ns(), read_errors=failed,
                  stopped_by_signal=stopped.is_set()))
    return 0  # Transient task read races are retained, not silently discarded.


if __name__ == "__main__":
    raise SystemExit(main())
