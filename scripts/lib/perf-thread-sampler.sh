#!/usr/bin/env bash

# Samples per-thread scheduler state for a process tree at high frequency.
# Usage: perf-sample-threads <root_pid> <duration_seconds> <output_csv>
# Emits one CSV row per sample: epoch_ms,pid,tid,state,wchan,utime_ticks,stime_ticks
# The consumer diffs consecutive rows per tid to attribute stall time.

set -euo pipefail

root="$1"
duration="$2"
output="$3"

if [ -z "$root" ] || [ ! -d /proc ]; then
  exit 0
fi

python3 - "$root" "$duration" "$output" <<'PY'
import os
import sys
import time

root = sys.argv[1]
duration = float(sys.argv[2])
output = sys.argv[3]

INTERVAL = 0.01


def tree_pids(pid):
    pids = [pid]
    stack = [pid]
    while stack:
        current = stack.pop()
        try:
            children = os.listdir(f"/proc/{current}/task")
        except OSError:
            continue
        for task in children:
            try:
                pids.extend(int(child) for child in os.listdir(f"/proc/{current}/task/{task}/children"))
            except OSError:
                pass
    # Include child processes discovered through children files above.
    return pids


def all_pids():
    seen = []
    stack = [int(root)]
    while stack:
        pid = stack.pop()
        seen.append(pid)
        try:
            with open(f"/proc/{pid}/task/{pid}/children") as handle:
                stack.extend(int(child) for child in handle.read().split())
        except OSError:
            pass
    return seen


def sample_threads(pid):
    rows = []
    base = f"/proc/{pid}/task"
    try:
        tasks = os.listdir(base)
    except OSError:
        return rows
    for tid in tasks:
        stat_path = f"{base}/{tid}/stat"
        wchan_path = f"{base}/{tid}/wchan"
        try:
            with open(stat_path) as handle:
                raw = handle.read()
            head_end = raw.rindex(")")
            fields = raw[head_end + 2:].split()
            state = fields[0]
            utime = int(fields[11])
            stime = int(fields[12])
            try:
                with open(wchan_path) as handle:
                    wchan = handle.read().strip() or "-"
            except OSError:
                wchan = "-"
            rows.append((pid, int(tid), state, wchan, utime, stime))
        except (OSError, ValueError):
            continue
    return rows


deadline = time.monotonic() + duration
with open(output, "w") as out:
    out.write("epoch_ms,pid,tid,state,wchan,utime,stime\n")
    while time.monotonic() < deadline:
        stamp = int(time.time() * 1000)
        for pid in all_pids():
            for row in sample_threads(pid):
                out.write(
                    f"{stamp},{row[0]},{row[1]},{row[2]},{row[3]},{row[4]},{row[5]}\n"
                )
        out.flush()
        time.sleep(INTERVAL)
PY
