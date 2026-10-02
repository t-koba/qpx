#!/usr/bin/env bash

# Samples per-thread scheduler state for a process tree at high frequency.
# Usage: perf-sample-threads <root_pid> <duration_seconds> <output_csv>
# Emits CPU and scheduler counters per thread, plus process RSS.
# Counter differences attribute workload CPU and run-queue delay.

set -euo pipefail

root="$1"
duration="$2"
output="$3"

if [ -z "$root" ] || [ ! -d /proc ]; then
  echo "thread diagnostics require a live Linux process" >&2
  exit 1
fi

source "$(dirname "${BASH_SOURCE[0]}")/perf-process-metrics.sh"
perf_proc_python - "$root" "$duration" "$output" \
  "${QPX_PERF_WEBDAV_SOCKET_DIAGNOSTICS:-0}" \
  "${QPX_PROXY_COMPARE_QPX_WEBDAV_PORT:-18092}" \
  "${QPX_PROXY_COMPARE_APACHE_PORT:-18083}" <<'PY'
import csv
import contextlib
import json
import os
import subprocess
import sys
import time

root = sys.argv[1]
duration = float(sys.argv[2])
output = sys.argv[3]

INTERVAL = 0.01
socket_diagnostics = sys.argv[4]
if socket_diagnostics not in ("0", "1"):
    raise SystemExit("WebDAV socket diagnostics must be 0 or 1")
qpx_port, reference_port = map(int, sys.argv[5:7])
if not all(0 < port < 65536 for port in (qpx_port, reference_port)):
    raise SystemExit("WebDAV socket diagnostic ports are invalid")
socket_filter = f"( sport = :{qpx_port} or sport = :{reference_port} )"


def all_pids():
    seen = set()
    stack = [int(root)]
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        try:
            tasks = os.listdir(f"/proc/{pid}/task")
        except FileNotFoundError:
            continue
        for task in tasks:
            try:
                with open(f"/proc/{pid}/task/{task}/children") as handle:
                    stack.extend(int(child) for child in handle.read().split())
            except FileNotFoundError:
                pass
    return sorted(seen)


def sample_threads(pid):
    rows = []
    base = f"/proc/{pid}/task"
    try:
        tasks = os.listdir(base)
    except FileNotFoundError:
        return rows
    rss_kb = 0
    try:
        with open(f"/proc/{pid}/status") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    rss_kb = int(line.split()[1])
                    break
    except FileNotFoundError:
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
            with open(wchan_path) as handle:
                wchan = handle.read().strip() or "-"
            with open(f"{base}/{tid}/schedstat") as handle:
                run_ns, queue_ns, timeslices = map(int, handle.read().split())
            comm = raw[raw.index("(") + 1:head_end]
            rows.append((pid, int(tid), state, wchan, utime, stime,
                         comm, run_ns, queue_ns, timeslices, rss_kb))
        except FileNotFoundError:
            continue
    return rows


if not os.path.isdir(f"/proc/{root}"):
    raise SystemExit("thread diagnostic root process does not exist")

deadline = time.monotonic() + duration
with contextlib.ExitStack() as stack:
    out = stack.enter_context(open(output, "w", newline=""))
    sockets = (stack.enter_context(open(output + ".sockets.jsonl", "w"))
               if socket_diagnostics == "1" else None)
    next_socket_sample = time.monotonic()
    writer = csv.writer(out)
    writer.writerow(("epoch_ms", "monotonic_ns", "pid", "tid", "state", "wchan",
                     "utime", "stime", "comm", "run_ns", "queue_delay_ns",
                     "timeslices", "rss_kb"))
    while time.monotonic() < deadline:
        stamp = int(time.time() * 1000)
        monotonic = time.monotonic_ns()
        pids = all_pids()
        for pid in pids:
            for row in sample_threads(pid):
                writer.writerow((stamp, monotonic, *row))
        out.flush()
        if sockets is not None and time.monotonic() >= next_socket_sample:
            started = time.monotonic_ns()
            result = subprocess.run(["ss", "-tinpH", "state", "established", socket_filter],
                                    check=True, capture_output=True, text=True, timeout=5)
            sockets.write(json.dumps({"monotonic_ns": started,
                                      "finished_monotonic_ns": time.monotonic_ns(),
                                      "root_pid": int(root), "process_ids": pids,
                                      "filter": socket_filter, "raw": result.stdout}) + "\n")
            sockets.flush()
            next_socket_sample = time.monotonic() + 0.5
        time.sleep(INTERVAL)
PY
