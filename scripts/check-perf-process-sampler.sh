#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/lib/perf-process-metrics.sh"
prepare_process_scheduler_accounting
work="$(mktemp -d)"
root=""
fd_monitor=""
rss_monitor=""
cleanup() {
  for pid in "$fd_monitor" "$rss_monitor" "$root"; do
    if [ -n "$pid" ]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  rm -rf "$work"
}
trap cleanup EXIT
python3 - "$work/ready" <<'PY_SERVER' &
import ctypes
import os
from pathlib import Path
import sys
import threading
import time
if ctypes.CDLL(None).prctl(4, 0, 0, 0, 0) != 0:
    raise SystemExit('failed to disable process dumping')
def churn_threads():
    while True:
        worker = threading.Thread(target=time.sleep, args=(0.001,))
        worker.start()
        worker.join()
threading.Thread(target=churn_threads, daemon=True).start()
Path(sys.argv[1]).write_text(str(os.getpid()))
work = Path(sys.argv[1]).parent
deadline = time.monotonic() + 30
while time.monotonic() < deadline:
    if (work / 'cpu-work').exists() and not (work / 'cpu-done').exists():
        consumed = []
        def consume_cpu():
            started = time.thread_time_ns()
            value = 1
            while time.thread_time_ns() - started < 35_000_000:
                value = (value * 3 + 1) % 1_000_003
            consumed.append(time.thread_time_ns() - started)
        worker = threading.Thread(target=consume_cpu)
        worker.start()
        worker.join()
        (work / 'cpu-done').write_text(str(consumed[0]))
    time.sleep(0.01)
PY_SERVER
root=$!
for ((attempt = 0; attempt < 100; attempt++)); do
  [ -s "$work/ready" ] && break
  kill -0 "$root"
  sleep 0.02
done
[ "$(cat "$work/ready")" = "$root" ]
if [ "$(id -u)" -ne 0 ]; then
  if python3 - "$root" <<'PY_PERMISSIONS'
from pathlib import Path
import sys
try:
    list((Path('/proc') / sys.argv[1] / 'fd').iterdir())
except PermissionError:
    raise SystemExit(1)
PY_PERMISSIONS
  then
    echo "non-dumpable process did not enforce descriptor permissions" >&2
    exit 1
  fi
fi
fd_before="$(process_tree_fd_count "$root")"
rss_before="$(process_tree_status_kb "$root" VmRSS)"
snapshot_process_tree_fds "$root" "$work/descriptors.json"
monitor_process_tree_fd_peak "$root" "$work/fd" "$fd_before" &
fd_monitor=$!
monitor_process_tree_rss_peak "$root" "$work/rss" "$rss_before" &
rss_monitor=$!
sleep 0.3
kill "$fd_monitor" "$rss_monitor"
wait "$fd_monitor" || true
wait "$rss_monitor" || true
fd_monitor=""
rss_monitor=""
[ "$(read_process_peak_file "$work/fd")" -ge "$fd_before" ]
[ "$(read_process_peak_file "$work/rss")" -ge "$rss_before" ]
python3 - "$work" <<'PY_RESULTS'
import csv
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
for kind in ('fd', 'rss'):
    metadata = json.loads((root / (kind + '.sampling.json')).read_text())
    rows = list(csv.DictReader((root / (kind + '.samples.csv')).open()))
    assert metadata['samples'] == len(rows) and len(rows) > 0
    assert all(int(row['value']) > 0 for row in rows)
assert json.loads((root / 'descriptors.json').read_text())
PY_RESULTS
cpu_before="$(process_tree_cpu_clock_ms "$root" "$work/cpu-before.json")"
scheduler_before="$(process_tree_scheduler_run_delay_ns "$root" "$work/scheduler-before.json")"
touch "$work/cpu-work"
for ((attempt = 0; attempt < 100; attempt++)); do
  [ -s "$work/cpu-done" ] && break
  kill -0 "$root"
  sleep 0.02
done
cpu_after="$(process_tree_cpu_clock_ms "$root" "$work/cpu-after.json")"
scheduler_after="$(process_tree_scheduler_run_delay_ns "$root" "$work/scheduler-after.json")"
scheduler_delta="$(process_tree_scheduler_delta_ns "$work/scheduler-before.json" "$work/scheduler-after.json")"
[ "$scheduler_delta" = "$(monotonic_counter_delta "real scheduler delay" "$scheduler_before" "$scheduler_after")" ]
if process_tree_scheduler_delta_ns "$work/scheduler-after.json" "$work/scheduler-before.json" >"$work/reversed-scheduler" 2>"$work/reversed-scheduler-error"; then
  echo "Reversed scheduler snapshots produced a valid counter delta" >&2
  exit 1
fi
cpu_delta="$(python3 "$ROOT_DIR/scripts/lib/perf-process-cpu.py" delta \
  "$work/cpu-before.json" "$work/cpu-after.json")"
[ "$(awk -v value="$cpu_delta" 'BEGIN { print (value >= 35) }')" -eq 1 ]
python3 - "$work" "$cpu_before" "$cpu_after" <<'PY_CPU'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
before = json.loads((root / 'cpu-before.json').read_text())
after = json.loads((root / 'cpu-after.json').read_text())
consumed = int((root / 'cpu-done').read_text())
assert before['measurement'] == after['measurement'] == 'linux_process_cpu_clock_ns_v1'
assert after['total_cpu_ns'] - before['total_cpu_ns'] >= consumed
assert float(sys.argv[3]) > float(sys.argv[2])
for record in (before, after):
    assert record['total_cpu_ns'] == sum(row['cpu_ns'] for row in record['processes'])
    assert all(0 < row['resolution_ns'] <= 1_000_000 for row in record['processes'])
    assert record['finished_monotonic_ns'] >= record['started_monotonic_ns']
PY_CPU
monotonic_counter_delta "real process CPU milliseconds" "$cpu_before" "$cpu_after" >"$work/monotonic-cpu-delta"
if monotonic_counter_delta "reversed real process CPU milliseconds" "$cpu_after" "$cpu_before" >"$work/reversed-cpu-delta" 2>"$work/reversed-cpu-error"; then
  echo "Reversed real CPU observations produced a valid counter delta" >&2
  exit 1
fi
kill "$root"
wait "$root" || true
if process_tree_fd_count "$root" >"$work/terminated-count" 2>"$work/terminated-error"; then
  echo "terminated process produced valid descriptor data" >&2
  exit 1
fi
if process_tree_cpu_clock_ms "$root" >"$work/terminated-cpu" 2>"$work/terminated-cpu-error"; then
  echo "terminated process produced valid CPU clock data" >&2
  exit 1
fi
if process_tree_scheduler_run_delay_ns "$root" >"$work/terminated-scheduler" 2>"$work/terminated-scheduler-error"; then
  echo "terminated process produced valid scheduler data" >&2
  exit 1
fi
root=""
echo "Real non-dumpable process resource, CPU clock, and scheduler sampling verified"
