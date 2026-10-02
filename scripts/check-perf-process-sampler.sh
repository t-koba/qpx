#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/lib/perf-process-metrics.sh"
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
import time
if ctypes.CDLL(None).prctl(4, 0, 0, 0, 0) != 0:
    raise SystemExit('failed to disable process dumping')
Path(sys.argv[1]).write_text(str(os.getpid()))
time.sleep(30)
PY_SERVER
root=$!
for attempt in {1..100}; do
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
kill "$root"
wait "$root" || true
if process_tree_fd_count "$root" >"$work/terminated-count" 2>"$work/terminated-error"; then
  echo "terminated process produced valid descriptor data" >&2
  exit 1
fi
root=""
echo "Real non-dumpable process resource sampling verified"
