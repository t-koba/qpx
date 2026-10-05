#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="${1:-$ROOT_DIR/target/perf/perf-audit-streaming-compare.jsonl}"
if [ "$(uname -s)" != Linux ] || [ "$#" -gt 1 ]; then
  echo "streaming CPU partition diagnostics require Linux and one optional output path" >&2
  exit 2
fi
command -v taskset >/dev/null
mkdir -p "$(dirname "$output")"
read -r observer_cpus client_cpus server_cpus < <(python3 - "$output.environment.json" <<'PY'
import json
import os
from pathlib import Path
import sys

available = sorted(os.sched_getaffinity(0))
if len(available) < 4:
    raise SystemExit("streaming CPU partition requires observer, client and two server CPUs")
observer, client, server = available[:1], available[1:2], available[2:]
Path(sys.argv[1]).write_text(json.dumps({
    "measurement": "streaming_observer_partition_diagnostic_v1",
    "available_cpus": available, "observer_cpus": observer,
    "client_cpus": client, "server_cpus": server,
    "diagnostic_cpu_partition": True,
    "fast_transfers": 64, "slow_transfers": 8, "sample_attempts": 3,
}, indent=2) + "\n")
print(*( ",".join(map(str, group)) for group in (observer, client, server)))
PY
)
# Validate the actual kernel affinity before launching any measured process.
for cpus in "$observer_cpus" "$client_cpus" "$server_cpus"; do
  taskset -c "$cpus" python3 - "$cpus" <<'PY'
import os
import sys
if set(os.sched_getaffinity(0)) != {int(value) for value in sys.argv[1].split(",")}:
    raise SystemExit("streaming actual CPU affinity differs from its declared partition")
PY
done
export QPX_STREAMING_COMPARE_CLIENT_CPUS="$client_cpus"
export QPX_STREAMING_COMPARE_SERVER_CPUS="$server_cpus"
export QPX_STREAMING_COMPARE_FAST_TRANSFERS=64
export QPX_STREAMING_COMPARE_SLOW_TRANSFERS=8
export QPX_STREAMING_COMPARE_SAMPLE_ATTEMPTS=3
exec taskset -c "$observer_cpus" bash "$ROOT_DIR/scripts/perf-audit-streaming-compare.sh" "$output"
