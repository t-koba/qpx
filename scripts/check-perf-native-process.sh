#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
wrapper="${1:?native profiler wrapper is required}"
probe_dir="$(mktemp -d "$ROOT_DIR/target/perf/native-ownership-probe.XXXXXX")"
cat >"$probe_dir/qpxd-native-probe.yaml" <<YAML
state_dir: "$probe_dir/state"
telemetry:
  system_log:
    level: warn
    format: json
runtime:
  worker_threads: 1
  acceptor_tasks_per_listener: 1
edges:
  - kind: reverse
    name: native-profiler-probe
    listen: 127.0.0.1:19095
    routes:
      - name: local-response
        match:
          path: ["/profile-probe"]
        target:
          type: local_response
          response:
            status: 200
            body: "native-profiler-probe"
YAML
QPX_NATIVE_PROFILE_DIR="$probe_dir" "$wrapper" run --config "$probe_dir/qpxd-native-probe.yaml" \
  >"$probe_dir/server.log" 2>&1 &
probe_pid=$!
cleanup() {
  if kill -0 "$probe_pid" 2>/dev/null; then
    kill -TERM "$probe_pid"
    wait "$probe_pid" || true
  fi
}
trap cleanup EXIT
ready=0
for _ in $(seq 1 100); do
  if ! kill -0 "$probe_pid" 2>/dev/null; then
    cat "$probe_dir/server.log" >&2
    echo "native profiler probe exited before readiness" >&2
    exit 1
  fi
  if curl -fsS --max-time 1 http://127.0.0.1:19095/profile-probe >"$probe_dir/response.txt"; then
    ready=1
    break
  fi
  sleep 0.1
done
[ "$ready" -eq 1 ]
[ "$(cat "$probe_dir/response.txt")" = native-profiler-probe ]
if [ "${QPX_NATIVE_PROFILE_MODE:-cpu}" = syscalls ]; then
  python3 - "$probe_dir/qpxd-native-probe.lifecycle.json" <<'PY_FILTER'
import json
from pathlib import Path
import sys
import time
path = Path(sys.argv[1])
for _ in range(100):
    if json.loads(path.read_text()).get("seccomp_filter_observed") is True:
        break
    time.sleep(0.01)
else:
    raise SystemExit("real syscall tracer did not install the required kernel filter")
PY_FILTER
fi
kill -TERM "$probe_pid"
status=0
wait "$probe_pid" || status=$?
if [ "$status" -ne 143 ]; then
  cat "$probe_dir/server.log" >&2
  echo "native profiler probe has unexpected shutdown status: $status" >&2
  exit 1
fi
python3 - "$probe_dir/qpxd-native-probe.lifecycle.json" <<'PY'
import json
import os
import sys
record = json.load(open(sys.argv[1]))
if (record.get("forced_shutdown") is not False or record.get("requested_signal") != 15
        or record.get("exit_status") not in (0, -15, 143)):
    raise SystemExit("native profiler probe did not stop gracefully")
if record.get("mode") == "syscalls" and record.get("seccomp_filter_observed") is not True:
    raise SystemExit("real syscall trace lacks the required kernel filter")
try:
    os.killpg(record["process_group"], 0)
except ProcessLookupError:
    pass
else:
    raise SystemExit("native profiler probe left its server process group alive")
PY
echo "Native profiler process ownership verified with a real qpxd server."
