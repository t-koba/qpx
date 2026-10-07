#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ "$(uname -s)" != Linux ]; then
  echo "Isolated HTTP/2 comparisons require Linux" >&2
  exit 1
fi
if [ "${1:-}" != --inside ]; then
  if [ "$#" -ne 1 ] && { [ "$#" -ne 2 ] || { [ "$1" != --native ] && [ "$1" != --phases ]; }; } \
    && { [ "$#" -ne 4 ] || [ "$1" != --phases ] || [ "$2" != --workers ]; } \
    && { [ "$#" -ne 3 ] || [ "$1" != --workers ]; }; then
    echo "usage: perf-audit-http2-isolated.sh [--native|--phases] [--workers 1|2|4] <comparison-jsonl>" >&2
    exit 2
  fi
  exec sudo --preserve-env=QPXD_BIN,GITHUB_SHA,QPX_HTTP2_COMPARE_LOG_DIR,QPXD_REAL_BIN,QPX_NATIVE_PROFILE_DIR,QPX_NATIVE_PERF_BIN,QPX_NATIVE_WRAPPER_SOURCE,QPX_PERF_NATIVE_IO_TIMELINE,QPX_PERF_MEMORY_MAP_DIAGNOSTICS \
    unshare --net bash "$ROOT_DIR/scripts/perf-audit-http2-isolated.sh" --inside "$@"
fi
shift
native=0
phases=0
body_sizes="1024 1048576"
stream_values="1 100"
case "${1:-}" in
  --native) native=1; shift ;;
  --phases) native=1; phases=1; shift ;;
esac
if [ "$native" = 1 ] && [ "$phases" = 0 ]; then
  export RUST_LOG=warn,qpx_perf_tls=debug
fi
if [ "${1:-}" = --workers ]; then
  if [ "$#" -ne 3 ] || { [ "$native" = 1 ] && [ "$phases" != 1 ]; }; then
    echo "Worker scaling requires normal measurement or phase diagnostics and one output path" >&2
    exit 2
  fi
  case "$2" in
    1|2|4) export QPX_HTTP2_COMPARE_SERVER_WORKERS="$2" ;;
    *) echo "Worker scaling requires 1, 2, or 4 server workers" >&2; exit 2 ;;
  esac
  shift 2
fi
if [ "$phases" = 1 ]; then
  export RUST_LOG=warn,qpx_perf_phase=debug
  export QPX_PERF_SCHEDULER_THREADS=1
  body_sizes=1024
  stream_values=100
fi
if [ "$#" -ne 1 ] || [ "$(id -u)" -ne 0 ]; then
  echo "Unsupported isolated HTTP/2 comparison invocation" >&2
  exit 2
fi
namespace="$(readlink /proc/self/ns/net)"
host_namespace="$(readlink /proc/1/ns/net)"
if [ "$namespace" = "$host_namespace" ]; then
  echo "HTTP/2 comparison must not change the host network namespace" >&2
  exit 1
fi
if [[ ! "${SUDO_UID:-}" =~ ^[0-9]+$ ]] || [[ ! "${SUDO_GID:-}" =~ ^[0-9]+$ ]] || [ "$SUDO_UID" -eq 0 ]; then
  echo "HTTP/2 comparison requires an unprivileged invoking user" >&2
  exit 1
fi
output="$1"
mkdir -p "$(dirname "$output")"
work_dir="$(mktemp -d "$(dirname "$output")/http2-environment.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT
ip link set dev lo mtu 1500 up
ip -json link show dev lo > "$work_dir/interfaces.json"
h2load_binary="$(command -v h2load)"
read -r client_cpus server_cpus < <(python3 - "$work_dir" "$output.environment.json" "$namespace" "$host_namespace" "$h2load_binary" "$native" "${QPX_HTTP2_COMPARE_SERVER_WORKERS:-}" <<'PY'
import json
import os
from pathlib import Path
import shlex
import sys

root = Path(sys.argv[1])
available = sorted(os.sched_getaffinity(0))
if len(available) < 4:
    raise SystemExit("HTTP/2 comparison requires two client CPUs and at least two server CPUs")
interfaces = json.loads((root / "interfaces.json").read_text())
if len(interfaces) != 1 or interfaces[0]["ifname"] != "lo" or interfaces[0]["mtu"] != 1500:
    raise SystemExit("HTTP/2 isolated loopback MTU was not applied")
client, server = available[:2], available[2:]
manifest = {
    "measurement": "http2_isolated_balanced_v1",
    "network_namespace": sys.argv[3], "host_network_namespace": sys.argv[4],
    "loopback_mtu": 1500, "available_cpus": available,
    "client_cpus": client, "server_cpus": server,
    "calibration_min_duration_ms": 8000,
    "diagnostic_instrumentation": sys.argv[6] == "1",
    "diagnostic_server_workers": int(sys.argv[7]) if sys.argv[7] else None,
    "configuration_diagnostic": bool(sys.argv[7]),
    "replaces_required_gate": False,
}
Path(sys.argv[2]).write_text(json.dumps(manifest, indent=2) + "\n")
client_arg = ",".join(map(str, client))
wrapper = root / "h2load"
wrapper.write_text("#!/usr/bin/env bash\nset -euo pipefail\nexec taskset -c "
                   + shlex.quote(client_arg) + " " + shlex.quote(sys.argv[5]) + ' "$@"\n')
wrapper.chmod(0o755)
print(client_arg, ",".join(map(str, server)))
PY
)
# Verify the actual taskset results before starting any measured process.
for cpus in "$client_cpus" "$server_cpus"; do
  taskset -c "$cpus" python3 - "$cpus" <<'PY'
import os
import sys
if set(os.sched_getaffinity(0)) != {int(value) for value in sys.argv[1].split(",")}:
    raise SystemExit("HTTP/2 actual CPU affinity does not match its declared partition")
PY
done
chown -R "$SUDO_UID:$SUDO_GID" "$work_dir" "$output.environment.json"
taskset -c "$server_cpus" setpriv --reuid "$SUDO_UID" --regid "$SUDO_GID" --init-groups env \
  PATH="$work_dir:$PATH" QPX_HTTP2_COMPARE_ENVIRONMENT_JSON="$output.environment.json" \
  QPX_HTTP2_COMPARE_NATIVE_DIAGNOSTICS="$native" QPX_HTTP2_COMPARE_CALIBRATION_MIN_DURATION_MS=8000 \
  QPX_HTTP2_COMPARE_BODY_SIZES="$body_sizes" \
  QPX_HTTP2_COMPARE_MAX_CONCURRENT_STREAMS_VALUES="$stream_values" QPX_HTTP2_COMPARE_SAMPLE_ATTEMPTS=3 \
  bash "$ROOT_DIR/scripts/perf-audit-http2-compare.sh" "$output"
if [ "${QPX_PERF_MEMORY_MAP_DIAGNOSTICS:-0}" = 1 ]; then
  python3 - "$QPX_HTTP2_COMPARE_LOG_DIR" <<'PY_MAPS'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
count = 0
for proxy in ('qpxd', 'nginx'):
    for body in (1024, 1048576):
        for streams in (1, 100):
            for round_index in (1, 2, 3):
                path = root / (f'http2.{proxy}.{body}.m{streams}.round-{round_index}'
                               '.attempt-1.rss-peak.memory-maps.json')
                record = json.loads(path.read_text())
                if (record.get('window') != 'after_workload_sampler_shutdown'
                        or record.get('monotonic_ns', 0) <= 0
                        or not record.get('processes')):
                    raise SystemExit(f'HTTP/2 memory map window is incomplete: {path}')
                for process in record['processes']:
                    if process.get('pid', 0) <= 0 or not process.get('mappings'):
                        raise SystemExit(f'HTTP/2 memory map process is incomplete: {path}')
                    for mapping in process['mappings']:
                        if mapping.get('kilobytes', {}).get('Rss', -1) < 0:
                            raise SystemExit(f'HTTP/2 memory map RSS is missing: {path}')
                count += 1
print(f'HTTP/2 memory map windows validated: {count}')
PY_MAPS
fi
if [ -n "${QPX_HTTP2_COMPARE_SERVER_WORKERS:-}" ]; then
  python3 - "$output" "$QPX_HTTP2_COMPARE_SERVER_WORKERS" "$phases" <<'PY_WORKERS'
import json
from pathlib import Path
import sys

records = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
dimensions = {(1024, 100)} if sys.argv[3] == '1' else {(size, streams) for size in (1024, 1048576) for streams in (1, 100)}
expected = {(role, size, streams) for role in ('qpxd', 'nginx', 'direct-backend') for size, streams in dimensions}
actual = {(row['proxy'], row['body_bytes'], row['max_concurrent_streams']) for row in records}
if len(records) != len(expected) or actual != expected:
    raise SystemExit("Worker scaling diagnostics lack the complete matched comparison")
if any(row['server_workers'] != int(sys.argv[2]) for row in records):
    raise SystemExit("Worker scaling diagnostics did not apply the requested worker count")
PY_WORKERS
fi
