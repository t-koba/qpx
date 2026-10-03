#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ "$(uname -s)" != Linux ]; then
  echo "Isolated HTTP/2 comparisons require Linux" >&2
  exit 1
fi
if [ "${1:-}" != --inside ]; then
  if [ "$#" -ne 1 ]; then
    echo "usage: perf-audit-http2-isolated.sh <comparison-jsonl>" >&2
    exit 2
  fi
  exec sudo --preserve-env=QPXD_BIN,GITHUB_SHA,QPX_HTTP2_COMPARE_LOG_DIR \
    unshare --net bash "$ROOT_DIR/scripts/perf-audit-http2-isolated.sh" --inside "$1"
fi
if [ "$#" -ne 2 ] || [ "$(id -u)" -ne 0 ]; then
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
output="$2"
mkdir -p "$(dirname "$output")"
work_dir="$(mktemp -d "$(dirname "$output")/http2-environment.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT
ip link set dev lo mtu 1500 up
ip -json link show dev lo > "$work_dir/interfaces.json"
h2load_binary="$(command -v h2load)"
read -r client_cpus server_cpus < <(python3 - "$work_dir" "$output.environment.json" "$namespace" "$host_namespace" "$h2load_binary" <<'PY'
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
    "diagnostic_instrumentation": False,
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
  QPX_HTTP2_COMPARE_NATIVE_DIAGNOSTICS=0 QPX_HTTP2_COMPARE_CALIBRATION_MIN_DURATION_MS=8000 \
  QPX_HTTP2_COMPARE_BODY_SIZES="1024 1048576" \
  QPX_HTTP2_COMPARE_MAX_CONCURRENT_STREAMS_VALUES="1 100" QPX_HTTP2_COMPARE_SAMPLE_ATTEMPTS=3 \
  bash "$ROOT_DIR/scripts/perf-audit-http2-compare.sh" "$output"
