#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ "$(uname -s)" != Linux ]; then
  echo "HTTP/2 MTU diagnostics require Linux network namespaces" >&2
  exit 1
fi
if [ "$#" -eq 0 ]; then
  exec sudo unshare --net bash "$ROOT_DIR/scripts/perf-diagnose-http2-mtu.sh" --inside
fi
if [ "$#" -ne 1 ] || [ "$1" != --inside ] || [ "$(id -u)" -ne 0 ]; then
  echo "unsupported HTTP/2 MTU diagnostic invocation" >&2
  exit 2
fi
namespace="$(readlink /proc/self/ns/net)"
initial_namespace="$(readlink /proc/1/ns/net)"
if [ "$namespace" = "$initial_namespace" ]; then
  echo "HTTP/2 MTU diagnostic must not change the host network namespace" >&2
  exit 1
fi
if [[ ! "${SUDO_UID:-}" =~ ^[0-9]+$ ]] || [[ ! "${SUDO_GID:-}" =~ ^[0-9]+$ ]] || [ "$SUDO_UID" -eq 0 ]; then
  echo "HTTP/2 MTU diagnostic requires an unprivileged invoking user" >&2
  exit 1
fi
mkdir -p "$ROOT_DIR/target/perf/profiles"
profile_dir="$(mktemp -d "$ROOT_DIR/target/perf/profiles/http2-mtu.XXXXXX")"
sampler_pid=""
stop_file=""
# shellcheck disable=SC2329
stop_sampler() {
  touch "$stop_file"
  local sampler_status=0
  wait "$sampler_pid" || sampler_status=$?
  sampler_pid=""
  return "$sampler_status"
}
# shellcheck disable=SC2329
cleanup_sampler() {
  if [ -n "$sampler_pid" ] && ! stop_sampler; then
    echo "HTTP/2 MTU TCP sampler failed during cleanup" >&2
  fi
}
trap cleanup_sampler EXIT
status=0
for mtu in 65536 1500; do
  phase_dir="$profile_dir/mtu-$mtu"
  mkdir "$phase_dir"
  ip link set dev lo mtu "$mtu" up
  ip -json link show dev lo > "$phase_dir/interfaces.json"
  python3 - "$phase_dir" "$namespace" "$initial_namespace" "$mtu" <<'PY_NAMESPACE'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
mtu = int(sys.argv[4])
interfaces = json.loads((root / "interfaces.json").read_text())
if len(interfaces) != 1 or interfaces[0]["ifname"] != "lo" or interfaces[0]["mtu"] != mtu:
    raise SystemExit("isolated HTTP/2 loopback MTU was not applied")
(root / "manifest.json").write_text(json.dumps({
    "measurement": "http2_isolated_mtu_v3", "diagnostic_instrumentation": True,
    "network_namespace": sys.argv[2], "host_network_namespace": sys.argv[3],
    "loopback_mtu": mtu, "body_bytes": 1048576, "max_concurrent_streams": 100,
    "required_samples_per_role": 3, "replaces_required_gate": False,
    "sampling_order": "default_mtu_then_ethernet_mtu_same_runner",
    "calibration_min_duration_ms": 8000,
}, indent=2) + "\n")
PY_NAMESPACE
  chown -R "$SUDO_UID:$SUDO_GID" "$profile_dir"
  # Preserve both experiments, including failed default-MTU measurements.
  python3 "$ROOT_DIR/scripts/lib/perf-tcp-sampler.py" --probe-only
  stop_file="$phase_dir/tcp-sampler.stop"
  python3 "$ROOT_DIR/scripts/lib/perf-tcp-sampler.py" \
    --output "$phase_dir/tcp-state.jsonl.gz" --stop-file "$stop_file" \
    --ports 18280 18281 18282 18283 18284 > "$phase_dir/tcp-sampler.log" 2>&1 &
  sampler_pid=$!
  phase_status=0
  setpriv --reuid "$SUDO_UID" --regid "$SUDO_GID" --init-groups env \
    QPX_HTTP2_COMPARE_NATIVE_DIAGNOSTICS=1 QPX_HTTP2_COMPARE_BODY_SIZES=1048576 \
    QPX_HTTP2_COMPARE_MAX_CONCURRENT_STREAMS_VALUES=100 \
    QPX_HTTP2_COMPARE_CALIBRATION_MIN_DURATION_MS=8000 \
    QPX_HTTP2_COMPARE_SAMPLE_ATTEMPTS=3 QPX_HTTP2_COMPARE_LOG_DIR="$phase_dir/logs" \
    bash "$ROOT_DIR/scripts/perf-audit-http2-compare.sh" "$phase_dir/comparison.jsonl" \
    || phase_status=$?
  sampler_status=0
  stop_sampler || sampler_status=$?
  printf '%s\n' "$sampler_status" > "$phase_dir/tcp-sampler-exit-status.txt"
  if [ "$sampler_status" -ne 0 ]; then
    echo "HTTP/2 MTU $mtu TCP sampler failed: $sampler_status" >&2
    status=1
  fi
  if [ "$phase_status" -eq 0 ]; then
    bash "$ROOT_DIR/scripts/check-http2-performance.sh" "$phase_dir/comparison.jsonl" \
      "$ROOT_DIR/perf/http2-performance-objectives.json" diagnostic-quality "$phase_dir/manifest.json" \
      > "$phase_dir/measurement-quality.log" 2>&1 || phase_status=$?
    if [ "$phase_status" -ne 0 ]; then
      cat "$phase_dir/measurement-quality.log" >&2
    fi
  fi
  printf '%s\n' "$phase_status" > "$phase_dir/exit-status.txt"
  if [ "$phase_status" -ne 0 ]; then
    echo "HTTP/2 MTU $mtu comparison failed: $phase_status" >&2
    status=1
  fi
done
exit "$status"
