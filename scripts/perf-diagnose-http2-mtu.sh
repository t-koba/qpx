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
if [ "$#" -eq 1 ] && [ "$1" = --observer ]; then
  exec sudo unshare --net bash "$ROOT_DIR/scripts/perf-diagnose-http2-mtu.sh" --inside-observer
fi
if [ "$#" -eq 1 ] && [ "$1" = --full ]; then
  exec sudo unshare --net bash "$ROOT_DIR/scripts/perf-diagnose-http2-mtu.sh" --inside-full
fi
if [ "$#" -eq 1 ] && [ "$1" = --full-affinity ]; then
  exec sudo unshare --net bash "$ROOT_DIR/scripts/perf-diagnose-http2-mtu.sh" --inside-full-affinity
fi
if [ "$#" -eq 1 ] && [ "$1" = --full-client ]; then
  exec sudo --preserve-env=QPX_NATIVE_PERF_BIN unshare --net bash "$ROOT_DIR/scripts/perf-diagnose-http2-mtu.sh" --inside-full-client
fi
if [ "$#" -eq 1 ] && [ "$1" = --balanced-affinity ]; then
  exec sudo unshare --net bash "$ROOT_DIR/scripts/perf-diagnose-http2-mtu.sh" --inside-balanced-affinity
fi
if [ "$#" -ne 1 ] || [[ "$1" != --inside && "$1" != --inside-observer && "$1" != --inside-full && "$1" != --inside-full-affinity && "$1" != --inside-full-client && "$1" != --inside-balanced-affinity ]] || [ "$(id -u)" -ne 0 ]; then
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
phases=(65536 1500)
body_sizes=1048576
stream_counts=100
if [ "$1" = --inside-observer ]; then
  phases=(1500-sampled 1500-unobserved)
elif [[ "$1" = --inside-full || "$1" = --inside-full-affinity || "$1" = --inside-full-client || "$1" = --inside-balanced-affinity ]]; then
  phases=(1500-full)
  body_sizes="1024 1048576"
  stream_counts="1 100"
fi
affinity_command=()
client_path="$PATH"
if [[ "$1" = --inside-full-affinity || "$1" = --inside-balanced-affinity ]]; then
  command -v taskset >/dev/null
  h2load_binary="$(command -v h2load)"
  client_count=1
  if [ "$1" = --inside-balanced-affinity ]; then
    client_count=2
  fi
  read -r client_cpus server_cpus < <(python3 - "$client_count" <<'PY_AFFINITY'
import os
import sys
cpus = sorted(os.sched_getaffinity(0))
client_count = int(sys.argv[1])
minimum_servers = 2 if client_count == 2 else 1
if len(cpus) < client_count + minimum_servers:
    raise SystemExit("HTTP/2 affinity diagnostic lacks CPUs for the declared partition")
print(",".join(map(str, cpus[:client_count])), ",".join(map(str, cpus[client_count:])))
PY_AFFINITY
  )
  mkdir "$profile_dir/client-bin"
  python3 - "$profile_dir/client-bin/h2load" "$client_cpus" "$h2load_binary" <<'PY_CLIENT'
from pathlib import Path
import shlex
import sys
path = Path(sys.argv[1])
path.write_text("#!/usr/bin/env bash\nset -euo pipefail\nexec taskset -c "
                + shlex.quote(sys.argv[2]) + " " + shlex.quote(sys.argv[3]) + ' "$@"\n')
path.chmod(0o755)
PY_CLIENT
  affinity_command=(taskset -c "$server_cpus")
  client_path="$profile_dir/client-bin:$PATH"
fi
if [ "$1" = --inside-full-client ]; then
  : "${QPX_NATIVE_PERF_BIN:?native perf executable is required}"
  [ -x "$QPX_NATIVE_PERF_BIN" ]
  export QPX_REAL_H2LOAD
  QPX_REAL_H2LOAD="$(command -v h2load)"
  export QPX_NATIVE_PROFILE_MODE=client-cpu
  export QPX_NATIVE_PROFILE_DIR="$profile_dir/client-profiles"
  export QPX_NATIVE_WRAPPER_SOURCE="$ROOT_DIR/scripts/lib/perf-native-process.py"
  mkdir "$profile_dir/client-bin" "$QPX_NATIVE_PROFILE_DIR"
  cat >"$profile_dir/client-bin/h2load" <<'CLIENT_PROFILE'
#!/usr/bin/env bash
set -euo pipefail
export QPXD_REAL_BIN="$QPX_REAL_H2LOAD"
exec python3 "$QPX_NATIVE_WRAPPER_SOURCE" "$@"
CLIENT_PROFILE
  chmod 755 "$profile_dir/client-bin/h2load"
  client_path="$profile_dir/client-bin:$PATH"
fi
for phase in "${phases[@]}"; do
  mtu="${phase%%-*}"
  sampled=true
  if [[ "$phase" = 1500-unobserved || "$phase" = 1500-full ]]; then
    sampled=false
  fi
  phase_dir="$profile_dir/mtu-$phase"
  mkdir "$phase_dir"
  ip link set dev lo mtu "$mtu" up
  ip -json link show dev lo > "$phase_dir/interfaces.json"
  python3 - "$phase_dir" "$namespace" "$initial_namespace" "$mtu" "$sampled" "$1" <<'PY_NAMESPACE'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
mtu = int(sys.argv[4])
interfaces = json.loads((root / "interfaces.json").read_text())
if len(interfaces) != 1 or interfaces[0]["ifname"] != "lo" or interfaces[0]["mtu"] != mtu:
    raise SystemExit("isolated HTTP/2 loopback MTU was not applied")
manifest = {
    "measurement": "http2_isolated_mtu_v3", "diagnostic_instrumentation": True,
    "network_namespace": sys.argv[2], "host_network_namespace": sys.argv[3],
    "loopback_mtu": mtu, "body_bytes": 1048576, "max_concurrent_streams": 100,
    "required_samples_per_role": 3, "replaces_required_gate": False,
    "sampling_order": ("sampled_then_unobserved_same_runner" if sys.argv[6] == "--inside-observer"
                       else "default_mtu_then_ethernet_mtu_same_runner"),
    "calibration_min_duration_ms": 8000,
    "tcp_sampling": sys.argv[5] == "true",
}
if sys.argv[6] in ("--inside-full", "--inside-full-affinity", "--inside-full-client", "--inside-balanced-affinity"):
    manifest.update({
        "measurement": "http2_isolated_full_quality_v1",
        "required_body_bytes": [1024, 1048576],
        "required_max_concurrent_streams": [1, 100],
        "sampling_order": "round_robin_interleaved",
        "strict_default_spread_limits": True,
    })
    del manifest["body_bytes"], manifest["max_concurrent_streams"]
if sys.argv[6] in ("--inside-full-affinity", "--inside-balanced-affinity"):
    import os
    available = sorted(os.sched_getaffinity(0))
    client_count = 2 if sys.argv[6] == "--inside-balanced-affinity" else 1
    measurement = ("http2_isolated_balanced_affinity_quality_v1" if client_count == 2
                   else "http2_isolated_full_affinity_quality_v1")
    manifest.update({"measurement": measurement,
                     "available_cpus": available, "client_cpus": available[:client_count],
                     "server_cpus": available[client_count:]})
if sys.argv[6] == "--inside-full-client":
    manifest.update({"measurement": "http2_client_cpu_profile_v1",
                     "client_cpu_profiler": "perf cpu-clock at 199 Hz without call graphs",
                     "client_profile_scope": "calibration_and_measurement",
                     "client_usage_includes_profiler": True})
(root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
PY_NAMESPACE
  chown -R "$SUDO_UID:$SUDO_GID" "$profile_dir"
  # Preserve both experiments, including failed default-MTU measurements.
  if [ "$sampled" = true ]; then
    python3 "$ROOT_DIR/scripts/lib/perf-tcp-sampler.py" --probe-only
    stop_file="$phase_dir/tcp-sampler.stop"
    python3 "$ROOT_DIR/scripts/lib/perf-tcp-sampler.py" \
      --output "$phase_dir/tcp-state.jsonl.gz" --stop-file "$stop_file" \
      --ports 18280 18281 18282 18283 18284 > "$phase_dir/tcp-sampler.log" 2>&1 &
    sampler_pid=$!
  fi
  phase_status=0
  "${affinity_command[@]}" setpriv --reuid "$SUDO_UID" --regid "$SUDO_GID" --init-groups env \
    QPX_NATIVE_PERF_BIN="${QPX_NATIVE_PERF_BIN:-}" \
    QPX_REAL_H2LOAD="${QPX_REAL_H2LOAD:-}" \
    QPX_NATIVE_PROFILE_MODE="${QPX_NATIVE_PROFILE_MODE:-cpu}" \
    QPX_NATIVE_PROFILE_DIR="${QPX_NATIVE_PROFILE_DIR:-}" \
    QPX_NATIVE_WRAPPER_SOURCE="${QPX_NATIVE_WRAPPER_SOURCE:-}" \
    PATH="$client_path" QPX_HTTP2_COMPARE_NATIVE_DIAGNOSTICS=1 QPX_HTTP2_COMPARE_BODY_SIZES="$body_sizes" \
    QPX_HTTP2_COMPARE_MAX_CONCURRENT_STREAMS_VALUES="$stream_counts" \
    QPX_HTTP2_COMPARE_CALIBRATION_MIN_DURATION_MS=8000 \
    QPX_HTTP2_COMPARE_SAMPLE_ATTEMPTS=3 QPX_HTTP2_COMPARE_LOG_DIR="$phase_dir/logs" \
    bash "$ROOT_DIR/scripts/perf-audit-http2-compare.sh" "$phase_dir/comparison.jsonl" \
    || phase_status=$?
  sampler_status=0
  if [ "$sampled" = true ]; then
    stop_sampler || sampler_status=$?
    printf '%s\n' "$sampler_status" > "$phase_dir/tcp-sampler-exit-status.txt"
  fi
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
    echo "HTTP/2 phase $phase comparison failed: $phase_status" >&2
    status=1
  fi
done
exit "$status"
