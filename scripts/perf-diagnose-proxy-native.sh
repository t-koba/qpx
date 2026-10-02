#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workload="${QPX_NATIVE_WORKLOAD:-proxy}"
export QPXD_REAL_BIN="${QPXD_BIN:-$ROOT_DIR/target/callgrind/qpxd}"
export QPX_NATIVE_PROFILE_DIR="$ROOT_DIR/target/perf/profiles/native"
export QPX_NATIVE_PERF_BIN="${QPX_NATIVE_PERF_BIN:?native perf executable is required}"
[ -x "$QPXD_REAL_BIN" ]
[ -x "$QPX_NATIVE_PERF_BIN" ]
mkdir -p "$QPX_NATIVE_PROFILE_DIR"
"$QPX_NATIVE_PERF_BIN" --version
wrapper="$QPX_NATIVE_PROFILE_DIR/qpxd-perf"
cat >"$wrapper" <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
if [ "$1" != run ]; then
  exec "$QPXD_REAL_BIN" "$@"
fi
role=""
previous=""
for argument in "$@"; do
  if [ "$previous" = --config ]; then
    role="${argument##*/}"
    role="${role%.yaml}"
  fi
  previous="$argument"
done
[ -n "$role" ]
setsid "$QPX_NATIVE_PERF_BIN" record -e cpu-clock -F 199 --clockid CLOCK_MONOTONIC \
  --call-graph dwarf,16384 -o "$QPX_NATIVE_PROFILE_DIR/$role.data" \
  -- "$QPXD_REAL_BIN" "$@" &
profile_pid=$!
cleanup() {
  trap - EXIT TERM INT
  if kill -0 "$profile_pid" 2>/dev/null; then
    kill -TERM -- "-$profile_pid"
  fi
  wait "$profile_pid" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
wait "$profile_pid"
WRAPPER
chmod 755 "$wrapper"
case "$workload" in
  proxy)
    QPXD_BIN="$wrapper" QPX_PROXY_COMPARE_THREAD_DIAGNOSTICS=1 \
      QPX_PROXY_COMPARE_PROXY_FILTER=qpxd-cache,nginx-cache,qpxd-feature-rich,nginx-feature-rich \
      QPX_PROXY_COMPARE_BODY_SIZES=1024 \
      bash "$ROOT_DIR/scripts/perf-audit-proxy-compare.sh"
    roles="qpxd-cache qpxd-feature-rich"
    log_directory="$ROOT_DIR/target/perf/proxy-compare-logs"
    expected_profiles=2
    minimum_reports=9
    ;;
  http2)
    QPXD_BIN="$wrapper" QPX_HTTP2_COMPARE_NATIVE_DIAGNOSTICS=1 \
      QPX_HTTP2_COMPARE_BODY_SIZES=1024 QPX_HTTP2_COMPARE_MAX_CONCURRENT_STREAMS_VALUES=100 \
      bash "$ROOT_DIR/scripts/perf-audit-http2-compare.sh"
    roles="qpxd-h2"
    log_directory="$ROOT_DIR/target/perf/http2-compare-logs"
    expected_profiles=1
    minimum_reports=3
    ;;
  *) echo "unsupported native CPU workload: $workload" >&2; exit 2 ;;
esac

# Harness shutdown also closes perf's output before report generation.
profiles=0
for profile in "$QPX_NATIVE_PROFILE_DIR"/*.data; do
  [ -f "$profile" ] || continue
  "$QPX_NATIVE_PERF_BIN" report --stdio --header --no-children \
    --sort symbol --percent-limit 0.5 -i "$profile" >"$profile.report.txt"
  if ! rg -q '^# Samples: [1-9]' "$profile.report.txt"; then
    echo "native CPU profile contains no samples: $profile" >&2
    exit 1
  fi
  profiles=$((profiles + 1))
done
if [ "$profiles" -ne "$expected_profiles" ]; then
  echo "native CPU profiling lacks required roles: observed $profiles; expected $expected_profiles" >&2
  exit 1
fi
reports=0
for role in $roles; do
  sample_role="$role"
  if [ "$workload" = http2 ]; then
    sample_role=qpxd
  fi
  for sample in "$log_directory"/*."$sample_role".*.rss-peak.samples.csv; do
    [ -f "$sample" ] || continue
    window="$(python3 - "$sample" <<'PY'
import csv
import sys
rows = list(csv.DictReader(open(sys.argv[1])))
if len(rows) < 2:
    raise SystemExit("native profile window requires at least two real workload samples")
first, last = int(rows[0]["monotonic_ns"]), int(rows[-1]["monotonic_ns"])
if first >= last:
    raise SystemExit("native profile workload sample times are not increasing")
def timestamp(value):
    return f"{value // 1_000_000_000}.{value % 1_000_000_000:09d}"
print(f"{timestamp(first)},{timestamp(last)}")
PY
)"
    "$QPX_NATIVE_PERF_BIN" report --stdio --header --no-children \
      --sort symbol --percent-limit 0.5 --time "$window" \
      -i "$QPX_NATIVE_PROFILE_DIR/$role.data" >"$sample.cpu-report.txt"
    if ! rg -q '^# Samples: [1-9]' "$sample.cpu-report.txt"; then
      echo "native workload CPU profile contains no samples: $sample" >&2
      exit 1
    fi
    reports=$((reports + 1))
  done
done
if [ "$reports" -lt "$minimum_reports" ]; then
  echo "native CPU profiling lacks complete workload windows: observed $reports" >&2
  exit 1
fi
echo "Native CPU profiles: $profiles"
echo "Native workload CPU reports: $reports"
