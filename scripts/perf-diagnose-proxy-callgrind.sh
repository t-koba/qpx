#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export QPXD_REAL_BIN="${QPXD_BIN:-$ROOT_DIR/target/callgrind/qpxd}"
workload="${QPX_CALLGRIND_WORKLOAD:-feature-rich}"
case "$workload" in
  feature-rich) proxy="qpxd-feature-rich"; reference="nginx-feature-rich" ;;
  cache-miss) proxy="qpxd-cache"; reference="nginx-cache" ;;
  *) echo "unsupported callgrind workload: $workload" >&2; exit 2 ;;
esac
export QPX_PROXY_PROFILE_DIR="$ROOT_DIR/target/perf/profiles/$workload"
[ -x "$QPXD_REAL_BIN" ]
mkdir -p "$QPX_PROXY_PROFILE_DIR"
wrapper="$QPX_PROXY_PROFILE_DIR/qpxd-callgrind"
cat >"$wrapper" <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
if [ "$1" != run ]; then
  exec "$QPXD_REAL_BIN" "$@"
fi
exec valgrind --tool=callgrind --instr-atstart=no \
  --callgrind-out-file="$QPX_PROXY_PROFILE_DIR/callgrind.%p.out" \
  "$QPXD_REAL_BIN" "$@"
WRAPPER
chmod 755 "$wrapper"
QPXD_BIN="$wrapper" \
  QPX_PROXY_COMPARE_THREAD_DIAGNOSTICS=1 \
  QPX_PROXY_COMPARE_CALLGRIND_DIAGNOSTICS=1 \
  QPX_PROXY_COMPARE_CALLGRIND_PROXY="$proxy" \
  QPX_PROXY_COMPARE_PROXY_FILTER="$proxy,$reference" \
  QPX_PROXY_COMPARE_BODY_SIZES=1024 \
  bash "$ROOT_DIR/scripts/perf-audit-proxy-compare.sh"
profiles=0
for profile in "$QPX_PROXY_PROFILE_DIR"/callgrind.*.out*; do
  [ -f "$profile" ] || continue
  case "$profile" in *.annotated.txt) continue ;; esac
  instructions="$(awk '/^(summary|totals):/ { if ($2 > maximum) maximum = $2 } END { print maximum + 0 }' "$profile")"
  [ "$instructions" -gt 0 ] || continue
  callgrind_annotate --auto=no "$profile" >"$profile.annotated.txt"
  profiles=$((profiles + 1))
done
if [ "$profiles" -eq 0 ]; then
  echo "$workload callgrind profiling produced no dumps" >&2
  exit 1
fi
echo "Callgrind workload: $workload; profiles: $profiles"
