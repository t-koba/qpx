#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export QPXD_REAL_BIN="${QPXD_BIN:-$ROOT_DIR/target/callgrind/qpxd}"
export QPX_FEATURE_PROFILE_DIR="$ROOT_DIR/target/perf/profiles/feature-rich"
[ -x "$QPXD_REAL_BIN" ]
mkdir -p "$QPX_FEATURE_PROFILE_DIR"
wrapper="$QPX_FEATURE_PROFILE_DIR/qpxd-callgrind"
cat >"$wrapper" <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
if [ "$1" != run ]; then
  exec "$QPXD_REAL_BIN" "$@"
fi
exec valgrind --tool=callgrind --instr-atstart=no \
  --callgrind-out-file="$QPX_FEATURE_PROFILE_DIR/callgrind.%p.out" \
  "$QPXD_REAL_BIN" "$@"
WRAPPER
chmod 755 "$wrapper"
QPXD_BIN="$wrapper" \
  QPX_PROXY_COMPARE_THREAD_DIAGNOSTICS=1 \
  QPX_PROXY_COMPARE_CALLGRIND_DIAGNOSTICS=1 \
  QPX_PROXY_COMPARE_PROXY_FILTER=qpxd-feature-rich,nginx-feature-rich \
  QPX_PROXY_COMPARE_BODY_SIZES=1024 \
  bash "$ROOT_DIR/scripts/perf-audit-proxy-compare.sh"
profiles=0
for profile in "$QPX_FEATURE_PROFILE_DIR"/callgrind.*.out*; do
  [ -f "$profile" ] || continue
  case "$profile" in *.annotated.txt) continue ;; esac
  instructions="$(awk '/^(summary|totals):/ { if ($2 > maximum) maximum = $2 } END { print maximum + 0 }' "$profile")"
  [ "$instructions" -gt 0 ] || continue
  callgrind_annotate --auto=no "$profile" >"$profile.annotated.txt"
  profiles=$((profiles + 1))
done
if [ "$profiles" -eq 0 ]; then
  echo "feature-rich callgrind profiling produced no dumps" >&2
  exit 1
fi
echo "Feature-rich callgrind profiles: $profiles"
