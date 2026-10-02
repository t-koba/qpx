#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE_BIN="${QPX_PERF_BASELINE_BIN:?QPX_PERF_BASELINE_BIN is required}"
CURRENT_BIN="${QPXD_BIN:-$ROOT_DIR/target/release/qpxd}"
REPETITION="${QPX_PERF_REPETITION:?QPX_PERF_REPETITION is required}"
OUT_JSON="${QPX_PROXY_COMPARE_JSON:?QPX_PROXY_COMPARE_JSON is required}"

case "$REPETITION" in
  1|2|3) ;;
  *) echo "performance repetition must be 1, 2, or 3" >&2; exit 2 ;;
esac
for binary in "$BASELINE_BIN" "$CURRENT_BIN"; do
  if [ ! -x "$binary" ]; then
    echo "missing performance comparison binary: $binary" >&2
    exit 1
  fi
done

# Both revisions use the current measurement harness on the same runner.
# Alternate the order between independent runs to expose order effects.
if [ "$REPETITION" = 2 ]; then
  revisions="current baseline"
else
  revisions="baseline current"
fi
failed=0
for revision in $revisions; do
  binary="$CURRENT_BIN"
  output="$OUT_JSON"
  logs="$ROOT_DIR/target/perf/proxy-compare-logs"
  revision_sha="${GITHUB_SHA:-$(git -C "$ROOT_DIR" rev-parse HEAD)}"
  if [ "$revision" = baseline ]; then
    binary="$BASELINE_BIN"
    revision_sha="${QPX_PERF_BASELINE_SHA:?QPX_PERF_BASELINE_SHA is required}"
    output="$ROOT_DIR/target/perf/perf-audit-baseline-proxy-compare.jsonl"
    logs="$ROOT_DIR/target/perf/baseline-proxy-compare-logs"
  fi
  if ! GITHUB_SHA="$revision_sha" QPXD_BIN="$binary" QPX_PROXY_MATRIX_LOG_DIR="$logs" \
    python3 "$ROOT_DIR/scripts/perf-evaluate.py" "$revision proxy comparison" -- \
      bash "$ROOT_DIR/scripts/perf-audit-proxy-matrix.sh" "$output"; then
    echo "$revision proxy comparison failed" >&2
    failed=1
  fi
done
exit "$failed"
