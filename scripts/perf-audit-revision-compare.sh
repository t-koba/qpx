#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE_BIN="${QPX_PERF_BASELINE_BIN:?QPX_PERF_BASELINE_BIN is required}"
CURRENT_BIN="${QPXD_BIN:-$ROOT_DIR/target/release/qpxd}"
REPETITION="${QPX_PERF_REPETITION:?QPX_PERF_REPETITION is required}"
CATEGORY="${1:-proxy}"
OUT_JSON="${2:-${QPX_PROXY_COMPARE_JSON:?comparison output is required}}"
case "$CATEGORY" in
  proxy)
    harness="perf-audit-proxy-matrix.sh"
    log_variable="QPX_PROXY_MATRIX_LOG_DIR"
    checker="check-origin-cache-performance.sh"
    objectives="origin-cache-performance-objectives.json"
    ;;
  http2)
    harness="perf-audit-http2-compare.sh"
    log_variable="QPX_HTTP2_COMPARE_LOG_DIR"
    checker="check-http2-performance.sh"
    objectives="http2-performance-objectives.json"
    ;;
  streaming)
    harness="perf-audit-streaming-compare.sh"
    log_variable="QPX_STREAMING_COMPARE_LOG_DIR"
    checker="check-streaming-performance.sh"
    objectives="streaming-performance-objectives.json"
    ;;
  *) echo "unsupported comparison category: $CATEGORY" >&2; exit 2 ;;
esac

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
  logs="$ROOT_DIR/target/perf/${CATEGORY}-compare-logs"
  revision_sha="${GITHUB_SHA:-$(git -C "$ROOT_DIR" rev-parse HEAD)}"
  if [ "$revision" = baseline ]; then
    binary="$BASELINE_BIN"
    revision_sha="${QPX_PERF_BASELINE_SHA:?QPX_PERF_BASELINE_SHA is required}"
    output="$ROOT_DIR/target/perf/perf-audit-baseline-${CATEGORY}-compare.jsonl"
    logs="$ROOT_DIR/target/perf/baseline-${CATEGORY}-compare-logs"
  fi
  if ! env GITHUB_SHA="$revision_sha" QPXD_BIN="$binary" "$log_variable=$logs" \
    python3 "$ROOT_DIR/scripts/perf-evaluate.py" "$revision $CATEGORY comparison" -- \
      bash "$ROOT_DIR/scripts/$harness" "$output"; then
    echo "$revision $CATEGORY comparison failed" >&2
    failed=1
  fi
  if [ "$revision" = baseline ]; then
    if ! python3 "$ROOT_DIR/scripts/perf-evaluate.py" "baseline $CATEGORY measurement quality" -- \
      bash "$ROOT_DIR/scripts/$checker" "$output" "$ROOT_DIR/perf/$objectives" measurement-quality; then
      echo "baseline $CATEGORY measurement quality failed" >&2
      failed=1
    fi
  fi
done
exit "$failed"
