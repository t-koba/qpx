#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ "$(uname -s)" != Linux ]; then
  echo "streaming window diagnostics require Linux resource accounting" >&2
  exit 1
fi
if [ -n "${QPX_STREAMING_COMPARE_SERVER_CPUS:-}${QPX_STREAMING_COMPARE_CLIENT_CPUS:-}" ]; then
  echo "streaming window diagnostics must retain normal CPU scheduling" >&2
  exit 1
fi
mkdir -p "$ROOT_DIR/target/perf/profiles"
profile_dir="$(mktemp -d "$ROOT_DIR/target/perf/profiles/streaming-window.XXXXXX")"
order="${QPX_STREAMING_WINDOW_ORDER:-normal-extended}"
case "$order" in
  normal-extended) windows=(normal extended) ;;
  extended-normal) windows=(extended normal) ;;
  *) echo "unsupported streaming window order: $order" >&2; exit 2 ;;
esac
python3 - "$profile_dir" "$order" "${QPXD_BIN:-$ROOT_DIR/target/release/qpxd}" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
root, order, binary = sys.argv[1:]
Path(root, "manifest.json").write_text(json.dumps({
    "measurement": "streaming_same_runner_window_comparison_v1",
    "sampling_order": order.split("-"), "replaces_required_gate": False,
    "diagnostic_cpu_partition": False,
    "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
    "windows": {"normal": {"fast_transfers": 8, "slow_transfers": 1},
                "extended": {"fast_transfers": 64, "slow_transfers": 8}},
}, indent=2) + "\n")
PY
failed=0
for window in "${windows[@]}"; do
  phase="$profile_dir/$window"
  mkdir "$phase"
  fast=8 slow=1 mode=acceptance
  if [ "$window" = extended ]; then
    fast=64 slow=8 mode=window-diagnostic
  fi
  ip -json link show dev lo > "$phase/interfaces-before.json"
  if ! QPX_STREAMING_COMPARE_FAST_TRANSFERS="$fast" \
    QPX_STREAMING_COMPARE_SLOW_TRANSFERS="$slow" \
    QPX_STREAMING_COMPARE_LOG_DIR="$phase/logs" \
    python3 "$ROOT_DIR/scripts/perf-evaluate.py" "streaming $window window measurement" -- \
      bash "$ROOT_DIR/scripts/perf-audit-streaming-compare.sh" "$phase/comparison.jsonl"; then
    failed=1
  fi
  ip -json link show dev lo > "$phase/interfaces-after.json"
  cmp "$phase/interfaces-before.json" "$phase/interfaces-after.json"
  if ! python3 "$ROOT_DIR/scripts/perf-evaluate.py" "streaming $window window objectives" -- \
    bash "$ROOT_DIR/scripts/check-streaming-performance.sh" "$phase/comparison.jsonl" \
    "$ROOT_DIR/perf/streaming-performance-objectives.json" "$mode"; then
    failed=1
  fi
done
exit "$failed"
