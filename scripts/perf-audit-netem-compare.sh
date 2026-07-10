#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_JSON="${1:-${QPX_NETEM_COMPARE_JSON:-$ROOT_DIR/target/perf/perf-audit-netem-proxy-compare.jsonl}}"
META_JSON="${QPX_NETEM_META_JSON:-$ROOT_DIR/target/perf/perf-audit-netem-profile.jsonl}"
DELAY="${QPX_NETEM_DELAY:-1ms}"
JITTER="${QPX_NETEM_JITTER:-0.2ms}"
LOSS="${QPX_NETEM_LOSS:-0.01%}"
MAX_READ_ERROR_RATE_PPM="${QPX_NETEM_PROXY_COMPARE_MAX_READ_ERROR_RATE_PPM:-1000}"

mkdir -p "$(dirname "$OUT_JSON")"

case "$MAX_READ_ERROR_RATE_PPM" in
  ''|*[!0-9]*)
    echo "QPX_NETEM_PROXY_COMPARE_MAX_READ_ERROR_RATE_PPM must be an integer from 0 to 1000000" >&2
    exit 1
    ;;
esac
if [ "$MAX_READ_ERROR_RATE_PPM" -gt 1000000 ]; then
  echo "QPX_NETEM_PROXY_COMPARE_MAX_READ_ERROR_RATE_PPM must be an integer from 0 to 1000000" >&2
  exit 1
fi

cleanup_netem() {
  sudo tc qdisc del dev lo root >/dev/null 2>&1 || true
}
trap cleanup_netem EXIT

if ! command -v tc >/dev/null 2>&1; then
  echo "missing required command: tc" >&2
  exit 1
fi

cleanup_netem
sudo tc qdisc add dev lo root netem delay "$DELAY" "$JITTER" loss "$LOSS"
python3 - "$META_JSON" "$DELAY" "$JITTER" "$LOSS" "$MAX_READ_ERROR_RATE_PPM" "${GITHUB_SHA:-unknown}" <<'PY'
import json
import sys

path, delay, jitter, loss, max_read_error_rate_ppm, commit = sys.argv[1:7]
record = {
    "bench": "network_condition_profile",
    "device": "lo",
    "emulation": "tc-netem",
    "delay": delay,
    "jitter": jitter,
    "loss": loss,
    "max_read_error_rate_ppm": int(max_read_error_rate_ppm),
    "commit": commit,
}
with open(path, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
PY

QPX_PROXY_COMPARE_DURATION_SECONDS="${QPX_NETEM_PROXY_COMPARE_DURATION_SECONDS:-5}" \
QPX_PROXY_COMPARE_BODY_SIZES="${QPX_NETEM_PROXY_COMPARE_BODY_SIZES:-1024 1048576}" \
QPX_PROXY_COMPARE_LOG_DIR="${QPX_NETEM_PROXY_COMPARE_LOG_DIR:-$ROOT_DIR/target/perf/netem-proxy-compare-logs}" \
QPX_PROXY_COMPARE_MAX_READ_ERROR_RATE_PPM="$MAX_READ_ERROR_RATE_PPM" \
QPX_PROXY_COMPARE_JSON="$OUT_JSON" \
"$ROOT_DIR/scripts/perf-audit-proxy-compare.sh" "$OUT_JSON"
