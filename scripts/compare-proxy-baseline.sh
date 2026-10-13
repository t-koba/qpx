#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE=check
THRESHOLD=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --generate-baseline) MODE=generate; shift ;;
    --threshold) THRESHOLD="${2:?missing threshold}"; shift 2 ;;
    --help|-h) echo "usage: $0 [--generate-baseline] [--threshold 0.10] <jsonl> [baseline-json] [objectives-json]"; exit 0 ;;
    --) shift; break ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) break ;;
  esac
done
JSONL="${1:-${QPX_PROXY_COMPARE_JSON:-}}"
BASELINE="${2:-${QPX_PROXY_COMPARE_BASELINE:-$ROOT_DIR/perf/baseline-proxy-compare.json}}"
OBJECTIVES="${3:-${QPX_PROXY_PERFORMANCE_OBJECTIVES:-$ROOT_DIR/perf/proxy-performance-objectives.json}}"
if [ -z "$JSONL" ]; then
  echo "missing proxy JSONL" >&2
  exit 2
fi
if [ "$MODE" = generate ]; then
  args=(generate "$JSONL" "$BASELINE")
  if [ -n "$THRESHOLD" ]; then args+=(--threshold "$THRESHOLD"); fi
else
  if [ -n "$THRESHOLD" ]; then
    echo "set the documented historical threshold in baseline JSON, not a gate-time override" >&2
    exit 2
  fi
  args=(check proxy "$JSONL" --baseline "$BASELINE" --objectives "$OBJECTIVES")
fi
exec python3 "$ROOT_DIR/scripts/perf-audit-policy.py" "${args[@]}"
