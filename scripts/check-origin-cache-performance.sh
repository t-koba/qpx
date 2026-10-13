#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JSONL="${1:-${QPX_PROXY_COMPARE_JSON:-}}"
OBJECTIVES="${2:-${QPX_ORIGIN_CACHE_PERFORMANCE_OBJECTIVES:-$ROOT_DIR/perf/origin-cache-performance-objectives.json}}"
if [ -z "$JSONL" ]; then
  echo "usage: scripts/check-origin-cache-performance.sh <jsonl> [objectives-json]" >&2
  exit 2
fi
# Competitive report only on shared runners; exit 75 means spread-invalid,
# never PASSED. Use perf-audit-policy.py run for paired gating and retries.
exec python3 "$ROOT_DIR/scripts/perf-audit-policy.py" check origin "$JSONL" --objectives "$OBJECTIVES"
