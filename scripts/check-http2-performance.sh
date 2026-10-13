#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JSONL="${1:-${QPX_HTTP2_COMPARE_JSON:-}}"
OBJECTIVES="${2:-${QPX_HTTP2_PERFORMANCE_OBJECTIVES:-$ROOT_DIR/perf/http2-performance-objectives.json}}"
if [ -z "$JSONL" ]; then
  echo "usage: scripts/check-http2-performance.sh <jsonl> [objectives-json]" >&2
  exit 2
fi
# Competitive report only on shared runners; exit 75 means spread-invalid,
# never PASSED. Use perf-audit-policy.py run for paired gating and retries.
exec python3 "$ROOT_DIR/scripts/perf-audit-policy.py" check http2 "$JSONL" --objectives "$OBJECTIVES"
