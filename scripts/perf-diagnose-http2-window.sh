#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export QPX_H2_REAL_CLIENT
QPX_H2_REAL_CLIENT="$(command -v h2load)"
[ -x "$QPX_H2_REAL_CLIENT" ]
work="$(mktemp -d "$ROOT_DIR/target/perf/http2-windows.XXXXXX")"
mkdir -p "$work/tools"
cat >"$work/tools/h2load" <<'CLIENT'
#!/usr/bin/env bash
set -euo pipefail
exec "$QPX_H2_REAL_CLIENT" --window-bits="$QPX_H2_WINDOW_BITS" \
  --connection-window-bits="$QPX_H2_WINDOW_BITS" "$@"
CLIENT
chmod 755 "$work/tools/h2load"
failed=0
for window in 30 24; do
  directory="$work/window-$window"
  mkdir -p "$directory"
  export QPX_H2_WINDOW_BITS="$window"
  python3 - "$directory/client.json" <<'PY_CONFIG'
import json
import os
from pathlib import Path
import sys
record = {'measurement': 'diagnostic_http2_client_window_comparison_v1',
          'stream_window_bits': int(os.environ['QPX_H2_WINDOW_BITS']),
          'connection_window_bits': int(os.environ['QPX_H2_WINDOW_BITS']),
          'client': os.environ['QPX_H2_REAL_CLIENT'], 'commit': os.environ['GITHUB_SHA']}
Path(sys.argv[1]).write_text(json.dumps(record, sort_keys=True) + '\n')
PY_CONFIG
  if ! PATH="$work/tools:$PATH" QPX_HTTP2_COMPARE_NATIVE_DIAGNOSTICS=1 \
    QPX_HTTP2_COMPARE_BODY_SIZES=1048576 QPX_HTTP2_COMPARE_MAX_CONCURRENT_STREAMS_VALUES=100 \
    QPX_HTTP2_COMPARE_LOG_DIR="$directory/logs" \
    python3 "$ROOT_DIR/scripts/perf-evaluate.py" "HTTP/2 window $window diagnostic" -- \
      bash "$ROOT_DIR/scripts/perf-audit-http2-compare.sh" "$directory/measurements.jsonl"; then
    failed=1
  fi
  if ! python3 "$ROOT_DIR/scripts/perf-evaluate.py" "HTTP/2 window $window measurement quality" -- \
    python3 - "$directory/measurements.jsonl" <<'PY_QUALITY'
import json
import math
from pathlib import Path
import sys
records = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines() if line.strip()]
if len(records) != 3 or {row['proxy'] for row in records} != {'qpxd', 'nginx', 'direct-backend'}:
    raise SystemExit('HTTP/2 window diagnostic requires all three actual servers')
failed = False
for row in records:
    if (row['valid'] is not True or row['diagnostic_instrumentation'] is not True
            or row['body_bytes'] != 1048576 or row['max_concurrent_streams'] != 100
            or row['failed_requests'] != 0 or row['complete_requests'] != row['benchmark_request_count']
            or row['valid_samples'] != 3):
        raise SystemExit('HTTP/2 window diagnostic lacks clean completed workload samples')
    limit = 1.1 if row['proxy'] == 'qpxd' else 1.25
    checks = []
    for metric in ('requests_per_sec_ratio', 'requests_per_total_cpu_second_ratio'):
        actual = row['sample_spread'][metric]
        if not math.isfinite(actual) or actual < 1:
            raise SystemExit('HTTP/2 window diagnostic has invalid sample spread')
        passed = actual <= limit
        failed |= not passed
        checks.append({'metric': metric, 'actual': actual, 'limit': limit, 'direction': 'max',
                       'passed': passed, 'violation_percent': max(0.0, (actual / limit - 1) * 100)})
    print(json.dumps({'bench': row['bench'], 'body_bytes': row['body_bytes'],
                      'proxy': row['proxy'], 'scope': 'diagnostic-measurement-quality',
                      'checks': checks, 'measurements': row}, sort_keys=True))
raise SystemExit(1 if failed else 0)
PY_QUALITY
  then
    failed=1
  fi
done
exit "$failed"
