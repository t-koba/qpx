#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export QPX_REAL_QPXD="${QPXD_BIN:-$ROOT_DIR/target/release/qpxd}"
export QPX_REAL_NGINX QPX_REAL_H2LOAD QPX_NATIVE_PERF_BIN QPX_NATIVE_WRAPPER_SOURCE
QPX_REAL_NGINX="$(command -v nginx)"
QPX_REAL_H2LOAD="$(command -v h2load)"
QPX_NATIVE_PERF_BIN="$(command -v strace)"
QPX_NATIVE_WRAPPER_SOURCE="$ROOT_DIR/scripts/lib/perf-native-process.py"
export QPX_NATIVE_PROFILE_MODE=syscalls
export QPX_NATIVE_PROFILE_DIR
mkdir -p "$ROOT_DIR/target/perf/profiles"
QPX_NATIVE_PROFILE_DIR="$(mktemp -d "$ROOT_DIR/target/perf/profiles/http2-io.XXXXXX")"
mkdir -p "$QPX_NATIVE_PROFILE_DIR/tools"
for program in qpxd nginx h2load; do
  wrapper="$QPX_NATIVE_PROFILE_DIR/tools/$program"
  cat >"$wrapper" <<'IO_WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
case "${0##*/}" in
  qpxd) export QPXD_REAL_BIN="$QPX_REAL_QPXD" ;;
  nginx) export QPXD_REAL_BIN="$QPX_REAL_NGINX" ;;
  h2load) export QPXD_REAL_BIN="$QPX_REAL_H2LOAD" ;;
  *) echo "unsupported syscall trace program" >&2; exit 2 ;;
esac
exec python3 "$QPX_NATIVE_WRAPPER_SOURCE" "$@"
IO_WRAPPER
  chmod 755 "$wrapper"
done
bash "$ROOT_DIR/scripts/check-perf-native-process.sh" "$QPX_NATIVE_PROFILE_DIR/tools/qpxd"
status=0
PATH="$QPX_NATIVE_PROFILE_DIR/tools:$PATH" QPXD_BIN="$QPX_NATIVE_PROFILE_DIR/tools/qpxd" \
  QPX_HTTP2_COMPARE_NATIVE_DIAGNOSTICS=1 QPX_HTTP2_COMPARE_BODY_SIZES=1048576 \
  QPX_HTTP2_COMPARE_MAX_CONCURRENT_STREAMS_VALUES=100 \
  bash "$ROOT_DIR/scripts/perf-audit-http2-compare.sh" || status=$?
python3 - "$QPX_NATIVE_PROFILE_DIR" <<'IO_SUMMARY'
import json
from pathlib import Path
import re
import sys
root = Path(sys.argv[1])
lifecycle = [json.loads(path.read_text()) for path in root.glob('*.lifecycle.json')]
if not lifecycle or any(row['forced_shutdown'] for row in lifecycle):
    raise SystemExit('syscall tracer lifecycle is missing or incomplete')
if not any(row['role'] == 'qpxd-h2' for row in lifecycle):
    raise SystemExit('syscall trace lacks the actual qpxd server')
for row in lifecycle:
    if row['role'].startswith('h2load-'):
        if row['requested_signal'] is not None or row['exit_status'] != 0:
            raise SystemExit('real h2load syscall trace did not complete cleanly')
    elif row['requested_signal'] != 15 or row['exit_status'] not in (0, -15, 143):
        raise SystemExit('real server syscall trace did not stop cleanly')
waits = []
for path in root.glob('*.syscalls.*'):
    for line in path.read_text(errors='replace').splitlines():
        duration = re.search(r'<([0-9.]+)>$', line)
        if duration and float(duration.group(1)) >= 1:
            waits.append({'trace': path.name, 'seconds': float(duration.group(1)), 'line': line})
if not list(root.glob('*.syscalls.*')):
    raise SystemExit('syscall tracing produced no actual trace files')
(root / 'wait-summary.json').write_text(json.dumps({
    'measurement': 'diagnostic_syscall_waits_v1', 'lifecycle': lifecycle,
    'waits_at_least_one_second': sorted(waits, key=lambda row: -row['seconds']),
}, indent=2) + '\n')
print(f'Real syscall trace captured {len(lifecycle)} processes and {len(waits)} long waits')
IO_SUMMARY
exit "$status"
