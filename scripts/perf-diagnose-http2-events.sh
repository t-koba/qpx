#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PERF_BIN="${QPX_NATIVE_PERF_BIN:?native perf executable is required}"
if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != --probe-only ]; }; then
  echo "unsupported kernel wait diagnostic argument" >&2
  exit 2
fi
mkdir -p "$ROOT_DIR/target/perf/profiles"
PROFILE_DIR="$(mktemp -d "$ROOT_DIR/target/perf/profiles/http2-events.XXXXXX")"
EVENTS=""
for syscall in epoll_wait epoll_pwait futex connect; do
  for phase in enter exit; do
    event="sys_${phase}_${syscall}"
    if [ ! -r "/sys/kernel/tracing/events/syscalls/$event/id" ]; then
      echo "required kernel wait tracepoint is unavailable: $event" >&2
      exit 1
    fi
    EVENTS="${EVENTS:+$EVENTS,}syscalls:$event"
  done
done
# Exercise the same kernel event recorder with a real socket before measurement.
"$PERF_BIN" record -v --no-buildid --clockid CLOCK_MONOTONIC -e "$EVENTS" \
  -o "$PROFILE_DIR/probe.data" -- python3 - <<'PY_PROBE'
import selectors
import socket
reader, writer = socket.socketpair()
try:
    with selectors.DefaultSelector() as selector:
        selector.register(reader, selectors.EVENT_READ)
        if selector.select(0.02):
            raise SystemExit("real socket probe became unexpectedly readable")
        writer.sendall(b"kernel-wait-probe")
        if not selector.select(1):
            raise SystemExit("real socket probe did not become readable")
        if reader.recv(64) != b"kernel-wait-probe":
            raise SystemExit("real socket probe response mismatch")
finally:
    reader.close()
    writer.close()
PY_PROBE
"$PERF_BIN" script -v --ns -F trace:comm,pid,tid,time,event,trace -i "$PROFILE_DIR/probe.data" \
  > "$PROFILE_DIR/probe.events.txt"
if ! rg -q 'syscalls:sys_exit_epoll_wait' "$PROFILE_DIR/probe.events.txt"; then
  echo "real socket probe produced no kernel wait events" >&2
  exit 1
fi
if [ "${1:-}" = --probe-only ]; then
  echo "Real kernel wait recorder and decoder probe passed"
  exit 0
fi
status=0
QPX_HTTP2_COMPARE_NATIVE_DIAGNOSTICS=1 QPX_HTTP2_COMPARE_BODY_SIZES=1048576 \
  QPX_HTTP2_COMPARE_MAX_CONCURRENT_STREAMS_VALUES=100 \
  "$PERF_BIN" record --no-buildid --clockid CLOCK_MONOTONIC -a -m 8M -e "$EVENTS" \
    -o "$PROFILE_DIR/measurement.data" -- bash "$ROOT_DIR/scripts/perf-audit-http2-compare.sh" \
    || status=$?
"$PERF_BIN" script --ns --show-lost-events -F trace:comm,pid,tid,time,event,trace \
  -i "$PROFILE_DIR/measurement.data" > "$PROFILE_DIR/measurement.events.txt"
if rg -q 'PERF_RECORD_LOST|LOST [1-9]' "$PROFILE_DIR/measurement.events.txt"; then
  echo "kernel wait recording lost events" >&2
  exit 1
fi
for process in qpxd nginx h2load; do
  if ! rg -q "^[[:space:]]*${process}[[:space:]]" "$PROFILE_DIR/measurement.events.txt"; then
    echo "kernel wait recording lacks an actual comparison process: $process" >&2
    exit 1
  fi
done
python3 - "$PROFILE_DIR" "$status" "$EVENTS" <<'PY_MANIFEST'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
(root / "manifest.json").write_text(json.dumps({
    "measurement": "http2_kernel_wait_events_v1", "clock": "CLOCK_MONOTONIC",
    "diagnostic_instrumentation": True, "payload_capture": False,
    "events": sys.argv[3].split(","), "benchmark_exit_status": int(sys.argv[2]),
    "required_processes": ["qpxd", "nginx", "h2load"],
    "event_stream": "measurement.events.txt",
}, indent=2) + "\n")
PY_MANIFEST
exit "$status"
