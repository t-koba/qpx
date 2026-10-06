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
for syscall in epoll_wait epoll_pwait connect; do
  for phase in enter exit; do
    event="sys_${phase}_${syscall}"
    if [ ! -r "/sys/kernel/tracing/events/syscalls/$event/id" ]; then
      echo "required kernel wait tracepoint is unavailable: $event" >&2
      exit 1
    fi
    EVENTS="${EVENTS:+$EVENTS,}syscalls:$event"
  done
done
TCP_EVENTS="tcp:tcp_retransmit_skb"
if [ ! -r /sys/kernel/tracing/events/tcp/tcp_retransmit_skb/id ]; then
  echo "required kernel TCP retransmission tracepoint is unavailable" >&2
  exit 1
fi
if [ "${QPX_PERF_NATIVE_IO_TIMELINE:-0}" = 1 ]; then
  if [ ! -r /sys/kernel/tracing/events/tcp/tcp_probe/id ]; then
    echo "required kernel TCP receive tracepoint is unavailable" >&2
    exit 1
  fi
  TCP_EVENTS="$TCP_EVENTS,tcp:tcp_probe"
fi
# Exercise the same kernel event recorder with a real socket before measurement.
"$PERF_BIN" record -v --no-buildid --clockid CLOCK_MONOTONIC -e "$EVENTS,$TCP_EVENTS" \
  -o "$PROFILE_DIR/probe.data" -- python3 - "$PROFILE_DIR/probe.tcp.json" <<'PY_PROBE'
import json
from pathlib import Path
import selectors
import socket
import sys
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind(("127.0.0.1", 0))
listener.listen(1)
listener.settimeout(1)
writer = socket.create_connection(listener.getsockname(), timeout=1)
reader, _ = listener.accept()
reader.settimeout(1)
try:
    with selectors.DefaultSelector() as selector:
        selector.register(reader, selectors.EVENT_READ)
        if selector.select(0.02):
            raise SystemExit("real socket probe became unexpectedly readable")
        writer.sendall(b"kernel-wait-probe")
        if not selector.select(1):
            raise SystemExit("real socket probe did not become readable")
        expected = b"kernel-wait-probe"
        received = b""
        while len(received) < len(expected):
            chunk = reader.recv(len(expected) - len(received))
            if not chunk:
                raise SystemExit("real TCP probe ended before the response")
            received += chunk
        if received != expected:
            raise SystemExit("real socket probe response mismatch")
        Path(sys.argv[1]).write_text(json.dumps({
            "local": "%s:%d" % reader.getsockname(),
            "peer": "%s:%d" % reader.getpeername(),
            "payload_bytes": len(expected),
        }) + "\n")
finally:
    reader.close()
    writer.close()
    listener.close()
PY_PROBE
"$PERF_BIN" script -v --ns -F trace:comm,pid,tid,time,event,trace -i "$PROFILE_DIR/probe.data" \
  > "$PROFILE_DIR/probe.events.txt"
if ! rg -q 'syscalls:sys_exit_epoll_wait' "$PROFILE_DIR/probe.events.txt"; then
  echo "real socket probe produced no kernel wait events" >&2
  exit 1
fi
if [ "${QPX_PERF_NATIVE_IO_TIMELINE:-0}" = 1 ]; then
  python3 "$ROOT_DIR/scripts/summarize-http2-io-timeline.py" --probe \
    "$PROFILE_DIR/probe.tcp.json" "$PROFILE_DIR/probe.events.txt"
fi
python3 "$ROOT_DIR/scripts/lib/perf-tcp-sampler.py" --probe-only
if [ "${1:-}" = --probe-only ]; then
  echo "Real kernel wait recorder and decoder probe passed"
  exit 0
fi
status=0
# Limit transport recording to the five owned benchmark listeners.
TCP_FILTER=""
TCP_PORTS=()
for port in "${QPX_HTTP2_COMPARE_BACKEND_PORT:-18280}" \
  "${QPX_HTTP2_COMPARE_QPX_PORT:-18281}" "${QPX_HTTP2_COMPARE_NGINX_PORT:-18282}" \
  "${QPX_HTTP2_COMPARE_BACKEND_H2_PORT:-18283}" "${QPX_HTTP2_COMPARE_NGINX_BACKEND_PORT:-18284}"; do
  if [[ ! "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    echo "invalid TCP diagnostic listener port: $port" >&2
    exit 2
  fi
  TCP_FILTER="${TCP_FILTER:+$TCP_FILTER || }sport == $port || dport == $port"
  TCP_PORTS+=("$port")
done
STOP_FILE="$PROFILE_DIR/tcp-sampler.stop"
python3 "$ROOT_DIR/scripts/lib/perf-tcp-sampler.py" \
  --output "$PROFILE_DIR/tcp-state.jsonl.gz" --stop-file "$STOP_FILE" \
  --ports "${TCP_PORTS[@]}" > "$PROFILE_DIR/tcp-sampler.log" 2>&1 &
sampler_pid=$!
# Invoked by the EXIT trap when recording or validation fails.
# shellcheck disable=SC2329
cleanup_sampler() {
  touch "$STOP_FILE"
  if ! wait "$sampler_pid"; then
    echo "TCP state sampler did not finish successfully" >&2
  fi
}
trap cleanup_sampler EXIT
tcp_record_args=(-e tcp:tcp_retransmit_skb --filter "$TCP_FILTER")
if [ "${QPX_PERF_NATIVE_IO_TIMELINE:-0}" = 1 ]; then
  tcp_record_args+=(-e tcp:tcp_probe --filter "$TCP_FILTER")
fi
QPX_HTTP2_COMPARE_NATIVE_DIAGNOSTICS=1 \
  QPX_HTTP2_COMPARE_BODY_SIZES="${QPX_HTTP2_COMPARE_BODY_SIZES:-1048576}" \
  QPX_HTTP2_COMPARE_MAX_CONCURRENT_STREAMS_VALUES=100 \
  "$PERF_BIN" record --no-buildid --clockid CLOCK_MONOTONIC -a -m 8M -e "$EVENTS" \
    "${tcp_record_args[@]}" \
    -o "$PROFILE_DIR/measurement.data" -- bash "$ROOT_DIR/scripts/perf-audit-http2-compare.sh" \
    || status=$?
touch "$STOP_FILE"
wait "$sampler_pid"
trap - EXIT
"$PERF_BIN" script --ns --show-lost-events -F trace:comm,pid,tid,time,event,trace \
  -i "$PROFILE_DIR/measurement.data" > "$PROFILE_DIR/measurement.events.txt"
if rg -q 'PERF_RECORD_LOST|LOST [1-9]' "$PROFILE_DIR/measurement.events.txt"; then
  echo "kernel wait recording lost events" >&2
  exit 1
fi
python3 - "$ROOT_DIR/target/perf/http2-compare-logs" "$PROFILE_DIR/measurement.events.txt" <<'PY_PROCESS'
import json
from pathlib import Path
import re
import sys
root = Path(sys.argv[1])
pids = set()
for sample in root.glob("http2.qpxd.*.rss-peak.sampling.json"):
    pid = json.loads(sample.read_text())["pid"]
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise SystemExit("qpxd resource sampling has an invalid process ID")
    pids.add(pid)
if not pids:
    raise SystemExit("kernel recording lacks real qpxd resource sample windows")
pattern = re.compile(r"^\s*.*?\s+(\d+)/(\d+)\s+\d+\.\d+:\s+syscalls:")
with Path(sys.argv[2]).open() as events:
    for line in events:
        match = pattern.match(line)
        if match and int(match[1]) in pids:
            break
    else:
        raise SystemExit("kernel recording lacks the sampled qpxd process")
PY_PROCESS
for process in nginx h2load; do
  if ! rg -q "^[[:space:]]*${process}[[:space:]]" "$PROFILE_DIR/measurement.events.txt"; then
    echo "kernel wait recording lacks an actual comparison process: $process" >&2
    exit 1
  fi
done
python3 - "$PROFILE_DIR" "$status" "$EVENTS,$TCP_EVENTS" "$TCP_FILTER" <<'PY_MANIFEST'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
(root / "manifest.json").write_text(json.dumps({
    "measurement": "http2_kernel_wait_events_v3", "clock": "CLOCK_MONOTONIC",
    "diagnostic_instrumentation": True, "payload_capture": False,
    "events": sys.argv[3].split(","), "benchmark_exit_status": int(sys.argv[2]),
    "tcp_filter": sys.argv[4],
    "tcp_state": "tcp-state.jsonl.gz", "tcp_sampling_interval_seconds": 0.1,
    "required_processes": ["qpxd", "nginx", "h2load"],
    "event_stream": "measurement.events.txt",
}, indent=2) + "\n")
PY_MANIFEST
if [ "${QPX_PERF_NATIVE_IO_TIMELINE:-0}" = 1 ]; then
  python3 "$ROOT_DIR/scripts/summarize-http2-io-timeline.py" \
    "$ROOT_DIR/target/perf/http2-compare-logs" "$PROFILE_DIR/measurement.events.txt" \
    "$PROFILE_DIR/io-timeline.json"
fi
exit "$status"
