#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_JSON="${QPX_ALLOCATION_PROFILE_JSON:-$ROOT_DIR/target/perf/perf-audit-allocation-profile.jsonl}"
PROFILE_DIR="${QPX_ALLOCATION_PROFILE_DIR:-$ROOT_DIR/target/perf/allocations}"
ALLOCATION_TARGET_DIR="${QPX_ALLOCATION_TARGET_DIR:-$ROOT_DIR/target/perf/allocation-target}"
QPXD_BIN="${QPXD_BIN:-}"
REQUESTS="${QPX_ALLOCATION_PROFILE_REQUESTS:-64}"
BODY_BYTES="${QPX_ALLOCATION_PROFILE_BODY_BYTES:-1024}"
BACKEND_PORT="${QPX_ALLOCATION_BACKEND_PORT:-18480}"
QPX_PORT="${QPX_ALLOCATION_QPX_PORT:-18481}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/qpx-allocation-profile.XXXXXX")"
LOG_DIR="$TMP_DIR/logs"
STATE_DIR="$TMP_DIR/state"
mkdir -p "$LOG_DIR" "$STATE_DIR" "$PROFILE_DIR" "$(dirname "$OUT_JSON")"
rm -f "$PROFILE_DIR"/dhat.qpxd.*.json

PIDS=()
QPXD_PID=""

cleanup() {
  local pid
  for pid in "${PIDS[@]:-}"; do
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
  done
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

build_qpxd_for_allocation() {
  if [ -n "$QPXD_BIN" ]; then
    verify_qpxd_symbols "$QPXD_BIN"
    return
  fi
  CARGO_PROFILE_RELEASE_DEBUG=1 \
    CARGO_PROFILE_RELEASE_STRIP=false \
    CARGO_TARGET_DIR="$ALLOCATION_TARGET_DIR" \
    cargo build -p qpxd --release --locked --features system-allocator
  QPXD_BIN="$ALLOCATION_TARGET_DIR/release/qpxd"
  verify_qpxd_symbols "$QPXD_BIN"
}

verify_qpxd_symbols() {
  local bin="$1"
  if [ ! -x "$bin" ]; then
    echo "missing qpxd binary: $bin" >&2
    exit 1
  fi
  if ! nm -an "$bin" 2>/dev/null | grep -q 'qpxd'; then
    echo "qpxd binary lacks symbols; allocation profiling requires an unstripped binary: $bin" >&2
    exit 1
  fi
}

wait_http() {
  local name="$1"
  local port="$2"
  local pid="$3"
  local log_file="$4"
  local tries=0
  while [ "$tries" -lt 600 ]; do
    if curl -fsS --max-time 2 -o /dev/null "http://127.0.0.1:${port}/bench" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "${name} exited before becoming ready" >&2
      cat "$log_file" >&2 || true
      exit 1
    fi
    tries=$((tries + 1))
    sleep 0.1
  done
  echo "timeout waiting for ${name} on port ${port}" >&2
  cat "$log_file" >&2 || true
  exit 1
}

start_backend() {
  cat >"$TMP_DIR/backend.py" <<'PY'
import socketserver
import sys
from http.server import BaseHTTPRequestHandler

port = int(sys.argv[1])
body = b"x" * int(sys.argv[2])

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "qpx-allocation-bench"
    def do_GET(self):
        if self.path != "/bench":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, fmt, *args):
        return

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

with Server(("127.0.0.1", port), Handler) as httpd:
    httpd.serve_forever()
PY
  python3 "$TMP_DIR/backend.py" "$BACKEND_PORT" "$BODY_BYTES" >"$LOG_DIR/backend.log" 2>&1 &
  local pid=$!
  PIDS+=("$pid")
  wait_http "allocation-backend" "$BACKEND_PORT" "$pid" "$LOG_DIR/backend.log"
}

start_qpxd_under_dhat() {
  local sample="$1"
  local config="$TMP_DIR/qpxd-allocation.yaml"
  local dhat_file="$PROFILE_DIR/dhat.qpxd.${sample}.%p.json"
  rm -f "$PROFILE_DIR/dhat.qpxd.${sample}."*.json
  cat >"$config" <<YAML
state_dir: "$STATE_DIR"
telemetry:
  system_log:
    level: warn
    format: json
runtime:
  worker_threads: 1
  acceptor_tasks_per_listener: 1
  reuse_port: false
edges:
  - kind: reverse
    name: allocation
    listen: 127.0.0.1:${QPX_PORT}
    routes:
      - name: bench
        streaming_requirement: required
        match: {}
        target:
          type: upstream
          upstreams: [http://127.0.0.1:${BACKEND_PORT}]
YAML
  QPX_STATE_DIR="$STATE_DIR" valgrind \
    --tool=dhat \
    --mode=heap \
    --dhat-out-file="$dhat_file" \
    "$QPXD_BIN" run --config "$config" >"$LOG_DIR/qpxd-dhat.log" 2>&1 &
  local pid=$!
  QPXD_PID="$pid"
  PIDS+=("$pid")
  wait_http "qpxd-dhat" "$QPX_PORT" "$pid" "$LOG_DIR/qpxd-dhat.log"
}

run_load() {
  local requests="$1"
  python3 - "$QPX_PORT" "$requests" "$BODY_BYTES" <<'PY'
import socket
import sys

port = int(sys.argv[1])
requests = int(sys.argv[2])
expected_body = int(sys.argv[3])

sock = socket.create_connection(("127.0.0.1", port), timeout=10)
sock.settimeout(10)
buffer = bytearray()

def recv_until(marker):
    while True:
        pos = buffer.find(marker)
        if pos >= 0:
            out = bytes(buffer[:pos + len(marker)])
            del buffer[:pos + len(marker)]
            return out
        chunk = sock.recv(65536)
        if not chunk:
            raise RuntimeError("connection closed while reading response")
        buffer.extend(chunk)

def recv_exact(length):
    while len(buffer) < length:
        chunk = sock.recv(65536)
        if not chunk:
            raise RuntimeError("connection closed while reading body")
        buffer.extend(chunk)
    out = bytes(buffer[:length])
    del buffer[:length]
    return out

for _ in range(requests):
    sock.sendall(
        b"GET /bench HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Connection: keep-alive\r\n"
        b"\r\n"
    )
    head = recv_until(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    status_parts = lines[0].split(" ", 2)
    if len(status_parts) < 2 or status_parts[1] != "200":
        raise RuntimeError(f"unexpected response status: {lines[0]}")
    content_length = None
    for line in lines[1:]:
        if line.lower().startswith("content-length:"):
            content_length = int(line.split(":", 1)[1].strip())
            break
    if content_length is None:
        raise RuntimeError("missing Content-Length")
    body = recv_exact(content_length)
    if len(body) != expected_body:
        raise RuntimeError(f"unexpected body length: {len(body)}")

sock.close()
PY
}

stop_qpxd_for_dhat_flush() {
  local pid="$QPXD_PID"
  if kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  fi
}

parse_dhat_sample() {
  local sample="$1"
  local requests="$2"
  local out_path="$3"
  local file
  file="$(find "$PROFILE_DIR" -maxdepth 1 -type f -name "dhat.qpxd.${sample}.*.json" | sort | tail -n 1)"
  if [ -z "$file" ]; then
    echo "missing DHAT output for ${sample} in $PROFILE_DIR" >&2
    exit 1
  fi
  python3 - "$file" "$out_path" "$requests" "$BODY_BYTES" "$sample" "${GITHUB_SHA:-unknown}" <<'PY'
import json
import sys

dhat_path, out_path, requests, body_bytes, sample, commit = sys.argv[1:7]
with open(dhat_path, "r", encoding="utf-8", errors="replace") as handle:
    data = json.load(handle)

def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)

alloc_bytes = None
alloc_count = None
peak_live_bytes = None
for key in ("tot_alloc_bytes", "total_alloc_bytes", "alloc_bytes"):
    if isinstance(data.get(key), (int, float)):
        alloc_bytes = int(data[key])
for key in ("tot_allocs", "total_allocs", "alloc_count"):
    if isinstance(data.get(key), (int, float)):
        alloc_count = int(data[key])
for key in ("max_live_bytes", "peak_live_bytes"):
    if isinstance(data.get(key), (int, float)):
        peak_live_bytes = int(data[key])

pps = data.get("pps")
if isinstance(pps, list):
    byte_candidates = [int(point["tb"]) for point in pps if isinstance(point, dict) and isinstance(point.get("tb"), (int, float))]
    count_candidates = [
        int(point[key])
        for point in pps
        if isinstance(point, dict)
        for key in ("tbk", "nb", "allocs")
        if isinstance(point.get(key), (int, float))
    ]
    live_candidates = [int(point["mb"]) for point in pps if isinstance(point, dict) and isinstance(point.get("mb"), (int, float))]
    if alloc_bytes is None and byte_candidates:
        alloc_bytes = sum(byte_candidates)
    if alloc_count is None and count_candidates:
        alloc_count = sum(count_candidates)
    if peak_live_bytes is None and live_candidates:
        peak_live_bytes = max(live_candidates)

if alloc_bytes is None:
    numeric_tb = [int(item["tb"]) for item in walk(data) if isinstance(item.get("tb"), (int, float))]
    alloc_bytes = sum(numeric_tb) if numeric_tb else None
if alloc_count is None:
    numeric_counts = [
        int(item[key])
        for item in walk(data)
        for key in ("tbk", "nb", "allocs")
        if isinstance(item.get(key), (int, float))
    ]
    alloc_count = sum(numeric_counts) if numeric_counts else None
if peak_live_bytes is None:
    live = [int(item["mb"]) for item in walk(data) if isinstance(item.get("mb"), (int, float))]
    peak_live_bytes = max(live) if live else None

if alloc_bytes is None or alloc_count is None:
    raise SystemExit("DHAT output did not contain allocation byte/count counters")

record = {
    "bench": "qpxd_allocation_profile_http1_reverse_sample",
    "tool": "valgrind-dhat",
    "sample": sample,
    "requests": int(requests),
    "body_bytes": int(body_bytes),
    "alloc_bytes": alloc_bytes,
    "alloc_count": alloc_count,
    "peak_live_bytes": peak_live_bytes,
    "dhat_file": dhat_path,
    "commit": commit,
}
with open(out_path, "w", encoding="utf-8") as handle:
    json.dump(record, handle, sort_keys=True, separators=(",", ":"))
PY
}

write_dhat_delta() {
  local base_record="$1"
  local double_record="$2"
  python3 - "$base_record" "$double_record" "$OUT_JSON" "$REQUESTS" "$BODY_BYTES" "${GITHUB_SHA:-unknown}" <<'PY'
import json
import sys

base_path, double_path, out_path, requests, body_bytes, commit = sys.argv[1:7]
with open(base_path, "r", encoding="utf-8") as handle:
    base = json.load(handle)
with open(double_path, "r", encoding="utf-8") as handle:
    double = json.load(handle)

requests = int(requests)
body_bytes = int(body_bytes)
delta_alloc_bytes = double["alloc_bytes"] - base["alloc_bytes"]
delta_alloc_count = double["alloc_count"] - base["alloc_count"]
if delta_alloc_bytes < 0 or delta_alloc_count < 0:
    raise SystemExit("DHAT delta is negative; allocation profile sample is invalid")
peak_candidates = [
    value
    for value in (base.get("peak_live_bytes"), double.get("peak_live_bytes"))
    if value is not None
]

record = {
    "bench": "qpxd_allocation_profile_http1_reverse",
    "tool": "valgrind-dhat-delta",
    "requests": requests,
    "double_requests": requests * 2,
    "body_bytes": body_bytes,
    "alloc_bytes_per_request": delta_alloc_bytes / requests,
    "alloc_count_per_request": delta_alloc_count / requests,
    "delta_alloc_bytes": delta_alloc_bytes,
    "delta_alloc_count": delta_alloc_count,
    "base_alloc_bytes": base["alloc_bytes"],
    "base_alloc_count": base["alloc_count"],
    "double_alloc_bytes": double["alloc_bytes"],
    "double_alloc_count": double["alloc_count"],
    "peak_live_bytes": max(peak_candidates) if peak_candidates else None,
    "base_dhat_file": base["dhat_file"],
    "double_dhat_file": double["dhat_file"],
    "commit": commit,
}
with open(out_path, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
PY
}

require_cmd curl
require_cmd cargo
require_cmd nm
require_cmd python3
require_cmd valgrind

build_qpxd_for_allocation
start_backend
base_record="$TMP_DIR/dhat-base.json"
double_record="$TMP_DIR/dhat-double.json"

start_qpxd_under_dhat "base"
run_load "$REQUESTS"
stop_qpxd_for_dhat_flush
parse_dhat_sample "base" "$REQUESTS" "$base_record"

start_qpxd_under_dhat "double"
run_load "$((REQUESTS * 2))"
stop_qpxd_for_dhat_flush
parse_dhat_sample "double" "$((REQUESTS * 2))" "$double_record"

write_dhat_delta "$base_record" "$double_record"
