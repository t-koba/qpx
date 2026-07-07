#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_JSON="${QPX_ALLOCATION_PROFILE_JSON:-$ROOT_DIR/target/perf/perf-audit-allocation-profile.jsonl}"
PROFILE_DIR="${QPX_ALLOCATION_PROFILE_DIR:-$ROOT_DIR/target/perf/allocations}"
QPXD_BIN="${QPXD_BIN:-$ROOT_DIR/target/release/qpxd}"
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

wait_http() {
  local name="$1"
  local port="$2"
  local pid="$3"
  local log_file="$4"
  local tries=0
  while [ "$tries" -lt 200 ]; do
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
  local config="$TMP_DIR/qpxd-allocation.yaml"
  local dhat_file="$PROFILE_DIR/dhat.qpxd.%p.json"
  cat >"$config" <<YAML
state_dir: "$STATE_DIR"
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
        match:
          path_prefix: /
        target:
          type: upstream
          upstreams: [http://127.0.0.1:${BACKEND_PORT}]
YAML
  QPX_STATE_DIR="$STATE_DIR" valgrind \
    --tool=dhat \
    --mode=heap \
    --show-top-n=0 \
    --dhat-out-file="$dhat_file" \
    "$QPXD_BIN" run --config "$config" >"$LOG_DIR/qpxd-dhat.log" 2>&1 &
  local pid=$!
  QPXD_PID="$pid"
  PIDS+=("$pid")
  wait_http "qpxd-dhat" "$QPX_PORT" "$pid" "$LOG_DIR/qpxd-dhat.log"
}

run_load() {
  local i
  for i in $(seq 1 "$REQUESTS"); do
    curl -fsS --max-time 10 -o /dev/null "http://127.0.0.1:${QPX_PORT}/bench"
  done
}

stop_qpxd_for_dhat_flush() {
  local pid="$QPXD_PID"
  if kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  fi
}

parse_dhat() {
  local file
  file="$(find "$PROFILE_DIR" -maxdepth 1 -type f -name 'dhat.qpxd.*.json' | sort | tail -n 1)"
  if [ -z "$file" ]; then
    echo "missing DHAT output in $PROFILE_DIR" >&2
    exit 1
  fi
  python3 - "$file" "$OUT_JSON" "$REQUESTS" "$BODY_BYTES" "${GITHUB_SHA:-unknown}" <<'PY'
import json
import sys

dhat_path, out_path, requests, body_bytes, commit = sys.argv[1:6]
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
    "bench": "qpxd_allocation_profile_http1_reverse",
    "tool": "valgrind-dhat",
    "requests": int(requests),
    "body_bytes": int(body_bytes),
    "alloc_bytes": alloc_bytes,
    "alloc_count": alloc_count,
    "peak_live_bytes": peak_live_bytes,
    "dhat_file": dhat_path,
    "commit": commit,
}
with open(out_path, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
PY
}

require_cmd curl
require_cmd python3
require_cmd valgrind

if [ ! -x "$QPXD_BIN" ]; then
  echo "missing qpxd binary: $QPXD_BIN" >&2
  exit 1
fi

start_backend
start_qpxd_under_dhat
run_load
stop_qpxd_for_dhat_flush
parse_dhat
