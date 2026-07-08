#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_JSON="${1:-${QPX_STREAMING_COMPARE_JSON:-$ROOT_DIR/target/perf/perf-audit-streaming-compare.jsonl}}"
LOG_ARTIFACT_DIR="${QPX_STREAMING_COMPARE_LOG_DIR:-$ROOT_DIR/target/perf/streaming-compare-logs}"
QPXD_BIN="${QPXD_BIN:-$ROOT_DIR/target/release/qpxd}"
STREAM_BYTES="${QPX_STREAMING_COMPARE_BYTES:-104857600}"
CHUNK_BYTES="${QPX_STREAMING_COMPARE_CHUNK_BYTES:-65536}"
SLOW_READ_DELAY_MS="${QPX_STREAMING_COMPARE_SLOW_READ_DELAY_MS:-1}"
SAMPLE_ATTEMPTS="${QPX_STREAMING_COMPARE_SAMPLE_ATTEMPTS:-3}"
BACKEND_PORT="${QPX_STREAMING_COMPARE_BACKEND_PORT:-18380}"
QPX_PORT="${QPX_STREAMING_COMPARE_QPX_PORT:-18381}"
NGINX_PORT="${QPX_STREAMING_COMPARE_NGINX_PORT:-18382}"
APACHE_PORT="${QPX_STREAMING_COMPARE_APACHE_PORT:-18383}"
LIGHTTPD_PORT="${QPX_STREAMING_COMPARE_LIGHTTPD_PORT:-18384}"
APACHE_BIN="${QPX_STREAMING_COMPARE_APACHE_BIN:-}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/qpx-streaming-compare.XXXXXX")"
LOG_DIR="$TMP_DIR/logs"
STATE_DIR="$TMP_DIR/state"
mkdir -p "$LOG_DIR" "$STATE_DIR" "$(dirname "$OUT_JSON")"

PIDS=()
ARTIFACTS_COLLECTED=0
BACKEND_PID=""
QPXD_PID=""
NGINX_PID=""
APACHE_PID=""
LIGHTTPD_PID=""

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

register_pid() {
  PIDS+=("$1")
}

collect_artifacts() {
  if [ "$ARTIFACTS_COLLECTED" -eq 1 ]; then
    return
  fi
  ARTIFACTS_COLLECTED=1
  rm -rf "$LOG_ARTIFACT_DIR"
  mkdir -p "$LOG_ARTIFACT_DIR"
  cp -R "$LOG_DIR"/. "$LOG_ARTIFACT_DIR"/ 2>/dev/null || true
  cp "$TMP_DIR"/*.yaml "$LOG_ARTIFACT_DIR"/ 2>/dev/null || true
  find "$TMP_DIR" -name '*.conf' -type f -exec cp {} "$LOG_ARTIFACT_DIR"/ \; 2>/dev/null || true
}

cleanup() {
  local pid
  for pid in "${PIDS[@]:-}"; do
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
  done
  collect_artifacts
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

clock_ticks() {
  getconf CLK_TCK 2>/dev/null || echo 100
}

children_of_pid() {
  local pid="$1"
  if command -v pgrep >/dev/null 2>&1; then
    pgrep -P "$pid" 2>/dev/null || true
  elif ps -o pid= --ppid "$pid" >/dev/null 2>&1; then
    ps -o pid= --ppid "$pid" 2>/dev/null | awk '{ print $1 }'
  fi
}

process_tree_pids() {
  local root="$1"
  local child
  if [ -z "$root" ]; then
    return
  fi
  echo "$root"
  for child in $(children_of_pid "$root"); do
    process_tree_pids "$child"
  done
}

proc_cpu_ticks() {
  local pid="$1"
  local stat="/proc/${pid}/stat"
  if [ ! -r "$stat" ]; then
    echo 0
    return
  fi
  awk '{
    comm_end = index($0, ") ")
    if (comm_end == 0) {
      print 0
      exit
    }
    rest = substr($0, comm_end + 2)
    split(rest, fields, " ")
    print fields[12] + fields[13]
  }' "$stat"
}

proc_status_value_kb() {
  local pid="$1"
  local key="$2"
  local status="/proc/${pid}/status"
  if [ ! -r "$status" ]; then
    echo 0
    return
  fi
  awk -v key="$key" '$1 == key ":" { print $2; found = 1; exit } END { if (!found) print 0 }' "$status"
}

process_tree_cpu_ms() {
  local root="$1"
  local hz pid ticks total_ticks
  if [ -z "$root" ] || [ ! -d /proc ]; then
    echo 0
    return
  fi
  hz="$(clock_ticks)"
  total_ticks=0
  for pid in $(process_tree_pids "$root"); do
    ticks="$(proc_cpu_ticks "$pid")"
    total_ticks=$((total_ticks + ticks))
  done
  awk -v ticks="$total_ticks" -v hz="$hz" 'BEGIN { printf "%.0f", (ticks * 1000) / hz }'
}

process_tree_status_kb() {
  local root="$1"
  local key="$2"
  local pid value total
  if [ -z "$root" ] || [ ! -d /proc ]; then
    echo 0
    return
  fi
  total=0
  for pid in $(process_tree_pids "$root"); do
    value="$(proc_status_value_kb "$pid" "$key")"
    total=$((total + value))
  done
  echo "$total"
}

start_streaming_backend() {
  cat >"$TMP_DIR/streaming_backend.py" <<'PY'
import socketserver
import sys
from http.server import BaseHTTPRequestHandler

port = int(sys.argv[1])
stream_bytes = int(sys.argv[2])
chunk_bytes = int(sys.argv[3])
payload = b"x" * chunk_bytes

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "qpx-streaming-bench"

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"OK")
            return
        if self.path != "/stream":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(stream_bytes))
        self.end_headers()
        remaining = stream_bytes
        while remaining > 0:
            n = min(chunk_bytes, remaining)
            self.wfile.write(payload[:n])
            self.wfile.flush()
            remaining -= n

    def log_message(self, fmt, *args):
        return

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

with Server(("127.0.0.1", port), Handler) as httpd:
    httpd.serve_forever()
PY
  python3 "$TMP_DIR/streaming_backend.py" "$BACKEND_PORT" "$STREAM_BYTES" "$CHUNK_BYTES" >"$LOG_DIR/backend.log" 2>&1 &
  BACKEND_PID=$!
  register_pid "$BACKEND_PID"
  wait_http "streaming-backend" "$BACKEND_PORT" "$BACKEND_PID" "$LOG_DIR/backend.log"
}

wait_http() {
  local name="$1"
  local port="$2"
  local pid="$3"
  local log_file="$4"
  local tries=0
  while [ "$tries" -lt 100 ]; do
    if curl -fsS --max-time 2 -o /dev/null "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
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

start_qpxd() {
  local config="$TMP_DIR/qpxd-streaming.yaml"
  cat >"$config" <<YAML
state_dir: "$STATE_DIR"
runtime:
  worker_threads: 1
  acceptor_tasks_per_listener: 1
  reuse_port: false
edges:
  - kind: reverse
    name: streaming
    listen: 127.0.0.1:${QPX_PORT}
    routes:
      - name: stream
        streaming_requirement: required
        match:
          path_prefix: /
        target:
          type: upstream
          upstreams: [http://127.0.0.1:${BACKEND_PORT}]
YAML
  QPX_STATE_DIR="$STATE_DIR" "$QPXD_BIN" run --config "$config" >"$LOG_DIR/qpxd.log" 2>&1 &
  QPXD_PID=$!
  register_pid "$QPXD_PID"
  wait_http "qpxd" "$QPX_PORT" "$QPXD_PID" "$LOG_DIR/qpxd.log"
}

start_nginx() {
  local prefix="$TMP_DIR/nginx"
  local config="$prefix/nginx.conf"
  mkdir -p "$prefix/logs"
  cat >"$config" <<NGINX
pid $prefix/nginx.pid;
error_log $prefix/logs/error.log warn;
worker_processes 1;
events { worker_connections 4096; }
http {
  access_log off;
  proxy_buffering off;
  server {
    listen 127.0.0.1:${NGINX_PORT};
    location / {
      proxy_http_version 1.1;
      proxy_set_header Connection "";
      proxy_pass http://127.0.0.1:${BACKEND_PORT};
    }
  }
}
NGINX
  nginx -p "$prefix" -c "$config" -g 'daemon off;' >"$LOG_DIR/nginx.log" 2>&1 &
  NGINX_PID=$!
  register_pid "$NGINX_PID"
  wait_http "nginx" "$NGINX_PORT" "$NGINX_PID" "$LOG_DIR/nginx.log"
}

apache_load_module() {
  local module="$1"
  local path
  for path in \
    "/usr/lib/apache2/modules/mod_${module}.so" \
    "$($APACHE_BIN -V 2>/dev/null | awk -F'\"' '/HTTPD_ROOT/ {print $2; exit}')/lib/httpd/modules/mod_${module}.so"; do
    if [ -f "$path" ]; then
      printf 'LoadModule %s_module %s\n' "$module" "$path"
      return
    fi
  done
  if [ "$module" = "mpm_event" ]; then
    return
  fi
}

start_apache() {
  local root="$TMP_DIR/apache"
  local config="$root/apache.conf"
  mkdir -p "$root/run" "$root/logs"
  {
    echo "ServerRoot \"$root\""
    echo "DefaultRuntimeDir \"$root/run\""
    echo "PidFile \"$root/run/apache.pid\""
    echo "ServerName 127.0.0.1"
    echo "Listen 127.0.0.1:${APACHE_PORT}"
    echo "ErrorLog \"$root/logs/error.log\""
    echo "LogLevel warn"
    echo "Mutex file:$root/run default"
    apache_load_module "mpm_event"
    apache_load_module "authn_core"
    apache_load_module "authz_core"
    apache_load_module "env"
    apache_load_module "proxy"
    apache_load_module "proxy_http"
    apache_load_module "unixd"
    echo "ProxyTimeout 60"
    echo "<VirtualHost 127.0.0.1:${APACHE_PORT}>"
    echo "  ProxyPass \"/\" \"http://127.0.0.1:${BACKEND_PORT}/\" retry=0 flushpackets=on keepalive=Off"
    echo "  ProxyPassReverse \"/\" \"http://127.0.0.1:${BACKEND_PORT}/\""
    echo "</VirtualHost>"
  } >"$config"
  "$APACHE_BIN" -f "$config" -DFOREGROUND >"$LOG_DIR/apache.log" 2>&1 &
  APACHE_PID=$!
  register_pid "$APACHE_PID"
  wait_http "apache" "$APACHE_PORT" "$APACHE_PID" "$LOG_DIR/apache.log"
}

start_lighttpd() {
  local root="$TMP_DIR/lighttpd"
  local config="$root/lighttpd.conf"
  mkdir -p "$root/www" "$root/logs"
  cat >"$config" <<LIGHTTPD
server.modules = ( "mod_proxy" )
server.document-root = "$root/www"
server.bind = "127.0.0.1"
server.port = ${LIGHTTPD_PORT}
server.pid-file = "$root/lighttpd.pid"
server.errorlog = "$root/logs/error.log"
proxy.server = ( "" => ( ( "host" => "127.0.0.1", "port" => ${BACKEND_PORT} ) ) )
LIGHTTPD
  lighttpd -D -f "$config" >"$LOG_DIR/lighttpd.log" 2>&1 &
  LIGHTTPD_PID=$!
  register_pid "$LIGHTTPD_PID"
  wait_http "lighttpd" "$LIGHTTPD_PORT" "$LIGHTTPD_PID" "$LOG_DIR/lighttpd.log"
}

run_client() {
  local proxy="$1"
  local port="$2"
  local read_mode="$3"
  local delay_ms="$4"
  python3 - "$proxy" "$port" "$read_mode" "$delay_ms" "$STREAM_BYTES" "$CHUNK_BYTES" <<'PY'
import json
import socket
import statistics
import sys
import time

proxy, port, read_mode, delay_ms, expected, chunk_bytes = sys.argv[1:7]
port = int(port)
delay = float(delay_ms) / 1000.0
expected = int(expected)
chunk_bytes = int(chunk_bytes)
started = time.perf_counter()
first_byte = None
last_chunk = None
gaps = []
received = 0
head = b""

sock = socket.create_connection(("127.0.0.1", port), timeout=10)
sock.settimeout(120)
sock.sendall(b"GET /stream HTTP/1.1\r\nHost: stream.local\r\nConnection: close\r\n\r\n")
while b"\r\n\r\n" not in head:
    data = sock.recv(1)
    if not data:
        raise SystemExit("connection closed before headers")
    if first_byte is None:
        first_byte = time.perf_counter()
    head += data
status_line = head.split(b"\r\n", 1)[0]
status = status_line.decode("ascii", "replace")
if not status.startswith("HTTP/1.1 200") and not status.startswith("HTTP/1.0 200"):
    raise SystemExit(f"unexpected status: {status}")
while True:
    data = sock.recv(chunk_bytes)
    if not data:
        break
    now = time.perf_counter()
    if first_byte is None:
        first_byte = now
    if last_chunk is not None:
        gaps.append((now - last_chunk) * 1000.0)
    last_chunk = now
    received += len(data)
    if read_mode == "slow":
        time.sleep(delay)
sock.close()
finished = time.perf_counter()
gaps_sorted = sorted(gaps)
def percentile(p):
    if not gaps_sorted:
        return 0.0
    index = min(len(gaps_sorted) - 1, max(0, int((len(gaps_sorted) * p + 99) // 100) - 1))
    return gaps_sorted[index]
print(json.dumps({
    "proxy": proxy,
    "read_mode": read_mode,
    "first_byte_ms": (first_byte - started) * 1000.0 if first_byte is not None else None,
    "p50_chunk_gap_ms": percentile(50),
    "p95_chunk_gap_ms": percentile(95),
    "p99_chunk_gap_ms": percentile(99),
    "max_chunk_gap_ms": max(gaps_sorted) if gaps_sorted else 0.0,
    "total_ms": (finished - started) * 1000.0,
    "bytes": received,
    "chunk_observations": len(gaps),
    "valid": received == expected,
}))
PY
}

run_one() {
  local proxy="$1"
  local port="$2"
  local resource_pid="$3"
  local read_mode="$4"
  local delay_ms="0"
  local cpu_before_ms cpu_after_ms cpu_ms rss_kb rss_peak_kb metrics requests_per_cpu_second commit
  local attempt valid
  if [ "$read_mode" = "slow" ]; then
    delay_ms="$SLOW_READ_DELAY_MS"
  fi
  attempt=1
  valid=false
  while [ "$attempt" -le "$SAMPLE_ATTEMPTS" ]; do
    cpu_before_ms="$(process_tree_cpu_ms "$resource_pid")"
    if ! metrics="$(run_client "$proxy" "$port" "$read_mode" "$delay_ms")"; then
      echo "${proxy} streaming client failed on attempt ${attempt}/${SAMPLE_ATTEMPTS}" >&2
      if [ "$attempt" -eq "$SAMPLE_ATTEMPTS" ]; then
        exit 1
      fi
      attempt=$((attempt + 1))
      continue
    fi
    cpu_after_ms="$(process_tree_cpu_ms "$resource_pid")"
    cpu_ms="$(awk -v before="$cpu_before_ms" -v after="$cpu_after_ms" 'BEGIN { delta = after - before; if (delta < 0) delta = 0; printf "%.0f", delta }')"
    rss_kb="$(process_tree_status_kb "$resource_pid" "VmRSS")"
    rss_peak_kb="$(process_tree_status_kb "$resource_pid" "VmHWM")"
    valid="$(python3 - "$metrics" <<'PY'
import json
import sys
print("true" if json.loads(sys.argv[1])["valid"] else "false")
PY
)"
    if [ "$valid" = true ]; then
      break
    fi
    echo "${proxy} produced an invalid streaming sample on attempt ${attempt}/${SAMPLE_ATTEMPTS}: ${metrics}" >&2
    attempt=$((attempt + 1))
  done
  requests_per_cpu_second="$(awk -v cpu_ms="$cpu_ms" 'BEGIN { if (cpu_ms > 0) printf "%.6f", 1000 / cpu_ms; else printf "null" }')"
  commit="${GITHUB_SHA:-unknown}"
  python3 - "$OUT_JSON" "$metrics" "$STREAM_BYTES" "$CHUNK_BYTES" "$cpu_ms" "$rss_kb" "$rss_peak_kb" "$requests_per_cpu_second" "$commit" <<'PY'
import json
import sys

out, metrics, stream_bytes, chunk_bytes, cpu_ms, rss_kb, rss_peak_kb, rpcpu, commit = sys.argv[1:10]
record = json.loads(metrics)
record.update({
    "bench": "proxy_compare_http1_streaming_reverse",
    "stream_bytes": int(stream_bytes),
    "chunk_bytes": int(chunk_bytes),
    "cpu_ms": int(cpu_ms),
    "rss_kb": int(rss_kb),
    "rss_peak_kb": int(rss_peak_kb),
    "requests_per_cpu_second": None if rpcpu == "null" else float(rpcpu),
    "commit": commit,
})
with open(out, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
if not record["valid"]:
    raise SystemExit(f"{record['proxy']} invalid streaming sample")
PY
}

require_cmd curl
require_cmd lighttpd
require_cmd nginx
require_cmd python3

if [ -z "$APACHE_BIN" ]; then
  if command -v apache2 >/dev/null 2>&1; then
    APACHE_BIN="$(command -v apache2)"
  elif command -v httpd >/dev/null 2>&1; then
    APACHE_BIN="$(command -v httpd)"
  else
    echo "missing required command: apache2 or httpd" >&2
    exit 1
  fi
fi

if [ ! -x "$QPXD_BIN" ]; then
  echo "missing qpxd binary: $QPXD_BIN" >&2
  exit 1
fi

: >"$OUT_JSON"
start_streaming_backend
start_qpxd
start_nginx
start_apache
start_lighttpd

for read_mode in fast slow; do
  run_one "direct-backend" "$BACKEND_PORT" "$BACKEND_PID" "$read_mode"
  run_one "qpxd" "$QPX_PORT" "$QPXD_PID" "$read_mode"
  run_one "nginx" "$NGINX_PORT" "$NGINX_PID" "$read_mode"
  run_one "apache" "$APACHE_PORT" "$APACHE_PID" "$read_mode"
  run_one "lighttpd" "$LIGHTTPD_PORT" "$LIGHTTPD_PID" "$read_mode"
done
