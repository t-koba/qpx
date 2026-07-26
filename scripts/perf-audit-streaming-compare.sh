#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/lib/temp-dir.sh"
OUT_JSON="${1:-${QPX_STREAMING_COMPARE_JSON:-$ROOT_DIR/target/perf/perf-audit-streaming-compare.jsonl}}"
LOG_ARTIFACT_DIR="${QPX_STREAMING_COMPARE_LOG_DIR:-$ROOT_DIR/target/perf/streaming-compare-logs}"
QPXD_BIN="${QPXD_BIN:-$ROOT_DIR/target/release/qpxd}"
STREAM_BYTES="${QPX_STREAMING_COMPARE_BYTES:-104857600}"
CHUNK_BYTES="${QPX_STREAMING_COMPARE_CHUNK_BYTES:-65536}"
SLOW_READ_DELAY_MS="${QPX_STREAMING_COMPARE_SLOW_READ_DELAY_MS:-1}"
FAST_TRANSFERS="${QPX_STREAMING_COMPARE_FAST_TRANSFERS:-8}"
SAMPLE_ATTEMPTS="${QPX_STREAMING_COMPARE_SAMPLE_ATTEMPTS:-3}"
MIN_VALID_SAMPLES="${QPX_STREAMING_COMPARE_MIN_VALID_SAMPLES:-}"
BACKEND_PORT="${QPX_STREAMING_COMPARE_BACKEND_PORT:-18380}"
QPX_PORT="${QPX_STREAMING_COMPARE_QPX_PORT:-18381}"
NGINX_PORT="${QPX_STREAMING_COMPARE_NGINX_PORT:-18382}"
APACHE_PORT="${QPX_STREAMING_COMPARE_APACHE_PORT:-18383}"
LIGHTTPD_PORT="${QPX_STREAMING_COMPARE_LIGHTTPD_PORT:-18384}"
APACHE_BIN="${QPX_STREAMING_COMPARE_APACHE_BIN:-}"

TMP_DIR="$(make_temp_dir qpx-streaming-compare)"
LOG_DIR="$TMP_DIR/logs"
STATE_DIR="$TMP_DIR/state"
mkdir -p "$LOG_DIR" "$STATE_DIR" "$(dirname "$OUT_JSON")"

PIDS=()
ARTIFACTS_COLLECTED=0
INVALID_SAMPLES=0
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
  find "$TMP_DIR" -name '*.valid-samples.jsonl' -type f -exec cp {} "$LOG_ARTIFACT_DIR"/ \; 2>/dev/null || true
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

source "$ROOT_DIR/scripts/lib/perf-process-metrics.sh"

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
telemetry:
  system_log:
    level: warn
    format: json
runtime:
  worker_threads: 1
  acceptor_tasks_per_listener: 1
  reuse_port: false
  upstream_proxy_max_concurrent_per_endpoint: 512
edges:
  - kind: reverse
    name: streaming
    listen: 127.0.0.1:${QPX_PORT}
    routes:
      - name: stream
        streaming_requirement: required
        streaming:
          max_response_body_bytes: ${STREAM_BYTES}
        match: {}
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
  upstream qpx_benchmark_backend {
    server 127.0.0.1:${BACKEND_PORT};
    keepalive 256;
  }
  server {
    listen 127.0.0.1:${NGINX_PORT};
    location / {
      proxy_http_version 1.1;
      proxy_set_header Connection "";
      proxy_pass http://qpx_benchmark_backend;
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
  python3 - "$proxy" "$port" "$read_mode" "$delay_ms" "$STREAM_BYTES" "$CHUNK_BYTES" "$FAST_TRANSFERS" <<'PY'
import json
import socket
import statistics
import sys
import time

proxy, port, read_mode, delay_ms, expected, chunk_bytes, fast_transfers = sys.argv[1:8]
port = int(port)
delay = float(delay_ms) / 1000.0
expected = int(expected)
chunk_bytes = int(chunk_bytes)
transfers = 1 if read_mode == "slow" else int(fast_transfers)
started = time.perf_counter()
first_byte_ms = []
gaps = []
received = 0

for _ in range(transfers):
    transfer_started = time.perf_counter()
    first_byte = None
    last_observation = None
    next_observation = chunk_bytes
    transfer_received = 0
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
        transfer_received += len(data)
        if transfer_received >= next_observation:
            if last_observation is not None:
                gaps.append((now - last_observation) * 1000.0)
            last_observation = now
            next_observation += chunk_bytes
            if read_mode == "slow":
                time.sleep(delay)
    sock.close()
    if transfer_received != expected:
        raise SystemExit(
            f"incomplete streaming transfer: received {transfer_received}, expected {expected}"
        )
    received += transfer_received
    first_byte_ms.append((first_byte - transfer_started) * 1000.0)
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
    "transfers": transfers,
    "first_byte_ms": statistics.median(first_byte_ms),
    "p50_chunk_gap_ms": percentile(50),
    "p95_chunk_gap_ms": percentile(95),
    "p99_chunk_gap_ms": percentile(99),
    "max_chunk_gap_ms": max(gaps_sorted) if gaps_sorted else 0.0,
    "total_ms": (finished - started) * 1000.0,
    "bytes": received,
    "gap_observation_bytes": chunk_bytes,
    "chunk_observations": len(gaps),
    "valid": received == expected * transfers,
}))
PY
}

run_one() {
  local proxy="$1"
  local port="$2"
  local resource_pid="$3"
  local read_mode="$4"
  local delay_ms="0"
  local cpu_before_ms cpu_after_ms cpu_ms backend_cpu_before_ms backend_cpu_after_ms
  local backend_cpu_ms total_cpu_ms rss_kb rss_peak_kb backend_rss_peak_kb total_rss_peak_kb metrics commit
  local fd_peak backend_fd_peak total_fd_peak fd_peak_file backend_fd_peak_file fd_peak_monitor_pid backend_fd_peak_monitor_pid
  local scheduler_before_ns scheduler_after_ns backend_scheduler_before_ns backend_scheduler_after_ns total_scheduler_run_delay_ns scheduler_queue_delay_us_per_transfer kernel_resource_metrics
  local requests_per_cpu_second requests_per_total_cpu_second
  local attempt valid samples_file valid_sample_count selected_sample
  if [ "$read_mode" = "slow" ]; then
    delay_ms="$SLOW_READ_DELAY_MS"
  fi
  local artifact="streaming.${proxy}.${read_mode}.round-${CURRENT_SAMPLE_ROUND:-0}"
  samples_file="$TMP_DIR/${artifact}.valid-samples.jsonl"
  : >"$samples_file"
  attempt=1
  valid=false
  while [ "$attempt" -le "$SAMPLE_ATTEMPTS" ]; do
    kernel_resource_metrics=false
    fd_peak=0
    backend_fd_peak=0
    fd_peak_monitor_pid=""
    backend_fd_peak_monitor_pid=""
    scheduler_before_ns=0
    backend_scheduler_before_ns=0
    if [ -d /proc ]; then
      kernel_resource_metrics=true
      fd_peak_file="$TMP_DIR/${artifact}.attempt-${attempt}.fd-peak"
      monitor_process_tree_fd_peak "$resource_pid" "$fd_peak_file" &
      fd_peak_monitor_pid=$!
      scheduler_before_ns="$(process_tree_scheduler_run_delay_ns "$resource_pid")"
      if [ "$resource_pid" != "$BACKEND_PID" ]; then
        backend_fd_peak_file="$TMP_DIR/${artifact}.attempt-${attempt}.backend-fd-peak"
        monitor_process_tree_fd_peak "$BACKEND_PID" "$backend_fd_peak_file" &
        backend_fd_peak_monitor_pid=$!
        backend_scheduler_before_ns="$(process_tree_scheduler_run_delay_ns "$BACKEND_PID")"
      fi
    fi
    cpu_before_ms="$(process_tree_cpu_ms "$resource_pid")"
    if [ "$resource_pid" = "$BACKEND_PID" ]; then
      backend_cpu_before_ms="$cpu_before_ms"
    else
      backend_cpu_before_ms="$(process_tree_cpu_ms "$BACKEND_PID")"
    fi
    if ! metrics="$(run_client "$proxy" "$port" "$read_mode" "$delay_ms")"; then
      if [ -n "$fd_peak_monitor_pid" ]; then
        kill "$fd_peak_monitor_pid" >/dev/null 2>&1 || true
        wait "$fd_peak_monitor_pid" 2>/dev/null || true
      fi
      if [ -n "$backend_fd_peak_monitor_pid" ]; then
        kill "$backend_fd_peak_monitor_pid" >/dev/null 2>&1 || true
        wait "$backend_fd_peak_monitor_pid" 2>/dev/null || true
      fi
      echo "${proxy} streaming client failed on attempt ${attempt}/${SAMPLE_ATTEMPTS}" >&2
      attempt=$((attempt + 1))
      continue
    fi
    if [ -n "$fd_peak_monitor_pid" ]; then
      kill "$fd_peak_monitor_pid" >/dev/null 2>&1 || true
      wait "$fd_peak_monitor_pid" 2>/dev/null || true
      fd_peak="$(cat "$fd_peak_file" 2>/dev/null || echo 0)"
    fi
    if [ -n "$backend_fd_peak_monitor_pid" ]; then
      kill "$backend_fd_peak_monitor_pid" >/dev/null 2>&1 || true
      wait "$backend_fd_peak_monitor_pid" 2>/dev/null || true
      backend_fd_peak="$(cat "$backend_fd_peak_file" 2>/dev/null || echo 0)"
    fi
    cpu_after_ms="$(process_tree_cpu_ms "$resource_pid")"
    if [ "$resource_pid" = "$BACKEND_PID" ]; then
      backend_cpu_after_ms="$cpu_after_ms"
    else
      backend_cpu_after_ms="$(process_tree_cpu_ms "$BACKEND_PID")"
    fi
    cpu_ms="$(awk -v before="$cpu_before_ms" -v after="$cpu_after_ms" 'BEGIN { delta = after - before; if (delta < 0) delta = 0; printf "%.0f", delta }')"
    backend_cpu_ms="$(awk -v before="$backend_cpu_before_ms" -v after="$backend_cpu_after_ms" 'BEGIN { delta = after - before; if (delta < 0) delta = 0; printf "%.0f", delta }')"
    if [ "$resource_pid" = "$BACKEND_PID" ]; then
      total_cpu_ms="$cpu_ms"
    else
      total_cpu_ms=$((cpu_ms + backend_cpu_ms))
    fi
    rss_kb="$(process_tree_status_kb "$resource_pid" "VmRSS")"
    rss_peak_kb="$(process_tree_status_kb "$resource_pid" "VmHWM")"
    backend_rss_peak_kb="$rss_peak_kb"
    scheduler_after_ns="$scheduler_before_ns"
    backend_scheduler_after_ns="$backend_scheduler_before_ns"
    if [ "$resource_pid" != "$BACKEND_PID" ]; then
      backend_rss_peak_kb="$(process_tree_status_kb "$BACKEND_PID" "VmHWM")"
    fi
    if [ "$kernel_resource_metrics" = true ]; then
      scheduler_after_ns="$(process_tree_scheduler_run_delay_ns "$resource_pid")"
      if [ "$resource_pid" != "$BACKEND_PID" ]; then
        backend_scheduler_after_ns="$(process_tree_scheduler_run_delay_ns "$BACKEND_PID")"
      fi
    fi
    total_rss_peak_kb=$((rss_peak_kb + backend_rss_peak_kb))
    total_fd_peak=$((fd_peak + backend_fd_peak))
    if [ "$resource_pid" = "$BACKEND_PID" ]; then
      total_rss_peak_kb="$rss_peak_kb"
      total_fd_peak="$fd_peak"
    fi
    total_scheduler_run_delay_ns="$(awk -v resource_before="$scheduler_before_ns" -v resource_after="$scheduler_after_ns" -v backend_before="$backend_scheduler_before_ns" -v backend_after="$backend_scheduler_after_ns" 'BEGIN { delta = (resource_after - resource_before) + (backend_after - backend_before); if (delta < 0) delta = 0; printf "%.0f", delta }')"
    valid="$(python3 - "$metrics" <<'PY'
import json
import sys
print("true" if json.loads(sys.argv[1])["valid"] else "false")
PY
    )"
    if [ "$valid" = true ]; then
      requests_per_cpu_second="$(python3 - "$metrics" "$cpu_ms" <<'PY'
import json
import sys

metrics = json.loads(sys.argv[1])
cpu_ms = float(sys.argv[2])
print("null" if cpu_ms <= 0 else f"{metrics['transfers'] * 1000.0 / cpu_ms:.6f}")
PY
)"
      requests_per_total_cpu_second="$(python3 - "$metrics" "$total_cpu_ms" <<'PY'
import json
import sys

metrics = json.loads(sys.argv[1])
cpu_ms = float(sys.argv[2])
print("null" if cpu_ms <= 0 else f"{metrics['transfers'] * 1000.0 / cpu_ms:.6f}")
PY
)"
      scheduler_queue_delay_us_per_transfer="$(python3 - "$metrics" "$total_scheduler_run_delay_ns" <<'PY'
import json
import sys
metrics = json.loads(sys.argv[1])
delay_ns = float(sys.argv[2])
print(f"{delay_ns / metrics['transfers'] / 1000.0:.6f}")
PY
)"
      python3 - "$samples_file" "$metrics" "$cpu_ms" "$backend_cpu_ms" "$total_cpu_ms" \
        "$rss_kb" "$rss_peak_kb" "$backend_rss_peak_kb" "$total_rss_peak_kb" \
        "$fd_peak" "$backend_fd_peak" "$total_fd_peak" "$total_scheduler_run_delay_ns" \
        "$scheduler_queue_delay_us_per_transfer" "$kernel_resource_metrics" "$requests_per_cpu_second" \
        "$requests_per_total_cpu_second" <<'PY'
import json
import sys

path, metrics, cpu_ms, backend_cpu_ms, total_cpu_ms, rss_kb, rss_peak_kb, backend_rss_peak_kb, total_rss_peak_kb, fd_peak, backend_fd_peak, total_fd_peak, total_scheduler_run_delay_ns, scheduler_queue_delay_us_per_transfer, kernel_resource_metrics, rpcpu, total_rpcpu = sys.argv[1:18]
record = json.loads(metrics)
record["cpu_ms"] = int(cpu_ms)
record["backend_cpu_ms"] = int(backend_cpu_ms)
record["total_cpu_ms"] = int(total_cpu_ms)
record["rss_kb"] = int(rss_kb)
record["rss_peak_kb"] = int(rss_peak_kb)
record["backend_rss_peak_kb"] = int(backend_rss_peak_kb)
record["total_rss_peak_kb"] = int(total_rss_peak_kb)
record["fd_peak"] = int(fd_peak)
record["backend_fd_peak"] = int(backend_fd_peak)
record["total_fd_peak"] = int(total_fd_peak)
record["total_scheduler_run_delay_ns"] = int(total_scheduler_run_delay_ns)
record["scheduler_queue_delay_us_per_transfer"] = float(scheduler_queue_delay_us_per_transfer)
record["kernel_resource_metrics"] = kernel_resource_metrics == "true"
record["requests_per_cpu_second"] = None if rpcpu == "null" else float(rpcpu)
record["requests_per_total_cpu_second"] = None if total_rpcpu == "null" else float(total_rpcpu)
with open(path, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
PY
      attempt=$((attempt + 1))
      continue
    fi
    echo "${proxy} produced an invalid streaming sample on attempt ${attempt}/${SAMPLE_ATTEMPTS}: ${metrics}" >&2
    attempt=$((attempt + 1))
  done
  valid_sample_count="$(wc -l <"$samples_file" | tr -d '[:space:]')"
  if [ "$valid_sample_count" -lt "$MIN_VALID_SAMPLES" ]; then
    echo "${proxy} produced ${valid_sample_count}/${SAMPLE_ATTEMPTS} valid streaming samples; ${MIN_VALID_SAMPLES} required" >&2
    INVALID_SAMPLES=$((INVALID_SAMPLES + 1))
    return
  fi
  selected_sample="$(python3 - "$samples_file" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    records = [json.loads(line) for line in handle if line.strip()]
records.sort(key=lambda record: record["total_ms"])
print(json.dumps(records[len(records) // 2], sort_keys=True, separators=(",", ":")))
PY
)"
  commit="${GITHUB_SHA:-unknown}"
  python3 - "$OUT_JSON" "$selected_sample" "$STREAM_BYTES" "$CHUNK_BYTES" "$SAMPLE_ATTEMPTS" "$valid_sample_count" "$commit" <<'PY'
import json
import sys

out, sample, stream_bytes, chunk_bytes, attempts, valid_samples, commit = sys.argv[1:8]
record = json.loads(sample)
record.update({
    "bench": "proxy_compare_http1_streaming_reverse",
    "stream_bytes": int(stream_bytes),
    "chunk_bytes": int(chunk_bytes),
    "sample_attempts": int(attempts),
    "valid_samples": int(valid_samples),
    "aggregation": "single_sample",
    "commit": commit,
})
with open(out, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
PY
}

require_cmd curl
require_cmd lighttpd
require_cmd nginx
require_cmd python3

case "$SAMPLE_ATTEMPTS" in
  ''|*[!0-9]*)
    echo "QPX_STREAMING_COMPARE_SAMPLE_ATTEMPTS must be a positive integer" >&2
    exit 1
    ;;
esac
if [ "$SAMPLE_ATTEMPTS" -eq 0 ]; then
  echo "QPX_STREAMING_COMPARE_SAMPLE_ATTEMPTS must be a positive integer" >&2
  exit 1
fi
case "$FAST_TRANSFERS" in
  ''|*[!0-9]*)
    echo "QPX_STREAMING_COMPARE_FAST_TRANSFERS must be a positive integer" >&2
    exit 1
    ;;
esac
if [ "$FAST_TRANSFERS" -eq 0 ]; then
  echo "QPX_STREAMING_COMPARE_FAST_TRANSFERS must be a positive integer" >&2
  exit 1
fi
if [ -z "$MIN_VALID_SAMPLES" ]; then
  MIN_VALID_SAMPLES=$((SAMPLE_ATTEMPTS / 2 + 1))
fi
case "$MIN_VALID_SAMPLES" in
  ''|*[!0-9]*)
    echo "QPX_STREAMING_COMPARE_MIN_VALID_SAMPLES must be a positive integer no greater than sample attempts" >&2
    exit 1
    ;;
esac
if [ "$MIN_VALID_SAMPLES" -eq 0 ] || [ "$MIN_VALID_SAMPLES" -gt "$SAMPLE_ATTEMPTS" ]; then
  echo "QPX_STREAMING_COMPARE_MIN_VALID_SAMPLES must be a positive integer no greater than sample attempts" >&2
  exit 1
fi

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

FINAL_OUT_JSON="$OUT_JSON"
RAW_OUT_JSON="$TMP_DIR/interleaved-raw.jsonl"
REQUESTED_SAMPLE_ATTEMPTS="$SAMPLE_ATTEMPTS"
REQUESTED_MIN_VALID_SAMPLES="$MIN_VALID_SAMPLES"
OUT_JSON="$RAW_OUT_JSON"
SAMPLE_ATTEMPTS=1
MIN_VALID_SAMPLES=1
: >"$OUT_JSON"

run_streaming_proxy_by_index() {
  local index="$1"
  local read_mode="$2"
  case "$index" in
    0) run_one "direct-backend" "$BACKEND_PORT" "$BACKEND_PID" "$read_mode" ;;
    1) run_one "qpxd" "$QPX_PORT" "$QPXD_PID" "$read_mode" ;;
    2) run_one "nginx" "$NGINX_PORT" "$NGINX_PID" "$read_mode" ;;
    3) run_one "apache" "$APACHE_PORT" "$APACHE_PID" "$read_mode" ;;
    4) run_one "lighttpd" "$LIGHTTPD_PORT" "$LIGHTTPD_PID" "$read_mode" ;;
    *) echo "invalid streaming benchmark index: ${index}" >&2; exit 1 ;;
  esac
}

for read_mode in fast slow; do
  round=1
  while [ "$round" -le "$REQUESTED_SAMPLE_ATTEMPTS" ]; do
    CURRENT_SAMPLE_ROUND="$round"
    start_index=$((((round - 1) * 4) % 5))
    offset=0
    while [ "$offset" -lt 5 ]; do
      if [ $((round % 2)) -eq 1 ]; then
        proxy_index=$(((start_index + offset) % 5))
      else
        proxy_index=$(((start_index - offset + 5) % 5))
      fi
      run_streaming_proxy_by_index "$proxy_index" "$read_mode"
      offset=$((offset + 1))
    done
    round=$((round + 1))
  done
done

python3 - "$RAW_OUT_JSON" "$FINAL_OUT_JSON" "$REQUESTED_SAMPLE_ATTEMPTS" \
  "$REQUESTED_MIN_VALID_SAMPLES" <<'PY'
import json
import math
import sys
from collections import defaultdict

raw_path, out_path, attempts, minimum = sys.argv[1:5]
attempts = int(attempts)
minimum = int(minimum)
proxies = ("direct-backend", "qpxd", "nginx", "apache", "lighttpd")
expected = {(read_mode, proxy) for read_mode in ("fast", "slow") for proxy in proxies}

groups = defaultdict(list)
with open(raw_path, "r", encoding="utf-8") as handle:
    for line in handle:
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("valid") is True:
            groups[(record["read_mode"], record["proxy"])].append(record)

def values(records, field):
    return sorted(
        float(record[field])
        for record in records
        if record.get(field) is not None and math.isfinite(float(record[field]))
    )

def lower(records, field):
    ordered = values(records, field)
    return None if not ordered else ordered[(len(ordered) - 1) // 2]

def upper(records, field):
    ordered = values(records, field)
    return None if not ordered else ordered[len(ordered) // 2]

def maximum(records, field):
    ordered = values(records, field)
    return None if not ordered else ordered[-1]

def spread(records, field):
    ordered = [value for value in values(records, field) if value > 0]
    return None if not ordered else ordered[-1] / ordered[0]

aggregated = []
for key in sorted(expected):
    records = groups.get(key, [])
    if len(records) < minimum:
        raise SystemExit(
            f"{key[1]} produced {len(records)}/{attempts} valid {key[0]} streaming samples; "
            f"{minimum} required"
        )
    records.sort(key=lambda record: record["total_ms"])
    record = dict(records[len(records) // 2])
    for field in (
        "total_ms",
        "first_byte_ms",
        "p50_chunk_gap_ms",
        "p95_chunk_gap_ms",
        "p99_chunk_gap_ms",
        "max_chunk_gap_ms",
        "cpu_ms",
        "backend_cpu_ms",
        "total_cpu_ms",
    ):
        record[field] = upper(records, field)
    record["requests_per_cpu_second"] = lower(records, "requests_per_cpu_second")
    record["requests_per_total_cpu_second"] = lower(
        records, "requests_per_total_cpu_second"
    )
    for field in (
        "rss_kb",
        "rss_peak_kb",
        "backend_rss_peak_kb",
        "total_rss_peak_kb",
        "fd_peak",
        "backend_fd_peak",
        "total_fd_peak",
        "total_scheduler_run_delay_ns",
        "scheduler_queue_delay_us_per_transfer",
    ):
        record[field] = maximum(records, field)
    record["kernel_resource_metrics"] = all(
        item.get("kernel_resource_metrics") is True for item in records
    )
    for field in (
        "bytes",
        "transfers",
        "gap_observation_bytes",
        "chunk_observations",
        "stream_bytes",
        "chunk_bytes",
        "cpu_ms",
        "backend_cpu_ms",
        "total_cpu_ms",
        "rss_kb",
        "rss_peak_kb",
        "backend_rss_peak_kb",
        "total_rss_peak_kb",
        "fd_peak",
        "backend_fd_peak",
        "total_fd_peak",
        "total_scheduler_run_delay_ns",
    ):
        if record.get(field) is not None:
            record[field] = int(record[field])
    record.update({
        "aggregation": "conservative_median_per_metric",
        "benchmark_schema_version": 4,
        "sample_attempts": attempts,
        "sampling_order": "round_robin_interleaved",
        "sample_spread": {
            "total_ms_ratio": spread(records, "total_ms"),
            "requests_per_cpu_second_ratio": spread(records, "requests_per_cpu_second"),
            "requests_per_total_cpu_second_ratio": spread(
                records, "requests_per_total_cpu_second"
            ),
            "p99_chunk_gap_ms_ratio": spread(records, "p99_chunk_gap_ms"),
        },
        "valid_samples": len(records),
    })
    aggregated.append(record)

with open(out_path, "w", encoding="utf-8") as handle:
    for record in aggregated:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
PY
