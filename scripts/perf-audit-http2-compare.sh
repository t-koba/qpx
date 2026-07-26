#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/lib/temp-dir.sh"
OUT_JSON="${1:-${QPX_HTTP2_COMPARE_JSON:-$ROOT_DIR/target/perf/perf-audit-http2-compare.jsonl}}"
LOG_ARTIFACT_DIR="${QPX_HTTP2_COMPARE_LOG_DIR:-$ROOT_DIR/target/perf/http2-compare-logs}"
QPXD_BIN="${QPXD_BIN:-$ROOT_DIR/target/release/qpxd}"
TARGET_DURATION_SECONDS="${QPX_HTTP2_COMPARE_TARGET_DURATION_SECONDS:-10}"
CALIBRATION_BYTES="${QPX_HTTP2_COMPARE_CALIBRATION_BYTES:-16777216}"
CALIBRATION_MIN_DURATION_MS="${QPX_HTTP2_COMPARE_CALIBRATION_MIN_DURATION_MS:-2000}"
CONCURRENCY="${QPX_HTTP2_COMPARE_CONCURRENCY:-64}"
MULTIPLEX_CONCURRENCY="${QPX_HTTP2_COMPARE_MULTIPLEX_CONCURRENCY:-1}"
CLIENT_THREADS="${QPX_HTTP2_COMPARE_CLIENT_THREADS:-4}"
MULTIPLEX_CLIENT_THREADS="${QPX_HTTP2_COMPARE_MULTIPLEX_CLIENT_THREADS:-1}"
MAX_CONCURRENT_STREAMS_VALUES="${QPX_HTTP2_COMPARE_MAX_CONCURRENT_STREAMS_VALUES:-1 100}"
MAX_CONCURRENT_STREAMS=""
BODY_SIZES="${QPX_HTTP2_COMPARE_BODY_SIZES:-1024 1048576}"
SAMPLE_ATTEMPTS="${QPX_HTTP2_COMPARE_SAMPLE_ATTEMPTS:-3}"
MIN_VALID_SAMPLES="${QPX_HTTP2_COMPARE_MIN_VALID_SAMPLES:-}"
PROFILE_QPXD_SECONDS="${QPX_HTTP2_COMPARE_PROFILE_QPXD_SECONDS:-0}"
QPXD_TLS_FORMAT="${QPX_HTTP2_COMPARE_QPXD_TLS_FORMAT:-pem}"
TLS_HOST="${QPX_HTTP2_COMPARE_TLS_HOST:-localhost}"
BACKEND_PORT="${QPX_HTTP2_COMPARE_BACKEND_PORT:-18280}"
BACKEND_H2_PORT="${QPX_HTTP2_COMPARE_BACKEND_H2_PORT:-18283}"
NGINX_BACKEND_PORT="${QPX_HTTP2_COMPARE_NGINX_BACKEND_PORT:-18284}"
QPX_PORT="${QPX_HTTP2_COMPARE_QPX_PORT:-18281}"
NGINX_PORT="${QPX_HTTP2_COMPARE_NGINX_PORT:-18282}"
AVAILABLE_PROCESSORS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
if [ "$AVAILABLE_PROCESSORS" -gt 4 ]; then
  AVAILABLE_PROCESSORS=4
fi
SERVER_WORKERS="${QPX_HTTP2_COMPARE_SERVER_WORKERS:-$AVAILABLE_PROCESSORS}"

TMP_DIR="$(make_temp_dir qpx-http2-compare)"
LOG_DIR="$TMP_DIR/logs"
STATE_DIR="$TMP_DIR/state"
mkdir -p "$LOG_DIR" "$STATE_DIR" "$(dirname "$OUT_JSON")"

PIDS=()
ARTIFACTS_COLLECTED=0
INVALID_SAMPLES=0
DIRECT_BACKEND_PID=""
QPX_BACKEND_PID=""
NGINX_BACKEND_PID=""
QPXD_PID=""
NGINX_PID=""

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
  find "$TMP_DIR" -name '*.h2load' -type f -exec cp {} "$LOG_ARTIFACT_DIR"/ \; 2>/dev/null || true
  find "$TMP_DIR" -name '*.latency.tsv' -type f -exec cp {} "$LOG_ARTIFACT_DIR"/ \; 2>/dev/null || true
  find "$TMP_DIR" -name '*.sample.txt' -type f -exec cp {} "$LOG_ARTIFACT_DIR"/ \; 2>/dev/null || true
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

first_body_size() {
  for size in $BODY_SIZES; do
    echo "$size"
    return
  done
  echo 1024
}

body_profile() {
  local size="$1"
  if [ "$size" -le 4096 ]; then
    echo "short"
  else
    echo "long"
  fi
}

source "$ROOT_DIR/scripts/lib/perf-process-metrics.sh"

wait_https() {
  local name="$1"
  local port="$2"
  local pid="$3"
  local log_file="$4"
  local path="${5:-/bench-$(first_body_size)}"
  local tries=0
  while [ "$tries" -lt 100 ]; do
    if curl -fsSk --http1.1 --max-time 2 --resolve "${TLS_HOST}:${port}:127.0.0.1" "https://${TLS_HOST}:${port}${path}" >/dev/null 2>&1; then
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

wait_http() {
  local name="$1"
  local port="$2"
  local pid="$3"
  local log_file="$4"
  local path="${5:-/bench-$(first_body_size)}"
  local tries=0
  while [ "$tries" -lt 100 ]; do
    if curl -fsS --max-time 2 "http://127.0.0.1:${port}${path}" >/dev/null 2>&1; then
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

make_certs() {
  openssl req \
    -x509 \
    -newkey rsa:2048 \
    -sha256 \
    -days 1 \
    -nodes \
    -subj "/CN=${TLS_HOST}" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:${TLS_HOST}" \
    -keyout "$TMP_DIR/server.key" \
    -out "$TMP_DIR/server.crt" \
    >"$LOG_DIR/openssl.log" 2>&1
  openssl pkcs12 \
    -export \
    -inkey "$TMP_DIR/server.key" \
    -in "$TMP_DIR/server.crt" \
    -out "$TMP_DIR/server.p12" \
    -passout pass:qpx-benchmark \
    >>"$LOG_DIR/openssl.log" 2>&1
}

prepare_backend_files() {
  local size
  mkdir -p "$TMP_DIR/backend-www"
  for size in $BODY_SIZES; do
    dd if=/dev/zero of="$TMP_DIR/backend-www/bench-${size}" bs="$size" count=1 status=none
  done
  cp "$TMP_DIR/backend-www/bench-$(first_body_size)" "$TMP_DIR/backend-www/bench"
}

start_http_backend() {
  local name="$1"
  local port="$2"
  local prefix="$TMP_DIR/${name}-backend-nginx"
  local config="$prefix/backend-nginx.conf"
  local pid
  mkdir -p "$prefix/logs"
  cat >"$config" <<NGINX
pid $prefix/backend-nginx.pid;
error_log $LOG_DIR/${name}-backend-error.log warn;
worker_processes ${SERVER_WORKERS};
events {
  worker_connections 16384;
}
http {
  access_log off;
  sendfile on;
  keepalive_requests 10000000;
  keepalive_timeout 65;
  server {
    listen 127.0.0.1:${port} backlog=8192;
    location / {
      default_type application/octet-stream;
      root $TMP_DIR/backend-www;
    }
  }
}
NGINX
  nginx -p "$prefix" -c "$config" -g 'daemon off;' >"$LOG_DIR/${name}-backend.log" 2>&1 &
  pid=$!
  register_pid "$pid"
  wait_http "${name}-backend" "$port" "$pid" "$LOG_DIR/${name}-backend.log"
  case "$name" in
    qpx) QPX_BACKEND_PID="$pid" ;;
    nginx) NGINX_BACKEND_PID="$pid" ;;
    *) echo "invalid HTTP backend name: ${name}" >&2; exit 1 ;;
  esac
}

start_direct_backend() {
  local prefix="$TMP_DIR/direct-backend-nginx"
  local config="$prefix/backend-nginx.conf"
  mkdir -p "$prefix/logs"
  cat >"$config" <<NGINX
pid $prefix/backend-nginx.pid;
error_log $LOG_DIR/direct-backend-error.log warn;
worker_processes ${SERVER_WORKERS};
events {
  worker_connections 16384;
}
http {
  access_log off;
  sendfile on;
  keepalive_requests 10000000;
  keepalive_timeout 65;
  server {
    listen 127.0.0.1:${BACKEND_H2_PORT} ssl http2;
    ssl_certificate $TMP_DIR/server.crt;
    ssl_certificate_key $TMP_DIR/server.key;
    location / {
      default_type application/octet-stream;
      root $TMP_DIR/backend-www;
    }
  }
}
NGINX
  nginx -p "$prefix" -c "$config" -g 'daemon off;' >"$LOG_DIR/direct-backend.log" 2>&1 &
  DIRECT_BACKEND_PID=$!
  register_pid "$DIRECT_BACKEND_PID"
  wait_https "direct-backend" "$BACKEND_H2_PORT" "$DIRECT_BACKEND_PID" "$LOG_DIR/direct-backend.log"
}

start_qpxd_h2() {
  local config="$TMP_DIR/qpxd-h2.yaml"
  local certificate_config
  if [ "$QPXD_TLS_FORMAT" = pkcs12 ]; then
    certificate_config="          pkcs12: \"$TMP_DIR/server.p12\"
          pkcs12_password_env: QPX_HTTP2_BENCH_PKCS12_PASSWORD"
  else
    certificate_config="          cert: \"$TMP_DIR/server.crt\"
          key: \"$TMP_DIR/server.key\""
  fi
  cat >"$config" <<YAML
state_dir: "$STATE_DIR"
telemetry:
  system_log:
    level: warn
    format: json
runtime:
  worker_threads: ${SERVER_WORKERS}
  # Keep the listener fan-out aligned with the worker pool. A single acceptor
  # serializes the 64 independent HTTP/2 connections before the worker pool
  # can process them, which measures the accept loop rather than the proxy.
  acceptor_tasks_per_listener: ${SERVER_WORKERS}
  reuse_port: true
  upstream_proxy_max_concurrent_per_endpoint: 2048
  upstream_max_idle_connections_per_origin: 1024
edges:
  - kind: reverse
    name: benchmark-h2
    listen: 127.0.0.1:${QPX_PORT}
    enforce_sni_host_match: false
    tls:
      certificates:
        - sni: ${TLS_HOST}
${certificate_config}
    routes:
      - name: bench
        streaming_requirement: required
        streaming:
          max_response_body_bytes: 134217728
        match: {}
        target:
          type: upstream
          upstreams: [http://127.0.0.1:${BACKEND_PORT}]
YAML
  QPX_HTTP2_BENCH_PKCS12_PASSWORD=qpx-benchmark \
    QPX_STATE_DIR="$STATE_DIR" \
    "$QPXD_BIN" run --config "$config" >"$LOG_DIR/qpxd-h2.log" 2>&1 &
  QPXD_PID=$!
  register_pid "$QPXD_PID"
  wait_https "qpxd-h2" "$QPX_PORT" "$QPXD_PID" "$LOG_DIR/qpxd-h2.log"
}

start_nginx_h2() {
  local prefix="$TMP_DIR/nginx-h2"
  local config="$prefix/nginx.conf"
  mkdir -p "$prefix/logs"
  cat >"$config" <<NGINX
pid $prefix/nginx.pid;
error_log $LOG_DIR/nginx-h2-error.log warn;
worker_processes ${SERVER_WORKERS};
events {
  worker_connections 16384;
}
http {
  access_log off;
  keepalive_requests 10000000;
  upstream qpx_benchmark_backend {
    server 127.0.0.1:${NGINX_BACKEND_PORT};
    keepalive 1024;
  }
  server {
    listen 127.0.0.1:${NGINX_PORT} ssl http2;
    ssl_certificate $TMP_DIR/server.crt;
    ssl_certificate_key $TMP_DIR/server.key;
    location / {
      proxy_http_version 1.1;
      proxy_set_header Connection "";
      proxy_buffering off;
      proxy_request_buffering off;
      proxy_pass http://qpx_benchmark_backend;
    }
  }
}
NGINX
  nginx -p "$prefix" -c "$config" -g 'daemon off;' >"$LOG_DIR/nginx-h2.log" 2>&1 &
  NGINX_PID=$!
  register_pid "$NGINX_PID"
  wait_https "nginx-h2" "$NGINX_PORT" "$NGINX_PID" "$LOG_DIR/nginx-h2.log"
}

parse_h2load() {
  local file="$1"
  local latency_file="$2"
  python3 - "$file" "$latency_file" <<'PY'
import json
import math
import re
import sys

text = open(sys.argv[1], "r", encoding="utf-8").read()
latency_path = sys.argv[2]

def number(pattern, default=None, cast=float):
    match = re.search(pattern, text)
    if not match:
        if default is None:
            raise SystemExit(f"missing h2load metric: {pattern}")
        return default
    return cast(match.group(1))

def ms(value, unit):
    value = float(value)
    if unit == "us":
        return value / 1000.0
    if unit == "ms":
        return value
    if unit == "s":
        return value * 1000.0
    return value

finished = re.search(
    r"finished in\s+([0-9.]+)(us|ms|s),\s+([0-9.]+)\s+req/s",
    text,
)
if finished is None:
    raise SystemExit("missing h2load completion metrics")
duration = ms(finished.group(1), finished.group(2)) / 1000.0
requests_per_sec = float(finished.group(3))
requests = number(r"requests:\s+([0-9]+)\s+total", cast=int)
started = number(r"requests:\s+[0-9]+\s+total,\s+([0-9]+)\s+started", cast=int)
done = number(r"requests:\s+[0-9]+\s+total,\s+[0-9]+\s+started,\s+([0-9]+)\s+done", cast=int)
succeeded = number(r"requests:.*?,\s+([0-9]+)\s+succeeded", cast=int)
failed = number(r"requests:.*?,\s+([0-9]+)\s+failed", cast=int)
errored = number(r"requests:.*?,\s+([0-9]+)\s+errored", cast=int)
timeout = number(r"requests:.*?,\s+([0-9]+)\s+timeout", cast=int)
process_failures = len(re.findall(r"^Process Request Failure:", text, flags=re.MULTILINE))
status_2xx = number(r"status codes:\s+([0-9]+)\s+2xx", cast=int)

def timing_row(label):
    return re.search(
        rf"^{label}\s*:\s+"
        r"([0-9.]+)([a-z]+)\s+([0-9.]+)([a-z]+)\s+"
        r"([0-9.]+)([a-z]+)\s+([0-9.]+)([a-z]+)\s+"
        r"([0-9.]+)([a-z]+)\s+([0-9.]+)([a-z]+)",
        text,
        flags=re.MULTILINE,
    )

latencies_us = []
latency_statuses = []
with open(latency_path, "r", encoding="utf-8") as handle:
    for line_number, line in enumerate(handle, start=1):
        if not line.strip():
            continue
        columns = line.rstrip("\n").split("\t")
        if len(columns) < 3:
            raise SystemExit(f"invalid h2load latency row {line_number}")
        try:
            latency_statuses.append(int(columns[1]))
            latencies_us.append(int(columns[2]))
        except ValueError as error:
            raise SystemExit(f"invalid h2load latency row {line_number}: {error}") from error

if len(latencies_us) != done:
    raise SystemExit(
        f"h2load latency row count {len(latencies_us)} does not match completed requests {done}"
    )
if not latencies_us:
    raise SystemExit("h2load latency log is empty")
if any(status < 200 or status >= 300 for status in latency_statuses):
    raise SystemExit("h2load latency log contains a non-2xx response")

latencies_us.sort()

def nearest_rank(values, quantile):
    return values[max(0, math.ceil(len(values) * quantile) - 1)]

latency_min_ms = latencies_us[0] / 1000.0
latency_max_ms = latencies_us[-1] / 1000.0
latency_p95_ms = nearest_rank(latencies_us, 0.95) / 1000.0
latency_p99_ms = nearest_rank(latencies_us, 0.99) / 1000.0
mean_ms = None
latency_summary = timing_row("request")
if latency_summary:
    mean_ms = ms(latency_summary.group(11), latency_summary.group(12))
else:
    legacy_latency_summary = re.search(
        r"time for request:\s+([0-9.]+)([a-z]+)\s+([0-9.]+)([a-z]+)\s+([0-9.]+)([a-z]+)",
        text,
    )
    if legacy_latency_summary:
        mean_ms = ms(legacy_latency_summary.group(5), legacy_latency_summary.group(6))
first_byte = timing_row("TTFB")
first_byte_mean_ms = None
if first_byte:
    first_byte_mean_ms = ms(first_byte.group(11), first_byte.group(12))
else:
    first_byte = re.search(
        r"time for 1st byte:\s+([0-9.]+)([a-z]+)\s+([0-9.]+)([a-z]+)\s+([0-9.]+)([a-z]+)",
        text,
    )
    if first_byte:
        first_byte_mean_ms = ms(first_byte.group(5), first_byte.group(6))
print(json.dumps({
    "duration_seconds": duration,
    "requests_per_sec": requests_per_sec,
    "requests": requests,
    "started_requests": started,
    "complete_requests": done,
    "succeeded_requests": succeeded,
    "failed_requests": failed + errored + timeout + process_failures,
    "process_request_failures": process_failures,
    "non_2xx_responses": max(done - status_2xx, 0),
    "mean_time_per_request_ms": mean_ms,
    "latency_min_ms": latency_min_ms,
    "latency_max_ms": latency_max_ms,
    "latency_p95_ms": latency_p95_ms,
    "latency_p99_ms": latency_p99_ms,
    "first_byte_mean_ms": first_byte_mean_ms,
}))
PY
}

parse_h2load_calibration() {
  local file="$1"
  python3 - "$file" <<'PY'
import re
import sys

text = open(sys.argv[1], "r", encoding="utf-8").read()
match = re.search(
    r"requests:\s+([0-9]+)\s+total,\s+([0-9]+)\s+started,\s+"
    r"([0-9]+)\s+done,\s+([0-9]+)\s+succeeded,\s+"
    r"([0-9]+)\s+failed,\s+([0-9]+)\s+errored,\s+([0-9]+)\s+timeout",
    text,
)
if match is None:
    raise SystemExit("h2load calibration output is missing request counters")
total, started, done, succeeded, failed, errored, timed_out = map(int, match.groups())
if total <= 0 or done != total or succeeded != done or failed or errored or timed_out:
    raise SystemExit("h2load calibration did not produce clean completed requests")
finished = re.search(r"finished in\s+([0-9.]+)(us|ms|s),", text)
if finished is None:
    raise SystemExit("h2load calibration output is missing duration")
duration = float(finished.group(1))
unit = finished.group(2)
if unit == "s":
    duration *= 1_000_000
elif unit == "ms":
    duration *= 1_000
print(done, max(1, round(duration)))
PY
}

run_one() {
  local proxy="$1"
  local port="$2"
  local resource_pid="$3"
  local backend_pid="$4"
  local body_bytes="$5"
  local body_kind
  local out warmup_out calibration_out latency_file cpu_before_ms cpu_after_ms cpu_ms backend_cpu_before_ms backend_cpu_after_ms
  local backend_cpu_ms total_cpu_ms rss_kb rss_peak_kb backend_rss_peak_kb total_rss_peak_kb metrics valid commit
  local fd_peak backend_fd_peak total_fd_peak fd_peak_file backend_fd_peak_file fd_peak_monitor_pid backend_fd_peak_monitor_pid
  local scheduler_before_ns scheduler_after_ns backend_scheduler_before_ns backend_scheduler_after_ns total_scheduler_run_delay_ns scheduler_queue_delay_us_per_request kernel_resource_metrics h2load_succeeded
  local requests_per_cpu_second requests_per_total_cpu_second
  local attempt failed_sample samples_file valid_sample_count selected_sample profile_pid
  local load_concurrency load_client_threads calibration_request_count calibration_requests calibration_duration_us calibration_min_duration_us minimum_requests benchmark_requests
  body_kind="$(body_profile "$body_bytes")"
  load_concurrency="$CONCURRENCY"
  load_client_threads="$CLIENT_THREADS"
  if [ "$MAX_CONCURRENT_STREAMS" -gt 1 ]; then
    load_concurrency="$MULTIPLEX_CONCURRENCY"
    load_client_threads="$MULTIPLEX_CLIENT_THREADS"
  fi
  local warmup_clients warmup_requests
  local artifact="http2.${proxy}.${body_bytes}.m${MAX_CONCURRENT_STREAMS}.round-${CURRENT_SAMPLE_ROUND:-0}"
  out="$TMP_DIR/${artifact}.h2load"
  warmup_out="$TMP_DIR/${artifact}.warmup.h2load"
  samples_file="$TMP_DIR/${artifact}.valid-samples.jsonl"
  : >"$samples_file"
  warmup_clients=$((load_client_threads * 2))
  warmup_requests=$((warmup_clients * 4))
  h2load -n "$warmup_requests" -c "$warmup_clients" -t "$load_client_threads" -m "$MAX_CONCURRENT_STREAMS" --connect-to "127.0.0.1:${port}" "https://${TLS_HOST}:${port}/bench-${body_bytes}" >"$warmup_out" 2>&1 || {
    echo "h2load warmup failed for ${proxy}" >&2
    cat "$warmup_out" >&2 || true
    exit 1
  }
  minimum_requests=$((load_concurrency * MAX_CONCURRENT_STREAMS))
  calibration_request_count=$(((CALIBRATION_BYTES + body_bytes - 1) / body_bytes))
  if [ "$calibration_request_count" -lt "$minimum_requests" ]; then
    calibration_request_count="$minimum_requests"
  fi
  calibration_out="$TMP_DIR/${artifact}.calibration.h2load"
  h2load -n "$calibration_request_count" -c "$load_concurrency" -t "$load_client_threads" -m "$MAX_CONCURRENT_STREAMS" --connect-to "127.0.0.1:${port}" "https://${TLS_HOST}:${port}/bench-${body_bytes}" >"$calibration_out" 2>&1 || {
    echo "h2load calibration failed for ${proxy}" >&2
    cat "$calibration_out" >&2 || true
    exit 1
  }
  read -r calibration_requests calibration_duration_us < <(parse_h2load_calibration "$calibration_out")
  calibration_min_duration_us=$((CALIBRATION_MIN_DURATION_MS * 1000))
  while [ "$calibration_duration_us" -lt "$calibration_min_duration_us" ]; do
    calibration_request_count=$(((calibration_requests * calibration_min_duration_us * 11 + calibration_duration_us * 10 - 1) / (calibration_duration_us * 10)))
    if [ "$calibration_request_count" -lt "$minimum_requests" ]; then
      calibration_request_count="$minimum_requests"
    fi
    h2load -n "$calibration_request_count" -c "$load_concurrency" -t "$load_client_threads" -m "$MAX_CONCURRENT_STREAMS" --connect-to "127.0.0.1:${port}" "https://${TLS_HOST}:${port}/bench-${body_bytes}" >"$calibration_out" 2>&1 || {
      echo "h2load stabilized calibration failed for ${proxy}" >&2
      cat "$calibration_out" >&2 || true
      exit 1
    }
    read -r calibration_requests calibration_duration_us < <(parse_h2load_calibration "$calibration_out")
  done
  benchmark_requests=$(((calibration_requests * TARGET_DURATION_SECONDS * 1000000 + calibration_duration_us - 1) / calibration_duration_us))
  if [ "$benchmark_requests" -lt "$minimum_requests" ]; then
    benchmark_requests="$minimum_requests"
  fi
  attempt=1
  failed_sample=""
  while [ "$attempt" -le "$SAMPLE_ATTEMPTS" ]; do
    out="$TMP_DIR/${artifact}.attempt-${attempt}.h2load"
    latency_file="$TMP_DIR/${artifact}.attempt-${attempt}.latency.tsv"
    profile_pid=""
    if [ "$proxy" = qpxd ] && [ "$PROFILE_QPXD_SECONDS" -gt 0 ]; then
      /usr/bin/sample "$resource_pid" "$PROFILE_QPXD_SECONDS" 1 \
        -file "$TMP_DIR/${artifact}.attempt-${attempt}.sample.txt" \
        >"$LOG_DIR/${artifact}.attempt-${attempt}.sample.log" 2>&1 &
      profile_pid=$!
    fi
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
      if [ "$resource_pid" != "$backend_pid" ]; then
        backend_fd_peak_file="$TMP_DIR/${artifact}.attempt-${attempt}.backend-fd-peak"
        monitor_process_tree_fd_peak "$backend_pid" "$backend_fd_peak_file" &
        backend_fd_peak_monitor_pid=$!
        backend_scheduler_before_ns="$(process_tree_scheduler_run_delay_ns "$backend_pid")"
      fi
    fi
    cpu_before_ms="$(process_tree_cpu_ms "$resource_pid")"
    if [ "$resource_pid" = "$backend_pid" ]; then
      backend_cpu_before_ms="$cpu_before_ms"
    else
      backend_cpu_before_ms="$(process_tree_cpu_ms "$backend_pid")"
    fi
    h2load_succeeded=true
    if ! h2load -n "$benchmark_requests" -c "$load_concurrency" -t "$load_client_threads" -m "$MAX_CONCURRENT_STREAMS" --log-file="$latency_file" --connect-to "127.0.0.1:${port}" "https://${TLS_HOST}:${port}/bench-${body_bytes}" >"$out" 2>&1; then
      h2load_succeeded=false
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
    if [ "$h2load_succeeded" != true ]; then
      echo "h2load failed for ${proxy} attempt ${attempt}/${SAMPLE_ATTEMPTS}" >&2
      cat "$out" >&2 || true
      failed_sample="$out"
      if [ -n "$profile_pid" ]; then
        wait "$profile_pid" || true
      fi
      attempt=$((attempt + 1))
      continue
    fi
    cpu_after_ms="$(process_tree_cpu_ms "$resource_pid")"
    if [ "$resource_pid" = "$backend_pid" ]; then
      backend_cpu_after_ms="$cpu_after_ms"
    else
      backend_cpu_after_ms="$(process_tree_cpu_ms "$backend_pid")"
    fi
    cpu_ms="$(awk -v before="$cpu_before_ms" -v after="$cpu_after_ms" 'BEGIN { delta = after - before; if (delta < 0) delta = 0; printf "%.0f", delta }')"
    backend_cpu_ms="$(awk -v before="$backend_cpu_before_ms" -v after="$backend_cpu_after_ms" 'BEGIN { delta = after - before; if (delta < 0) delta = 0; printf "%.0f", delta }')"
    if [ "$resource_pid" = "$backend_pid" ]; then
      total_cpu_ms="$cpu_ms"
    else
      total_cpu_ms=$((cpu_ms + backend_cpu_ms))
    fi
    rss_kb="$(process_tree_status_kb "$resource_pid" "VmRSS")"
    rss_peak_kb="$(process_tree_status_kb "$resource_pid" "VmHWM")"
    backend_rss_peak_kb="$rss_peak_kb"
    scheduler_after_ns="$scheduler_before_ns"
    backend_scheduler_after_ns="$backend_scheduler_before_ns"
    if [ "$resource_pid" != "$backend_pid" ]; then
      backend_rss_peak_kb="$(process_tree_status_kb "$backend_pid" "VmHWM")"
    fi
    if [ "$kernel_resource_metrics" = true ]; then
      scheduler_after_ns="$(process_tree_scheduler_run_delay_ns "$resource_pid")"
      if [ "$resource_pid" != "$backend_pid" ]; then
        backend_scheduler_after_ns="$(process_tree_scheduler_run_delay_ns "$backend_pid")"
      fi
    fi
    total_rss_peak_kb=$((rss_peak_kb + backend_rss_peak_kb))
    total_fd_peak=$((fd_peak + backend_fd_peak))
    if [ "$resource_pid" = "$backend_pid" ]; then
      total_rss_peak_kb="$rss_peak_kb"
      total_fd_peak="$fd_peak"
    fi
    total_scheduler_run_delay_ns="$(awk -v resource_before="$scheduler_before_ns" -v resource_after="$scheduler_after_ns" -v backend_before="$backend_scheduler_before_ns" -v backend_after="$backend_scheduler_after_ns" 'BEGIN { delta = (resource_after - resource_before) + (backend_after - backend_before); if (delta < 0) delta = 0; printf "%.0f", delta }')"
    if [ -n "$profile_pid" ]; then
      wait "$profile_pid" || true
    fi
    metrics="$(parse_h2load "$out" "$latency_file")"
    rm -f "$latency_file"
    valid="$(python3 - "$metrics" <<'PY'
import json
import sys
m = json.loads(sys.argv[1])
print("true" if m["requests"] > 0 and m["requests"] == m["started_requests"] == m["complete_requests"] == m["succeeded_requests"] and m["failed_requests"] == 0 and m["non_2xx_responses"] == 0 else "false")
PY
    )"
    if [ "$valid" = true ]; then
      requests_per_cpu_second="$(python3 - "$metrics" "$cpu_ms" <<'PY'
import json
import sys
m = json.loads(sys.argv[1])
cpu_ms = float(sys.argv[2])
print("null" if cpu_ms <= 0 else f"{m['requests'] / (cpu_ms / 1000.0):.6f}")
PY
)"
      requests_per_total_cpu_second="$(python3 - "$metrics" "$total_cpu_ms" <<'PY'
import json
import sys
m = json.loads(sys.argv[1])
cpu_ms = float(sys.argv[2])
print("null" if cpu_ms <= 0 else f"{m['requests'] / (cpu_ms / 1000.0):.6f}")
PY
)"
      scheduler_queue_delay_us_per_request="$(python3 - "$metrics" "$total_scheduler_run_delay_ns" <<'PY'
import json
import sys
m = json.loads(sys.argv[1])
delay_ns = float(sys.argv[2])
print(f"{delay_ns / m['requests'] / 1000.0:.6f}")
PY
)"
      python3 - "$samples_file" "$metrics" "$cpu_ms" "$backend_cpu_ms" "$total_cpu_ms" \
        "$rss_kb" "$rss_peak_kb" "$backend_rss_peak_kb" "$total_rss_peak_kb" \
        "$fd_peak" "$backend_fd_peak" "$total_fd_peak" "$total_scheduler_run_delay_ns" \
        "$scheduler_queue_delay_us_per_request" "$kernel_resource_metrics" "$requests_per_cpu_second" \
        "$requests_per_total_cpu_second" "$calibration_requests" \
        "$calibration_duration_us" "$benchmark_requests" <<'PY'
import json
import sys

(
    path,
    metrics,
    cpu_ms,
    backend_cpu_ms,
    total_cpu_ms,
    rss_kb,
    rss_peak_kb,
    backend_rss_peak_kb,
    total_rss_peak_kb,
    fd_peak,
    backend_fd_peak,
    total_fd_peak,
    total_scheduler_run_delay_ns,
    scheduler_queue_delay_us_per_request,
    kernel_resource_metrics,
    rpcpu,
    total_rpcpu,
    calibration_requests,
    calibration_duration_us,
    benchmark_requests,
) = sys.argv[1:21]
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
record["scheduler_queue_delay_us_per_request"] = float(scheduler_queue_delay_us_per_request)
record["kernel_resource_metrics"] = kernel_resource_metrics == "true"
record["requests_per_cpu_second"] = None if rpcpu == "null" else float(rpcpu)
record["requests_per_total_cpu_second"] = None if total_rpcpu == "null" else float(total_rpcpu)
record["calibration_requests"] = int(calibration_requests)
record["calibration_duration_ms"] = int(calibration_duration_us) / 1000.0
record["benchmark_request_count"] = int(benchmark_requests)
with open(path, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
PY
      attempt=$((attempt + 1))
      continue
    fi
    failed_sample="$out"
    echo "${proxy} produced an invalid HTTP/2 benchmark sample on attempt ${attempt}/${SAMPLE_ATTEMPTS}" >&2
    cat "$out" >&2 || true
    attempt=$((attempt + 1))
  done
  valid_sample_count="$(wc -l <"$samples_file" | tr -d '[:space:]')"
  if [ "$valid_sample_count" -lt "$MIN_VALID_SAMPLES" ]; then
    echo "${proxy} produced ${valid_sample_count}/${SAMPLE_ATTEMPTS} valid HTTP/2 samples; ${MIN_VALID_SAMPLES} required" >&2
    if [ -n "$failed_sample" ]; then
      cat "$failed_sample" >&2 || true
    fi
    INVALID_SAMPLES=$((INVALID_SAMPLES + 1))
    return
  fi
  selected_sample="$(python3 - "$samples_file" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    records = [json.loads(line) for line in handle if line.strip()]
records.sort(key=lambda record: record["requests_per_sec"])
print(json.dumps(records[(len(records) - 1) // 2], sort_keys=True, separators=(",", ":")))
PY
)"
  commit="${GITHUB_SHA:-unknown}"
  python3 - "$OUT_JSON" "$selected_sample" "$proxy" "$body_kind" "$body_bytes" "$load_concurrency" "$load_client_threads" "$MAX_CONCURRENT_STREAMS" "$SAMPLE_ATTEMPTS" "$valid_sample_count" "$SERVER_WORKERS" "$commit" <<'PY'
import json
import sys

out, sample, proxy, body_kind, body_bytes, concurrency, client_threads, max_streams, attempts, valid_samples, server_workers, commit = sys.argv[1:13]
record = json.loads(sample)
record.update({
    "bench": "proxy_compare_http2_reverse",
    "proxy": proxy,
    "body_profile": body_kind,
    "sample_attempts": int(attempts),
    "valid_samples": int(valid_samples),
    "aggregation": "single_sample",
})
record["concurrency"] = int(concurrency)
record["client_threads"] = int(client_threads)
record["server_workers"] = int(server_workers)
record["max_concurrent_streams"] = int(max_streams)
record["body_bytes"] = int(body_bytes)
record["valid"] = True
record["commit"] = commit
with open(out, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
PY
}

require_cmd curl
require_cmd h2load
require_cmd nginx
require_cmd openssl
require_cmd python3

case "$QPXD_TLS_FORMAT" in
  pem|pkcs12) ;;
  *)
    echo "QPX_HTTP2_COMPARE_QPXD_TLS_FORMAT must be pem or pkcs12" >&2
    exit 1
    ;;
esac

for concurrency_value in "$CONCURRENCY" "$MULTIPLEX_CONCURRENCY"; do
  case "$concurrency_value" in
    ''|*[!0-9]*)
      echo "HTTP/2 comparison concurrency values must be positive integers" >&2
      exit 1
      ;;
  esac
  if [ "$concurrency_value" -eq 0 ]; then
    echo "HTTP/2 comparison concurrency values must be positive integers" >&2
    exit 1
  fi
done
for duration_value in "$TARGET_DURATION_SECONDS"; do
  case "$duration_value" in
    ''|*[!0-9]*)
      echo "HTTP/2 comparison duration values must be positive integers" >&2
      exit 1
      ;;
  esac
  if [ "$duration_value" -eq 0 ]; then
    echo "HTTP/2 comparison duration values must be positive integers" >&2
    exit 1
  fi
done
case "$SERVER_WORKERS" in
  ''|*[!0-9]*)
    echo "QPX_HTTP2_COMPARE_SERVER_WORKERS must be a positive integer" >&2
    exit 1
    ;;
esac
if [ "$SERVER_WORKERS" -eq 0 ]; then
  echo "QPX_HTTP2_COMPARE_SERVER_WORKERS must be a positive integer" >&2
  exit 1
fi
case "$CALIBRATION_BYTES" in
  ''|*[!0-9]*)
    echo "QPX_HTTP2_COMPARE_CALIBRATION_BYTES must be a positive integer" >&2
    exit 1
    ;;
esac
case "$CALIBRATION_MIN_DURATION_MS" in
  ''|*[!0-9]*)
    echo "QPX_HTTP2_COMPARE_CALIBRATION_MIN_DURATION_MS must be a positive integer" >&2
    exit 1
    ;;
esac
if [ "$CALIBRATION_MIN_DURATION_MS" -eq 0 ]; then
  echo "QPX_HTTP2_COMPARE_CALIBRATION_MIN_DURATION_MS must be a positive integer" >&2
  exit 1
fi
if [ "$CALIBRATION_BYTES" -eq 0 ]; then
  echo "QPX_HTTP2_COMPARE_CALIBRATION_BYTES must be a positive integer" >&2
  exit 1
fi
case "$CLIENT_THREADS" in
  ''|*[!0-9]*)
    echo "QPX_HTTP2_COMPARE_CLIENT_THREADS must be a positive integer" >&2
    exit 1
    ;;
esac
case "$MULTIPLEX_CLIENT_THREADS" in
  ''|*[!0-9]*)
    echo "QPX_HTTP2_COMPARE_MULTIPLEX_CLIENT_THREADS must be a positive integer" >&2
    exit 1
    ;;
esac
if [ "$CLIENT_THREADS" -eq 0 ] || [ "$CLIENT_THREADS" -gt "$CONCURRENCY" ]; then
  echo "QPX_HTTP2_COMPARE_CLIENT_THREADS must not exceed HTTP/2 single-stream client concurrency" >&2
  exit 1
fi
if [ "$MULTIPLEX_CLIENT_THREADS" -eq 0 ] \
  || [ "$MULTIPLEX_CLIENT_THREADS" -gt "$MULTIPLEX_CONCURRENCY" ]; then
  echo "QPX_HTTP2_COMPARE_MULTIPLEX_CLIENT_THREADS must not exceed multiplex client concurrency" >&2
  exit 1
fi

case "$SAMPLE_ATTEMPTS" in
  ''|*[!0-9]*)
    echo "QPX_HTTP2_COMPARE_SAMPLE_ATTEMPTS must be a positive integer" >&2
    exit 1
    ;;
esac
if [ "$SAMPLE_ATTEMPTS" -eq 0 ]; then
  echo "QPX_HTTP2_COMPARE_SAMPLE_ATTEMPTS must be a positive integer" >&2
  exit 1
fi
case "$PROFILE_QPXD_SECONDS" in
  *[!0-9]*)
    echo "QPX_HTTP2_COMPARE_PROFILE_QPXD_SECONDS must be a non-negative integer" >&2
    exit 1
    ;;
esac
if [ "$PROFILE_QPXD_SECONDS" -gt 0 ] && [ ! -x /usr/bin/sample ]; then
  echo "QPX_HTTP2_COMPARE_PROFILE_QPXD_SECONDS requires /usr/bin/sample" >&2
  exit 1
fi
if [ -z "$MIN_VALID_SAMPLES" ]; then
  MIN_VALID_SAMPLES=$((SAMPLE_ATTEMPTS / 2 + 1))
fi
case "$MIN_VALID_SAMPLES" in
  ''|*[!0-9]*)
    echo "QPX_HTTP2_COMPARE_MIN_VALID_SAMPLES must be a positive integer no greater than sample attempts" >&2
    exit 1
    ;;
esac
if [ "$MIN_VALID_SAMPLES" -eq 0 ] || [ "$MIN_VALID_SAMPLES" -gt "$SAMPLE_ATTEMPTS" ]; then
  echo "QPX_HTTP2_COMPARE_MIN_VALID_SAMPLES must be a positive integer no greater than sample attempts" >&2
  exit 1
fi

max_stream_value_count=0
for max_streams in $MAX_CONCURRENT_STREAMS_VALUES; do
  case "$max_streams" in
    ''|*[!0-9]*)
      echo "QPX_HTTP2_COMPARE_MAX_CONCURRENT_STREAMS_VALUES must contain positive integers" >&2
      exit 1
      ;;
  esac
  if [ "$max_streams" -eq 0 ]; then
    echo "QPX_HTTP2_COMPARE_MAX_CONCURRENT_STREAMS_VALUES must contain positive integers" >&2
    exit 1
  fi
  max_stream_value_count=$((max_stream_value_count + 1))
done
if [ "$max_stream_value_count" -eq 0 ]; then
  echo "QPX_HTTP2_COMPARE_MAX_CONCURRENT_STREAMS_VALUES must not be empty" >&2
  exit 1
fi

if [ ! -x "$QPXD_BIN" ]; then
  echo "missing qpxd binary: $QPXD_BIN" >&2
  exit 1
fi

: >"$OUT_JSON"
make_certs
prepare_backend_files
start_http_backend qpx "$BACKEND_PORT"
start_http_backend nginx "$NGINX_BACKEND_PORT"
start_direct_backend
start_qpxd_h2
start_nginx_h2

FINAL_OUT_JSON="$OUT_JSON"
RAW_OUT_JSON="$TMP_DIR/interleaved-raw.jsonl"
REQUESTED_SAMPLE_ATTEMPTS="$SAMPLE_ATTEMPTS"
REQUESTED_MIN_VALID_SAMPLES="$MIN_VALID_SAMPLES"
OUT_JSON="$RAW_OUT_JSON"
SAMPLE_ATTEMPTS=1
MIN_VALID_SAMPLES=1
: >"$OUT_JSON"

run_http2_proxy_by_index() {
  local index="$1"
  local body_bytes="$2"
  case "$index" in
    0) run_one "direct-backend" "$BACKEND_H2_PORT" "$DIRECT_BACKEND_PID" "$DIRECT_BACKEND_PID" "$body_bytes" ;;
    1) run_one "qpxd" "$QPX_PORT" "$QPXD_PID" "$QPX_BACKEND_PID" "$body_bytes" ;;
    2) run_one "nginx" "$NGINX_PORT" "$NGINX_PID" "$NGINX_BACKEND_PID" "$body_bytes" ;;
    *) echo "invalid HTTP/2 benchmark index: ${index}" >&2; exit 1 ;;
  esac
}

for body_bytes in $BODY_SIZES; do
  for max_streams in $MAX_CONCURRENT_STREAMS_VALUES; do
    MAX_CONCURRENT_STREAMS="$max_streams"
    round=1
    while [ "$round" -le "$REQUESTED_SAMPLE_ATTEMPTS" ]; do
      CURRENT_SAMPLE_ROUND="$round"
      start_index=$(((round - 1) % 3))
      offset=0
      while [ "$offset" -lt 3 ]; do
        if [ $((round % 2)) -eq 1 ]; then
          proxy_index=$(((start_index + offset) % 3))
        else
          proxy_index=$(((start_index - offset + 3) % 3))
        fi
        run_http2_proxy_by_index "$proxy_index" "$body_bytes"
        offset=$((offset + 1))
      done
      round=$((round + 1))
    done
  done
done

python3 - "$RAW_OUT_JSON" "$FINAL_OUT_JSON" "$REQUESTED_SAMPLE_ATTEMPTS" \
  "$REQUESTED_MIN_VALID_SAMPLES" "$BODY_SIZES" "$MAX_CONCURRENT_STREAMS_VALUES" \
  "$TARGET_DURATION_SECONDS" <<'PY'
import json
import math
import sys
from collections import defaultdict

raw_path, out_path, attempts, minimum, body_sizes, stream_values, target_duration = sys.argv[1:8]
attempts = int(attempts)
minimum = int(minimum)
target_duration = float(target_duration)
expected = {
    (proxy, int(body_bytes), int(max_streams))
    for proxy in ("direct-backend", "qpxd", "nginx")
    for body_bytes in body_sizes.split()
    for max_streams in stream_values.split()
}

groups = defaultdict(list)
with open(raw_path, "r", encoding="utf-8") as handle:
    for line in handle:
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("valid") is not True:
            continue
        key = (record["proxy"], int(record["body_bytes"]), int(record["max_concurrent_streams"]))
        groups[key].append(record)

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
            f"{key[0]} produced {len(records)}/{attempts} valid HTTP/2 samples "
            f"for {key[1]} bytes and m={key[2]}; {minimum} required"
        )
    records.sort(key=lambda record: record["requests_per_sec"])
    record = dict(records[(len(records) - 1) // 2])
    for field in (
        "requests",
        "started_requests",
        "complete_requests",
        "succeeded_requests",
        "calibration_requests",
        "benchmark_request_count",
        "requests_per_sec",
        "requests_per_cpu_second",
        "requests_per_total_cpu_second",
    ):
        record[field] = lower(records, field)
    for field in (
        "duration_seconds",
        "calibration_duration_ms",
        "mean_time_per_request_ms",
        "latency_p95_ms",
        "latency_p99_ms",
        "latency_max_ms",
        "first_byte_mean_ms",
        "cpu_ms",
        "backend_cpu_ms",
        "total_cpu_ms",
    ):
        record[field] = upper(records, field)
    record["latency_min_ms"] = lower(records, "latency_min_ms")
    for field in (
        "failed_requests",
        "process_request_failures",
        "non_2xx_responses",
        "rss_kb",
        "rss_peak_kb",
        "backend_rss_peak_kb",
        "total_rss_peak_kb",
        "fd_peak",
        "backend_fd_peak",
        "total_fd_peak",
        "total_scheduler_run_delay_ns",
        "scheduler_queue_delay_us_per_request",
    ):
        record[field] = maximum(records, field)
    record["kernel_resource_metrics"] = all(
        item.get("kernel_resource_metrics") is True for item in records
    )
    for field in (
        "requests",
        "started_requests",
        "complete_requests",
        "succeeded_requests",
        "calibration_requests",
        "benchmark_request_count",
        "failed_requests",
        "process_request_failures",
        "non_2xx_responses",
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
        if record[field] is not None:
            record[field] = int(record[field])
    record.update({
        "aggregation": "conservative_median_per_metric",
        "target_duration_seconds": target_duration,
        "benchmark_schema_version": 6,
        "sample_attempts": attempts,
        "sampling_order": "round_robin_interleaved",
        "sample_spread": {
            "requests_per_sec_ratio": spread(records, "requests_per_sec"),
            "requests_per_cpu_second_ratio": spread(records, "requests_per_cpu_second"),
            "requests_per_total_cpu_second_ratio": spread(
                records, "requests_per_total_cpu_second"
            ),
            "mean_time_per_request_ms_ratio": spread(records, "mean_time_per_request_ms"),
        },
        "valid_samples": len(records),
    })
    aggregated.append(record)

with open(out_path, "w", encoding="utf-8") as handle:
    for record in aggregated:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
PY
