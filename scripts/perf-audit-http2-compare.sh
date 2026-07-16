#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/lib/temp-dir.sh"
OUT_JSON="${1:-${QPX_HTTP2_COMPARE_JSON:-$ROOT_DIR/target/perf/perf-audit-http2-compare.jsonl}}"
LOG_ARTIFACT_DIR="${QPX_HTTP2_COMPARE_LOG_DIR:-$ROOT_DIR/target/perf/http2-compare-logs}"
QPXD_BIN="${QPXD_BIN:-$ROOT_DIR/target/release/qpxd}"
DURATION_SECONDS="${QPX_HTTP2_COMPARE_DURATION_SECONDS:-10}"
CONCURRENCY="${QPX_HTTP2_COMPARE_CONCURRENCY:-64}"
MULTIPLEX_CONCURRENCY="${QPX_HTTP2_COMPARE_MULTIPLEX_CONCURRENCY:-8}"
CLIENT_THREADS="${QPX_HTTP2_COMPARE_CLIENT_THREADS:-4}"
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
QPX_PORT="${QPX_HTTP2_COMPARE_QPX_PORT:-18281}"
NGINX_PORT="${QPX_HTTP2_COMPARE_NGINX_PORT:-18282}"

TMP_DIR="$(make_temp_dir qpx-http2-compare)"
LOG_DIR="$TMP_DIR/logs"
STATE_DIR="$TMP_DIR/state"
mkdir -p "$LOG_DIR" "$STATE_DIR" "$(dirname "$OUT_JSON")"

PIDS=()
ARTIFACTS_COLLECTED=0
INVALID_SAMPLES=0
BACKEND_PID=""
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

start_backend() {
  local prefix="$TMP_DIR/backend-nginx"
  local config="$prefix/backend-nginx.conf"
  local size
  mkdir -p "$prefix/logs" "$prefix/www"
  for size in $BODY_SIZES; do
    dd if=/dev/zero of="$prefix/www/bench-${size}" bs="$size" count=1 status=none
  done
  cp "$prefix/www/bench-$(first_body_size)" "$prefix/www/bench"
  cat >"$config" <<NGINX
pid $prefix/backend-nginx.pid;
error_log $prefix/logs/error.log warn;
worker_processes 1;
events {
  worker_connections 16384;
}
http {
  access_log off;
  sendfile on;
  keepalive_requests 10000000;
  keepalive_timeout 65;
  server {
    listen 127.0.0.1:${BACKEND_PORT};
    location / {
      default_type application/octet-stream;
      root $prefix/www;
    }
  }
  server {
    listen 127.0.0.1:${BACKEND_H2_PORT} ssl http2;
    ssl_certificate $TMP_DIR/server.crt;
    ssl_certificate_key $TMP_DIR/server.key;
    location / {
      default_type application/octet-stream;
      root $prefix/www;
    }
  }
}
NGINX
  nginx -p "$prefix" -c "$config" -g 'daemon off;' >"$LOG_DIR/backend.log" 2>&1 &
  BACKEND_PID=$!
  register_pid "$BACKEND_PID"
  wait_http "backend" "$BACKEND_PORT" "$BACKEND_PID" "$LOG_DIR/backend.log"
  wait_https "backend-h2" "$BACKEND_H2_PORT" "$BACKEND_PID" "$LOG_DIR/backend.log"
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
  worker_threads: 1
  acceptor_tasks_per_listener: 1
  reuse_port: false
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
error_log $prefix/logs/error.log warn;
worker_processes 1;
events {
  worker_connections 16384;
}
http {
  access_log off;
  keepalive_requests 10000000;
  upstream qpx_benchmark_backend {
    server 127.0.0.1:${BACKEND_PORT};
    keepalive 1024;
  }
  server {
    listen 127.0.0.1:${NGINX_PORT} ssl http2;
    ssl_certificate $TMP_DIR/server.crt;
    ssl_certificate_key $TMP_DIR/server.key;
    location / {
      proxy_http_version 1.1;
      proxy_set_header Connection "";
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

duration = number(r"finished in\s+([0-9.]+)s")
requests_per_sec = number(r"finished in\s+[0-9.]+s,\s+([0-9.]+)\s+req/s")
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

run_one() {
  local proxy="$1"
  local port="$2"
  local resource_pid="$3"
  local body_bytes="$4"
  local body_kind
  local out warmup_out latency_file cpu_before_ms cpu_after_ms cpu_ms backend_cpu_before_ms backend_cpu_after_ms
  local backend_cpu_ms total_cpu_ms rss_kb rss_peak_kb metrics valid commit
  local requests_per_cpu_second requests_per_total_cpu_second
  local attempt failed_sample samples_file valid_sample_count selected_sample profile_pid
  local load_concurrency
  body_kind="$(body_profile "$body_bytes")"
  load_concurrency="$CONCURRENCY"
  if [ "$MAX_CONCURRENT_STREAMS" -gt 1 ]; then
    load_concurrency="$MULTIPLEX_CONCURRENCY"
  fi
  local warmup_clients warmup_requests
  local artifact="http2.${proxy}.${body_bytes}.m${MAX_CONCURRENT_STREAMS}.round-${CURRENT_SAMPLE_ROUND:-0}"
  out="$TMP_DIR/${artifact}.h2load"
  warmup_out="$TMP_DIR/${artifact}.warmup.h2load"
  samples_file="$TMP_DIR/${artifact}.valid-samples.jsonl"
  : >"$samples_file"
  warmup_clients=$((CLIENT_THREADS * 2))
  warmup_requests=$((warmup_clients * 4))
  h2load -n "$warmup_requests" -c "$warmup_clients" -t "$CLIENT_THREADS" -m "$MAX_CONCURRENT_STREAMS" --connect-to "127.0.0.1:${port}" "https://${TLS_HOST}:${port}/bench-${body_bytes}" >"$warmup_out" 2>&1 || {
    echo "h2load warmup failed for ${proxy}" >&2
    cat "$warmup_out" >&2 || true
    exit 1
  }
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
    cpu_before_ms="$(process_tree_cpu_ms "$resource_pid")"
    if [ "$resource_pid" = "$BACKEND_PID" ]; then
      backend_cpu_before_ms="$cpu_before_ms"
    else
      backend_cpu_before_ms="$(process_tree_cpu_ms "$BACKEND_PID")"
    fi
    if ! h2load -D "$DURATION_SECONDS" -c "$load_concurrency" -t "$CLIENT_THREADS" -m "$MAX_CONCURRENT_STREAMS" --log-file="$latency_file" --connect-to "127.0.0.1:${port}" "https://${TLS_HOST}:${port}/bench-${body_bytes}" >"$out" 2>&1; then
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
    if [ -n "$profile_pid" ]; then
      wait "$profile_pid" || true
    fi
    metrics="$(parse_h2load "$out" "$latency_file")"
    rm -f "$latency_file"
    valid="$(python3 - "$metrics" <<'PY'
import json
import sys
m = json.loads(sys.argv[1])
print("true" if m["requests"] > 0 and m["requests"] == m["complete_requests"] and m["failed_requests"] == 0 and m["non_2xx_responses"] == 0 else "false")
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
      python3 - "$samples_file" "$metrics" "$cpu_ms" "$backend_cpu_ms" "$total_cpu_ms" \
        "$rss_kb" "$rss_peak_kb" "$requests_per_cpu_second" \
        "$requests_per_total_cpu_second" <<'PY'
import json
import sys

path, metrics, cpu_ms, backend_cpu_ms, total_cpu_ms, rss_kb, rss_peak_kb, rpcpu, total_rpcpu = sys.argv[1:10]
record = json.loads(metrics)
record["cpu_ms"] = int(cpu_ms)
record["backend_cpu_ms"] = int(backend_cpu_ms)
record["total_cpu_ms"] = int(total_cpu_ms)
record["rss_kb"] = int(rss_kb)
record["rss_peak_kb"] = int(rss_peak_kb)
record["requests_per_cpu_second"] = None if rpcpu == "null" else float(rpcpu)
record["requests_per_total_cpu_second"] = None if total_rpcpu == "null" else float(total_rpcpu)
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
  python3 - "$OUT_JSON" "$selected_sample" "$proxy" "$body_kind" "$body_bytes" "$load_concurrency" "$CLIENT_THREADS" "$MAX_CONCURRENT_STREAMS" "$SAMPLE_ATTEMPTS" "$valid_sample_count" "$commit" <<'PY'
import json
import sys

out, sample, proxy, body_kind, body_bytes, concurrency, client_threads, max_streams, attempts, valid_samples, commit = sys.argv[1:12]
record = json.loads(sample)
record.update({
    "bench": "proxy_compare_http2_reverse",
    "proxy": proxy,
    "body_profile": body_kind,
    "sample_attempts": int(attempts),
    "valid_samples": int(valid_samples),
    "aggregation": "single_sample",
})
record.pop("started_requests", None)
record["concurrency"] = int(concurrency)
record["client_threads"] = int(client_threads)
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
case "$CLIENT_THREADS" in
  ''|*[!0-9]*)
    echo "QPX_HTTP2_COMPARE_CLIENT_THREADS must be a positive integer" >&2
    exit 1
    ;;
esac
if [ "$CLIENT_THREADS" -eq 0 ] \
  || [ "$CLIENT_THREADS" -gt "$CONCURRENCY" ] \
  || [ "$CLIENT_THREADS" -gt "$MULTIPLEX_CONCURRENCY" ]; then
  echo "QPX_HTTP2_COMPARE_CLIENT_THREADS must not exceed either client concurrency" >&2
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
start_backend
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
    0) run_one "direct-backend" "$BACKEND_H2_PORT" "$BACKEND_PID" "$body_bytes" ;;
    1) run_one "qpxd" "$QPX_PORT" "$QPXD_PID" "$body_bytes" ;;
    2) run_one "nginx" "$NGINX_PORT" "$NGINX_PID" "$body_bytes" ;;
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
  "$DURATION_SECONDS" <<'PY'
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
        "complete_requests",
        "succeeded_requests",
        "requests_per_sec",
        "requests_per_cpu_second",
        "requests_per_total_cpu_second",
    ):
        record[field] = lower(records, field)
    for field in (
        "duration_seconds",
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
    ):
        record[field] = maximum(records, field)
    for field in (
        "requests",
        "complete_requests",
        "succeeded_requests",
        "failed_requests",
        "process_request_failures",
        "non_2xx_responses",
        "cpu_ms",
        "backend_cpu_ms",
        "total_cpu_ms",
        "rss_kb",
        "rss_peak_kb",
    ):
        if record[field] is not None:
            record[field] = int(record[field])
    record.update({
        "aggregation": "conservative_median_per_metric",
        "benchmark_duration_seconds": target_duration,
        "benchmark_schema_version": 4,
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
