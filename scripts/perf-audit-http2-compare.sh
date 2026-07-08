#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_JSON="${1:-${QPX_HTTP2_COMPARE_JSON:-$ROOT_DIR/target/perf/perf-audit-http2-compare.jsonl}}"
LOG_ARTIFACT_DIR="${QPX_HTTP2_COMPARE_LOG_DIR:-$ROOT_DIR/target/perf/http2-compare-logs}"
QPXD_BIN="${QPXD_BIN:-$ROOT_DIR/target/release/qpxd}"
DURATION_SECONDS="${QPX_HTTP2_COMPARE_DURATION_SECONDS:-10}"
CONCURRENCY="${QPX_HTTP2_COMPARE_CONCURRENCY:-64}"
MAX_CONCURRENT_STREAMS="${QPX_HTTP2_COMPARE_MAX_CONCURRENT_STREAMS:-100}"
BODY_SIZES="${QPX_HTTP2_COMPARE_BODY_SIZES:-1024 1048576}"
TLS_HOST="${QPX_HTTP2_COMPARE_TLS_HOST:-localhost}"
BACKEND_PORT="${QPX_HTTP2_COMPARE_BACKEND_PORT:-18280}"
QPX_PORT="${QPX_HTTP2_COMPARE_QPX_PORT:-18281}"
NGINX_PORT="${QPX_HTTP2_COMPARE_NGINX_PORT:-18282}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/qpx-http2-compare.XXXXXX")"
LOG_DIR="$TMP_DIR/logs"
STATE_DIR="$TMP_DIR/state"
mkdir -p "$LOG_DIR" "$STATE_DIR" "$(dirname "$OUT_JSON")"

PIDS=()
ARTIFACTS_COLLECTED=0
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
  worker_connections 4096;
}
http {
  access_log off;
  sendfile on;
  keepalive_timeout 65;
  server {
    listen 127.0.0.1:${BACKEND_PORT};
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
}

start_qpxd_h2() {
  local config="$TMP_DIR/qpxd-h2.yaml"
  cat >"$config" <<YAML
state_dir: "$STATE_DIR"
runtime:
  worker_threads: 1
  acceptor_tasks_per_listener: 1
  reuse_port: false
edges:
  - kind: reverse
    name: benchmark-h2
    listen: 127.0.0.1:${QPX_PORT}
    enforce_sni_host_match: false
    tls:
      certificates:
        - sni: ${TLS_HOST}
          cert: "$TMP_DIR/server.crt"
          key: "$TMP_DIR/server.key"
    routes:
      - name: bench
        streaming_requirement: required
        match:
          path_prefix: /
        target:
          type: upstream
          upstreams: [http://127.0.0.1:${BACKEND_PORT}]
YAML
  QPX_STATE_DIR="$STATE_DIR" "$QPXD_BIN" run --config "$config" >"$LOG_DIR/qpxd-h2.log" 2>&1 &
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
  worker_connections 4096;
}
http {
  access_log off;
  server {
    listen 127.0.0.1:${NGINX_PORT} ssl http2;
    ssl_certificate $TMP_DIR/server.crt;
    ssl_certificate_key $TMP_DIR/server.key;
    location / {
      proxy_http_version 1.1;
      proxy_set_header Connection "";
      proxy_pass http://127.0.0.1:${BACKEND_PORT};
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
  python3 - "$file" <<'PY'
import json
import re
import sys

text = open(sys.argv[1], "r", encoding="utf-8").read()

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
status_2xx = number(r"status codes:\s+([0-9]+)\s+2xx", cast=int)
latency = re.search(
    r"time for request:\s+([0-9.]+)([a-z]+)\s+([0-9.]+)([a-z]+)\s+([0-9.]+)([a-z]+)",
    text,
)
latency_min_ms = None
latency_max_ms = None
mean_ms = None
if latency:
    latency_min_ms = ms(latency.group(1), latency.group(2))
    latency_max_ms = ms(latency.group(3), latency.group(4))
    mean_ms = ms(latency.group(5), latency.group(6))
first_byte = re.search(
    r"time for 1st byte:\s+([0-9.]+)([a-z]+)\s+([0-9.]+)([a-z]+)\s+([0-9.]+)([a-z]+)",
    text,
)
first_byte_mean_ms = None
if first_byte:
    first_byte_mean_ms = ms(first_byte.group(5), first_byte.group(6))
print(json.dumps({
    "duration_seconds": duration,
    "requests_per_sec": requests_per_sec,
    "requests": requests,
    "started_requests": started,
    "complete_requests": done,
    "succeeded_requests": succeeded,
    "failed_requests": failed + errored + timeout,
    "non_2xx_responses": max(done - status_2xx, 0),
    "mean_time_per_request_ms": mean_ms,
    "latency_min_ms": latency_min_ms,
    "latency_max_ms": latency_max_ms,
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
  local out cpu_before_ms cpu_after_ms cpu_ms rss_kb rss_peak_kb metrics valid commit requests_per_cpu_second
  body_kind="$(body_profile "$body_bytes")"
  out="$TMP_DIR/http2.${proxy}.${body_bytes}.h2load"
  h2load -n 16 -c 4 -m "$MAX_CONCURRENT_STREAMS" -k "https://${TLS_HOST}:${port}/bench-${body_bytes}" >"$TMP_DIR/http2.${proxy}.${body_bytes}.warmup.h2load" 2>&1
  cpu_before_ms="$(process_tree_cpu_ms "$resource_pid")"
  h2load -D "$DURATION_SECONDS" -c "$CONCURRENCY" -m "$MAX_CONCURRENT_STREAMS" -k "https://${TLS_HOST}:${port}/bench-${body_bytes}" >"$out" 2>&1 || {
    echo "h2load failed for ${proxy}" >&2
    cat "$out" >&2 || true
    exit 1
  }
  cpu_after_ms="$(process_tree_cpu_ms "$resource_pid")"
  cpu_ms="$(awk -v before="$cpu_before_ms" -v after="$cpu_after_ms" 'BEGIN { delta = after - before; if (delta < 0) delta = 0; printf "%.0f", delta }')"
  rss_kb="$(process_tree_status_kb "$resource_pid" "VmRSS")"
  rss_peak_kb="$(process_tree_status_kb "$resource_pid" "VmHWM")"
  metrics="$(parse_h2load "$out")"
  valid="$(python3 - "$metrics" <<'PY'
import json
import sys
m = json.loads(sys.argv[1])
print("true" if m["requests"] > 0 and m["requests"] == m["complete_requests"] and m["failed_requests"] == 0 and m["non_2xx_responses"] == 0 else "false")
PY
)"
  requests_per_cpu_second="$(python3 - "$metrics" "$cpu_ms" <<'PY'
import json
import sys
m = json.loads(sys.argv[1])
cpu_ms = float(sys.argv[2])
print("null" if cpu_ms <= 0 else f"{m['requests'] / (cpu_ms / 1000.0):.6f}")
PY
)"
  commit="${GITHUB_SHA:-unknown}"
  python3 - "$OUT_JSON" "$metrics" "$proxy" "$body_kind" "$body_bytes" "$cpu_ms" "$rss_kb" "$rss_peak_kb" "$requests_per_cpu_second" "$valid" "$commit" <<'PY'
import json
import sys

out, metrics, proxy, body_kind, body_bytes, cpu_ms, rss_kb, rss_peak_kb, rpcpu, valid, commit = sys.argv[1:12]
record = json.loads(metrics)
record.update({
    "bench": "proxy_compare_http2_reverse",
    "proxy": proxy,
    "body_profile": body_kind,
})
record.pop("started_requests", None)
record["concurrency"] = int(__import__("os").environ.get("QPX_HTTP2_COMPARE_CONCURRENCY", "64"))
record["max_concurrent_streams"] = int(__import__("os").environ.get("QPX_HTTP2_COMPARE_MAX_CONCURRENT_STREAMS", "100"))
record["body_bytes"] = int(body_bytes)
record["cpu_ms"] = int(cpu_ms)
record["rss_kb"] = int(rss_kb)
record["rss_peak_kb"] = int(rss_peak_kb)
record["requests_per_cpu_second"] = None if rpcpu == "null" else float(rpcpu)
record["valid"] = valid == "true"
record["commit"] = commit
with open(out, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
PY
  if [ "$valid" != true ]; then
    echo "${proxy} produced an invalid HTTP/2 benchmark sample" >&2
    cat "$out" >&2 || true
    exit 1
  fi
}

require_cmd curl
require_cmd h2load
require_cmd nginx
require_cmd openssl
require_cmd python3

if [ ! -x "$QPXD_BIN" ]; then
  echo "missing qpxd binary: $QPXD_BIN" >&2
  exit 1
fi

: >"$OUT_JSON"
make_certs
start_backend
start_qpxd_h2
start_nginx_h2

for body_bytes in $BODY_SIZES; do
  run_one "qpxd" "$QPX_PORT" "$QPXD_PID" "$body_bytes"
  run_one "nginx" "$NGINX_PORT" "$NGINX_PID" "$body_bytes"
done
