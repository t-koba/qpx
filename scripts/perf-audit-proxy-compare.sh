#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_JSON="${1:-${QPX_PROXY_COMPARE_JSON:-$ROOT_DIR/target/perf/perf-audit-proxy-compare.jsonl}}"
LOG_ARTIFACT_DIR="${QPX_PROXY_COMPARE_LOG_DIR:-$ROOT_DIR/target/perf/proxy-compare-logs}"
QPXD_BIN="${QPXD_BIN:-$ROOT_DIR/target/release/qpxd}"
DURATION_SECONDS="${QPX_PROXY_COMPARE_DURATION_SECONDS:-10}"
CONCURRENCY="${QPX_PROXY_COMPARE_CONCURRENCY:-64}"
THREADS="${QPX_PROXY_COMPARE_THREADS:-2}"
WRK_TIMEOUT="${QPX_PROXY_COMPARE_WRK_TIMEOUT:-30s}"
BODY_SIZES="${QPX_PROXY_COMPARE_BODY_SIZES:-1024 1048576}"
SAMPLE_ATTEMPTS="${QPX_PROXY_COMPARE_SAMPLE_ATTEMPTS:-3}"
MIN_VALID_SAMPLES="${QPX_PROXY_COMPARE_MIN_VALID_SAMPLES:-}"
WARMUP_COOLDOWN_SECONDS="${QPX_PROXY_COMPARE_WARMUP_COOLDOWN_SECONDS:-0.25}"
MAX_READ_ERROR_RATE_PPM="${QPX_PROXY_COMPARE_MAX_READ_ERROR_RATE_PPM:-1000}"
HOST_HEADER="${QPX_PROXY_COMPARE_HOST:-bench.local}"
APACHE_BIN="${QPX_PROXY_COMPARE_APACHE_BIN:-}"
SCALE_WORKERS="${QPX_PROXY_COMPARE_SCALE_WORKERS:-}"
MAX_SCALE_WORKERS="${QPX_PROXY_COMPARE_MAX_SCALE_WORKERS:-4}"
PROXY_FILTER="${QPX_PROXY_COMPARE_PROXY_FILTER:-}"

BACKEND_PORT="${QPX_PROXY_COMPARE_BACKEND_PORT:-18080}"
BACKEND_WORKERS="${QPX_PROXY_COMPARE_BACKEND_WORKERS:-2}"
HEALTH_CHECK_INTERVAL_MS="${QPX_PROXY_COMPARE_HEALTH_CHECK_INTERVAL_MS:-5000}"
QPX_PORT="${QPX_PROXY_COMPARE_QPX_PORT:-18081}"
NGINX_PORT="${QPX_PROXY_COMPARE_NGINX_PORT:-18082}"
APACHE_PORT="${QPX_PROXY_COMPARE_APACHE_PORT:-18083}"
LIGHTTPD_PORT="${QPX_PROXY_COMPARE_LIGHTTPD_PORT:-18084}"
QPX_FORWARD_PORT="${QPX_PROXY_COMPARE_QPX_FORWARD_PORT:-18085}"
SQUID_PORT="${QPX_PROXY_COMPARE_SQUID_PORT:-18086}"
SCALE_BASE_PORT="${QPX_PROXY_COMPARE_SCALE_BASE_PORT:-18100}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/qpx-proxy-compare.XXXXXX")"
LOG_DIR="$TMP_DIR/logs"
STATE_DIR="$TMP_DIR/state"
mkdir -p "$LOG_DIR" "$STATE_DIR" "$(dirname "$OUT_JSON")"

PIDS=()
ARTIFACTS_COLLECTED=0
INVALID_SAMPLES=0
LAST_STARTED_PID=""
BACKEND_PID=""
QPXD_PID=""
NGINX_PID=""
APACHE_PID=""
LIGHTTPD_PID=""
QPX_FORWARD_PID=""
SQUID_PID=""

cpu_count() {
  if command -v nproc >/dev/null 2>&1; then
    nproc
  elif command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.ncpu
  else
    echo 1
  fi
}

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

default_scale_workers() {
  local cores max workers
  cores="$(cpu_count)"
  max="$MAX_SCALE_WORKERS"
  if [ "$cores" -lt "$max" ]; then
    max="$cores"
  fi
  workers="1"
  if [ "$max" -ge 2 ]; then
    workers="$workers 2"
  fi
  if [ "$max" -ge 4 ]; then
    workers="$workers 4"
  fi
  echo "$workers"
}

collect_artifacts() {
  if [ "$ARTIFACTS_COLLECTED" -eq 1 ]; then
    return
  fi
  ARTIFACTS_COLLECTED=1
  rm -rf "$LOG_ARTIFACT_DIR"
  mkdir -p "$LOG_ARTIFACT_DIR"
  cp -R "$LOG_DIR"/. "$LOG_ARTIFACT_DIR"/ 2>/dev/null || true
  cp "$TMP_DIR"/*.wrk "$LOG_ARTIFACT_DIR"/ 2>/dev/null || true
  cp "$TMP_DIR"/*.lua "$LOG_ARTIFACT_DIR"/ 2>/dev/null || true
  cp "$TMP_DIR"/*.warmup "$LOG_ARTIFACT_DIR"/ 2>/dev/null || true
  cp "$TMP_DIR"/*.valid-samples.tsv "$LOG_ARTIFACT_DIR"/ 2>/dev/null || true
  cp "$TMP_DIR"/*.jsonl "$LOG_ARTIFACT_DIR"/ 2>/dev/null || true
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

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

register_pid() {
  PIDS+=("$1")
}

source "$ROOT_DIR/scripts/lib/perf-process-metrics.sh"

json_number_or_null() {
  local value="$1"
  if [ -z "$value" ]; then
    echo "null"
  else
    echo "$value"
  fi
}

read_error_rate_allowed() {
  local read_errors="$1"
  local completed_requests="$2"
  [ "$completed_requests" -gt 0 ] &&
    [ $((read_errors * 1000000)) -le $((completed_requests * MAX_READ_ERROR_RATE_PPM)) ]
}

record_invalid_sample() {
  local bench="$1"
  local proxy="$2"
  local body_kind="$3"
  local body_bytes="$4"
  local status_before="$5"
  local status_after="$6"
  local error_code="$7"
  local commit
  commit="${GITHUB_SHA:-unknown}"
  printf '{"bench":"%s","proxy":"%s","body_profile":"%s","duration_seconds":%s,"threads":%s,"concurrency":%s,"body_bytes":%s,"sample_attempts":%s,"valid_samples":0,"aggregation":"single_sample","requests":0,"complete_requests":0,"failed_requests":1,"connect_errors":0,"read_errors":0,"write_errors":0,"timeout_errors":0,"max_read_error_rate_ppm":%s,"non_2xx_responses":0,"bad_length_responses":0,"status_before":"%s","status_after":"%s","requests_per_sec":0,"mean_time_per_request_ms":null,"latency_p50_ms":null,"latency_p90_ms":null,"latency_p95_ms":null,"latency_p99_ms":null,"latency_p999_ms":null,"transfer_kbytes_per_sec":0,"cpu_ms":null,"rss_kb":null,"rss_peak_kb":null,"requests_per_cpu_second":null,"valid":false,"error":"%s","commit":"%s"}\n' \
    "$bench" "$proxy" "$body_kind" "$DURATION_SECONDS" "$THREADS" "$CONCURRENCY" "$body_bytes" "$SAMPLE_ATTEMPTS" "$MAX_READ_ERROR_RATE_PPM" "$status_before" "$status_after" "$error_code" "$commit" >>"$OUT_JSON"
  INVALID_SAMPLES=$((INVALID_SAMPLES + 1))
}

dump_service_log() {
  local log_file="$1"
  local extra
  cat "$log_file" >&2 || true
  for extra in "${log_file%.*}"*.log; do
    if [ "$extra" != "$log_file" ] && [ -f "$extra" ]; then
      echo "--- ${extra} ---" >&2
      cat "$extra" >&2 || true
    fi
  done
}

dump_benchmark_logs() {
  local log
  for log in "$LOG_DIR"/*.log; do
    if [ -f "$log" ]; then
      echo "--- ${log} ---" >&2
      cat "$log" >&2 || true
    fi
  done
}

wait_http() {
  local name="$1"
  local port="$2"
  local pid="$3"
  local log_file="$4"
  local path="${5:-/bench-$(first_body_size)}"
  local tries=0
  while [ "$tries" -lt 100 ]; do
    if curl -fsS --max-time 2 -H "Host: ${HOST_HEADER}" "http://127.0.0.1:${port}${path}" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "${name} exited before becoming ready" >&2
      dump_service_log "$log_file"
      exit 1
    fi
    tries=$((tries + 1))
    sleep 0.1
  done
  echo "timeout waiting for ${name} on port ${port}" >&2
  dump_service_log "$log_file"
  exit 1
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
worker_processes ${BACKEND_WORKERS};
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
  local pid=$!
  LAST_STARTED_PID="$pid"
  BACKEND_PID="$pid"
  register_pid "$pid"
  wait_http "backend" "$BACKEND_PORT" "$pid" "$LOG_DIR/backend.log"
}

start_qpxd_reverse() {
  local name="$1"
  local port="$2"
  local worker_threads="$3"
  local acceptor_tasks="$4"
  local reuse_port="$5"
  local config="$TMP_DIR/${name}.yaml"
  cat >"$config" <<YAML
state_dir: "$STATE_DIR"
telemetry:
  system_log:
    level: warn
    format: json
runtime:
  worker_threads: ${worker_threads}
  acceptor_tasks_per_listener: ${acceptor_tasks}
  reuse_port: ${reuse_port}
  upstream_proxy_max_concurrent_per_endpoint: 512
edges:
  - kind: reverse
    name: ${name}
    listen: 127.0.0.1:${port}
    routes:
      - name: bench
        streaming_requirement: required
        streaming:
          max_response_body_bytes: 134217728
        match:
          host: [${HOST_HEADER}]
        health_check:
          interval_ms: ${HEALTH_CHECK_INTERVAL_MS}
          fail_threshold: 1000000
          cooldown_ms: 1
        target:
          type: upstream
          upstreams: [http://127.0.0.1:${BACKEND_PORT}]
YAML
  QPX_STATE_DIR="$STATE_DIR" "$QPXD_BIN" run --config "$config" >"$LOG_DIR/${name}.log" 2>&1 &
  local pid=$!
  LAST_STARTED_PID="$pid"
  register_pid "$pid"
  wait_http "$name" "$port" "$pid" "$LOG_DIR/${name}.log"
}

start_qpxd() {
  start_qpxd_reverse "qpxd" "$QPX_PORT" 1 1 false
  QPXD_PID="$LAST_STARTED_PID"
}

start_qpxd_forward() {
  local config="$TMP_DIR/qpxd-forward.yaml"
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
  - kind: forward
    name: benchmark-forward
    listen: 127.0.0.1:${QPX_FORWARD_PORT}
    default_action:
      type: direct
    rules: []
YAML
  QPX_STATE_DIR="$STATE_DIR" "$QPXD_BIN" run --config "$config" >"$LOG_DIR/qpxd-forward.log" 2>&1 &
  local pid=$!
  LAST_STARTED_PID="$pid"
  QPX_FORWARD_PID="$pid"
  register_pid "$pid"
  wait_forward "qpxd-forward" "$QPX_FORWARD_PORT" "$pid" "$LOG_DIR/qpxd-forward.log"
}

start_nginx() {
  local prefix="$TMP_DIR/nginx"
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
  local pid=$!
  LAST_STARTED_PID="$pid"
  NGINX_PID="$pid"
  register_pid "$pid"
  wait_http "nginx" "$NGINX_PORT" "$pid" "$LOG_DIR/nginx.log"
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
    apache_load_module "proxy"
    apache_load_module "proxy_http"
    apache_load_module "unixd"
    echo "KeepAlive On"
    echo "MaxKeepAliveRequests 0"
    echo "KeepAliveTimeout 30"
    echo "ProxyTimeout 30"
    echo "<VirtualHost 127.0.0.1:${APACHE_PORT}>"
    echo "  ProxyPass \"/\" \"http://127.0.0.1:${BACKEND_PORT}/\" retry=0 max=128 smax=128 ttl=60 acquire=3000"
    echo "  ProxyPassReverse \"/\" \"http://127.0.0.1:${BACKEND_PORT}/\""
    echo "</VirtualHost>"
  } >"$config"
  "$APACHE_BIN" -f "$config" -DFOREGROUND >"$LOG_DIR/apache.log" 2>&1 &
  local pid=$!
  LAST_STARTED_PID="$pid"
  APACHE_PID="$pid"
  register_pid "$pid"
  wait_http "apache" "$APACHE_PORT" "$pid" "$LOG_DIR/apache.log"
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
  local pid=$!
  LAST_STARTED_PID="$pid"
  LIGHTTPD_PID="$pid"
  register_pid "$pid"
  wait_http "lighttpd" "$LIGHTTPD_PORT" "$pid" "$LOG_DIR/lighttpd.log"
}

start_squid() {
  local root="$TMP_DIR/squid"
  local config="$root/squid.conf"
  local run_group
  local run_user
  local service_name
  run_group="$(id -gn)"
  run_user="$(id -un)"
  # Squid embeds this name in POSIX shared-memory object names. Keep it short
  # enough for platforms with conservative shm_open name limits, such as macOS.
  service_name="qpx$$"
  mkdir -p "$root/cache" "$root/logs" "$root/run"
  cat >"$config" <<SQUID
pid_filename $root/run/squid.pid
http_port 127.0.0.1:${SQUID_PORT}
visible_hostname qpx-perf-audit
cache_effective_user ${run_user}
cache_effective_group ${run_group}
access_log stdio:$root/logs/access.log
cache_log $LOG_DIR/squid-cache.log
coredump_dir $root/cache
cache deny all
acl allsrc src all
http_access allow allsrc
via on
forwarded_for delete
SQUID
  squid -N -n "$service_name" -f "$config" >"$LOG_DIR/squid.log" 2>&1 &
  local pid=$!
  LAST_STARTED_PID="$pid"
  SQUID_PID="$pid"
  register_pid "$pid"
  wait_forward "squid" "$SQUID_PORT" "$pid" "$LOG_DIR/squid.log"
}

extract_metric() {
  local file="$1"
  local key="$2"
  awk -v key="$key" '$1 == key { print $2; exit }' "$file"
}

extract_metric_or_zero() {
  local file="$1"
  local key="$2"
  local value
  value="$(extract_metric "$file" "$key")"
  if [ -z "$value" ]; then
    echo 0
  else
    echo "$value"
  fi
}

probe_status() {
  local port="$1"
  local path="${2:-/bench-$(first_body_size)}"
  curl -sS --max-time 5 -o /dev/null -w '%{http_code}' \
    -H "Host: ${HOST_HEADER}" \
    "http://127.0.0.1:${port}${path}"
}

probe_forward_status() {
  local port="$1"
  local path="${2:-/bench-$(first_body_size)}"
  curl -sS --max-time 5 -o /dev/null -w '%{http_code}' \
    --noproxy '' \
    -x "http://127.0.0.1:${port}" \
    "http://127.0.0.1:${BACKEND_PORT}${path}"
}

safe_probe_status() {
  local status
  if ! status="$(probe_status "$@" 2>/dev/null)"; then
    if [ -z "$status" ]; then
      echo "000"
    else
      echo "$status"
    fi
    return
  fi
  echo "$status"
}

safe_probe_forward_status() {
  local status
  if ! status="$(probe_forward_status "$@" 2>/dev/null)"; then
    if [ -z "$status" ]; then
      echo "000"
    else
      echo "$status"
    fi
    return
  fi
  echo "$status"
}

expect_status_ok() {
  local proxy="$1"
  local port="$2"
  local phase="$3"
  local path="$4"
  local status
  local tries=0
  while [ "$tries" -lt 40 ]; do
    status="$(safe_probe_status "$port" "$path")"
    if [ "$status" = "200" ]; then
      return 0
    fi
    tries=$((tries + 1))
    sleep 0.25
  done
  echo "${proxy} returned HTTP ${status} during ${phase}; refusing to record invalid benchmark" >&2
  dump_benchmark_logs
  return 1
}

expect_forward_status_ok() {
  local proxy="$1"
  local port="$2"
  local phase="$3"
  local path="$4"
  local status
  local tries=0
  while [ "$tries" -lt 40 ]; do
    status="$(safe_probe_forward_status "$port" "$path")"
    if [ "$status" = "200" ]; then
      return 0
    fi
    tries=$((tries + 1))
    sleep 0.25
  done
  echo "${proxy} returned HTTP ${status} during ${phase}; refusing to record invalid benchmark" >&2
  dump_benchmark_logs
  return 1
}

wait_forward() {
  local name="$1"
  local port="$2"
  local pid="$3"
  local log_file="$4"
  local path="${5:-/bench-$(first_body_size)}"
  local tries=0
  while [ "$tries" -lt 100 ]; do
    if curl -fsS --max-time 2 --noproxy '' -x "http://127.0.0.1:${port}" "http://127.0.0.1:${BACKEND_PORT}${path}" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "${name} exited before becoming ready" >&2
      dump_service_log "$log_file"
      exit 1
    fi
    tries=$((tries + 1))
    sleep 0.1
  done
  echo "timeout waiting for ${name} on port ${port}" >&2
  dump_service_log "$log_file"
  exit 1
}

run_one() {
  local bench="$1"
  local proxy="$2"
  local port="$3"
  local mode="$4"
  local request_target="$5"
  local request_host="$6"
  local body_bytes="$7"
  local resource_pid="$8"
  if [ -n "$PROXY_FILTER" ]; then
    case ",${PROXY_FILTER}," in
      *",${proxy},"*) ;;
      *) return 0 ;;
    esac
  fi
  local body_kind
  local url="http://127.0.0.1:${port}/"
  local artifact_name="${bench}.${proxy}.${body_bytes}.round-${CURRENT_SAMPLE_ROUND:-0}"
  local out="$TMP_DIR/${artifact_name}.wrk"
  local warmup_out="$TMP_DIR/${artifact_name}.warmup"
  local lua="$TMP_DIR/${artifact_name}.lua"
  local status_before status_after
  local cpu_before_ms cpu_after_ms cpu_ms rss_kb rss_peak_kb
  local attempt failed_sample samples_file valid_sample_count median_index selected_sample
  body_kind="$(body_profile "$body_bytes")"

  cat >"$lua" <<LUA
local expected = ${body_bytes}
local threads = {}

setup = function(thread)
  table.insert(threads, thread)
end

init = function(args)
  responses = 0
  non_200 = 0
  bad_length = 0
end

request = function()
  return wrk.format("GET", "${request_target}", { ["Host"] = "${request_host}" })
end

response = function(status, headers, body)
  responses = responses + 1
  if status ~= 200 then
    non_200 = non_200 + 1
  end
  if body == nil or string.len(body) ~= expected then
    bad_length = bad_length + 1
  end
end

done = function(summary, latency, requests)
  local seconds = summary.duration / 1000000
  local total_responses = 0
  local total_non_200 = 0
  local total_bad_length = 0
  for _, thread in ipairs(threads) do
    total_responses = total_responses + tonumber(thread:get("responses") or 0)
    total_non_200 = total_non_200 + tonumber(thread:get("non_200") or 0)
    total_bad_length = total_bad_length + tonumber(thread:get("bad_length") or 0)
  end
  io.write(string.format("qpx_complete_requests %d\n", total_responses))
  io.write(string.format("qpx_summary_requests %d\n", summary.requests))
  io.write(string.format("qpx_non_2xx_responses %d\n", total_non_200))
  io.write(string.format("qpx_bad_length_responses %d\n", total_bad_length))
  io.write(string.format("qpx_requests_per_sec %.6f\n", summary.requests / seconds))
  io.write(string.format("qpx_transfer_kbytes_per_sec %.6f\n", summary.bytes / 1024 / seconds))
  io.write(string.format("qpx_latency_p50_ms %.6f\n", latency:percentile(50) / 1000))
  io.write(string.format("qpx_latency_p90_ms %.6f\n", latency:percentile(90) / 1000))
  io.write(string.format("qpx_latency_p95_ms %.6f\n", latency:percentile(95) / 1000))
  io.write(string.format("qpx_latency_p99_ms %.6f\n", latency:percentile(99) / 1000))
  io.write(string.format("qpx_latency_p999_ms %.6f\n", latency:percentile(99.9) / 1000))
end
LUA

  if [ "$mode" = "forward" ]; then
    if ! expect_forward_status_ok "$proxy" "$port" "preflight" "/bench-${body_bytes}"; then
      status_before="$(safe_probe_forward_status "$port" "/bench-${body_bytes}")"
      record_invalid_sample "$bench" "$proxy" "$body_kind" "$body_bytes" "$status_before" "$status_before" "preflight_failed"
      return 0
    fi
  else
    if ! expect_status_ok "$proxy" "$port" "preflight" "/bench-${body_bytes}"; then
      status_before="$(safe_probe_status "$port" "/bench-${body_bytes}")"
      record_invalid_sample "$bench" "$proxy" "$body_kind" "$body_bytes" "$status_before" "$status_before" "preflight_failed"
      return 0
    fi
  fi
  if ! wrk -t"$THREADS" -c16 -d2s --timeout "$WRK_TIMEOUT" -s "$lua" "$url" >"$warmup_out" 2>&1; then
    echo "wrk warmup failed for ${proxy}" >&2
    cat "$warmup_out" >&2 || true
    record_invalid_sample "$bench" "$proxy" "$body_kind" "$body_bytes" "200" "200" "warmup_failed"
    return 0
  fi
  sleep "$WARMUP_COOLDOWN_SECONDS"
  if [ "$mode" = "forward" ]; then
    status_before="$(safe_probe_forward_status "$port" "/bench-${body_bytes}")"
  else
    status_before="$(safe_probe_status "$port" "/bench-${body_bytes}")"
  fi
  local complete summary_requests failed fatal_errors non_2xx bad_length write_errors read_errors connect_errors timeout_errors rps mean_ms transfer_kbps commit valid
  local latency_p50_ms latency_p90_ms latency_p95_ms latency_p99_ms latency_p999_ms requests_per_cpu_second
  samples_file="$TMP_DIR/${artifact_name}.valid-samples.tsv"
  : >"$samples_file"
  attempt=1
  failed_sample=""
  while [ "$attempt" -le "$SAMPLE_ATTEMPTS" ]; do
    out="$TMP_DIR/${artifact_name}.attempt-${attempt}.wrk"
    cpu_before_ms="$(process_tree_cpu_ms "$resource_pid")"
    if ! wrk -t"$THREADS" -c"$CONCURRENCY" -d"${DURATION_SECONDS}s" --timeout "$WRK_TIMEOUT" -s "$lua" "$url" >"$out" 2>&1; then
      echo "wrk failed for ${proxy} attempt ${attempt}/${SAMPLE_ATTEMPTS}" >&2
      cat "$out" >&2 || true
      failed_sample="$out"
      attempt=$((attempt + 1))
      continue
    fi
    cpu_after_ms="$(process_tree_cpu_ms "$resource_pid")"
    cpu_ms="$(awk -v before="$cpu_before_ms" -v after="$cpu_after_ms" 'BEGIN { delta = after - before; if (delta < 0) delta = 0; printf "%.0f", delta }')"
    rss_kb="$(process_tree_status_kb "$resource_pid" "VmRSS")"
    rss_peak_kb="$(process_tree_status_kb "$resource_pid" "VmHWM")"
    if [ "$mode" = "forward" ]; then
      status_after="$(safe_probe_forward_status "$port" "/bench-${body_bytes}")"
    else
      status_after="$(safe_probe_status "$port" "/bench-${body_bytes}")"
    fi
    complete="$(extract_metric_or_zero "$out" "qpx_complete_requests")"
    summary_requests="$(extract_metric_or_zero "$out" "qpx_summary_requests")"
    non_2xx="$(extract_metric_or_zero "$out" "qpx_non_2xx_responses")"
    bad_length="$(extract_metric_or_zero "$out" "qpx_bad_length_responses")"
    rps="$(extract_metric "$out" "qpx_requests_per_sec")"
    transfer_kbps="$(extract_metric "$out" "qpx_transfer_kbytes_per_sec")"
    latency_p50_ms="$(extract_metric "$out" "qpx_latency_p50_ms")"
    latency_p90_ms="$(extract_metric "$out" "qpx_latency_p90_ms")"
    latency_p95_ms="$(extract_metric "$out" "qpx_latency_p95_ms")"
    latency_p99_ms="$(extract_metric "$out" "qpx_latency_p99_ms")"
    latency_p999_ms="$(extract_metric "$out" "qpx_latency_p999_ms")"
    mean_ms="$(awk '
    /Latency/ {
      value = $2
      unit = substr(value, length(value) - 1)
      number = substr(value, 1, length(value) - 2)
      if (unit == "us") print number / 1000
      else if (unit == "ms") print number
      else if (unit == "s") print number * 1000
      exit
    }
  ' "$out")"
    connect_errors="$(awk '/Socket errors:/ { for (i = 1; i <= NF; i++) if ($i == "connect") { value = $(i + 1); gsub(/,/, "", value); print value; exit } }' "$out")"
    read_errors="$(awk '/Socket errors:/ { for (i = 1; i <= NF; i++) if ($i == "read") { value = $(i + 1); gsub(/,/, "", value); print value; exit } }' "$out")"
    write_errors="$(awk '/Socket errors:/ { for (i = 1; i <= NF; i++) if ($i == "write") { value = $(i + 1); gsub(/,/, "", value); print value; exit } }' "$out")"
    timeout_errors="$(awk '/Socket errors:/ { for (i = 1; i <= NF; i++) if ($i == "timeout") { value = $(i + 1); gsub(/,/, "", value); print value; exit } }' "$out")"
    connect_errors="${connect_errors:-0}"
    read_errors="${read_errors:-0}"
    write_errors="${write_errors:-0}"
    timeout_errors="${timeout_errors:-0}"
    fatal_errors=$((connect_errors + write_errors + timeout_errors))
    failed=$((connect_errors + read_errors + write_errors + timeout_errors))
    commit="${GITHUB_SHA:-unknown}"
    if [ -z "$rps" ] || [ -z "$mean_ms" ] || [ -z "$transfer_kbps" ] || [ -z "$latency_p99_ms" ]; then
      echo "${proxy} wrk output is missing required throughput fields" >&2
      cat "$out" >&2 || true
      failed_sample="$out"
      attempt=$((attempt + 1))
      continue
    fi
    requests_per_cpu_second="$(awk -v requests="$summary_requests" -v cpu_ms="$cpu_ms" 'BEGIN { if (cpu_ms > 0) printf "%.6f", requests / (cpu_ms / 1000); else printf "null" }')"
    valid="$([ "$complete" -gt 0 ] && [ "$summary_requests" = "$complete" ] && [ "$fatal_errors" = 0 ] && read_error_rate_allowed "$read_errors" "$complete" && [ "$non_2xx" = 0 ] && [ "$bad_length" = 0 ] && [ "$status_before" = 200 ] && [ "$status_after" = 200 ] && echo true || echo false)"
    if [ "$valid" = true ]; then
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$rps" "$complete" "$summary_requests" "$failed" "$connect_errors" "$read_errors" "$write_errors" "$timeout_errors" "$non_2xx" "$bad_length" "$mean_ms" "$transfer_kbps" "$latency_p50_ms" "$latency_p90_ms" "$latency_p95_ms" "$latency_p99_ms" "$latency_p999_ms" "$cpu_ms" "$rss_kb" "$rss_peak_kb" "$requests_per_cpu_second" "$status_before" "$status_after" >>"$samples_file"
      attempt=$((attempt + 1))
      continue
    fi
    failed_sample="$out"
    echo "${proxy} produced an invalid benchmark sample on attempt ${attempt}/${SAMPLE_ATTEMPTS}" >&2
    echo "complete=${complete} summary_requests=${summary_requests} failed=${failed} connect_errors=${connect_errors} read_errors=${read_errors} write_errors=${write_errors} timeout_errors=${timeout_errors} max_read_error_rate_ppm=${MAX_READ_ERROR_RATE_PPM} non_2xx=${non_2xx} bad_length=${bad_length} status_before=${status_before} status_after=${status_after}" >&2
    cat "$out" >&2 || true
    attempt=$((attempt + 1))
  done
  valid_sample_count="$(wc -l <"$samples_file" | tr -d '[:space:]')"
  if [ "$valid_sample_count" -lt "$MIN_VALID_SAMPLES" ]; then
    if [ "$mode" = "forward" ]; then
      status_after="$(safe_probe_forward_status "$port" "/bench-${body_bytes}")"
    else
      status_after="$(safe_probe_status "$port" "/bench-${body_bytes}")"
    fi
    echo "${proxy} produced ${valid_sample_count}/${SAMPLE_ATTEMPTS} valid benchmark samples; ${MIN_VALID_SAMPLES} required" >&2
    record_invalid_sample "$bench" "$proxy" "$body_kind" "$body_bytes" "${status_before:-200}" "$status_after" "insufficient_valid_samples"
    if [ -n "${failed_sample:-}" ]; then
      cat "$failed_sample" >&2 || true
    fi
    return 0
  fi
  median_index=$(((valid_sample_count + 1) / 2))
  selected_sample="$(LC_ALL=C sort -t $'\t' -k1,1n "$samples_file" | sed -n "${median_index}p")"
  if [ -z "$selected_sample" ]; then
    record_invalid_sample "$bench" "$proxy" "$body_kind" "$body_bytes" "${status_before:-200}" "${status_after:-200}" "sample_aggregation_failed"
    return 0
  fi
  IFS=$'\t' read -r rps complete summary_requests failed connect_errors read_errors write_errors timeout_errors non_2xx bad_length mean_ms transfer_kbps latency_p50_ms latency_p90_ms latency_p95_ms latency_p99_ms latency_p999_ms cpu_ms rss_kb rss_peak_kb requests_per_cpu_second status_before status_after <<<"$selected_sample"
  commit="${GITHUB_SHA:-unknown}"
  valid=true
  printf '{"bench":"%s","proxy":"%s","body_profile":"%s","duration_seconds":%s,"threads":%s,"concurrency":%s,"body_bytes":%s,"sample_attempts":%s,"valid_samples":%s,"aggregation":"single_sample","requests":%s,"complete_requests":%s,"failed_requests":%s,"connect_errors":%s,"read_errors":%s,"write_errors":%s,"timeout_errors":%s,"max_read_error_rate_ppm":%s,"non_2xx_responses":%s,"bad_length_responses":%s,"status_before":"%s","status_after":"%s","requests_per_sec":%s,"mean_time_per_request_ms":%s,"latency_p50_ms":%s,"latency_p90_ms":%s,"latency_p95_ms":%s,"latency_p99_ms":%s,"latency_p999_ms":%s,"transfer_kbytes_per_sec":%s,"cpu_ms":%s,"rss_kb":%s,"rss_peak_kb":%s,"requests_per_cpu_second":%s,"valid":%s,"commit":"%s"}\n' \
    "$bench" "$proxy" "$body_kind" "$DURATION_SECONDS" "$THREADS" "$CONCURRENCY" "$body_bytes" "$SAMPLE_ATTEMPTS" "$valid_sample_count" "$summary_requests" "$complete" "$failed" "$connect_errors" "$read_errors" "$write_errors" "$timeout_errors" "$MAX_READ_ERROR_RATE_PPM" "$non_2xx" "$bad_length" "$status_before" "$status_after" "$rps" "$mean_ms" "$latency_p50_ms" "$latency_p90_ms" "$latency_p95_ms" "$latency_p99_ms" "$latency_p999_ms" "$transfer_kbps" "$(json_number_or_null "$cpu_ms")" "$(json_number_or_null "$rss_kb")" "$(json_number_or_null "$rss_peak_kb")" "$requests_per_cpu_second" "$valid" "$commit" >>"$OUT_JSON"
}

require_cmd curl
require_cmd lighttpd
require_cmd nginx
require_cmd jq
require_cmd squid
require_cmd wrk

case "$BACKEND_WORKERS" in
  ''|*[!0-9]*)
    echo "QPX_PROXY_COMPARE_BACKEND_WORKERS must be a positive integer" >&2
    exit 1
    ;;
esac
if [ "$BACKEND_WORKERS" -eq 0 ]; then
  echo "QPX_PROXY_COMPARE_BACKEND_WORKERS must be a positive integer" >&2
  exit 1
fi

case "$HEALTH_CHECK_INTERVAL_MS" in
  ''|*[!0-9]*)
    echo "QPX_PROXY_COMPARE_HEALTH_CHECK_INTERVAL_MS must be a positive integer" >&2
    exit 1
    ;;
esac
if [ "$HEALTH_CHECK_INTERVAL_MS" -eq 0 ]; then
  echo "QPX_PROXY_COMPARE_HEALTH_CHECK_INTERVAL_MS must be a positive integer" >&2
  exit 1
fi

case "$SAMPLE_ATTEMPTS" in
  ''|*[!0-9]*)
    echo "QPX_PROXY_COMPARE_SAMPLE_ATTEMPTS must be a positive integer" >&2
    exit 1
    ;;
esac
if [ "$SAMPLE_ATTEMPTS" -eq 0 ]; then
  echo "QPX_PROXY_COMPARE_SAMPLE_ATTEMPTS must be a positive integer" >&2
  exit 1
fi
if [ -z "$MIN_VALID_SAMPLES" ]; then
  MIN_VALID_SAMPLES=$((SAMPLE_ATTEMPTS / 2 + 1))
fi
case "$MIN_VALID_SAMPLES" in
  ''|*[!0-9]*)
    echo "QPX_PROXY_COMPARE_MIN_VALID_SAMPLES must be a positive integer no greater than sample attempts" >&2
    exit 1
    ;;
esac
if [ "$MIN_VALID_SAMPLES" -eq 0 ] || [ "$MIN_VALID_SAMPLES" -gt "$SAMPLE_ATTEMPTS" ]; then
  echo "QPX_PROXY_COMPARE_MIN_VALID_SAMPLES must be a positive integer no greater than sample attempts" >&2
  exit 1
fi

case "$MAX_READ_ERROR_RATE_PPM" in
  ''|*[!0-9]*)
    echo "QPX_PROXY_COMPARE_MAX_READ_ERROR_RATE_PPM must be an integer from 0 to 1000000" >&2
    exit 1
    ;;
esac
if [ "$MAX_READ_ERROR_RATE_PPM" -gt 1000000 ]; then
  echo "QPX_PROXY_COMPARE_MAX_READ_ERROR_RATE_PPM must be an integer from 0 to 1000000" >&2
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
if [ -z "$SCALE_WORKERS" ]; then
  SCALE_WORKERS="$(default_scale_workers)"
fi
start_backend
start_qpxd
start_nginx
start_apache
start_lighttpd
start_qpxd_forward
start_squid

FINAL_OUT_JSON="$OUT_JSON"
RAW_OUT_JSON="$TMP_DIR/interleaved-raw.jsonl"
REQUESTED_SAMPLE_ATTEMPTS="$SAMPLE_ATTEMPTS"
REQUESTED_MIN_VALID_SAMPLES="$MIN_VALID_SAMPLES"
OUT_JSON="$RAW_OUT_JSON"
SAMPLE_ATTEMPTS=1
MIN_VALID_SAMPLES=1
: >"$OUT_JSON"

run_reverse_proxy_by_index() {
  local index="$1"
  local body_bytes="$2"
  case "$index" in
    0) run_one "proxy_compare_http1_reverse" "direct-backend" "$BACKEND_PORT" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$BACKEND_PID" ;;
    1) run_one "proxy_compare_http1_reverse" "qpxd" "$QPX_PORT" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$QPXD_PID" ;;
    2) run_one "proxy_compare_http1_reverse" "nginx" "$NGINX_PORT" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$NGINX_PID" ;;
    3) run_one "proxy_compare_http1_reverse" "apache" "$APACHE_PORT" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$APACHE_PID" ;;
    4) run_one "proxy_compare_http1_reverse" "lighttpd" "$LIGHTTPD_PORT" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$LIGHTTPD_PID" ;;
    *) echo "invalid reverse proxy benchmark index: ${index}" >&2; exit 1 ;;
  esac
}

for body_bytes in $BODY_SIZES; do
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
      run_reverse_proxy_by_index "$proxy_index" "$body_bytes"
      offset=$((offset + 1))
    done
    if [ $((round % 2)) -eq 1 ]; then
      run_one "proxy_compare_http1_forward" "qpxd-forward" "$QPX_FORWARD_PORT" "forward" "http://127.0.0.1:${BACKEND_PORT}/bench-${body_bytes}" "127.0.0.1:${BACKEND_PORT}" "$body_bytes" "$QPX_FORWARD_PID"
      run_one "proxy_compare_http1_forward" "squid" "$SQUID_PORT" "forward" "http://127.0.0.1:${BACKEND_PORT}/bench-${body_bytes}" "127.0.0.1:${BACKEND_PORT}" "$body_bytes" "$SQUID_PID"
    else
      run_one "proxy_compare_http1_forward" "squid" "$SQUID_PORT" "forward" "http://127.0.0.1:${BACKEND_PORT}/bench-${body_bytes}" "127.0.0.1:${BACKEND_PORT}" "$body_bytes" "$SQUID_PID"
      run_one "proxy_compare_http1_forward" "qpxd-forward" "$QPX_FORWARD_PORT" "forward" "http://127.0.0.1:${BACKEND_PORT}/bench-${body_bytes}" "127.0.0.1:${BACKEND_PORT}" "$body_bytes" "$QPX_FORWARD_PID"
    fi
    round=$((round + 1))
  done
done

for workers in $SCALE_WORKERS; do
  scale_pid=""
  scale_port=$((SCALE_BASE_PORT + workers))
  if [ "$workers" -eq 1 ]; then
    start_qpxd_reverse "qpxd-scale-${workers}" "$scale_port" "$workers" "$workers" false
  else
    start_qpxd_reverse "qpxd-scale-${workers}" "$scale_port" "$workers" "$workers" true
  fi
  scale_pid="$LAST_STARTED_PID"
  for body_bytes in $BODY_SIZES; do
    round=1
    while [ "$round" -le "$REQUESTED_SAMPLE_ATTEMPTS" ]; do
      CURRENT_SAMPLE_ROUND="$round"
      run_one "proxy_scale_http1_reverse" "qpxd-workers-${workers}" "$scale_port" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$scale_pid"
      round=$((round + 1))
    done
  done
done

jq -cs \
  --argjson attempts "$REQUESTED_SAMPLE_ATTEMPTS" \
  --argjson minimum "$REQUESTED_MIN_VALID_SAMPLES" \
  --argjson backend_workers "$BACKEND_WORKERS" \
  --argjson health_check_interval_ms "$HEALTH_CHECK_INTERVAL_MS" \
  --argjson logical_cpus "$(cpu_count)" '
    def lower_median:
      map(select(type == "number"))
      | sort
      | if length == 0 then null else .[((length - 1) / 2 | floor)] end;
    def upper_median:
      map(select(type == "number"))
      | sort
      | if length == 0 then null else .[(length / 2 | floor)] end;
    def maximum:
      map(select(type == "number"))
      | if length == 0 then null else max end;
    def spread_ratio:
      map(select(type == "number" and . > 0))
      | if length == 0 then null else max / min end;
    group_by([.bench, .proxy, .body_bytes])[]
    | . as $all
    | [$all[] | select(.valid == true)] as $valid
    | if ($valid | length) >= $minimum then
        ($valid | sort_by(.requests_per_sec)) as $ordered
        | $ordered[((($ordered | length) - 1) / 2 | floor)]
        | .aggregation = "conservative_median_per_metric"
        | .sample_attempts = $attempts
        | .valid_samples = ($valid | length)
        | .sampling_order = "round_robin_interleaved"
        | .benchmark_schema_version = 2
        | .backend_workers = $backend_workers
        | .health_check_interval_ms = $health_check_interval_ms
        | .logical_cpus = $logical_cpus
        | .requests = ([$valid[].requests] | lower_median)
        | .complete_requests = ([$valid[].complete_requests] | lower_median)
        | .connect_errors = ([$valid[].connect_errors] | maximum)
        | .read_errors = ([$valid[].read_errors] | maximum)
        | .write_errors = ([$valid[].write_errors] | maximum)
        | .timeout_errors = ([$valid[].timeout_errors] | maximum)
        | .failed_requests = (.connect_errors + .read_errors + .write_errors + .timeout_errors)
        | .non_2xx_responses = ([$valid[].non_2xx_responses] | maximum)
        | .bad_length_responses = ([$valid[].bad_length_responses] | maximum)
        | .requests_per_sec = ([$valid[].requests_per_sec] | lower_median)
        | .mean_time_per_request_ms = ([$valid[].mean_time_per_request_ms] | upper_median)
        | .latency_p50_ms = ([$valid[].latency_p50_ms] | upper_median)
        | .latency_p90_ms = ([$valid[].latency_p90_ms] | upper_median)
        | .latency_p95_ms = ([$valid[].latency_p95_ms] | upper_median)
        | .latency_p99_ms = ([$valid[].latency_p99_ms] | upper_median)
        | .latency_p999_ms = ([$valid[].latency_p999_ms] | upper_median)
        | .transfer_kbytes_per_sec = ([$valid[].transfer_kbytes_per_sec] | lower_median)
        | .cpu_ms = ([$valid[].cpu_ms] | upper_median)
        | .rss_kb = ([$valid[].rss_kb] | maximum)
        | .rss_peak_kb = ([$valid[].rss_peak_kb] | maximum)
        | .requests_per_cpu_second = ([$valid[].requests_per_cpu_second] | lower_median)
        | .sample_spread = {
            requests_per_sec_ratio: ([$valid[].requests_per_sec] | spread_ratio),
            latency_p99_ratio: ([$valid[].latency_p99_ms] | spread_ratio),
            requests_per_cpu_second_ratio: ([$valid[].requests_per_cpu_second] | spread_ratio)
          }
      else
        $all[0]
        | .aggregation = "conservative_median_per_metric"
        | .sample_attempts = $attempts
        | .valid_samples = ($valid | length)
        | .sampling_order = "round_robin_interleaved"
        | .benchmark_schema_version = 2
        | .backend_workers = $backend_workers
        | .health_check_interval_ms = $health_check_interval_ms
        | .logical_cpus = $logical_cpus
        | .valid = false
        | .error = "insufficient_valid_samples"
      end
  ' "$RAW_OUT_JSON" >"$FINAL_OUT_JSON"
OUT_JSON="$FINAL_OUT_JSON"
SAMPLE_ATTEMPTS="$REQUESTED_SAMPLE_ATTEMPTS"
MIN_VALID_SAMPLES="$REQUESTED_MIN_VALID_SAMPLES"
INVALID_SAMPLES="$(jq -s '[.[] | select(.valid != true)] | length' "$OUT_JSON")"

if [ "$INVALID_SAMPLES" -gt 0 ]; then
  echo "proxy comparison produced ${INVALID_SAMPLES} invalid sample(s)" >&2
  exit 1
fi
