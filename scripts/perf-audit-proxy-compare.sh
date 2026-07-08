#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_JSON="${1:-${QPX_PROXY_COMPARE_JSON:-$ROOT_DIR/target/perf/perf-audit-proxy-compare.jsonl}}"
LOG_ARTIFACT_DIR="${QPX_PROXY_COMPARE_LOG_DIR:-$ROOT_DIR/target/perf/proxy-compare-logs}"
QPXD_BIN="${QPXD_BIN:-$ROOT_DIR/target/release/qpxd}"
DURATION_SECONDS="${QPX_PROXY_COMPARE_DURATION_SECONDS:-10}"
CONCURRENCY="${QPX_PROXY_COMPARE_CONCURRENCY:-64}"
THREADS="${QPX_PROXY_COMPARE_THREADS:-2}"
BODY_SIZES="${QPX_PROXY_COMPARE_BODY_SIZES:-1024 1048576}"
HOST_HEADER="${QPX_PROXY_COMPARE_HOST:-bench.local}"
APACHE_BIN="${QPX_PROXY_COMPARE_APACHE_BIN:-}"
SCALE_WORKERS="${QPX_PROXY_COMPARE_SCALE_WORKERS:-}"
MAX_SCALE_WORKERS="${QPX_PROXY_COMPARE_MAX_SCALE_WORKERS:-4}"

BACKEND_PORT="${QPX_PROXY_COMPARE_BACKEND_PORT:-18080}"
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
    close = index($0, ") ")
    if (close == 0) {
      print 0
      exit
    }
    rest = substr($0, close + 2)
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

json_number_or_null() {
  local value="$1"
  if [ -z "$value" ]; then
    echo "null"
  else
    echo "$value"
  fi
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
runtime:
  worker_threads: ${worker_threads}
  acceptor_tasks_per_listener: ${acceptor_tasks}
  reuse_port: ${reuse_port}
edges:
  - kind: reverse
    name: ${name}
    listen: 127.0.0.1:${port}
    routes:
      - name: bench
        streaming_requirement: required
        match:
          host: [${HOST_HEADER}]
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
runtime:
  worker_threads: 1
  acceptor_tasks_per_listener: 1
  reuse_port: false
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
    apache_load_module "env"
    apache_load_module "proxy"
    apache_load_module "proxy_http"
    apache_load_module "unixd"
    echo "ProxyTimeout 30"
    echo "<VirtualHost 127.0.0.1:${APACHE_PORT}>"
    echo "  SetEnv proxy-initial-not-pooled 1"
    echo "  SetEnv proxy-nokeepalive 1"
    echo "  ProxyPass \"/\" \"http://127.0.0.1:${BACKEND_PORT}/\" retry=0 keepalive=Off max=128 smax=128 ttl=60 acquire=3000"
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
  service_name="qpx_proxy_compare_$$"
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

expect_status_ok() {
  local proxy="$1"
  local port="$2"
  local phase="$3"
  local path="$4"
  local status
  status="$(probe_status "$port" "$path")"
  if [ "$status" != "200" ]; then
    echo "${proxy} returned HTTP ${status} during ${phase}; refusing to record invalid benchmark" >&2
    return 1
  fi
}

expect_forward_status_ok() {
  local proxy="$1"
  local port="$2"
  local phase="$3"
  local path="$4"
  local status
  status="$(probe_forward_status "$port" "$path")"
  if [ "$status" != "200" ]; then
    echo "${proxy} returned HTTP ${status} during ${phase}; refusing to record invalid benchmark" >&2
    return 1
  fi
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
  local body_kind
  local url="http://127.0.0.1:${port}/"
  local artifact_name="${bench}.${proxy}.${body_bytes}"
  local out="$TMP_DIR/${artifact_name}.wrk"
  local lua="$TMP_DIR/${artifact_name}.lua"
  local status_before status_after
  local cpu_before_ms cpu_after_ms cpu_ms rss_kb rss_peak_kb
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
    expect_forward_status_ok "$proxy" "$port" "preflight" "/bench-${body_bytes}"
  else
    expect_status_ok "$proxy" "$port" "preflight" "/bench-${body_bytes}"
  fi
  wrk -t"$THREADS" -c16 -d2s -s "$lua" "$url" >"$TMP_DIR/${artifact_name}.warmup" 2>&1
  if [ "$mode" = "forward" ]; then
    status_before="$(probe_forward_status "$port" "/bench-${body_bytes}")"
  else
    status_before="$(probe_status "$port" "/bench-${body_bytes}")"
  fi
  cpu_before_ms="$(process_tree_cpu_ms "$resource_pid")"
  wrk -t"$THREADS" -c"$CONCURRENCY" -d"${DURATION_SECONDS}s" -s "$lua" "$url" >"$out" 2>&1 || {
    echo "wrk failed for ${proxy}" >&2
    cat "$out" >&2 || true
    exit 1
  }
  cpu_after_ms="$(process_tree_cpu_ms "$resource_pid")"
  cpu_ms="$(awk -v before="$cpu_before_ms" -v after="$cpu_after_ms" 'BEGIN { delta = after - before; if (delta < 0) delta = 0; printf "%.0f", delta }')"
  rss_kb="$(process_tree_status_kb "$resource_pid" "VmRSS")"
  rss_peak_kb="$(process_tree_status_kb "$resource_pid" "VmHWM")"
  if [ "$mode" = "forward" ]; then
    status_after="$(probe_forward_status "$port" "/bench-${body_bytes}")"
  else
    status_after="$(probe_status "$port" "/bench-${body_bytes}")"
  fi

  local complete summary_requests failed non_2xx bad_length write_errors read_errors connect_errors timeout_errors rps mean_ms transfer_kbps commit valid
  local latency_p50_ms latency_p90_ms latency_p95_ms latency_p99_ms latency_p999_ms requests_per_cpu_second
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
  failed=$((connect_errors + read_errors + write_errors + timeout_errors))
  commit="${GITHUB_SHA:-unknown}"
  if [ -z "$rps" ] || [ -z "$mean_ms" ] || [ -z "$transfer_kbps" ] || [ -z "$latency_p99_ms" ]; then
    echo "${proxy} wrk output is missing required throughput fields" >&2
    cat "$out" >&2 || true
    exit 1
  fi
  requests_per_cpu_second="$(awk -v requests="$summary_requests" -v cpu_ms="$cpu_ms" 'BEGIN { if (cpu_ms > 0) printf "%.6f", requests / (cpu_ms / 1000); else printf "null" }')"
  valid="$([ "$complete" -gt 0 ] && [ "$summary_requests" = "$complete" ] && [ "$failed" = 0 ] && [ "$non_2xx" = 0 ] && [ "$bad_length" = 0 ] && [ "$status_before" = 200 ] && [ "$status_after" = 200 ] && echo true || echo false)"
  printf '{"bench":"%s","proxy":"%s","body_profile":"%s","duration_seconds":%s,"threads":%s,"concurrency":%s,"body_bytes":%s,"requests":%s,"complete_requests":%s,"failed_requests":%s,"non_2xx_responses":%s,"bad_length_responses":%s,"write_errors":%s,"status_before":"%s","status_after":"%s","requests_per_sec":%s,"mean_time_per_request_ms":%s,"latency_p50_ms":%s,"latency_p90_ms":%s,"latency_p95_ms":%s,"latency_p99_ms":%s,"latency_p999_ms":%s,"transfer_kbytes_per_sec":%s,"cpu_ms":%s,"rss_kb":%s,"rss_peak_kb":%s,"requests_per_cpu_second":%s,"valid":%s,"commit":"%s"}\n' \
    "$bench" "$proxy" "$body_kind" "$DURATION_SECONDS" "$THREADS" "$CONCURRENCY" "$body_bytes" "$summary_requests" "$complete" "$failed" "$non_2xx" "$bad_length" "$write_errors" "$status_before" "$status_after" "$rps" "$mean_ms" "$latency_p50_ms" "$latency_p90_ms" "$latency_p95_ms" "$latency_p99_ms" "$latency_p999_ms" "$transfer_kbps" "$(json_number_or_null "$cpu_ms")" "$(json_number_or_null "$rss_kb")" "$(json_number_or_null "$rss_peak_kb")" "$requests_per_cpu_second" "$valid" "$commit" >>"$OUT_JSON"

  if [ "$valid" != true ]; then
    echo "${proxy} produced an invalid benchmark sample" >&2
    echo "complete=${complete} summary_requests=${summary_requests} failed=${failed} non_2xx=${non_2xx} bad_length=${bad_length} write_errors=${write_errors} status_before=${status_before} status_after=${status_after}" >&2
    cat "$out" >&2 || true
    exit 1
  fi
}

require_cmd curl
require_cmd lighttpd
require_cmd nginx
require_cmd squid
require_cmd wrk

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

for body_bytes in $BODY_SIZES; do
  run_one "proxy_compare_http1_reverse" "direct-backend" "$BACKEND_PORT" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$BACKEND_PID"
  run_one "proxy_compare_http1_reverse" "qpxd" "$QPX_PORT" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$QPXD_PID"
  run_one "proxy_compare_http1_reverse" "nginx" "$NGINX_PORT" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$NGINX_PID"
  run_one "proxy_compare_http1_reverse" "apache" "$APACHE_PORT" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$APACHE_PID"
  run_one "proxy_compare_http1_reverse" "lighttpd" "$LIGHTTPD_PORT" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$LIGHTTPD_PID"

  run_one "proxy_compare_http1_forward" "qpxd-forward" "$QPX_FORWARD_PORT" "forward" "http://127.0.0.1:${BACKEND_PORT}/bench-${body_bytes}" "127.0.0.1:${BACKEND_PORT}" "$body_bytes" "$QPX_FORWARD_PID"
  run_one "proxy_compare_http1_forward" "squid" "$SQUID_PORT" "forward" "http://127.0.0.1:${BACKEND_PORT}/bench-${body_bytes}" "127.0.0.1:${BACKEND_PORT}" "$body_bytes" "$SQUID_PID"
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
    run_one "proxy_scale_http1_reverse" "qpxd-workers-${workers}" "$scale_port" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$scale_pid"
  done
done
