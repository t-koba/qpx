#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_JSON="${1:-${QPX_PROXY_COMPARE_JSON:-$ROOT_DIR/target/perf/nightly-proxy-compare.jsonl}}"
LOG_ARTIFACT_DIR="${QPX_PROXY_COMPARE_LOG_DIR:-$ROOT_DIR/target/perf/proxy-compare-logs}"
QPXD_BIN="${QPXD_BIN:-$ROOT_DIR/target/release/qpxd}"
REQUESTS="${QPX_PROXY_COMPARE_REQUESTS:-5000}"
CONCURRENCY="${QPX_PROXY_COMPARE_CONCURRENCY:-64}"
BODY_BYTES="${QPX_PROXY_COMPARE_BODY_BYTES:-1024}"
HOST_HEADER="${QPX_PROXY_COMPARE_HOST:-bench.local}"
APACHE_BIN="${QPX_PROXY_COMPARE_APACHE_BIN:-}"

BACKEND_PORT="${QPX_PROXY_COMPARE_BACKEND_PORT:-18080}"
QPX_PORT="${QPX_PROXY_COMPARE_QPX_PORT:-18081}"
NGINX_PORT="${QPX_PROXY_COMPARE_NGINX_PORT:-18082}"
APACHE_PORT="${QPX_PROXY_COMPARE_APACHE_PORT:-18083}"
LIGHTTPD_PORT="${QPX_PROXY_COMPARE_LIGHTTPD_PORT:-18084}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/qpx-proxy-compare.XXXXXX")"
LOG_DIR="$TMP_DIR/logs"
STATE_DIR="$TMP_DIR/state"
mkdir -p "$LOG_DIR" "$STATE_DIR" "$(dirname "$OUT_JSON")"

PIDS=()
ARTIFACTS_COLLECTED=0

collect_artifacts() {
  if [ "$ARTIFACTS_COLLECTED" -eq 1 ]; then
    return
  fi
  ARTIFACTS_COLLECTED=1
  rm -rf "$LOG_ARTIFACT_DIR"
  mkdir -p "$LOG_ARTIFACT_DIR"
  cp -R "$LOG_DIR"/. "$LOG_ARTIFACT_DIR"/ 2>/dev/null || true
  cp "$TMP_DIR"/*.ab "$LOG_ARTIFACT_DIR"/ 2>/dev/null || true
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

wait_http() {
  local name="$1"
  local port="$2"
  local pid="$3"
  local log_file="$4"
  local tries=0
  while [ "$tries" -lt 100 ]; do
    if curl -fsS --max-time 2 -H "Host: ${HOST_HEADER}" "http://127.0.0.1:${port}/bench" >/dev/null 2>&1; then
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
  local prefix="$TMP_DIR/backend-nginx"
  local config="$prefix/backend-nginx.conf"
  mkdir -p "$prefix/logs" "$prefix/www"
  dd if=/dev/zero of="$prefix/www/bench" bs="$BODY_BYTES" count=1 status=none
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
    location = /bench {
      default_type application/octet-stream;
      alias $prefix/www/bench;
    }
  }
}
NGINX
  nginx -p "$prefix" -c "$config" -g 'daemon off;' >"$LOG_DIR/backend.log" 2>&1 &
  local pid=$!
  register_pid "$pid"
  wait_http "backend" "$BACKEND_PORT" "$pid" "$LOG_DIR/backend.log"
}

start_qpxd() {
  local config="$TMP_DIR/qpxd.yaml"
  cat >"$config" <<YAML
state_dir: "$STATE_DIR"
edges:
  - kind: reverse
    name: benchmark
    listen: 127.0.0.1:${QPX_PORT}
    routes:
      - name: bench
        streaming_requirement: required
        match:
          host: [${HOST_HEADER}]
        target:
          type: upstream
          upstreams: [http://127.0.0.1:${BACKEND_PORT}]
YAML
  QPX_STATE_DIR="$STATE_DIR" "$QPXD_BIN" run --config "$config" >"$LOG_DIR/qpxd.log" 2>&1 &
  local pid=$!
  register_pid "$pid"
  wait_http "qpxd" "$QPX_PORT" "$pid" "$LOG_DIR/qpxd.log"
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
  register_pid "$pid"
  wait_http "lighttpd" "$LIGHTTPD_PORT" "$pid" "$LOG_DIR/lighttpd.log"
}

extract_ab_value() {
  local file="$1"
  local pattern="$2"
  awk -F: -v pattern="$pattern" '
    $1 ~ pattern {
      gsub(/^[ \t]+/, "", $2)
      split($2, parts, " ")
      print parts[1]
      exit
    }
  ' "$file"
}

extract_ab_int_or_zero() {
  local file="$1"
  local pattern="$2"
  local value
  value="$(extract_ab_value "$file" "$pattern")"
  if [ -z "$value" ]; then
    echo 0
  else
    echo "$value"
  fi
}

probe_status() {
  local port="$1"
  curl -sS --max-time 5 -o /dev/null -w '%{http_code}' \
    -H "Host: ${HOST_HEADER}" \
    "http://127.0.0.1:${port}/bench"
}

expect_status_ok() {
  local proxy="$1"
  local port="$2"
  local phase="$3"
  local status
  status="$(probe_status "$port")"
  if [ "$status" != "200" ]; then
    echo "${proxy} returned HTTP ${status} during ${phase}; refusing to record invalid benchmark" >&2
    return 1
  fi
}

run_one() {
  local proxy="$1"
  local port="$2"
  local out="$TMP_DIR/${proxy}.ab"
  local url="http://127.0.0.1:${port}/bench"
  local status_before status_after

  expect_status_ok "$proxy" "$port" "preflight"
  ab -k -n 200 -c 16 -H "Host: ${HOST_HEADER}" "$url" >"$TMP_DIR/${proxy}.warmup" 2>&1
  status_before="$(probe_status "$port")"
  ab -k -n "$REQUESTS" -c "$CONCURRENCY" -H "Host: ${HOST_HEADER}" "$url" >"$out" 2>&1 || {
    echo "ab failed for ${proxy}" >&2
    cat "$out" >&2 || true
    exit 1
  }
  status_after="$(probe_status "$port")"

  local complete failed non_2xx write_errors rps mean_ms transfer_kbps commit valid
  complete="$(extract_ab_int_or_zero "$out" "Complete requests")"
  failed="$(extract_ab_int_or_zero "$out" "Failed requests")"
  non_2xx="$(extract_ab_int_or_zero "$out" "Non-2xx responses")"
  write_errors="$(extract_ab_int_or_zero "$out" "Write errors")"
  rps="$(extract_ab_value "$out" "Requests per second")"
  mean_ms="$(awk -F: '/Time per request/ && $0 !~ /across all concurrent requests/ {gsub(/^[ \t]+/, "", $2); split($2, parts, " "); print parts[1]; exit}' "$out")"
  transfer_kbps="$(extract_ab_value "$out" "Transfer rate")"
  commit="${GITHUB_SHA:-unknown}"
  if [ -z "$rps" ] || [ -z "$mean_ms" ] || [ -z "$transfer_kbps" ]; then
    echo "${proxy} ab output is missing required throughput fields" >&2
    cat "$out" >&2 || true
    exit 1
  fi
  valid="$([ "$complete" = "$REQUESTS" ] && [ "$failed" = 0 ] && [ "$non_2xx" = 0 ] && [ "$write_errors" = 0 ] && [ "$status_before" = 200 ] && [ "$status_after" = 200 ] && echo true || echo false)"
  printf '{"bench":"proxy_compare_http1_reverse","proxy":"%s","requests":%s,"concurrency":%s,"body_bytes":%s,"complete_requests":%s,"failed_requests":%s,"non_2xx_responses":%s,"write_errors":%s,"status_before":"%s","status_after":"%s","requests_per_sec":%s,"mean_time_per_request_ms":%s,"transfer_kbytes_per_sec":%s,"valid":%s,"commit":"%s"}\n' \
    "$proxy" "$REQUESTS" "$CONCURRENCY" "$BODY_BYTES" "$complete" "$failed" "$non_2xx" "$write_errors" "$status_before" "$status_after" "$rps" "$mean_ms" "$transfer_kbps" "$valid" "$commit" >>"$OUT_JSON"

  if [ "$valid" != true ]; then
    echo "${proxy} produced an invalid benchmark sample" >&2
    echo "complete=${complete} failed=${failed} non_2xx=${non_2xx} write_errors=${write_errors} status_before=${status_before} status_after=${status_after}" >&2
    cat "$out" >&2 || true
    exit 1
  fi
}

require_cmd ab
require_cmd curl
require_cmd lighttpd
require_cmd nginx

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
start_backend
start_qpxd
start_nginx
start_apache
start_lighttpd

run_one "direct-backend" "$BACKEND_PORT"
run_one "qpxd" "$QPX_PORT"
run_one "nginx" "$NGINX_PORT"
run_one "apache" "$APACHE_PORT"
run_one "lighttpd" "$LIGHTTPD_PORT"
