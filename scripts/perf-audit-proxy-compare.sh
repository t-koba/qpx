#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/lib/temp-dir.sh"
OUT_JSON="${1:-${QPX_PROXY_COMPARE_JSON:-$ROOT_DIR/target/perf/perf-audit-proxy-compare.jsonl}}"
LOG_ARTIFACT_DIR="${QPX_PROXY_COMPARE_LOG_DIR:-$ROOT_DIR/target/perf/proxy-compare-logs}"
QPXD_BIN="${QPXD_BIN:-$ROOT_DIR/target/release/qpxd}"
DURATION_SECONDS="${QPX_PROXY_COMPARE_DURATION_SECONDS:-10}"
CONCURRENCY="${QPX_PROXY_COMPARE_CONCURRENCY:-64}"
THREADS="${QPX_PROXY_COMPARE_THREADS:-2}"
WRK_TIMEOUT="${QPX_PROXY_COMPARE_WRK_TIMEOUT:-30s}"
BODY_SIZES="${QPX_PROXY_COMPARE_BODY_SIZES:-1024 1048576}"
LOCAL_ORIGIN_BODY_BYTES=1024
SAMPLE_ATTEMPTS="${QPX_PROXY_COMPARE_SAMPLE_ATTEMPTS:-3}"
MIN_VALID_SAMPLES="${QPX_PROXY_COMPARE_MIN_VALID_SAMPLES:-}"
WARMUP_COOLDOWN_SECONDS="${QPX_PROXY_COMPARE_WARMUP_COOLDOWN_SECONDS:-0.25}"
ACCESS_LOG_DRAIN_SECONDS="${QPX_PROXY_COMPARE_ACCESS_LOG_DRAIN_SECONDS:-1.25}"
LOG_COMPACTION_SETTLE_SECONDS="${QPX_PROXY_COMPARE_LOG_COMPACTION_SETTLE_SECONDS:-0.75}"
REPEATED_PROXY_SETTLE_SECONDS="${QPX_PROXY_COMPARE_REPEATED_PROXY_SETTLE_SECONDS:-2}"
MAX_READ_ERROR_RATE_PPM="${QPX_PROXY_COMPARE_MAX_READ_ERROR_RATE_PPM:-1000}"
HOST_HEADER="${QPX_PROXY_COMPARE_HOST:-bench.local}"
APACHE_BIN="${QPX_PROXY_COMPARE_APACHE_BIN:-}"
SCALE_WORKERS="${QPX_PROXY_COMPARE_SCALE_WORKERS:-}"
MAX_SCALE_WORKERS="${QPX_PROXY_COMPARE_MAX_SCALE_WORKERS:-4}"
PROXY_FILTER="${QPX_PROXY_COMPARE_PROXY_FILTER:-}"
PROFILE_PROXY="${QPX_PROXY_COMPARE_PROFILE_PROXY:-}"
PROFILE_SECONDS="${QPX_PROXY_COMPARE_PROFILE_SECONDS:-0}"
ARTIFACT_LOG_HEAD_LINES="${QPX_PROXY_COMPARE_ARTIFACT_LOG_HEAD_LINES:-3}"
ARTIFACT_LOG_TAIL_LINES="${QPX_PROXY_COMPARE_ARTIFACT_LOG_TAIL_LINES:-100}"

BACKEND_PORT="${QPX_PROXY_COMPARE_BACKEND_PORT:-18080}"
BACKEND_WORKERS="${QPX_PROXY_COMPARE_BACKEND_WORKERS:-3}"
LOCAL_ORIGIN_WORKERS="${QPX_PROXY_COMPARE_LOCAL_ORIGIN_WORKERS:-3}"
CACHE_WORKERS="${QPX_PROXY_COMPARE_CACHE_WORKERS:-4}"
FEATURE_RICH_WORKERS="${QPX_PROXY_COMPARE_FEATURE_RICH_WORKERS:-4}"
WEBDAV_WORKERS="${QPX_PROXY_COMPARE_WEBDAV_WORKERS:-2}"
WEBDAV_BLOCKING_THREADS="${QPX_PROXY_COMPARE_WEBDAV_BLOCKING_THREADS:-16}"
APACHE_START_SERVERS="${QPX_PROXY_COMPARE_APACHE_START_SERVERS:-3}"
APACHE_THREADS_PER_CHILD="${QPX_PROXY_COMPARE_APACHE_THREADS_PER_CHILD:-25}"
APACHE_REQUEST_WORKERS="${QPX_PROXY_COMPARE_APACHE_REQUEST_WORKERS:-400}"
HEALTH_CHECK_INTERVAL_MS="${QPX_PROXY_COMPARE_HEALTH_CHECK_INTERVAL_MS:-5000}"
QPX_PORT="${QPX_PROXY_COMPARE_QPX_PORT:-18081}"
NGINX_PORT="${QPX_PROXY_COMPARE_NGINX_PORT:-18082}"
APACHE_PORT="${QPX_PROXY_COMPARE_APACHE_PORT:-18083}"
LIGHTTPD_PORT="${QPX_PROXY_COMPARE_LIGHTTPD_PORT:-18084}"
QPX_FORWARD_PORT="${QPX_PROXY_COMPARE_QPX_FORWARD_PORT:-18085}"
SQUID_PORT="${QPX_PROXY_COMPARE_SQUID_PORT:-18086}"
QPX_ORIGIN_PORT="${QPX_PROXY_COMPARE_QPX_ORIGIN_PORT:-18087}"
QPX_CACHE_PORT="${QPX_PROXY_COMPARE_QPX_CACHE_PORT:-18088}"
NGINX_CACHE_PORT="${QPX_PROXY_COMPARE_NGINX_CACHE_PORT:-18089}"
QPX_FEATURE_RICH_PORT="${QPX_PROXY_COMPARE_QPX_FEATURE_RICH_PORT:-18090}"
NGINX_FEATURE_RICH_PORT="${QPX_PROXY_COMPARE_NGINX_FEATURE_RICH_PORT:-18091}"
QPX_WEBDAV_PORT="${QPX_PROXY_COMPARE_QPX_WEBDAV_PORT:-18092}"
SCALE_BASE_PORT="${QPX_PROXY_COMPARE_SCALE_BASE_PORT:-18100}"

validate_prefixed_environment() {
  local name supported
  supported="$(sed -nE 's/.*\$\{(QPX_PROXY_COMPARE_[A-Z0-9_]+).*/\1/p' "${BASH_SOURCE[0]}" | sort -u)"
  while IFS='=' read -r name _; do
    case "$name" in
      QPX_PROXY_COMPARE_*)
        if ! grep -Fxq "$name" <<<"$supported"; then
          echo "unsupported proxy comparison environment variable: $name" >&2
          exit 1
        fi
        ;;
    esac
  done < <(env)
}

validate_prefixed_environment

TMP_DIR="$(make_temp_dir qpx-proxy-compare)"
LOG_DIR="$TMP_DIR/logs"
STATE_DIR="$TMP_DIR/state"
ORIGIN_ROOT="$TMP_DIR/origin-www"
mkdir -p "$LOG_DIR" "$STATE_DIR" "$ORIGIN_ROOT/dav" "$(dirname "$OUT_JSON")"

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
QPX_ORIGIN_PID=""
QPX_WEBDAV_PID=""
QPX_CACHE_PID=""
NGINX_CACHE_PID=""
QPX_FEATURE_RICH_PID=""
NGINX_FEATURE_RICH_PID=""
LAST_TIMED_PROXY=""

proxy_selected() {
  local proxy="$1"
  if [ -z "$PROXY_FILTER" ]; then
    return 0
  fi
  case ",${PROXY_FILTER}," in
    *",${proxy},"*) return 0 ;;
    *) return 1 ;;
  esac
}

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

copy_bounded_log_artifact() {
  local source="$1"
  local destination="$2"
  if [ ! -f "$source" ]; then
    return
  fi
  {
    head -n "$ARTIFACT_LOG_HEAD_LINES" "$source"
    tail -n "$ARTIFACT_LOG_TAIL_LINES" "$source"
  } >"$destination"
}

collect_artifacts() {
  local source name
  if [ "$ARTIFACTS_COLLECTED" -eq 1 ]; then
    return
  fi
  ARTIFACTS_COLLECTED=1
  rm -rf "$LOG_ARTIFACT_DIR"
  mkdir -p "$LOG_ARTIFACT_DIR"
  for source in "$LOG_DIR"/*; do
    if [ ! -f "$source" ]; then
      continue
    fi
    name="$(basename "$source")"
    if [[ "$name" == *-access.log ]]; then
      copy_bounded_log_artifact "$source" "$LOG_ARTIFACT_DIR/${name%.log}.sample.log"
    else
      cp "$source" "$LOG_ARTIFACT_DIR/"
    fi
  done
  cp "$TMP_DIR"/*.wrk "$LOG_ARTIFACT_DIR"/ 2>/dev/null || true
  cp "$TMP_DIR"/*.lua "$LOG_ARTIFACT_DIR"/ 2>/dev/null || true
  cp "$TMP_DIR"/*.warmup "$LOG_ARTIFACT_DIR"/ 2>/dev/null || true
  cp "$TMP_DIR"/*.valid-samples.tsv "$LOG_ARTIFACT_DIR"/ 2>/dev/null || true
  cp "$TMP_DIR"/*.sample.txt "$LOG_ARTIFACT_DIR"/ 2>/dev/null || true
  cp "$LOG_DIR"/*.sample.log "$LOG_ARTIFACT_DIR"/ 2>/dev/null || true
  cp "$TMP_DIR"/*.jsonl "$LOG_ARTIFACT_DIR"/ 2>/dev/null || true
  cp "$TMP_DIR"/*.yaml "$LOG_ARTIFACT_DIR"/ 2>/dev/null || true
  find "$TMP_DIR" -name '*.conf' -type f -exec cp {} "$LOG_ARTIFACT_DIR"/ \; 2>/dev/null || true
}

cleanup() {
  local exit_status=$?
  local pid
  set +e
  for pid in "${PIDS[@]:-}"; do
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
  done
  collect_artifacts || true
  rm -rf "$TMP_DIR"
  return "$exit_status"
}
trap cleanup EXIT

compact_feature_rich_access_log() {
  local proxy="$1"
  local source=""
  local sample=""
  local temporary=""
  case "$proxy" in
    qpxd-feature-rich)
      source="$LOG_DIR/qpxd-feature-rich-access.log"
      sample="$LOG_DIR/qpxd-feature-rich-access.sample.log"
      ;;
    nginx-feature-rich)
      source="$TMP_DIR/nginx-feature-rich/logs/access.log"
      sample="$LOG_DIR/nginx-feature-rich-access.sample.log"
      ;;
    *) return 0 ;;
  esac
  if [ ! -f "$source" ]; then
    return 0
  fi
  temporary="${sample}.tmp"
  {
    if [ -f "$sample" ]; then
      head -n "$ARTIFACT_LOG_HEAD_LINES" "$sample"
    else
      head -n "$ARTIFACT_LOG_HEAD_LINES" "$source"
    fi
    tail -n "$ARTIFACT_LOG_TAIL_LINES" "$source"
  } >"$temporary"
  mv "$temporary" "$sample"
  : >"$source"
}

is_feature_rich_proxy() {
  case "$1" in
    qpxd-feature-rich|nginx-feature-rich) return 0 ;;
    *) return 1 ;;
  esac
}

drain_feature_rich_access_log() {
  if is_feature_rich_proxy "$1"; then
    sleep "$ACCESS_LOG_DRAIN_SECONDS"
  fi
}

settle_feature_rich_log_compaction() {
  if is_feature_rich_proxy "$1"; then
    sleep "$LOG_COMPACTION_SETTLE_SECONDS"
  fi
}

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
      tail -c 65536 "$log" >&2 || true
    fi
  done
}

expect_rich_access_log_output() {
  local name="$1"
  local path="$2"
  local attempt=0
  while [ "$attempt" -lt 20 ]; do
    if [ -s "$path" ] && tail -n 100 "$path" | grep -Eq 'HTTP/1\.[01]" 200'; then
      return
    fi
    attempt=$((attempt + 1))
    sleep 0.1
  done
  echo "${name} did not emit verifiable access log output" >&2
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
  mkdir -p "$prefix/logs"
  for size in $BODY_SIZES; do
    dd if=/dev/zero of="$ORIGIN_ROOT/bench-${size}" bs="$size" count=1 status=none
    cp "$ORIGIN_ROOT/bench-${size}" "$ORIGIN_ROOT/dav/bench-${size}"
  done
  if [ ! -f "$ORIGIN_ROOT/bench-${LOCAL_ORIGIN_BODY_BYTES}" ]; then
    dd if=/dev/zero of="$ORIGIN_ROOT/bench-${LOCAL_ORIGIN_BODY_BYTES}" bs="$LOCAL_ORIGIN_BODY_BYTES" count=1 status=none
    cp "$ORIGIN_ROOT/bench-${LOCAL_ORIGIN_BODY_BYTES}" "$ORIGIN_ROOT/dav/bench-${LOCAL_ORIGIN_BODY_BYTES}"
  fi
  cp "$ORIGIN_ROOT/bench-$(first_body_size)" "$ORIGIN_ROOT/bench"
  ln -s "../bench-$(first_body_size)" "$ORIGIN_ROOT/dav/forbidden-symlink"
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
    location = /__qpx_perf_route_evidence {
      default_type text/plain;
      add_header X-Qpx-Perf-Upstream-Via "\$http_via" always;
      return 200 "qpx backend route evidence\n";
    }
    location / {
      default_type application/octet-stream;
      root $ORIGIN_ROOT;
      add_header Cache-Control "public, max-age=600" always;
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

start_qpxd_origin() {
  local config="$TMP_DIR/qpxd-origin.yaml"
  local local_body
  printf -v local_body '%*s' 1024 ''
  local_body="${local_body// /x}"
  cat >"$config" <<YAML
state_dir: "$STATE_DIR"
telemetry:
  system_log:
    level: warn
    format: json
runtime:
  worker_threads: ${LOCAL_ORIGIN_WORKERS}
  acceptor_tasks_per_listener: ${LOCAL_ORIGIN_WORKERS}
  reuse_port: true
edges:
  - kind: reverse
    name: qpxd-origin
    listen: 127.0.0.1:${QPX_ORIGIN_PORT}
    routes:
      - name: local-response
        match:
          host: [${HOST_HEADER}]
          path: ["/local-1024"]
          method: [GET, HEAD]
        target:
          type: local_response
          response:
            status: 200
            content_type: application/octet-stream
            body: "${local_body}"
YAML
  if ! QPX_STATE_DIR="$STATE_DIR" "$QPXD_BIN" check --config "$config" >"$LOG_DIR/qpxd-origin-check.log" 2>&1; then
    echo "qpxd-origin benchmark config validation failed" >&2
    dump_service_log "$LOG_DIR/qpxd-origin-check.log"
    exit 1
  fi
  QPX_STATE_DIR="$STATE_DIR" "$QPXD_BIN" run --config "$config" >"$LOG_DIR/qpxd-origin.log" 2>&1 &
  local pid=$!
  QPX_ORIGIN_PID="$pid"
  register_pid "$pid"
  wait_http "qpxd-origin" "$QPX_ORIGIN_PORT" "$pid" "$LOG_DIR/qpxd-origin.log" "/local-1024"
}

start_qpxd_webdav() {
  local config="$TMP_DIR/qpxd-webdav.yaml"
  cat >"$config" <<YAML
state_dir: "$STATE_DIR"
telemetry:
  system_log:
    level: warn
    format: json
origins:
  webdav:
    - name: benchmark
      root: "$ORIGIN_ROOT/dav"
      metadata: "$TMP_DIR/qpxd-webdav.redb"
      max_depth: 32
      max_multistatus_entries: 10000
      max_lock_timeout_seconds: 86400
runtime:
  worker_threads: ${WEBDAV_WORKERS}
  max_blocking_threads: ${WEBDAV_BLOCKING_THREADS}
  acceptor_tasks_per_listener: ${WEBDAV_WORKERS}
  reuse_port: true
edges:
  - kind: reverse
    name: qpxd-webdav
    listen: 127.0.0.1:${QPX_WEBDAV_PORT}
    routes:
      - name: webdav
        match:
          host: [${HOST_HEADER}]
          path: ["/dav/**"]
        path_rewrite:
          strip_prefix: /dav
        target:
          type: webdav
          origin: benchmark
YAML
  if ! QPX_STATE_DIR="$STATE_DIR" "$QPXD_BIN" check --config "$config" >"$LOG_DIR/qpxd-webdav-check.log" 2>&1; then
    echo "qpxd-webdav benchmark config validation failed" >&2
    dump_service_log "$LOG_DIR/qpxd-webdav-check.log"
    exit 1
  fi
  QPX_STATE_DIR="$STATE_DIR" "$QPXD_BIN" run --config "$config" >"$LOG_DIR/qpxd-webdav.log" 2>&1 &
  local pid=$!
  QPX_WEBDAV_PID="$pid"
  register_pid "$pid"
  wait_http "qpxd-webdav" "$QPX_WEBDAV_PORT" "$pid" "$LOG_DIR/qpxd-webdav.log" "/dav/bench-$(first_body_size)"
}

start_qpxd_cache() {
  local name="$1"
  local port="$2"
  local rich="$3"
  local config="$TMP_DIR/${name}.yaml"
  local access_log=""
  local guard=""
  local route_features=""
  local rate_limit=""
  local guard_route=""
  local headers=""
  local http_policy=""
  local http_modules=""
  local workers="$CACHE_WORKERS"
  if [ "$rich" = true ]; then
    workers="$FEATURE_RICH_WORKERS"
    access_log="
  access_log:
    enabled: true
    path: \"$LOG_DIR/${name}-access.log\"
    format: combined
    rotation: never"
    guard="
http:
  guard_profiles:
    - name: production-rich
      normalize:
        path: true
        query: true
        headers: true
      protocol_safety:
        smuggling: true
        invalid_framing: true
      limits:
        header_count: 128
        header_bytes: 32768
        path_bytes: 4096
        query_pairs: 64"
    guard_route="
        http_guard_profile: production-rich"
    rate_limit="
        rate_limit:
          enabled: true
          requests:
            rps: 1000000000
            burst: 1000000000"
    headers="
        headers:
          request_set:
            X-Qpx-Benchmark: feature-rich
          request_add:
            X-Forwarded-By: qpx
          request_remove: [X-Internal-Only]
          response_set:
            X-Content-Type-Options: nosniff
          response_add:
            X-Qpx-Feature-Set: rich"
    http_policy="
        http:
          forwarded:
            trusted_peers: [127.0.0.1/32]
            by: qpx-rich
            untrusted_chain: discard
          api_metadata:
            deprecation_unix_seconds: 2000000000
            sunset_unix_seconds: 2000003600
            links:
              - target: https://bench.local/migration
                relation: successor-version
                media_type: text/html"
    http_modules="
        http_modules:
          - type: cache_purge
            id: benchmark-purge
            order: -100
            settings:
              methods: [PURGE]
              require_identity: false
              allowed_peers: [127.0.0.1/32]
          - type: response_compression
            id: benchmark-compression
            order: 50
            settings:
              min_body_bytes: 1
              max_body_bytes: 2097152
              content_types: [application/octet-stream]
              gzip: true
              brotli: true
              zstd: true"
    route_features="${headers}${rate_limit}${guard_route}${http_policy}${http_modules}"
  fi
  cat >"$config" <<YAML
state_dir: "$STATE_DIR"
telemetry:
  system_log:
    level: warn
    format: json${access_log}${guard}
caches:
  - name: ${name}-disk
    kind: disk
    path: "$TMP_DIR/${name}-cache"
    max_bytes: 1073741824
    sweep_interval_secs: 60
    timeout_ms: 1500
    max_object_bytes: 2097152
runtime:
  worker_threads: ${workers}
  acceptor_tasks_per_listener: ${workers}
  reuse_port: true
  upstream_proxy_max_concurrent_per_endpoint: 512
edges:
  - kind: reverse
    name: ${name}
    listen: 127.0.0.1:${port}
    routes:
      - name: benchmark
        match:
          host: [${HOST_HEADER}]
          path: ["/bench-*"]
          method: [GET, HEAD]${route_features}
        cache:
          enabled: true
          backend: ${name}-disk
          namespace: ${name}
          default_ttl_secs: 600
          max_object_bytes: 2097152
        target:
          type: upstream
          upstreams: [http://127.0.0.1:${BACKEND_PORT}]
YAML
  if ! QPX_STATE_DIR="$STATE_DIR" "$QPXD_BIN" check --config "$config" >"$LOG_DIR/${name}-check.log" 2>&1; then
    echo "${name} benchmark config validation failed" >&2
    dump_service_log "$LOG_DIR/${name}-check.log"
    exit 1
  fi
  QPX_STATE_DIR="$STATE_DIR" "$QPXD_BIN" run --config "$config" >"$LOG_DIR/${name}.log" 2>&1 &
  local pid=$!
  LAST_STARTED_PID="$pid"
  register_pid "$pid"
  wait_http "$name" "$port" "$pid" "$LOG_DIR/${name}.log"
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

start_nginx_cache() {
  local name="$1"
  local port="$2"
  local rich="$3"
  local prefix="$TMP_DIR/${name}"
  local config="$prefix/nginx.conf"
  local access_log="access_log off;"
  local rich_http=""
  local rich_location=""
  local nginx_rate_limit=""
  local workers="$CACHE_WORKERS"
  mkdir -p "$prefix/logs" "$prefix/cache"
  if [ "$rich" = true ]; then
    workers="$FEATURE_RICH_WORKERS"
    access_log="access_log $prefix/logs/access.log qpx_rich buffer=256k flush=1s;"
    nginx_rate_limit="
  limit_req_zone \$binary_remote_addr zone=${name}_rate:10m rate=1000000r/s;"
    rich_http="${nginx_rate_limit}
  log_format qpx_rich '\$remote_addr:\$remote_port - - [\$time_iso8601] \"\$request\" \$status \$body_bytes_sent \"\$http_referer\" \"\$http_user_agent\" request_time=\$request_time';
  gzip on;
  gzip_types application/octet-stream;"
    rich_location="
      proxy_set_header X-Qpx-Benchmark feature-rich;
      proxy_set_header X-Forwarded-By nginx;
      proxy_hide_header X-Internal-Only;
      add_header X-Content-Type-Options nosniff always;
      add_header X-Qpx-Feature-Set rich always;
      add_header Deprecation \"@2000000000\" always;
      add_header Sunset \"Wed, 18 May 2033 04:33:20 GMT\" always;
      add_header Link \"<https://bench.local/migration>; rel=successor-version; type=text/html\" always;"
    rich_location="
      limit_req zone=${name}_rate burst=100000 nodelay;${rich_location}"
  fi
  cat >"$config" <<NGINX
pid $prefix/nginx.pid;
error_log $prefix/logs/error.log warn;
worker_processes ${workers};
events {
  worker_connections 4096;
}
http {
  ${rich_http}
  ${access_log}
  proxy_cache_path $prefix/cache levels=1:2 keys_zone=${name}_cache:128m max_size=1g inactive=10m use_temp_path=off;
  upstream ${name}_backend {
    server 127.0.0.1:${BACKEND_PORT};
    keepalive 256;
  }
  server {
    listen 127.0.0.1:${port};
    location / {
      proxy_http_version 1.1;
      proxy_set_header Connection \"\";
      proxy_cache ${name}_cache;
      proxy_cache_lock on;
      proxy_cache_valid 200 10m;
      proxy_cache_key \"\$scheme\$proxy_host\$request_uri\";
      add_header X-Cache-Status \$upstream_cache_status always;${rich_location}
      proxy_pass http://${name}_backend;
    }
  }
}
NGINX
  nginx -p "$prefix" -c "$config" -g 'daemon off;' >"$LOG_DIR/${name}.log" 2>&1 &
  local pid=$!
  LAST_STARTED_PID="$pid"
  register_pid "$pid"
  wait_http "$name" "$port" "$pid" "$LOG_DIR/${name}.log"
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
  local server_limit=$(((APACHE_REQUEST_WORKERS + APACHE_THREADS_PER_CHILD - 1) / APACHE_THREADS_PER_CHILD))
  local min_spare_threads=$((APACHE_START_SERVERS * APACHE_THREADS_PER_CHILD))
  local max_spare_threads=$((APACHE_THREADS_PER_CHILD * 10))
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
    apache_load_module "alias"
    apache_load_module "dav"
    apache_load_module "dav_fs"
    apache_load_module "proxy"
    apache_load_module "proxy_http"
    apache_load_module "unixd"
    echo "ServerLimit ${server_limit}"
    echo "StartServers ${APACHE_START_SERVERS}"
    echo "ThreadLimit ${APACHE_THREADS_PER_CHILD}"
    echo "ThreadsPerChild ${APACHE_THREADS_PER_CHILD}"
    echo "MaxRequestWorkers ${APACHE_REQUEST_WORKERS}"
    echo "MinSpareThreads ${min_spare_threads}"
    echo "MaxSpareThreads ${max_spare_threads}"
    echo "KeepAlive On"
    echo "MaxKeepAliveRequests 0"
    echo "KeepAliveTimeout 30"
    echo "ProxyTimeout 30"
    echo "DavLockDB \"$root/run/DavLock\""
    echo "Alias \"/dav/\" \"$ORIGIN_ROOT/dav/\""
    echo "<Directory \"$ORIGIN_ROOT/dav\">"
    echo "  Options -Indexes -FollowSymLinks"
    echo "  AllowOverride None"
    echo "  Require all granted"
    echo "</Directory>"
    echo "<Location /dav/>"
    echo "  Dav On"
    echo "</Location>"
    echo "<VirtualHost 127.0.0.1:${APACHE_PORT}>"
    echo "  ProxyPass \"/dav/\" \"!\""
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

expect_qpx_backend_route_evidence() {
  local headers="$TMP_DIR/qpxd.backend-route-headers"
  local path="/__qpx_perf_route_evidence"
  local tries=0
  while [ "$tries" -lt 40 ]; do
    if curl -fsS --max-time 5 -H "Host: ${HOST_HEADER}" -D "$headers" -o /dev/null \
      "http://127.0.0.1:${QPX_PORT}${path}" &&
      grep -Eiq '^x-qpx-perf-upstream-via:[[:space:]]*1\.1[[:space:]]+qpx([[:space:]]|$)' "$headers"; then
      return 0
    fi
    tries=$((tries + 1))
    sleep 0.1
  done
  echo "qpxd reverse benchmark did not produce backend route evidence" >&2
  cat "$headers" >&2 || true
  dump_benchmark_logs
  return 1
}

expect_status_rejected() {
  local proxy="$1"
  local port="$2"
  local path="$3"
  local status
  local tries=0
  while [ "$tries" -lt 40 ]; do
    status="$(safe_probe_status "$port" "$path")"
    case "$status" in
      000|2??) ;;
      *) return 0 ;;
    esac
    tries=$((tries + 1))
    sleep 0.25
  done
  echo "${proxy} did not reject forbidden origin symlink ${path}; refusing non-equivalent benchmark" >&2
  dump_benchmark_logs
  return 1
}

expect_cache_hit() {
  local name="$1"
  local port="$2"
  local header_pattern="$3"
  local path="$4"
  local headers="$TMP_DIR/${name}.cache-headers"
  local tries=0
  while [ "$tries" -lt 40 ]; do
    if curl -fsS --max-time 5 -H "Host: ${HOST_HEADER}" -D "$headers" -o /dev/null \
      "http://127.0.0.1:${port}${path}" && grep -Eiq "$header_pattern" "$headers"; then
      return 0
    fi
    tries=$((tries + 1))
    sleep 0.1
  done
  echo "${name} did not produce a verified cache hit for ${path}" >&2
  cat "$headers" >&2 || true
  dump_benchmark_logs
  exit 1
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
  local expected_cache_header="${9:-}"
  local expected_cache_result="${10:-}"
  local probe_path="/bench-${body_bytes}"
  if [ "$mode" != "forward" ]; then
    probe_path="$request_target"
  fi
  if ! proxy_selected "$proxy"; then
    return 0
  fi
  if [ "$proxy" = "$LAST_TIMED_PROXY" ]; then
    sleep "$REPEATED_PROXY_SETTLE_SECONDS"
  fi
  LAST_TIMED_PROXY="$proxy"
  local body_kind
  local url="http://127.0.0.1:${port}/"
  local artifact_name="${bench}.${proxy}.${body_bytes}.round-${CURRENT_SAMPLE_ROUND:-0}"
  local out="$TMP_DIR/${artifact_name}.wrk"
  local warmup_out="$TMP_DIR/${artifact_name}.warmup"
  local lua="$TMP_DIR/${artifact_name}.lua"
  local status_before status_after
  local cpu_before_ms cpu_after_ms cpu_ms rss_kb rss_baseline_kb rss_peak_kb rss_growth_kb
  local rss_peak_file rss_peak_monitor_pid
  local fd_baseline fd_peak fd_growth fd_peak_file fd_peak_monitor_pid kernel_resource_metrics
  local scheduler_before_ns scheduler_after_ns scheduler_run_delay_ns scheduler_queue_delay_us_per_request
  local attempt failed_sample samples_file valid_sample_count median_index selected_sample profile_pid wrk_succeeded
  body_kind="$(body_profile "$body_bytes")"

  cat >"$lua" <<LUA
local expected = ${body_bytes}
local threads = {}
local next_thread_index = 0

setup = function(thread)
  thread:set("thread_index", next_thread_index)
  next_thread_index = next_thread_index + 1
  table.insert(threads, thread)
end

init = function(args)
  responses = 0
  non_200 = 0
  bad_length = 0
  cache_result_errors = 0
  request_sequence = 0
  request_namespace = (args and args[1]) or "default"
end

request = function()
  local target = "${request_target}"
  if "${expected_cache_result}" ~= "" then
    request_sequence = request_sequence + 1
    target = target .. "?qpx_cache_miss=" .. request_namespace .. "-" .. tostring(thread_index) .. "-" .. tostring(request_sequence)
  end
  return wrk.format("GET", target, { ["Host"] = "${request_host}" })
end

response = function(status, headers, body)
  responses = responses + 1
  if status ~= 200 then
    non_200 = non_200 + 1
  end
  if body == nil or string.len(body) ~= expected then
    bad_length = bad_length + 1
  end
  if "${expected_cache_result}" ~= "" then
    local matched = false
    for name, value in pairs(headers) do
      if string.lower(name) == "${expected_cache_header}" and string.find(string.lower(value), "${expected_cache_result}", 1, true) then
        matched = true
        break
      end
    end
    if not matched then
      cache_result_errors = cache_result_errors + 1
    end
  end
end

done = function(summary, latency, requests)
  local seconds = summary.duration / 1000000
  local total_responses = 0
  local total_non_200 = 0
  local total_bad_length = 0
  local total_cache_result_errors = 0
  for _, thread in ipairs(threads) do
    total_responses = total_responses + tonumber(thread:get("responses") or 0)
    total_non_200 = total_non_200 + tonumber(thread:get("non_200") or 0)
    total_bad_length = total_bad_length + tonumber(thread:get("bad_length") or 0)
    total_cache_result_errors = total_cache_result_errors + tonumber(thread:get("cache_result_errors") or 0)
  end
  io.write(string.format("qpx_complete_requests %d\n", total_responses))
  io.write(string.format("qpx_summary_requests %d\n", summary.requests))
  io.write(string.format("qpx_non_2xx_responses %d\n", total_non_200))
  io.write(string.format("qpx_bad_length_responses %d\n", total_bad_length))
  io.write(string.format("qpx_cache_result_errors %d\n", total_cache_result_errors))
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
    if ! expect_forward_status_ok "$proxy" "$port" "preflight" "$probe_path"; then
      status_before="$(safe_probe_forward_status "$port" "$probe_path")"
      record_invalid_sample "$bench" "$proxy" "$body_kind" "$body_bytes" "$status_before" "$status_before" "preflight_failed"
      return 0
    fi
  else
    if ! expect_status_ok "$proxy" "$port" "preflight" "$probe_path"; then
      status_before="$(safe_probe_status "$port" "$probe_path")"
      record_invalid_sample "$bench" "$proxy" "$body_kind" "$body_bytes" "$status_before" "$status_before" "preflight_failed"
      return 0
    fi
  fi
  local warmup_namespace="warmup-${artifact_name}"
  if ! wrk -t"$THREADS" -c16 -d2s --timeout "$WRK_TIMEOUT" -s "$lua" "$url" -- "$warmup_namespace" >"$warmup_out" 2>&1; then
    echo "wrk warmup failed for ${proxy}" >&2
    cat "$warmup_out" >&2 || true
    record_invalid_sample "$bench" "$proxy" "$body_kind" "$body_bytes" "200" "200" "warmup_failed"
    return 0
  fi
  sleep "$WARMUP_COOLDOWN_SECONDS"
  if [ "$mode" = "forward" ]; then
    status_before="$(safe_probe_forward_status "$port" "$probe_path")"
  else
    status_before="$(safe_probe_status "$port" "$probe_path")"
  fi
  local complete summary_requests failed fatal_errors non_2xx bad_length cache_result_errors cache_writeback_verified write_errors read_errors connect_errors timeout_errors rps mean_ms transfer_kbps commit valid
  local latency_p50_ms latency_p90_ms latency_p95_ms latency_p99_ms latency_p999_ms requests_per_cpu_second
  samples_file="$TMP_DIR/${artifact_name}.valid-samples.tsv"
  : >"$samples_file"
  attempt=1
  failed_sample=""
  while [ "$attempt" -le "$SAMPLE_ATTEMPTS" ]; do
    out="$TMP_DIR/${artifact_name}.attempt-${attempt}.wrk"
    profile_pid=""
    if [ "$proxy" = "$PROFILE_PROXY" ] && [ "$PROFILE_SECONDS" -gt 0 ]; then
      /usr/bin/sample "$resource_pid" "$PROFILE_SECONDS" 1 \
        -file "$TMP_DIR/${artifact_name}.attempt-${attempt}.sample.txt" \
        >"$LOG_DIR/${artifact_name}.attempt-${attempt}.sample.log" 2>&1 &
      profile_pid=$!
    fi
    kernel_resource_metrics=false
    rss_baseline_kb=0
    rss_peak_kb=0
    rss_growth_kb=0
    rss_peak_file="$TMP_DIR/${artifact_name}.attempt-${attempt}.rss-peak"
    rss_peak_monitor_pid=""
    fd_baseline=0
    fd_peak=0
    fd_growth=0
    fd_peak_file="$TMP_DIR/${artifact_name}.attempt-${attempt}.fd-peak"
    fd_peak_monitor_pid=""
    scheduler_before_ns=0
    if [ -d /proc ]; then
      kernel_resource_metrics=true
      rss_baseline_kb="$(process_tree_status_kb "$resource_pid" "VmRSS")"
      fd_baseline="$(process_tree_fd_count "$resource_pid")"
      monitor_process_tree_rss_peak "$resource_pid" "$rss_peak_file" "$rss_baseline_kb" &
      rss_peak_monitor_pid=$!
      monitor_process_tree_fd_peak "$resource_pid" "$fd_peak_file" "$fd_baseline" &
      fd_peak_monitor_pid=$!
      scheduler_before_ns="$(process_tree_scheduler_run_delay_ns "$resource_pid")"
    fi
    cpu_before_ms="$(process_tree_cpu_ms "$resource_pid")"
    io_syscr_before=0
    io_syscw_before=0
    if [ -d /proc ]; then
      io_syscr_before="$(process_tree_io_counter "$resource_pid" "syscr")"
      io_syscw_before="$(process_tree_io_counter "$resource_pid" "syscw")"
    fi
    wrk_succeeded=true
    if ! wrk -t"$THREADS" -c"$CONCURRENCY" -d"${DURATION_SECONDS}s" --timeout "$WRK_TIMEOUT" -s "$lua" "$url" -- "sample-${artifact_name}-${attempt}" >"$out" 2>&1; then
      wrk_succeeded=false
    fi
    if [ -n "$fd_peak_monitor_pid" ]; then
      kill "$fd_peak_monitor_pid" >/dev/null 2>&1 || true
      wait "$fd_peak_monitor_pid" 2>/dev/null || true
      fd_peak="$(cat "$fd_peak_file" 2>/dev/null || echo 0)"
      fd_growth="$(peak_growth "$fd_baseline" "$fd_peak")"
    fi
    if [ -n "$rss_peak_monitor_pid" ]; then
      kill "$rss_peak_monitor_pid" >/dev/null 2>&1 || true
      wait "$rss_peak_monitor_pid" 2>/dev/null || true
      rss_peak_kb="$(cat "$rss_peak_file" 2>/dev/null || echo 0)"
      rss_growth_kb="$(peak_growth "$rss_baseline_kb" "$rss_peak_kb")"
    fi
    scheduler_after_ns="$scheduler_before_ns"
    if [ "$kernel_resource_metrics" = true ]; then
      scheduler_after_ns="$(process_tree_scheduler_run_delay_ns "$resource_pid")"
    fi
    scheduler_run_delay_ns="$(awk -v before="$scheduler_before_ns" -v after="$scheduler_after_ns" 'BEGIN { delta = after - before; if (delta < 0) delta = 0; printf "%.0f", delta }')"
    if [ "$wrk_succeeded" != true ]; then
      echo "wrk failed for ${proxy} attempt ${attempt}/${SAMPLE_ATTEMPTS}" >&2
      cat "$out" >&2 || true
      failed_sample="$out"
      if [ -n "$profile_pid" ]; then
        wait "$profile_pid" || true
      fi
      compact_feature_rich_access_log "$proxy"
      settle_feature_rich_log_compaction "$proxy"
      attempt=$((attempt + 1))
      continue
    fi
    if [ -n "$profile_pid" ]; then
      wait "$profile_pid" || true
    fi
    drain_feature_rich_access_log "$proxy"
    cpu_after_ms="$(process_tree_cpu_ms "$resource_pid")"
    if [ -d /proc ]; then
      io_syscr_delta=$(( $(process_tree_io_counter "$resource_pid" "syscr") - io_syscr_before ))
      io_syscw_delta=$(( $(process_tree_io_counter "$resource_pid" "syscw") - io_syscw_before ))
      [ "$io_syscr_delta" -lt 0 ] 2>/dev/null && io_syscr_delta=0
      [ "$io_syscw_delta" -lt 0 ] 2>/dev/null && io_syscw_delta=0
      {
        echo "qpx_proc_io_syscr_delta $io_syscr_delta"
        echo "qpx_proc_io_syscw_delta $io_syscw_delta"
      } >>"$out"
    fi
    cpu_ms="$(awk -v before="$cpu_before_ms" -v after="$cpu_after_ms" 'BEGIN { delta = after - before; if (delta < 0) delta = 0; printf "%.0f", delta }')"
    rss_kb="$(process_tree_status_kb "$resource_pid" "VmRSS")"
    if [ "$mode" = "forward" ]; then
      status_after="$(safe_probe_forward_status "$port" "$probe_path")"
    else
      status_after="$(safe_probe_status "$port" "$probe_path")"
    fi
    compact_feature_rich_access_log "$proxy"
    settle_feature_rich_log_compaction "$proxy"
    complete="$(extract_metric_or_zero "$out" "qpx_complete_requests")"
    summary_requests="$(extract_metric_or_zero "$out" "qpx_summary_requests")"
    non_2xx="$(extract_metric_or_zero "$out" "qpx_non_2xx_responses")"
    bad_length="$(extract_metric_or_zero "$out" "qpx_bad_length_responses")"
    cache_result_errors="$(extract_metric_or_zero "$out" "qpx_cache_result_errors")"
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
    scheduler_queue_delay_us_per_request="$(awk -v delay_ns="$scheduler_run_delay_ns" -v requests="$summary_requests" 'BEGIN { if (requests > 0) printf "%.6f", delay_ns / requests / 1000; else printf "null" }')"
    valid="$([ "$complete" -gt 0 ] && [ "$summary_requests" = "$complete" ] && [ "$fatal_errors" = 0 ] && read_error_rate_allowed "$read_errors" "$complete" && [ "$non_2xx" = 0 ] && [ "$bad_length" = 0 ] && [ "$cache_result_errors" = 0 ] && [ "$status_before" = 200 ] && [ "$status_after" = 200 ] && echo true || echo false)"
    cache_writeback_verified=false
    if [ "$valid" = true ] && [ -n "$expected_cache_result" ]; then
      expect_cache_hit \
        "$proxy" \
        "$port" \
        "^${expected_cache_header}:.*hit" \
        "${request_target}?qpx_cache_writeback_verify=${artifact_name}-${attempt}"
      cache_writeback_verified=true
    fi
    if [ "$valid" = true ]; then
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$rps" "$complete" "$summary_requests" "$failed" "$connect_errors" "$read_errors" "$write_errors" "$timeout_errors" "$non_2xx" "$bad_length" "$cache_result_errors" "$cache_writeback_verified" "$mean_ms" "$transfer_kbps" "$latency_p50_ms" "$latency_p90_ms" "$latency_p95_ms" "$latency_p99_ms" "$latency_p999_ms" "$cpu_ms" "$rss_kb" "$rss_baseline_kb" "$rss_peak_kb" "$rss_growth_kb" "$requests_per_cpu_second" "$fd_baseline" "$fd_peak" "$fd_growth" "$scheduler_run_delay_ns" "$scheduler_queue_delay_us_per_request" "$kernel_resource_metrics" "$status_before" "$status_after" >>"$samples_file"
      if [ "${STOP_AFTER_FIRST_VALID_SAMPLE:-false}" = true ]; then
        break
      fi
      attempt=$((attempt + 1))
      continue
    fi
    failed_sample="$out"
    echo "${proxy} produced an invalid benchmark sample on attempt ${attempt}/${SAMPLE_ATTEMPTS}" >&2
    echo "complete=${complete} summary_requests=${summary_requests} failed=${failed} connect_errors=${connect_errors} read_errors=${read_errors} write_errors=${write_errors} timeout_errors=${timeout_errors} max_read_error_rate_ppm=${MAX_READ_ERROR_RATE_PPM} non_2xx=${non_2xx} bad_length=${bad_length} cache_result_errors=${cache_result_errors} status_before=${status_before} status_after=${status_after}" >&2
    cat "$out" >&2 || true
    attempt=$((attempt + 1))
  done
  valid_sample_count="$(wc -l <"$samples_file" | tr -d '[:space:]')"
  if [ "$valid_sample_count" -lt "$MIN_VALID_SAMPLES" ]; then
    if [ "$mode" = "forward" ]; then
      status_after="$(safe_probe_forward_status "$port" "$probe_path")"
    else
      status_after="$(safe_probe_status "$port" "$probe_path")"
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
  IFS=$'\t' read -r rps complete summary_requests failed connect_errors read_errors write_errors timeout_errors non_2xx bad_length cache_result_errors cache_writeback_verified mean_ms transfer_kbps latency_p50_ms latency_p90_ms latency_p95_ms latency_p99_ms latency_p999_ms cpu_ms rss_kb rss_baseline_kb rss_peak_kb rss_growth_kb requests_per_cpu_second fd_baseline fd_peak fd_growth scheduler_run_delay_ns scheduler_queue_delay_us_per_request kernel_resource_metrics status_before status_after <<<"$selected_sample"
  commit="${GITHUB_SHA:-unknown}"
  valid=true
  printf '{"bench":"%s","proxy":"%s","body_profile":"%s","duration_seconds":%s,"threads":%s,"concurrency":%s,"body_bytes":%s,"sample_attempts":%s,"valid_samples":%s,"aggregation":"single_sample","requests":%s,"complete_requests":%s,"failed_requests":%s,"connect_errors":%s,"read_errors":%s,"write_errors":%s,"timeout_errors":%s,"max_read_error_rate_ppm":%s,"non_2xx_responses":%s,"bad_length_responses":%s,"cache_result_errors":%s,"cache_writeback_verified":%s,"status_before":"%s","status_after":"%s","requests_per_sec":%s,"mean_time_per_request_ms":%s,"latency_p50_ms":%s,"latency_p90_ms":%s,"latency_p95_ms":%s,"latency_p99_ms":%s,"latency_p999_ms":%s,"transfer_kbytes_per_sec":%s,"cpu_ms":%s,"rss_kb":%s,"rss_baseline_kb":%s,"rss_peak_kb":%s,"rss_growth_kb":%s,"requests_per_cpu_second":%s,"fd_baseline":%s,"fd_peak":%s,"fd_growth":%s,"scheduler_run_delay_ns":%s,"scheduler_queue_delay_us_per_request":%s,"kernel_resource_metrics":%s,"valid":%s,"commit":"%s"}\n' \
    "$bench" "$proxy" "$body_kind" "$DURATION_SECONDS" "$THREADS" "$CONCURRENCY" "$body_bytes" "$SAMPLE_ATTEMPTS" "$valid_sample_count" "$summary_requests" "$complete" "$failed" "$connect_errors" "$read_errors" "$write_errors" "$timeout_errors" "$MAX_READ_ERROR_RATE_PPM" "$non_2xx" "$bad_length" "$cache_result_errors" "$cache_writeback_verified" "$status_before" "$status_after" "$rps" "$mean_ms" "$latency_p50_ms" "$latency_p90_ms" "$latency_p95_ms" "$latency_p99_ms" "$latency_p999_ms" "$transfer_kbps" "$(json_number_or_null "$cpu_ms")" "$(json_number_or_null "$rss_kb")" "$(json_number_or_null "$rss_baseline_kb")" "$(json_number_or_null "$rss_peak_kb")" "$(json_number_or_null "$rss_growth_kb")" "$requests_per_cpu_second" "$fd_baseline" "$fd_peak" "$fd_growth" "$scheduler_run_delay_ns" "$scheduler_queue_delay_us_per_request" "$kernel_resource_metrics" "$valid" "$commit" >>"$OUT_JSON"
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

for worker_spec in \
  "QPX_PROXY_COMPARE_CONCURRENCY:$CONCURRENCY" \
  "QPX_PROXY_COMPARE_THREADS:$THREADS" \
  "QPX_PROXY_COMPARE_LOCAL_ORIGIN_WORKERS:$LOCAL_ORIGIN_WORKERS" \
  "QPX_PROXY_COMPARE_CACHE_WORKERS:$CACHE_WORKERS" \
  "QPX_PROXY_COMPARE_FEATURE_RICH_WORKERS:$FEATURE_RICH_WORKERS" \
  "QPX_PROXY_COMPARE_WEBDAV_WORKERS:$WEBDAV_WORKERS" \
  "QPX_PROXY_COMPARE_WEBDAV_BLOCKING_THREADS:$WEBDAV_BLOCKING_THREADS" \
  "QPX_PROXY_COMPARE_APACHE_START_SERVERS:$APACHE_START_SERVERS" \
  "QPX_PROXY_COMPARE_APACHE_THREADS_PER_CHILD:$APACHE_THREADS_PER_CHILD" \
  "QPX_PROXY_COMPARE_APACHE_REQUEST_WORKERS:$APACHE_REQUEST_WORKERS"; do
  worker_name="${worker_spec%%:*}"
  worker_value="${worker_spec#*:}"
  case "$worker_value" in
    ''|*[!0-9]*)
      echo "${worker_name} must be a positive integer" >&2
      exit 1
      ;;
  esac
  if [ "$worker_value" -eq 0 ]; then
    echo "${worker_name} must be a positive integer" >&2
    exit 1
  fi
done
if [ $((APACHE_START_SERVERS * APACHE_THREADS_PER_CHILD)) -gt "$APACHE_REQUEST_WORKERS" ]; then
  echo "Apache initial event workers must not exceed MaxRequestWorkers" >&2
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

for seconds_spec in \
  "QPX_PROXY_COMPARE_WARMUP_COOLDOWN_SECONDS:$WARMUP_COOLDOWN_SECONDS" \
  "QPX_PROXY_COMPARE_ACCESS_LOG_DRAIN_SECONDS:$ACCESS_LOG_DRAIN_SECONDS" \
  "QPX_PROXY_COMPARE_LOG_COMPACTION_SETTLE_SECONDS:$LOG_COMPACTION_SETTLE_SECONDS" \
  "QPX_PROXY_COMPARE_REPEATED_PROXY_SETTLE_SECONDS:$REPEATED_PROXY_SETTLE_SECONDS"; do
  seconds_name="${seconds_spec%%:*}"
  seconds_value="${seconds_spec#*:}"
  if [[ ! "$seconds_value" =~ ^([0-9]+([.][0-9]*)?|[.][0-9]+)$ ]]; then
    echo "${seconds_name} must be a non-negative number" >&2
    exit 1
  fi
done

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
case "$PROFILE_SECONDS" in
  ''|*[!0-9]*)
    echo "QPX_PROXY_COMPARE_PROFILE_SECONDS must be a non-negative integer" >&2
    exit 1
    ;;
esac
if [ "$PROFILE_SECONDS" -gt 0 ] && [ -z "$PROFILE_PROXY" ]; then
  echo "QPX_PROXY_COMPARE_PROFILE_SECONDS requires QPX_PROXY_COMPARE_PROFILE_PROXY" >&2
  exit 1
fi
if [ "$PROFILE_SECONDS" -gt 0 ] && [ ! -x /usr/bin/sample ]; then
  echo "QPX_PROXY_COMPARE_PROFILE_SECONDS requires /usr/bin/sample" >&2
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
if proxy_selected qpxd; then
  start_qpxd
  expect_qpx_backend_route_evidence
fi
if proxy_selected nginx; then start_nginx; fi
if proxy_selected apache || proxy_selected apache-webdav; then start_apache; fi
if proxy_selected lighttpd; then start_lighttpd; fi
if proxy_selected qpxd-local; then start_qpxd_origin; fi
if proxy_selected qpxd-webdav; then start_qpxd_webdav; fi
if proxy_selected qpxd-cache; then
  start_qpxd_cache "qpxd-cache" "$QPX_CACHE_PORT" false
  QPX_CACHE_PID="$LAST_STARTED_PID"
fi
if proxy_selected nginx-cache; then
  start_nginx_cache "nginx-cache" "$NGINX_CACHE_PORT" false
  NGINX_CACHE_PID="$LAST_STARTED_PID"
fi
if proxy_selected qpxd-feature-rich; then
  start_qpxd_cache "qpxd-feature-rich" "$QPX_FEATURE_RICH_PORT" true
  QPX_FEATURE_RICH_PID="$LAST_STARTED_PID"
fi
if proxy_selected nginx-feature-rich; then
  start_nginx_cache "nginx-feature-rich" "$NGINX_FEATURE_RICH_PORT" true
  NGINX_FEATURE_RICH_PID="$LAST_STARTED_PID"
fi
if proxy_selected qpxd-forward; then start_qpxd_forward; fi
if proxy_selected squid; then start_squid; fi

if proxy_selected qpxd-webdav; then
  expect_status_rejected "qpxd-webdav" "$QPX_WEBDAV_PORT" "/dav/forbidden-symlink"
fi
if proxy_selected apache-webdav; then
  expect_status_rejected "apache-webdav" "$APACHE_PORT" "/dav/forbidden-symlink"
fi

if proxy_selected qpxd-cache; then
  expect_cache_hit "qpxd-cache" "$QPX_CACHE_PORT" '^cache-status:.*hit' "/bench-$(first_body_size)"
fi
if proxy_selected nginx-cache; then
  expect_cache_hit "nginx-cache" "$NGINX_CACHE_PORT" '^x-cache-status:[[:space:]]*HIT' "/bench-$(first_body_size)"
fi
if proxy_selected qpxd-feature-rich; then
  expect_cache_hit "qpxd-feature-rich" "$QPX_FEATURE_RICH_PORT" '^cache-status:.*hit' "/bench-$(first_body_size)"
fi
if proxy_selected nginx-feature-rich; then
  expect_cache_hit "nginx-feature-rich" "$NGINX_FEATURE_RICH_PORT" '^x-cache-status:[[:space:]]*HIT' "/bench-$(first_body_size)"
fi

FINAL_OUT_JSON="$OUT_JSON"
RAW_OUT_JSON="$TMP_DIR/interleaved-raw.jsonl"
REQUESTED_SAMPLE_ATTEMPTS="$SAMPLE_ATTEMPTS"
REQUESTED_MIN_VALID_SAMPLES="$MIN_VALID_SAMPLES"
OUT_JSON="$RAW_OUT_JSON"
SAMPLE_ATTEMPTS=3
MIN_VALID_SAMPLES=1
STOP_AFTER_FIRST_VALID_SAMPLE=true
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

round=1
while [ "$round" -le "$REQUESTED_SAMPLE_ATTEMPTS" ]; do
  CURRENT_SAMPLE_ROUND="$round"
  if [ $((round % 2)) -eq 1 ]; then
    run_one "origin_local_http1" "qpxd-local" "$QPX_ORIGIN_PORT" "reverse" "/local-${LOCAL_ORIGIN_BODY_BYTES}" "$HOST_HEADER" "$LOCAL_ORIGIN_BODY_BYTES" "$QPX_ORIGIN_PID"
    run_one "origin_local_http1" "nginx-static" "$BACKEND_PORT" "reverse" "/bench-${LOCAL_ORIGIN_BODY_BYTES}" "$HOST_HEADER" "$LOCAL_ORIGIN_BODY_BYTES" "$BACKEND_PID"
  else
    run_one "origin_local_http1" "nginx-static" "$BACKEND_PORT" "reverse" "/bench-${LOCAL_ORIGIN_BODY_BYTES}" "$HOST_HEADER" "$LOCAL_ORIGIN_BODY_BYTES" "$BACKEND_PID"
    run_one "origin_local_http1" "qpxd-local" "$QPX_ORIGIN_PORT" "reverse" "/local-${LOCAL_ORIGIN_BODY_BYTES}" "$HOST_HEADER" "$LOCAL_ORIGIN_BODY_BYTES" "$QPX_ORIGIN_PID"
  fi
  round=$((round + 1))
done

for body_bytes in $BODY_SIZES; do
  if proxy_selected qpxd-cache; then
    expect_cache_hit "qpxd-cache" "$QPX_CACHE_PORT" '^cache-status:.*hit' "/bench-${body_bytes}"
  fi
  if proxy_selected nginx-cache; then
    expect_cache_hit "nginx-cache" "$NGINX_CACHE_PORT" '^x-cache-status:[[:space:]]*HIT' "/bench-${body_bytes}"
  fi
  if proxy_selected qpxd-feature-rich; then
    expect_cache_hit "qpxd-feature-rich" "$QPX_FEATURE_RICH_PORT" '^cache-status:.*hit' "/bench-${body_bytes}"
  fi
  if proxy_selected nginx-feature-rich; then
    expect_cache_hit "nginx-feature-rich" "$NGINX_FEATURE_RICH_PORT" '^x-cache-status:[[:space:]]*HIT' "/bench-${body_bytes}"
  fi
  round=1
  while [ "$round" -le "$REQUESTED_SAMPLE_ATTEMPTS" ]; do
    CURRENT_SAMPLE_ROUND="$round"
    if [ $((round % 2)) -eq 1 ]; then
      run_one "origin_webdav_http1" "qpxd-webdav" "$QPX_WEBDAV_PORT" "reverse" "/dav/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$QPX_WEBDAV_PID"
      run_one "origin_webdav_http1" "apache-webdav" "$APACHE_PORT" "reverse" "/dav/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$APACHE_PID"
      run_one "proxy_cache_hit_http1" "qpxd-cache" "$QPX_CACHE_PORT" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$QPX_CACHE_PID"
      run_one "proxy_cache_hit_http1" "nginx-cache" "$NGINX_CACHE_PORT" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$NGINX_CACHE_PID"
      run_one "feature_rich_cache_hit_http1" "qpxd-feature-rich" "$QPX_FEATURE_RICH_PORT" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$QPX_FEATURE_RICH_PID"
      run_one "feature_rich_cache_hit_http1" "nginx-feature-rich" "$NGINX_FEATURE_RICH_PORT" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$NGINX_FEATURE_RICH_PID"
    else
      run_one "origin_webdav_http1" "apache-webdav" "$APACHE_PORT" "reverse" "/dav/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$APACHE_PID"
      run_one "origin_webdav_http1" "qpxd-webdav" "$QPX_WEBDAV_PORT" "reverse" "/dav/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$QPX_WEBDAV_PID"
      run_one "proxy_cache_hit_http1" "nginx-cache" "$NGINX_CACHE_PORT" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$NGINX_CACHE_PID"
      run_one "proxy_cache_hit_http1" "qpxd-cache" "$QPX_CACHE_PORT" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$QPX_CACHE_PID"
      run_one "feature_rich_cache_hit_http1" "nginx-feature-rich" "$NGINX_FEATURE_RICH_PORT" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$NGINX_FEATURE_RICH_PID"
      run_one "feature_rich_cache_hit_http1" "qpxd-feature-rich" "$QPX_FEATURE_RICH_PORT" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$QPX_FEATURE_RICH_PID"
    fi
    round=$((round + 1))
  done
done

if proxy_selected qpxd-cache || proxy_selected nginx-cache; then
  body_bytes=1024
  round=1
  while [ "$round" -le "$REQUESTED_SAMPLE_ATTEMPTS" ]; do
    CURRENT_SAMPLE_ROUND="$round"
    if [ $((round % 2)) -eq 1 ]; then
      run_one "proxy_cache_miss_http1" "qpxd-cache" "$QPX_CACHE_PORT" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$QPX_CACHE_PID" "cache-status" "miss"
      run_one "proxy_cache_miss_http1" "nginx-cache" "$NGINX_CACHE_PORT" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$NGINX_CACHE_PID" "x-cache-status" "miss"
    else
      run_one "proxy_cache_miss_http1" "nginx-cache" "$NGINX_CACHE_PORT" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$NGINX_CACHE_PID" "x-cache-status" "miss"
      run_one "proxy_cache_miss_http1" "qpxd-cache" "$QPX_CACHE_PORT" "reverse" "/bench-${body_bytes}" "$HOST_HEADER" "$body_bytes" "$QPX_CACHE_PID" "cache-status" "miss"
    fi
    round=$((round + 1))
  done
fi

if proxy_selected qpxd-cache; then
  expect_cache_hit "qpxd-cache" "$QPX_CACHE_PORT" '^cache-status:.*hit' "/bench-$(first_body_size)"
fi
if proxy_selected nginx-cache; then
  expect_cache_hit "nginx-cache" "$NGINX_CACHE_PORT" '^x-cache-status:[[:space:]]*HIT' "/bench-$(first_body_size)"
fi
if proxy_selected qpxd-feature-rich; then
  expect_cache_hit "qpxd-feature-rich" "$QPX_FEATURE_RICH_PORT" '^cache-status:.*hit' "/bench-$(first_body_size)"
  compact_feature_rich_access_log "qpxd-feature-rich"
  expect_rich_access_log_output \
    "qpxd-feature-rich" \
    "$LOG_DIR/qpxd-feature-rich-access.sample.log"
fi
if proxy_selected nginx-feature-rich; then
  expect_cache_hit "nginx-feature-rich" "$NGINX_FEATURE_RICH_PORT" '^x-cache-status:[[:space:]]*HIT' "/bench-$(first_body_size)"
  compact_feature_rich_access_log "nginx-feature-rich"
  expect_rich_access_log_output \
    "nginx-feature-rich" \
    "$LOG_DIR/nginx-feature-rich-access.sample.log"
fi

for workers in $SCALE_WORKERS; do
  if ! proxy_selected "qpxd-workers-${workers}"; then
    continue
  fi
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
  --argjson local_origin_workers "$LOCAL_ORIGIN_WORKERS" \
  --argjson cache_workers "$CACHE_WORKERS" \
  --argjson feature_rich_workers "$FEATURE_RICH_WORKERS" \
  --argjson webdav_workers "$WEBDAV_WORKERS" \
  --argjson webdav_blocking_threads "$WEBDAV_BLOCKING_THREADS" \
  --argjson apache_request_workers "$APACHE_REQUEST_WORKERS" \
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
    def majority_spread_ratio:
      map(select(type == "number" and . > 0))
      | sort
      | . as $values
      | if length == 0 then null
        else ((length / 2 | floor) + 1) as $window
        | [range(0; length - $window + 1) as $start
            | $values[$start + $window - 1] / $values[$start]]
        | min
        end;
    group_by([.bench, .proxy, .body_bytes])[]
    | . as $all
    | [$all[] | select(.valid == true)] as $valid
    | if ($valid | length) >= $minimum then
        ($valid | sort_by(.requests_per_sec)) as $ordered
        | $ordered[((($ordered | length) - 1) / 2 | floor)]
        # Resource triples must stay internally consistent (growth == peak -
        # baseline), so copy each family from the single sample with the
        # highest peak instead of maximizing every field independently.
        | . as $record
        | (($valid | max_by(.rss_peak_kb)) as $rss_sample
          | (($valid | max_by(.fd_peak)) as $fd_sample
            | $record
            | .rss_kb = $rss_sample.rss_kb
            | .rss_baseline_kb = $rss_sample.rss_baseline_kb
            | .rss_peak_kb = $rss_sample.rss_peak_kb
            | .rss_growth_kb = $rss_sample.rss_growth_kb
            | .fd_baseline = $fd_sample.fd_baseline
            | .fd_peak = $fd_sample.fd_peak
            | .fd_growth = $fd_sample.fd_growth))
        | .aggregation = "conservative_median_per_metric"
        | .sample_attempts = $attempts
        | .valid_samples = ($valid | length)
        | .sampling_order = "round_robin_interleaved"
        | .sample_spread_basis = "tightest_valid_majority"
        | .benchmark_schema_version = 4
        | .resource_measurement = "sampled_workload_peak_v1"
        | .backend_workers = $backend_workers
        | .role_workers = (if .proxy == "qpxd-webdav" then $webdav_workers elif (.proxy == "apache" or .proxy == "apache-webdav") then $apache_request_workers elif (.proxy | endswith("feature-rich")) then $feature_rich_workers elif (.proxy == "qpxd-cache" or .proxy == "nginx-cache") then $cache_workers elif .proxy == "qpxd-local" then $local_origin_workers elif (.proxy == "direct-backend" or .proxy == "nginx-static") then $backend_workers elif (.proxy | startswith("qpxd-workers-")) then (.proxy | ltrimstr("qpxd-workers-") | tonumber) else 1 end)
        | .blocking_workers = (if .proxy == "qpxd-webdav" then $webdav_blocking_threads else null end)
        | .execution_model = (if (.proxy == "apache" or .proxy == "apache-webdav") then "thread-per-request" else "async-io" end)
        | .workload_profile = (if .bench == "origin_local_http1" then "local_origin_default_v1" elif .bench == "origin_webdav_http1" then "webdav_filesystem_redb_symlink_safe_v2" elif .bench == "proxy_cache_hit_http1" then "persistent_cache_hit_v1" elif .bench == "proxy_cache_miss_http1" then "persistent_cache_unique_miss_v1" elif .bench == "feature_rich_cache_hit_http1" then "feature_rich_cache_hit_v1" else "minimal_proxy_v1" end)
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
        | .cache_result_errors = ([$valid[].cache_result_errors] | maximum)
        | .cache_writeback_verified = ([$valid[].cache_writeback_verified] | all)
        | .requests_per_sec = ([$valid[].requests_per_sec] | lower_median)
        | .mean_time_per_request_ms = ([$valid[].mean_time_per_request_ms] | upper_median)
        | .latency_p50_ms = ([$valid[].latency_p50_ms] | upper_median)
        | .latency_p90_ms = ([$valid[].latency_p90_ms] | upper_median)
        | .latency_p95_ms = ([$valid[].latency_p95_ms] | upper_median)
        | .latency_p99_ms = ([$valid[].latency_p99_ms] | upper_median)
        | .latency_p999_ms = ([$valid[].latency_p999_ms] | upper_median)
        | .transfer_kbytes_per_sec = ([$valid[].transfer_kbytes_per_sec] | lower_median)
        | .cpu_ms = ([$valid[].cpu_ms] | upper_median)
        | .scheduler_run_delay_ns = ([$valid[].scheduler_run_delay_ns] | maximum)
        | .scheduler_queue_delay_us_per_request = ([$valid[].scheduler_queue_delay_us_per_request] | maximum)
        | .kernel_resource_metrics = ([$valid[].kernel_resource_metrics] | all)
        | .requests_per_cpu_second = ([$valid[].requests_per_cpu_second] | lower_median)
        | .sample_spread = {
            requests_per_sec_ratio: ([$valid[].requests_per_sec] | majority_spread_ratio),
            latency_p99_ratio: ([$valid[].latency_p99_ms] | majority_spread_ratio),
            requests_per_cpu_second_ratio: ([$valid[].requests_per_cpu_second] | majority_spread_ratio)
          }
      else
        $all[0]
        | .aggregation = "conservative_median_per_metric"
        | .sample_attempts = $attempts
        | .valid_samples = ($valid | length)
        | .sampling_order = "round_robin_interleaved"
        | .sample_spread_basis = "tightest_valid_majority"
        | .benchmark_schema_version = 4
        | .resource_measurement = "sampled_workload_peak_v1"
        | .backend_workers = $backend_workers
        | .role_workers = (if .proxy == "qpxd-webdav" then $webdav_workers elif (.proxy == "apache" or .proxy == "apache-webdav") then $apache_request_workers elif (.proxy | endswith("feature-rich")) then $feature_rich_workers elif (.proxy == "qpxd-cache" or .proxy == "nginx-cache") then $cache_workers elif .proxy == "qpxd-local" then $local_origin_workers elif (.proxy == "direct-backend" or .proxy == "nginx-static") then $backend_workers elif (.proxy | startswith("qpxd-workers-")) then (.proxy | ltrimstr("qpxd-workers-") | tonumber) else 1 end)
        | .blocking_workers = (if .proxy == "qpxd-webdav" then $webdav_blocking_threads else null end)
        | .execution_model = (if (.proxy == "apache" or .proxy == "apache-webdav") then "thread-per-request" else "async-io" end)
        | .workload_profile = (if .bench == "origin_local_http1" then "local_origin_default_v1" elif .bench == "origin_webdav_http1" then "webdav_filesystem_redb_symlink_safe_v2" elif .bench == "proxy_cache_hit_http1" then "persistent_cache_hit_v1" elif .bench == "proxy_cache_miss_http1" then "persistent_cache_unique_miss_v1" elif .bench == "feature_rich_cache_hit_http1" then "feature_rich_cache_hit_v1" else "minimal_proxy_v1" end)
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
