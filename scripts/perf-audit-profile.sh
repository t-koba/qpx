#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/lib/temp-dir.sh"
PROFILE_DIR="${QPX_PERF_PROFILE_DIR:-$ROOT_DIR/target/perf/profiles}"
PROFILE_JSON="${QPX_PERF_PROFILE_JSON:-$ROOT_DIR/target/perf/perf-audit-profile-summary.jsonl}"
PROFILE_EVENTS="${QPX_PERF_PROFILE_EVENTS:-$ROOT_DIR/target/perf/perf-audit-profile-events.jsonl}"
PROFILE_REQUESTS="${QPX_PERF_PROFILE_REQUESTS:-1024}"
PROFILE_CONCURRENCY="${QPX_PERF_PROFILE_CONCURRENCY:-4}"
PROFILE_HTTP2_WARMUP_TIME="${QPX_PERF_PROFILE_HTTP2_WARMUP_TIME:-1s}"
PROFILE_HTTP2_DURATION="${QPX_PERF_PROFILE_HTTP2_DURATION:-1s}"
PROFILE_HTTP2_WARMUP_DELAY_SECONDS="${QPX_PERF_PROFILE_HTTP2_WARMUP_DELAY_SECONDS:-1.1}"
MIN_INSTRUCTIONS="${QPX_PERF_PROFILE_MIN_INSTRUCTIONS:-1000000}"
DEFAULT_QPXD_BIN="$ROOT_DIR/target/callgrind/qpxd"
QPXD_BIN="${QPXD_BIN:-$DEFAULT_QPXD_BIN}"
BACKEND_PORT="${QPX_PERF_PROFILE_BACKEND_PORT:-18480}"
QPX_HTTP1_PORT="${QPX_PERF_PROFILE_HTTP1_PORT:-18481}"
QPX_HTTP2_PORT="${QPX_PERF_PROFILE_HTTP2_PORT:-18482}"
QPX_CACHE_PROFILE_PORT="${QPX_PERF_PROFILE_CACHE_PORT:-18483}"
QPX_CACHE_MISS_PROFILE_PORT="${QPX_PERF_PROFILE_CACHE_MISS_PORT:-18484}"

TMP_DIR="$(make_temp_dir qpx-perf-profile)"
LOG_DIR="$TMP_DIR/logs"
mkdir -p "$PROFILE_DIR" "$LOG_DIR" "$(dirname "$PROFILE_JSON")"
rm -rf "$PROFILE_DIR/logs"
: >"$PROFILE_JSON"
: >"$PROFILE_EVENTS"

PIDS=()
BACKEND_PID=""
HTTP2_PROFILE_COMPLETED_REQUESTS=0

cleanup() {
  local pid
  for pid in "${PIDS[@]:-}"; do
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
  done
  mkdir -p "$PROFILE_DIR/logs"
  cp -R "$LOG_DIR"/. "$PROFILE_DIR/logs"/ 2>/dev/null || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

positive_integer() {
  case "$2" in
    ''|*[!0-9]*)
      echo "$1 must be a positive integer" >&2
      exit 1
      ;;
  esac
  if [ "$2" -eq 0 ]; then
    echo "$1 must be a positive integer" >&2
    exit 1
  fi
}

json_escape() {
  python3 -c 'import json, sys; print(json.dumps(sys.argv[1]))' "$1"
}

make_certificate() {
  openssl req \
    -x509 \
    -newkey rsa:2048 \
    -sha256 \
    -days 1 \
    -nodes \
    -subj "/CN=localhost" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
    -keyout "$TMP_DIR/server.key" \
    -out "$TMP_DIR/server.crt" \
    >"$LOG_DIR/openssl.log" 2>&1
}

start_backend() {
  local prefix="$TMP_DIR/backend"
  local config="$prefix/nginx.conf"
  mkdir -p "$prefix/logs" "$prefix/www"
  local backend_access_log="$prefix/logs/access.log"
  : >"$backend_access_log"
  dd if=/dev/zero of="$prefix/www/bench" bs=1024 count=1 status=none
  cat >"$config" <<NGINX
pid $prefix/nginx.pid;
error_log $prefix/logs/error.log warn;
worker_processes 1;
events { worker_connections 4096; }
http {
  access_log $backend_access_log combined;
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
}
NGINX
  nginx -p "$prefix" -c "$config" -g 'daemon off;' >"$LOG_DIR/backend.log" 2>&1 &
  BACKEND_PID=$!
  PIDS+=("$BACKEND_PID")
  wait_http "backend" "$BACKEND_PORT" "$BACKEND_PID" "$LOG_DIR/backend.log" false
}

write_qpx_config() {
  local protocol="$1"
  local port="$2"
  local config="$3"
  local tls=""
  local cache_backend=""
  local cache_route=""
  if [ "$protocol" = http2 ]; then
    tls="    enforce_sni_host_match: false
    tls:
      certificates:
        - sni: localhost
          cert: \"$TMP_DIR/server.crt\"
          key: \"$TMP_DIR/server.key\""
  fi
  if [ "$protocol" = cache-http1 ] || [ "$protocol" = cache-miss-http1 ]; then
    cache_backend="caches:
  - name: profile-disk
    kind: disk
    path: \"$TMP_DIR/profile-cache\"
    max_bytes: 1073741824
    sweep_interval_secs: 60
    timeout_ms: 1500
    max_object_bytes: 2097152
"
    cache_route="        cache:
          enabled: true
          backend: profile-disk
          namespace: profile
          default_ttl_secs: 600
          max_object_bytes: 2097152"
  fi
  cat >"$config" <<YAML
state_dir: "$TMP_DIR/state-${protocol}"
telemetry:
  system_log:
    level: warn
    format: json
${cache_backend}runtime:
  worker_threads: 1
  acceptor_tasks_per_listener: 1
  reuse_port: false
  upstream_proxy_max_concurrent_per_endpoint: 512
  upstream_max_idle_connections_per_origin: 256
edges:
  - kind: reverse
    name: profile-${protocol}
    listen: 127.0.0.1:${port}
${tls}
    routes:
      - name: bench
        streaming_requirement: required
        streaming:
          max_response_body_bytes: 1048576
        match: {}
${cache_route}
        target:
          type: upstream
          upstreams: [http://127.0.0.1:${BACKEND_PORT}]
YAML
}

wait_http() {
  local name="$1"
  local port="$2"
  local pid="$3"
  local log_file="$4"
  local tls="$5"
  local tries=0
  while [ "$tries" -lt 600 ]; do
    if [ "$tls" = true ]; then
      if curl -fsSk --http1.1 --max-time 2 --resolve "localhost:${port}:127.0.0.1" \
        "https://localhost:${port}/bench" >/dev/null 2>&1; then
        return
      fi
    elif curl -fsS --http1.1 --max-time 2 "http://127.0.0.1:${port}/bench" \
      >/dev/null 2>&1; then
      return
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

run_http1_load() {
  local output="$1"
  local port="$2"
  local requests="${3:-$PROFILE_REQUESTS}"
  local expected_cache_status="${4:-}"
  local unique_miss="${5:-}"
  if ! python3 - "$port" "$requests" "$PROFILE_CONCURRENCY" "$expected_cache_status" "$unique_miss" >"$output" 2>&1 <<'PY'
import concurrent.futures
import socket
import sys

port = int(sys.argv[1])
requests = int(sys.argv[2])
concurrency = int(sys.argv[3])
expected_cache_status = sys.argv[4].encode("ascii") if sys.argv[4] else None
unique_miss = bool(sys.argv[5])


def read_response(stream, buffered):
    while b"\r\n\r\n" not in buffered:
        chunk = stream.recv(64 * 1024)
        if not chunk:
            raise RuntimeError("connection closed while reading response head")
        buffered += chunk
    raw_head, buffered = buffered.split(b"\r\n\r\n", 1)
    lines = raw_head.split(b"\r\n")
    if lines[0] != b"HTTP/1.1 200 OK":
        raise RuntimeError(f"unexpected response status: {lines[0]!r}")
    headers = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if not separator:
            raise RuntimeError(f"malformed response header: {line!r}")
        headers.setdefault(name.strip().lower(), []).append(value.strip().lower())
    if headers.get(b"connection") == [b"close"]:
        raise RuntimeError("profile response disabled HTTP/1.1 connection reuse")
    lengths = headers.get(b"content-length", [])
    if lengths != [b"1024"]:
        raise RuntimeError(f"unexpected content-length: {lengths!r}")
    if expected_cache_status is not None:
        values = headers.get(b"cache-status", [])
        if not any(expected_cache_status in value for value in values):
            raise RuntimeError(
                f"unexpected cache-status: {values!r}, expected token {expected_cache_status!r}"
            )
    while len(buffered) < 1024:
        chunk = stream.recv(64 * 1024)
        if not chunk:
            raise RuntimeError("connection closed while reading response body")
        buffered += chunk
    body, buffered = buffered[:1024], buffered[1024:]
    if body != bytes(1024):
        raise RuntimeError("profile response body does not match the origin payload")
    return buffered


def run_connection(connection_index):
    assigned = requests // concurrency
    if connection_index < requests % concurrency:
        assigned += 1
    if unique_miss:
        request_template = (
            f"GET /bench?qpx_cache_miss=profile-{connection_index}-{{sequence}} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
        )
    else:
        request_template = (
            f"GET /bench HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
        )
    completed = 0
    buffered = b""
    with socket.create_connection(("127.0.0.1", port), timeout=30) as stream:
        stream.settimeout(30)
        for sequence in range(assigned):
            if unique_miss:
                request = request_template.format(sequence=sequence).encode("ascii")
            else:
                request = request_template.encode("ascii")
            stream.sendall(request)
            buffered = read_response(stream, buffered)
            completed += 1
    return completed


with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
    completed = sum(executor.map(run_connection, range(concurrency)))
if completed != requests:
    raise SystemExit(f"completed {completed}/{requests} HTTP/1.1 requests")
print(f"HTTP/1.1 requests: {completed}")
print(f"Persistent connections: {concurrency}")
print(f"Reused requests: {completed - concurrency}")
PY
  then
    cat "$output" >&2
    echo "HTTP/1 profile load failed" >&2
    return 1
  fi
}

run_http2_profile_load() {
  local output="$1"
  local qpx_pid="$2"
  local client_pid
  local client_status=0

  # Keep one h2load process alive across TLS/HTTP/2 warm-up and measurement.
  # Starting a second process after warm-up redoes the TLS handshake and makes
  # callgrind report handshake crypto instead of the HTTP/2 request path.
  h2load -D "$PROFILE_HTTP2_DURATION" \
    --warm-up-time "$PROFILE_HTTP2_WARMUP_TIME" \
    -c "$PROFILE_CONCURRENCY" \
    -m "$PROFILE_CONCURRENCY" \
    --connect-to "127.0.0.1:${QPX_HTTP2_PORT}" \
    "https://localhost:${QPX_HTTP2_PORT}/bench" \
    >"$output" 2>&1 &
  client_pid=$!
  sleep "$PROFILE_HTTP2_WARMUP_DELAY_SECONDS"
  callgrind_control -i on "$qpx_pid" >/dev/null
  wait "$client_pid" || client_status=$?
  callgrind_control -i off "$qpx_pid" >/dev/null || true
  if [ "$client_status" -ne 0 ]; then
    cat "$output" >&2
    echo "HTTP/2 profile load failed with status ${client_status}" >&2
    return 1
  fi
  HTTP2_PROFILE_COMPLETED_REQUESTS="$(python3 - "$output" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
row = re.search(
    r"requests:\s+([0-9]+) total,\s+([0-9]+) started,\s+([0-9]+) done,\s+"
    r"([0-9]+) succeeded,\s+([0-9]+) failed,\s+([0-9]+) errored,\s+([0-9]+) timeout",
    text,
)
if row is None:
    raise SystemExit("h2load output is missing request counters")
values = [int(value) for value in row.groups()]
total, started, done, succeeded, failed, errored, timed_out = values
if total == 0 or started == 0 or done == 0 or succeeded == 0:
    raise SystemExit("HTTP/2 profile load did not complete any measured requests")
if failed != 0 or errored != 0 or timed_out != 0:
    raise SystemExit("HTTP/2 profile load reported failures")
print(succeeded)
PY
)"
}

annotate_profile() {
  local target="$1"
  local protocol="$2"
  local file="$3"
  local commit="${GITHUB_SHA:-unknown}"
  local instructions command annotated
  if [ ! -s "$file" ] || ! grep -q '^events:.*Ir' "$file"; then
    echo "callgrind output is missing instruction events: ${file}" >&2
    return 1
  fi
  instructions="$(awk '
    /^summary:/ { summary = $2 }
    /^totals:/ { totals = $2 }
    END { printf "%.0f\n", (summary > totals ? summary : totals) }
  ' "$file")"
  instructions="${instructions:-0}"
  if ! [[ "$instructions" =~ ^[0-9]+$ ]] || [ "$instructions" -lt "$MIN_INSTRUCTIONS" ]; then
    echo "callgrind output has too few instructions (${instructions}): ${file}" >&2
    return 1
  fi
  command="$(awk -F':  ' '/^cmd:/ { print $2; exit }' "$file")"
  command="${command:-unknown}"
  case "$command" in
    *qpxd*" run --config "*) ;;
    *)
      echo "callgrind output does not profile qpxd directly: ${command}" >&2
      return 1
      ;;
  esac
  annotated="${file}.annotated.txt"
  callgrind_annotate --threshold=99 "$file" >"$annotated" 2>"${annotated}.err"
  printf '{"bench":"callgrind_hot_path_profile","target":%s,"protocol":%s,"command":%s,"instructions":%s,"callgrind_file":%s,"annotated_file":%s,"commit":%s}\n' \
    "$(json_escape "$target")" \
    "$(json_escape "$protocol")" \
    "$(json_escape "$command")" \
    "$instructions" \
    "$(json_escape "${file#"$ROOT_DIR"/}")" \
    "$(json_escape "${annotated#"$ROOT_DIR"/}")" \
    "$(json_escape "$commit")" >>"$PROFILE_JSON"
}

profile_instructions() {
  local file="$1"
  awk '
    /^summary:/ { if ($2 > maximum) maximum = $2 }
    /^totals:/ { if ($2 > maximum) maximum = $2 }
    END { printf "%.0f\n", maximum }
  ' "$file"
}

select_profile_dump() {
  local prefix="$1"
  local file instructions selected="" maximum=0
  for file in "$prefix" "$prefix".*; do
    [ -f "$file" ] || continue
    instructions="$(profile_instructions "$file")"
    instructions="${instructions:-0}"
    if [[ "$instructions" =~ ^[0-9]+$ ]] && [ "$instructions" -gt "$maximum" ]; then
      selected="$file"
      maximum="$instructions"
    fi
  done
  if [ -z "$selected" ]; then
    echo "callgrind did not produce a profile dump for ${prefix}" >&2
    return 1
  fi
  printf '%s\n' "$selected"
}

verify_cache_hit_response() {
  local port="$1"
  local attempt
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS --http1.1 --max-time 5 -D - -o /dev/null "http://127.0.0.1:${port}/bench" 2>/dev/null \
      | tr -d '\r' | grep -qi '^cache-status:.*hit'; then
      return 0
    fi
    sleep 0.2
  done
  echo "cache profile did not observe a HIT response after warm-up" >&2
  return 1
}

run_profile() {
  local protocol="$1"
  local port="$2"
  local target="${3:-qpxd_reverse_${protocol}}"
  local profile_protocol="http1"
  case "$protocol" in
    http2) profile_protocol="http2" ;;
    *) profile_protocol="http1" ;;
  esac
  local config="$TMP_DIR/qpxd-${protocol}.yaml"
  local output="$PROFILE_DIR/callgrind.${target}.out"
  local load_output="$LOG_DIR/load-${protocol}.txt"
  local qpx_log="$LOG_DIR/qpxd-${protocol}.log"
  local pid tls selected_output warmup_requests measured_requests
  tls=false
  warmup_requests=0
  measured_requests="$PROFILE_REQUESTS"
  if [ "$protocol" = http2 ]; then tls=true; fi
  write_qpx_config "$protocol" "$port" "$config"
  rm -f "$output" "$output".*
  valgrind \
    --tool=callgrind \
    --instr-atstart=no \
    --child-silent-after-fork=yes \
    --callgrind-out-file="$output" \
    "$QPXD_BIN" run --config "$config" >"$qpx_log" 2>&1 &
  pid=$!
  PIDS+=("$pid")
  wait_http "qpxd-${protocol}" "$port" "$pid" "$qpx_log" "$tls"
  if [ "$protocol" = http2 ]; then
    # h2load timing mode does not expose warm-up counters; this records the
    # number of connections that were primed before callgrind was enabled.
    warmup_requests="$PROFILE_CONCURRENCY"
    run_http2_profile_load "$load_output" "$pid"
    measured_requests="$HTTP2_PROFILE_COMPLETED_REQUESTS"
  elif [ "$protocol" = cache-http1 ]; then
    # Warm up the disk cache and the keep-alive connections before recording,
    # so the measured instructions reflect the cache hit path only. The loader
    # rejects any response that is not served with a HIT cache status.
    warmup_requests="$PROFILE_CONCURRENCY"
    run_http1_load "$LOG_DIR/warmup-cache.txt" "$port" "$PROFILE_CONCURRENCY"
    verify_cache_hit_response "$port"
    callgrind_control -i on "$pid" >/dev/null
    run_http1_load "$load_output" "$port" "" "hit"
    callgrind_control -i off "$pid" >/dev/null
  elif [ "$protocol" = cache-miss-http1 ]; then
    # Unique URLs per request: every measured request is a cold miss that
    # runs the full lookup chain, the upstream fetch, and the async disk
    # writeback, so the profile reflects the cache miss path only.
    warmup_requests="$PROFILE_CONCURRENCY"
    run_http1_load "$LOG_DIR/warmup-cache-miss.txt" "$port" "$PROFILE_CONCURRENCY" "" "miss"
    callgrind_control -i on "$pid" >/dev/null
    run_http1_load "$load_output" "$port" "" "miss" "miss"
    callgrind_control -i off "$pid" >/dev/null
  else
    callgrind_control -i on "$pid" >/dev/null
    run_http1_load "$load_output" "$port"
    callgrind_control -i off "$pid" >/dev/null
  fi
  callgrind_control -d "$pid" >/dev/null
  kill -TERM "$pid"
  local exit_status=0
  wait "$pid" || exit_status=$?
  if [ "$exit_status" -ne 0 ] && [ "$exit_status" -ne 143 ]; then
    echo "profiled qpxd exited with status ${exit_status}" >&2
    return 1
  fi
  selected_output="$(select_profile_dump "$output")"
  annotate_profile "$target" "$profile_protocol" "$selected_output"
  printf '{"bench":"callgrind_profile_load","target":%s,"requests":%s,"warmup_requests":%s,"concurrency":%s,"http1_connection_reuse":%s,"valid":true,"commit":%s}\n' \
    "$(json_escape "$target")" \
    "$measured_requests" \
    "$warmup_requests" \
    "$PROFILE_CONCURRENCY" \
    "$([ "$profile_protocol" = http1 ] && echo true || echo false)" \
    "$(json_escape "${GITHUB_SHA:-unknown}")" >>"$PROFILE_EVENTS"
}

require_cmd callgrind_annotate
require_cmd callgrind_control
require_cmd curl
require_cmd h2load
require_cmd nm
require_cmd nginx
require_cmd openssl
require_cmd python3
require_cmd valgrind
positive_integer QPX_PERF_PROFILE_REQUESTS "$PROFILE_REQUESTS"
positive_integer QPX_PERF_PROFILE_CONCURRENCY "$PROFILE_CONCURRENCY"
positive_integer QPX_PERF_PROFILE_MIN_INSTRUCTIONS "$MIN_INSTRUCTIONS"
if [ "$PROFILE_CONCURRENCY" -gt "$PROFILE_REQUESTS" ]; then
  echo "QPX_PERF_PROFILE_CONCURRENCY must not exceed QPX_PERF_PROFILE_REQUESTS" >&2
  exit 1
fi
if [ $((PROFILE_REQUESTS % PROFILE_CONCURRENCY)) -ne 0 ]; then
  echo "QPX_PERF_PROFILE_REQUESTS must be divisible by QPX_PERF_PROFILE_CONCURRENCY" >&2
  exit 1
fi
if [ "$QPXD_BIN" = "$DEFAULT_QPXD_BIN" ]; then
  cargo build -p qpxd --profile callgrind --locked --bin qpxd --features http3-backend-qpx
fi
if [ ! -x "$QPXD_BIN" ]; then
  echo "missing qpxd binary: $QPXD_BIN" >&2
  exit 1
fi
if ! nm -an "$QPXD_BIN" 2>/dev/null | awk 'index($0, "qpxd") { found = 1 } END { exit(found ? 0 : 1) }'; then
  echo "qpxd binary lacks symbols; callgrind profiling requires an unstripped binary: $QPXD_BIN" >&2
  exit 1
fi

make_certificate
start_backend
run_profile http1 "$QPX_HTTP1_PORT"
run_profile http2 "$QPX_HTTP2_PORT"
run_profile cache-http1 "$QPX_CACHE_PROFILE_PORT" qpxd_cache_hit_http1
run_profile cache-miss-http1 "$QPX_CACHE_MISS_PROFILE_PORT" qpxd_cache_miss_http1
