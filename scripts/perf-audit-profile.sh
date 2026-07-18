#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/lib/temp-dir.sh"
PROFILE_DIR="${QPX_PERF_PROFILE_DIR:-$ROOT_DIR/target/perf/profiles}"
PROFILE_JSON="${QPX_PERF_PROFILE_JSON:-$ROOT_DIR/target/perf/perf-audit-profile-summary.jsonl}"
PROFILE_EVENTS="${QPX_PERF_PROFILE_EVENTS:-$ROOT_DIR/target/perf/perf-audit-profile-events.jsonl}"
PROFILE_REQUESTS="${QPX_PERF_PROFILE_REQUESTS:-32}"
PROFILE_CONCURRENCY="${QPX_PERF_PROFILE_CONCURRENCY:-4}"
MIN_INSTRUCTIONS="${QPX_PERF_PROFILE_MIN_INSTRUCTIONS:-1000000}"
DEFAULT_QPXD_BIN="$ROOT_DIR/target/callgrind/qpxd"
QPXD_BIN="${QPXD_BIN:-$DEFAULT_QPXD_BIN}"
BACKEND_PORT="${QPX_PERF_PROFILE_BACKEND_PORT:-18480}"
QPX_HTTP1_PORT="${QPX_PERF_PROFILE_HTTP1_PORT:-18481}"
QPX_HTTP2_PORT="${QPX_PERF_PROFILE_HTTP2_PORT:-18482}"

TMP_DIR="$(make_temp_dir qpx-perf-profile)"
LOG_DIR="$TMP_DIR/logs"
mkdir -p "$PROFILE_DIR" "$LOG_DIR" "$(dirname "$PROFILE_JSON")"
: >"$PROFILE_JSON"
: >"$PROFILE_EVENTS"

PIDS=()
BACKEND_PID=""

cleanup() {
  local pid
  for pid in "${PIDS[@]:-}"; do
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
  done
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
  if [ "$protocol" = http2 ]; then
    tls="    enforce_sni_host_match: false
    tls:
      certificates:
        - sni: localhost
          cert: \"$TMP_DIR/server.crt\"
          key: \"$TMP_DIR/server.key\""
  fi
  cat >"$config" <<YAML
state_dir: "$TMP_DIR/state-${protocol}"
telemetry:
  system_log:
    level: warn
    format: json
runtime:
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
  ab -n "$PROFILE_REQUESTS" -c "$PROFILE_CONCURRENCY" -k \
    "http://127.0.0.1:${QPX_HTTP1_PORT}/bench" >"$output" 2>&1
  python3 - "$output" "$PROFILE_REQUESTS" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
expected = int(sys.argv[2])
complete = re.search(r"Complete requests:\s+([0-9]+)", text)
failed = re.search(r"Failed requests:\s+([0-9]+)", text)
if complete is None or failed is None:
    raise SystemExit("ab output is missing request counters")
if int(complete.group(1)) != expected or int(failed.group(1)) != 0:
    raise SystemExit("HTTP/1 profile load did not complete successfully")
PY
}

run_http2_profile_load() {
  local output="$1"
  local qpx_pid="$2"
  local warmup_output="$LOG_DIR/http2-profile-warmup.txt"
  local client_status=0

  # Warm up the TLS, HTTP/2, HPACK and origin connection state in a completed
  # request before enabling callgrind. Timing-script based warmup was racy:
  # h2load may complete the timed requests before nginx flushes its access log,
  # leaving the profiler with an empty or partial measurement window.
  if ! h2load -n "$PROFILE_CONCURRENCY" -c "$PROFILE_CONCURRENCY" \
    -m "$PROFILE_CONCURRENCY" \
    --connect-to "127.0.0.1:${QPX_HTTP2_PORT}" \
    "https://localhost:${QPX_HTTP2_PORT}/bench" >"$warmup_output" 2>&1; then
    cat "$warmup_output" >&2
    echo "HTTP/2 profile warmup failed" >&2
    return 1
  fi

  callgrind_control -i on "$qpx_pid" >/dev/null
  h2load -n "$PROFILE_REQUESTS" -c "$PROFILE_CONCURRENCY" \
    -m "$PROFILE_CONCURRENCY" \
    --connect-to "127.0.0.1:${QPX_HTTP2_PORT}" \
    "https://localhost:${QPX_HTTP2_PORT}/bench" \
    >"$output" 2>&1 || client_status=$?
  callgrind_control -i off "$qpx_pid" >/dev/null || true
  if [ "$client_status" -ne 0 ]; then
    cat "$output" >&2
    echo "HTTP/2 profile load failed with status ${client_status}" >&2
    return 1
  fi
  python3 - "$output" "$PROFILE_REQUESTS" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
expected = int(sys.argv[2])
row = re.search(
    r"requests:\s+([0-9]+) total,\s+([0-9]+) started,\s+([0-9]+) done,\s+"
    r"([0-9]+) succeeded,\s+([0-9]+) failed,\s+([0-9]+) errored,\s+([0-9]+) timeout",
    text,
)
if row is None:
    raise SystemExit("h2load output is missing request counters")
values = [int(value) for value in row.groups()]
total, started, done, succeeded, failed, errored, timed_out = values
if (total, started, done, succeeded) != (expected, expected, expected, expected):
    raise SystemExit("HTTP/2 profile load did not complete the measured requests")
if failed != 0 or errored != 0 or timed_out != 0:
    raise SystemExit("HTTP/2 profile load reported failures")
PY
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

run_profile() {
  local protocol="$1"
  local port="$2"
  local config="$TMP_DIR/qpxd-${protocol}.yaml"
  local output="$PROFILE_DIR/callgrind.qpxd_reverse_${protocol}.out"
  local load_output="$LOG_DIR/load-${protocol}.txt"
  local qpx_log="$LOG_DIR/qpxd-${protocol}.log"
  local pid tls selected_output warmup_requests
  tls=false
  warmup_requests=0
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
    warmup_requests="$PROFILE_CONCURRENCY"
    run_http2_profile_load "$load_output" "$pid"
  else
    callgrind_control -i on "$pid" >/dev/null
    run_http1_load "$load_output"
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
  annotate_profile "qpxd_reverse_${protocol}" "$protocol" "$selected_output"
  printf '{"bench":"callgrind_profile_load","target":%s,"requests":%s,"warmup_requests":%s,"concurrency":%s,"valid":true,"commit":%s}\n' \
    "$(json_escape "qpxd_reverse_${protocol}")" \
    "$PROFILE_REQUESTS" \
    "$warmup_requests" \
    "$PROFILE_CONCURRENCY" \
    "$(json_escape "${GITHUB_SHA:-unknown}")" >>"$PROFILE_EVENTS"
}

require_cmd ab
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
