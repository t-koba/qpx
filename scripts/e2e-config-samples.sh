#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR="$ROOT_DIR/config/usecases/99-test-fixtures"
QPXD_BIN="${QPXD_BIN:-$ROOT_DIR/target/debug/qpxd}"
QPXF_BIN="${QPXF_BIN:-$ROOT_DIR/target/debug/qpxf}"
IPC_CONFIG_DIR="$ROOT_DIR/config/usecases/12-ipc-gateway"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/qpx-e2e.XXXXXX")"
STATE_DIR="$TMP_DIR/state"
LOG_DIR="$TMP_DIR/logs"
IPC_RUNTIME_DIR="$TMP_DIR/runtime"
IPC_CGI_ROOT="$ROOT_DIR/config/usecases/12-ipc-gateway/assets/cgi"
IPC_WASM_MODULE="$ROOT_DIR/config/usecases/12-ipc-gateway/assets/wasm/echo.wat"
mkdir -p "$STATE_DIR" "$LOG_DIR" "$IPC_RUNTIME_DIR"
CURL_MAX_TIME_SEC="${CURL_MAX_TIME_SEC:-8}"
CURL_RETRY_COUNT="${CURL_RETRY_COUNT:-12}"
CURL_RETRY_DELAY_SEC="${CURL_RETRY_DELAY_SEC:-0}"
CURL_RETRY_MAX_TIME_SEC="${CURL_RETRY_MAX_TIME_SEC:-12}"
WAIT_PID_TIMEOUT_SEC="${WAIT_PID_TIMEOUT_SEC:-10}"
NC_TIMEOUT_SEC="${NC_TIMEOUT_SEC:-10}"

# Retry transient curl failures (e.g. empty reply) to reduce CI flakiness.
CURL_RETRY_ARGS=(
  --retry "$CURL_RETRY_COUNT"
  --retry-all-errors
  --retry-connrefused
  --retry-delay "$CURL_RETRY_DELAY_SEC"
  --retry-max-time "$CURL_RETRY_MAX_TIME_SEC"
)

PIDS=()
LAST_PID=""

register_pid() {
  PIDS+=("$1")
}

cleanup() {
  local status=$?
  if [ "$status" -ne 0 ]; then
    echo "[E2E] failed; dumping logs from $LOG_DIR" >&2
    if [ -d "$LOG_DIR" ]; then
      local log_file
      for log_file in "$LOG_DIR"/*.log; do
        [ -e "$log_file" ] || continue
        echo "--- $log_file ---" >&2
        sed -n '1,240p' "$log_file" >&2 || true
      done
    fi
  fi
  local pid
  for pid in "${PIDS[@]:-}"; do
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
  done
  if [ "${KEEP_E2E_TMP:-0}" = "1" ]; then
    echo "[E2E] keeping temporary directory: $TMP_DIR" >&2
  else
    rm -rf "$TMP_DIR"
  fi
  return "$status"
}
trap cleanup EXIT

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

assert_eq() {
  local expected="$1"
  local actual="$2"
  local message="$3"
  if [ "$expected" != "$actual" ]; then
    echo "ASSERT FAILED: $message (expected=$expected actual=$actual)" >&2
    exit 1
  fi
}

assert_file_contains() {
  local file="$1"
  local pattern="$2"
  local message="$3"
  if ! grep -Eiq "$pattern" "$file"; then
    echo "ASSERT FAILED: $message" >&2
    echo "--- $file ---" >&2
    cat "$file" >&2 || true
    echo "-------------" >&2
    exit 1
  fi
}

normalize_headers() {
  local in_file="$1"
  local out_file="$2"
  tr -d '\r' <"$in_file" >"$out_file"
}

port_open() {
  local port="$1"
  nc -z 127.0.0.1 "$port" >/dev/null 2>&1 || (echo >/dev/tcp/127.0.0.1/"$port") >/dev/null 2>&1
}

wait_port() {
  local port="$1"
  local pid="$2"
  local log_file="$3"
  local tries=0

  while [ "$tries" -lt 100 ]; do
    if port_open "$port"; then
      return 0
    fi
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "qpxd exited before opening port $port" >&2
      cat "$log_file" >&2 || true
      exit 1
    fi
    tries=$((tries + 1))
    sleep 0.1
  done

  echo "timeout waiting for port $port" >&2
  cat "$log_file" >&2 || true
  exit 1
}

wait_socket() {
  local socket_path="$1"
  local pid="$2"
  local log_file="$3"
  local tries=0

  while [ "$tries" -lt 100 ]; do
    if [ -S "$socket_path" ]; then
      return 0
    fi
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "qpxf exited before creating socket $socket_path" >&2
      cat "$log_file" >&2 || true
      exit 1
    fi
    tries=$((tries + 1))
    sleep 0.1
  done

  echo "timeout waiting for socket $socket_path" >&2
  cat "$log_file" >&2 || true
  exit 1
}

start_qpxd() {
  local config_file="$1"
  local port="$2"
  local log_file="$3"
  QPX_STATE_DIR="$STATE_DIR" "$QPXD_BIN" run --config "$config_file" >"$log_file" 2>&1 &
  local pid=$!
  register_pid "$pid"
  wait_port "$port" "$pid" "$log_file"
  LAST_PID="$pid"
}

start_qpxf_tcp() {
  local config_file="$1"
  local listen_addr="$2"
  local log_file="$3"
  XDG_RUNTIME_DIR="$IPC_RUNTIME_DIR" \
  QPXF_SAMPLE_CGI_ROOT="$IPC_CGI_ROOT" \
  QPXF_SAMPLE_WASM_MODULE="$IPC_WASM_MODULE" \
  QPXF_TCP_LISTEN="$listen_addr" \
    "$QPXF_BIN" --config "$config_file" >"$log_file" 2>&1 &
  local pid=$!
  register_pid "$pid"
  wait_port "${listen_addr##*:}" "$pid" "$log_file"
  LAST_PID="$pid"
}

start_qpxf_unix() {
  local config_file="$1"
  local listen_uri="$2"
  local log_file="$3"
  local socket_path="${listen_uri#unix://}"
  XDG_RUNTIME_DIR="$IPC_RUNTIME_DIR" \
  QPXF_UNIX_LISTEN="$listen_uri" \
  QPXF_SAMPLE_CGI_ROOT="$IPC_CGI_ROOT" \
  QPXF_SAMPLE_WASM_MODULE="$IPC_WASM_MODULE" \
    "$QPXF_BIN" --config "$config_file" >"$log_file" 2>&1 &
  local pid=$!
  register_pid "$pid"
  wait_socket "$socket_path" "$pid" "$log_file"
  LAST_PID="$pid"
}

stop_pid() {
  local pid="$1"
  if kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  fi
}

write_http_response() {
  local out_file="$1"
  local body="$2"
  local extra_header="${3:-}"
  local body_len
  body_len=$(printf "%s" "$body" | wc -c | tr -d ' ')

  {
    printf 'HTTP/1.1 200 OK\r\n'
    if [ -n "$extra_header" ]; then
      printf '%s\r\n' "$extra_header"
    fi
    printf 'Content-Length: %s\r\n' "$body_len"
    printf 'Connection: close\r\n'
    printf '\r\n'
    printf '%s' "$body"
  } >"$out_file"
}

serve_once() {
  local port="$1"
  local response_file="$2"
  local capture_file="$3"
  (timeout "${NC_TIMEOUT_SEC}" nc -l "$port" <"$response_file" >"$capture_file") &
  local pid=$!
  register_pid "$pid"
  local tries=0
  while [ "$tries" -lt 80 ]; do
    if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
      break
    fi
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "backend stub exited before serving port $port" >&2
      return 1
    fi
    tries=$((tries + 1))
    sleep 0.05
  done
  if ! lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "backend stub did not open port $port in time" >&2
    return 1
  fi
  LAST_PID="$pid"
}

wait_pid_with_timeout() {
  local pid="$1"
  local timeout_sec="$2"
  local tries=0
  local max_tries=$((timeout_sec * 10))

  while kill -0 "$pid" >/dev/null 2>&1; do
    if [ "$tries" -ge "$max_tries" ]; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
      echo "process timeout waiting for pid=$pid" >&2
      return 1
    fi
    tries=$((tries + 1))
    sleep 0.1
  done

  wait "$pid" >/dev/null 2>&1 || true
}

run_forward_suite() {
  echo "[E2E] forward suite"
  local proxy_log="$LOG_DIR/forward.log"
  local qpx_pid
  start_qpxd "$CONFIG_DIR/e2e-forward.yaml" 18150 "$proxy_log"
  qpx_pid="$LAST_PID"

  local status
  status=$(curl -sS --max-time "$CURL_MAX_TIME_SEC" --connect-timeout 2 "${CURL_RETRY_ARGS[@]}" --noproxy '' -x http://127.0.0.1:18150 \
    -o "$TMP_DIR/forward_block.body" \
    -D "$TMP_DIR/forward_block.headers" \
    -w '%{http_code}' \
    http://blocked.invalid/)
  assert_eq "403" "$status" "forward block status"
  assert_eq "blocked" "$(cat "$TMP_DIR/forward_block.body")" "forward block body"

  local response_file="$TMP_DIR/forward_headers.response"
  local capture_file="$TMP_DIR/forward_headers.capture"
  write_http_response "$response_file" "OK"
  local backend_pid
  serve_once 19091 "$response_file" "$capture_file"
  backend_pid="$LAST_PID"
  # Forward may perform background connections (e.g. proxy readiness checks) that can consume our
  # one-shot backend stub. If that happens, restart it before issuing the request.
  for _ in {1..5}; do
    sleep 0.1
    if ! kill -0 "$backend_pid" >/dev/null 2>&1; then
      serve_once 19091 "$response_file" "$capture_file"
      backend_pid="$LAST_PID"
      break
    fi
  done
  status=$(curl -sS --max-time "$CURL_MAX_TIME_SEC" --connect-timeout 2 "${CURL_RETRY_ARGS[@]}" --noproxy '' -x http://127.0.0.1:18150 \
    -o "$TMP_DIR/forward_headers.body" \
    -D "$TMP_DIR/forward_headers.headers" \
    -w '%{http_code}' \
    http://127.0.0.1:19091/headers)
  wait_pid_with_timeout "$backend_pid" "$WAIT_PID_TIMEOUT_SEC"
  assert_eq "200" "$status" "forward /headers status"
  assert_eq "OK" "$(cat "$TMP_DIR/forward_headers.body")" "forward /headers body"
  normalize_headers "$TMP_DIR/forward_headers.headers" "$TMP_DIR/forward_headers.headers.norm"
  assert_file_contains "$TMP_DIR/forward_headers.headers.norm" '^x-e2e-proxy: qpx-e2e$' "forward response header rewrite"
  normalize_headers "$capture_file" "$capture_file.norm"
  assert_file_contains "$capture_file.norm" '^x-test-proxy: qpx-e2e$' "forward request header rewrite"

  status=$(curl -sS --max-time "$CURL_MAX_TIME_SEC" --connect-timeout 2 "${CURL_RETRY_ARGS[@]}" --noproxy '' -x http://127.0.0.1:18150 \
    -o "$TMP_DIR/forward_auth_challenge.body" \
    -D "$TMP_DIR/forward_auth_challenge.headers" \
    -w '%{http_code}' \
    http://127.0.0.1:19091/auth/protected)
  assert_eq "407" "$status" "forward auth challenge status"
  normalize_headers "$TMP_DIR/forward_auth_challenge.headers" "$TMP_DIR/forward_auth_challenge.headers.norm"
  assert_file_contains "$TMP_DIR/forward_auth_challenge.headers.norm" '^proxy-authenticate:' "forward auth challenge header"

  response_file="$TMP_DIR/forward_auth_ok.response"
  capture_file="$TMP_DIR/forward_auth_ok.capture"
  write_http_response "$response_file" "AUTH_OK"
  serve_once 19091 "$response_file" "$capture_file"
  backend_pid="$LAST_PID"
  status=$(curl -sS --max-time "$CURL_MAX_TIME_SEC" --connect-timeout 2 "${CURL_RETRY_ARGS[@]}" --noproxy '' -x http://127.0.0.1:18150 \
    --proxy-user tester:secret \
    -o "$TMP_DIR/forward_auth_ok.body" \
    -D "$TMP_DIR/forward_auth_ok.headers" \
    -w '%{http_code}' \
    http://127.0.0.1:19091/auth/protected)
  wait_pid_with_timeout "$backend_pid" "$WAIT_PID_TIMEOUT_SEC"
  assert_eq "200" "$status" "forward auth success status"
  assert_eq "AUTH_OK" "$(cat "$TMP_DIR/forward_auth_ok.body")" "forward auth success body"

  stop_pid "$qpx_pid"
}

run_reverse_suite() {
  echo "[E2E] reverse suite"
  local proxy_log="$LOG_DIR/reverse.log"
  local qpx_pid
  start_qpxd "$CONFIG_DIR/e2e-reverse.yaml" 19150 "$proxy_log"
  qpx_pid="$LAST_PID"

  local response_file="$TMP_DIR/reverse.response"
  local capture_file="$TMP_DIR/reverse.capture"
  write_http_response "$response_file" "REVERSE_OK"
  local backend_pid
  serve_once 19092 "$response_file" "$capture_file"
  backend_pid="$LAST_PID"

  # Reverse has background upstream health checks that may connect immediately on startup.
  # If the first probe consumes our one-shot backend stub, restart it before issuing the request.
  for _ in {1..5}; do
    sleep 0.1
    if ! kill -0 "$backend_pid" >/dev/null 2>&1; then
      serve_once 19092 "$response_file" "$capture_file"
      backend_pid="$LAST_PID"
      break
    fi
  done

  local status
  status=$(curl -sS --max-time "$CURL_MAX_TIME_SEC" --connect-timeout 2 "${CURL_RETRY_ARGS[@]}" \
    -H 'Host: reverse.local' \
    -o "$TMP_DIR/reverse.body" \
    -D "$TMP_DIR/reverse.headers" \
    -w '%{http_code}' \
    http://127.0.0.1:19150/reverse-check)
  wait_pid_with_timeout "$backend_pid" "$WAIT_PID_TIMEOUT_SEC"

  assert_eq "200" "$status" "reverse status"
  assert_eq "REVERSE_OK" "$(cat "$TMP_DIR/reverse.body")" "reverse body"
  normalize_headers "$capture_file" "$capture_file.norm"
  assert_file_contains "$capture_file.norm" '^GET /reverse-check HTTP/1\.1$' "reverse routed request path"

  stop_pid "$qpx_pid"
}

run_transparent_suite() {
  echo "[E2E] transparent suite"
  local proxy_log="$LOG_DIR/transparent.log"
  local qpx_pid
  start_qpxd "$CONFIG_DIR/e2e-transparent.yaml" 15150 "$proxy_log"
  qpx_pid="$LAST_PID"

  local status
  status=$(curl -sS --max-time "$CURL_MAX_TIME_SEC" --connect-timeout 2 "${CURL_RETRY_ARGS[@]}" \
    -H 'Host: blocked.invalid' \
    -o "$TMP_DIR/transparent_block.body" \
    -D "$TMP_DIR/transparent_block.headers" \
    -w '%{http_code}' \
    http://127.0.0.1:15150/blocked)
  assert_eq "403" "$status" "transparent block status"
  assert_eq "forbidden" "$(cat "$TMP_DIR/transparent_block.body")" "transparent block body"

  local response_file="$TMP_DIR/transparent_trace.response"
  local capture_file="$TMP_DIR/transparent_trace.capture"
  write_http_response "$response_file" "TRACE_OK"
  local backend_pid
  serve_once 19093 "$response_file" "$capture_file"
  backend_pid="$LAST_PID"

  # Transparent may perform background connections (e.g. upstream readiness checks) that can consume
  # our one-shot backend stub. If that happens, restart it before issuing the request.
  for _ in {1..5}; do
    sleep 0.1
    if ! kill -0 "$backend_pid" >/dev/null 2>&1; then
      serve_once 19093 "$response_file" "$capture_file"
      backend_pid="$LAST_PID"
      break
    fi
  done

  status=$(curl -sS --max-time "$CURL_MAX_TIME_SEC" --connect-timeout 2 "${CURL_RETRY_ARGS[@]}" \
    -H 'Host: 127.0.0.1:19093' \
    -o "$TMP_DIR/transparent_trace.body" \
    -D "$TMP_DIR/transparent_trace.headers" \
    -w '%{http_code}' \
    http://127.0.0.1:15150/trace)
  wait_pid_with_timeout "$backend_pid" "$WAIT_PID_TIMEOUT_SEC"

  assert_eq "200" "$status" "transparent /trace status"
  assert_eq "TRACE_OK" "$(cat "$TMP_DIR/transparent_trace.body")" "transparent /trace body"
  normalize_headers "$capture_file" "$capture_file.norm"
  assert_file_contains "$capture_file.norm" '^x-transparent-test: enabled$' "transparent request header rewrite"

  stop_pid "$qpx_pid"
}

run_ipc_gateway_suite() {
  echo "[E2E] ipc gateway suite"

  local qpxf_log="$LOG_DIR/qpxf-unix.log"
  local qpxd_log="$LOG_DIR/ipc-unix.log"
  local qpxf_pid
  local qpxd_pid
  local status
  local qpxf_listen="unix://$IPC_RUNTIME_DIR/qpxf.sock"

  start_qpxf_unix "$IPC_CONFIG_DIR/qpxf.yaml" "$qpxf_listen" "$qpxf_log"
  qpxf_pid="$LAST_PID"

  QPXF_UNIX_LISTEN="$qpxf_listen" \
  QPX_IPC_GATEWAY_LISTEN="127.0.0.1:18098" \
  XDG_RUNTIME_DIR="$IPC_RUNTIME_DIR" \
    start_qpxd "$IPC_CONFIG_DIR/qpx.yaml" 18098 "$qpxd_log"
  qpxd_pid="$LAST_PID"

  status=$(curl -sS --max-time "$CURL_MAX_TIME_SEC" --connect-timeout 2 "${CURL_RETRY_ARGS[@]}" \
    -o "$TMP_DIR/ipc_unix_cgi.body" \
    -D "$TMP_DIR/ipc_unix_cgi.headers" \
    -w '%{http_code}' \
    http://127.0.0.1:18098/cgi-bin/health)
  assert_eq "200" "$status" "ipc unix cgi status"
  assert_eq "ok from qpxf cgi" "$(tr -d '\r' <"$TMP_DIR/ipc_unix_cgi.body")" "ipc unix cgi body"

  status=$(curl -sS --max-time "$CURL_MAX_TIME_SEC" --connect-timeout 2 "${CURL_RETRY_ARGS[@]}" \
    -o "$TMP_DIR/ipc_unix_wasm.body" \
    -D "$TMP_DIR/ipc_unix_wasm.headers" \
    -w '%{http_code}' \
    http://127.0.0.1:18098/wasm/echo)
  assert_eq "200" "$status" "ipc unix wasm status"
  assert_eq "ok from qpxf wasm" "$(tr -d '\r' <"$TMP_DIR/ipc_unix_wasm.body")" "ipc unix wasm body"

  stop_pid "$qpxd_pid"
  stop_pid "$qpxf_pid"

  qpxf_log="$LOG_DIR/qpxf-tcp.log"
  qpxd_log="$LOG_DIR/ipc-tcp.log"
  start_qpxf_tcp "$IPC_CONFIG_DIR/qpxf-tcp.yaml" "127.0.0.1:19098" "$qpxf_log"
  qpxf_pid="$LAST_PID"

  QPXF_TCP_LISTEN="127.0.0.1:19098" \
  QPX_IPC_GATEWAY_TCP_LISTEN="127.0.0.1:18099" \
  XDG_RUNTIME_DIR="$IPC_RUNTIME_DIR" \
    start_qpxd "$IPC_CONFIG_DIR/qpx-tcp.yaml" 18099 "$qpxd_log"
  qpxd_pid="$LAST_PID"

  status=$(curl -sS --max-time "$CURL_MAX_TIME_SEC" --connect-timeout 2 "${CURL_RETRY_ARGS[@]}" \
    -o "$TMP_DIR/ipc_tcp_cgi.body" \
    -D "$TMP_DIR/ipc_tcp_cgi.headers" \
    -w '%{http_code}' \
    http://127.0.0.1:18099/cgi-bin/health)
  assert_eq "200" "$status" "ipc tcp cgi status"
  assert_eq "ok from qpxf cgi" "$(tr -d '\r' <"$TMP_DIR/ipc_tcp_cgi.body")" "ipc tcp cgi body"

  status=$(curl -sS --max-time "$CURL_MAX_TIME_SEC" --connect-timeout 2 "${CURL_RETRY_ARGS[@]}" \
    -o "$TMP_DIR/ipc_tcp_wasm.body" \
    -D "$TMP_DIR/ipc_tcp_wasm.headers" \
    -w '%{http_code}' \
    http://127.0.0.1:18099/wasm/echo)
  assert_eq "200" "$status" "ipc tcp wasm status"
  assert_eq "ok from qpxf wasm" "$(tr -d '\r' <"$TMP_DIR/ipc_tcp_wasm.body")" "ipc tcp wasm body"

  stop_pid "$qpxd_pid"
  stop_pid "$qpxf_pid"
}

main() {
  require_cmd cargo
  require_cmd curl
  require_cmd nc
  require_cmd timeout
  require_cmd lsof

  if [ ! -x "$QPXD_BIN" ]; then
    echo "[E2E] building qpxd"
    cargo build -q -p qpxd --locked
  fi
  if [ ! -x "$QPXF_BIN" ]; then
    echo "[E2E] building qpxf"
    cargo build -q -p qpxf --locked
  fi
  if [ ! -x "$QPXD_BIN" ]; then
    echo "missing built qpxd binary: $QPXD_BIN" >&2
    exit 1
  fi
  if [ ! -x "$QPXF_BIN" ]; then
    echo "missing built qpxf binary: $QPXF_BIN" >&2
    exit 1
  fi

  run_forward_suite
  run_reverse_suite
  run_transparent_suite
  run_ipc_gateway_suite
  echo "[E2E] all sample-config checks passed"
}

main "$@"
