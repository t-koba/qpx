#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR="$ROOT_DIR/config/usecases/06-local-response"
QPXD_BIN="${QPXD_BIN:-$ROOT_DIR/target/debug/qpxd}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/qpx-local-response-e2e.XXXXXX")"
STATE_DIR="$TMP_DIR/state"
LOG_DIR="$TMP_DIR/logs"
mkdir -p "$STATE_DIR" "$LOG_DIR"

FORWARD_PORT=18181
REVERSE_PORT=19181
TRANSPARENT_PORT=15181

PIDS=()
LAST_PID=""

register_pid() {
  PIDS+=("$1")
}

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

assert_eq() {
  local expected="$1"
  local actual="$2"
  local message="$3"
  if [ "$expected" != "$actual" ]; then
    echo "ASSERT FAILED: $message (expected=$expected actual=$actual)" >&2
    exit 1
  fi
}

assert_contains() {
  local file="$1"
  local pattern="$2"
  local message="$3"
  if ! tr -d '\r' <"$file" | grep -Eiq "$pattern"; then
    echo "ASSERT FAILED: $message" >&2
    echo "--- $file ---" >&2
    cat "$file" >&2 || true
    echo "-------------" >&2
    exit 1
  fi
}

assert_not_contains() {
  local file="$1"
  local pattern="$2"
  local message="$3"
  if tr -d '\r' <"$file" | grep -Eiq "$pattern"; then
    echo "ASSERT FAILED: $message" >&2
    echo "--- $file ---" >&2
    cat "$file" >&2 || true
    echo "-------------" >&2
    exit 1
  fi
}

wait_port() {
  local port="$1"
  local pid="$2"
  local log_file="$3"
  local tries=0
  while [ "$tries" -lt 100 ]; do
    if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
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

stop_pid() {
  local pid="$1"
  if kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  fi
}

run_forward_suite() {
  echo "[LOCAL-E2E] forward local response"
  local log_file="$LOG_DIR/local-forward.log"
  start_qpxd "$CONFIG_DIR/forward-debug.yaml" "$FORWARD_PORT" "$log_file"
  local qpid="$LAST_PID"

  local status
  status=$(curl -sS --max-time 8 --noproxy '' -x "http://127.0.0.1:${FORWARD_PORT}" \
    -H 'Host: proxy.local' \
    -o "$TMP_DIR/forward-health.body" \
    -D "$TMP_DIR/forward-health.headers" \
    -w '%{http_code}' \
    http://proxy.local/proxy/healthz)
  assert_eq "200" "$status" "forward health status"
  assert_eq '{"status":"ok","component":"qpx-forward"}' "$(cat "$TMP_DIR/forward-health.body")" "forward health body"
  assert_contains "$TMP_DIR/forward-health.headers" '^x-qpx-route: local-healthz$' "forward local response header"

  status=$(curl -sS --max-time 8 --noproxy '' -x "http://127.0.0.1:${FORWARD_PORT}" \
    -o "$TMP_DIR/forward-block.body" \
    -D "$TMP_DIR/forward-block.headers" \
    -w '%{http_code}' \
    http://test.phishing.invalid/)
  assert_eq "451" "$status" "forward block status"
  assert_eq 'blocked by security policy' "$(cat "$TMP_DIR/forward-block.body")" "forward block body"
  assert_contains "$TMP_DIR/forward-block.headers" '^x-policy-reason: security-category$' "forward block policy header"

  status=$(curl -sS --max-time 8 --noproxy '' -x "http://127.0.0.1:${FORWARD_PORT}" \
    --head \
    -o /dev/null \
    -D "$TMP_DIR/forward-head.headers" \
    -w '%{http_code}' \
    http://test.phishing.invalid/)
  assert_eq "451" "$status" "forward HEAD status"
  assert_not_contains "$TMP_DIR/forward-head.headers" '^content-length:' "forward HEAD should not include content-length"
  assert_not_contains "$TMP_DIR/forward-head.headers" '^transfer-encoding:' "forward HEAD should not include transfer-encoding"

  stop_pid "$qpid"
}

run_reverse_suite() {
  echo "[LOCAL-E2E] reverse local response"
  local log_file="$LOG_DIR/local-reverse.log"
  start_qpxd "$CONFIG_DIR/reverse-maintenance.yaml" "$REVERSE_PORT" "$log_file"
  local qpid="$LAST_PID"

  local status
  status=$(curl -sS --max-time 8 \
    -H 'Host: app.example.com' \
    -o "$TMP_DIR/reverse-status.body" \
    -D "$TMP_DIR/reverse-status.headers" \
    -w '%{http_code}' \
    "http://127.0.0.1:${REVERSE_PORT}/status")
  assert_eq "200" "$status" "reverse /status status"
  assert_eq '{"ok":true,"source":"qpx-reverse"}' "$(cat "$TMP_DIR/reverse-status.body")" "reverse /status body"

  status=$(curl -sS --max-time 8 \
    -H 'Host: app.example.com' \
    -o "$TMP_DIR/reverse-maint.body" \
    -D "$TMP_DIR/reverse-maint.headers" \
    -w '%{http_code}' \
    "http://127.0.0.1:${REVERSE_PORT}/maintenance/window")
  assert_eq "503" "$status" "reverse /maintenance status"
  assert_contains "$TMP_DIR/reverse-maint.body" 'Maintenance' "reverse maintenance body"

  status=$(curl -sS --max-time 8 \
    --head \
    -H 'Host: app.example.com' \
    -o /dev/null \
    -D "$TMP_DIR/reverse-head.headers" \
    -w '%{http_code}' \
    "http://127.0.0.1:${REVERSE_PORT}/status")
  assert_eq "200" "$status" "reverse HEAD status"
  assert_not_contains "$TMP_DIR/reverse-head.headers" '^content-length:' "reverse HEAD should not include content-length"
  assert_not_contains "$TMP_DIR/reverse-head.headers" '^transfer-encoding:' "reverse HEAD should not include transfer-encoding"

  stop_pid "$qpid"
}

run_transparent_suite() {
  echo "[LOCAL-E2E] transparent local response"
  local log_file="$LOG_DIR/local-transparent.log"
  start_qpxd "$CONFIG_DIR/transparent-captive-portal.yaml" "$TRANSPARENT_PORT" "$log_file"
  local qpid="$LAST_PID"

  local status
  status=$(curl -sS --max-time 8 \
    -H 'Host: connectivitycheck.gstatic.com' \
    -o "$TMP_DIR/transparent-portal.body" \
    -D "$TMP_DIR/transparent-portal.headers" \
    -w '%{http_code}' \
    "http://127.0.0.1:${TRANSPARENT_PORT}/generate_204")
  assert_eq "200" "$status" "transparent portal status"
  assert_contains "$TMP_DIR/transparent-portal.body" 'Network Login Required' "transparent portal body"
  assert_contains "$TMP_DIR/transparent-portal.headers" '^cache-control: no-store$' "transparent portal cache header"

  status=$(curl -sS --max-time 8 \
    --head \
    -H 'Host: connectivitycheck.gstatic.com' \
    -o /dev/null \
    -D "$TMP_DIR/transparent-head.headers" \
    -w '%{http_code}' \
    "http://127.0.0.1:${TRANSPARENT_PORT}/generate_204")
  assert_eq "200" "$status" "transparent HEAD status"
  assert_not_contains "$TMP_DIR/transparent-head.headers" '^content-length:' "transparent HEAD should not include content-length"
  assert_not_contains "$TMP_DIR/transparent-head.headers" '^transfer-encoding:' "transparent HEAD should not include transfer-encoding"

  stop_pid "$qpid"
}

main() {
  require_cmd cargo
  require_cmd curl
  require_cmd lsof

  echo "[LOCAL-E2E] building qpxd"
  cargo build -q -p qpxd

  run_forward_suite
  run_reverse_suite
  run_transparent_suite
  echo "[LOCAL-E2E] all local-response checks passed"
}

main "$@"
