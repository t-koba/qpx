#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QPXD_BIN="${QPXD_BIN:-$ROOT_DIR/target/debug/qpxd}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/qpx-h2-e2e.XXXXXX")"
STATE_DIR="$TMP_DIR/state"
LOG_DIR="$TMP_DIR/logs"
mkdir -p "$STATE_DIR" "$LOG_DIR"

PORT_BASE=$((30000 + ($$ % 10000)))
REV_H2C_PROXY_PORT=$((PORT_BASE + 10))
REV_H2C_BACKEND_PORT=$((PORT_BASE + 11))
TRANS_PROXY_PORT=$((PORT_BASE + 12))
TRANS_BACKEND_PORT=$((PORT_BASE + 13))
REV_TLS_PROXY_PORT=$((PORT_BASE + 14))
REV_TLS_BACKEND_PORT=$((PORT_BASE + 15))

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
  return 0
}

write_reverse_backend_config() {
  local cfg="$1"
  local listen_port="$2"
  local ok_body="$3"
  local ok_path="$4"
  cat >"$cfg" <<YAML
version: 1
state_dir: "${STATE_DIR}"
reverse:
  - name: h2-backend
    listen: "127.0.0.1:${listen_port}"
    routes:
      - match:
          path: ["${ok_path}"]
        upstreams: []
        local_response:
          status: 200
          body: "${ok_body}"
      - match: {}
        upstreams: []
        local_response:
          status: 418
          body: "ROUTE_MISS"
YAML
}

write_transparent_backend_config() {
  local cfg="$1"
  local listen_port="$2"
  cat >"$cfg" <<YAML
version: 1
state_dir: "${STATE_DIR}"
listeners:
  - name: transparent-http2-backend
    mode: forward
    listen: "127.0.0.1:${listen_port}"
    default_action:
      type: respond
      local_response:
        status: 428
        body: "HEADER_MISSING"
    rules:
      - name: trace-with-header
        match:
          host: ["127.0.0.1"]
          path: ["/trace"]
          headers:
            - name: "x-transparent-test"
              value: "enabled"
        action:
          type: respond
          local_response:
            status: 200
            body: "H2TRACE!"
YAML
}

run_reverse_h2c_suite() {
  echo "[H2-E2E] reverse h2c"
  local backend_cfg="$TMP_DIR/reverse-h2c-backend.yaml"
  local proxy_cfg="$TMP_DIR/reverse-h2c-proxy.yaml"

  write_reverse_backend_config "$backend_cfg" "$REV_H2C_BACKEND_PORT" "H2REV!!" "/h2"

  cat >"$proxy_cfg" <<YAML
version: 1
state_dir: "${STATE_DIR}"
reverse:
  - name: e2e-reverse-h2c
    listen: "127.0.0.1:${REV_H2C_PROXY_PORT}"
    routes:
      - match:
          host: ["reverse.local"]
        upstreams: ["http://127.0.0.1:${REV_H2C_BACKEND_PORT}"]
        lb: round_robin
        retry:
          attempts: 1
          backoff_ms: 20
        timeout_ms: 5000
YAML

  local backend_log="$LOG_DIR/reverse-h2c-backend.log"
  start_qpxd "$backend_cfg" "$REV_H2C_BACKEND_PORT" "$backend_log"
  local bpid="$LAST_PID"

  local proxy_log="$LOG_DIR/reverse-h2c-proxy.log"
  start_qpxd "$proxy_cfg" "$REV_H2C_PROXY_PORT" "$proxy_log"
  local qpid="$LAST_PID"

  local status
  status=$(curl -sS --http2-prior-knowledge --max-time 8 \
    -H 'Host: reverse.local' \
    -o "$TMP_DIR/reverse-h2c.body" \
    -D "$TMP_DIR/reverse-h2c.headers" \
    -w '%{http_code}' \
    "http://127.0.0.1:${REV_H2C_PROXY_PORT}/h2")

  assert_eq "200" "$status" "reverse h2c status"
  assert_eq "H2REV!!" "$(cat "$TMP_DIR/reverse-h2c.body")" "reverse h2c body"

  stop_pid "$qpid"
  stop_pid "$bpid"
}

run_transparent_h2c_suite() {
  echo "[H2-E2E] transparent h2c"
  local backend_cfg="$TMP_DIR/transparent-h2c-backend.yaml"
  local proxy_cfg="$TMP_DIR/transparent-h2c-proxy.yaml"

  write_transparent_backend_config "$backend_cfg" "$TRANS_BACKEND_PORT"

  cat >"$proxy_cfg" <<YAML
version: 1
state_dir: "${STATE_DIR}"
listeners:
  - name: e2e-transparent
    mode: transparent
    listen: "127.0.0.1:${TRANS_PROXY_PORT}"
    default_action: { type: direct }
    rules:
      - name: block-transparent-host
        match:
          host: ["blocked.invalid"]
        action: { type: block }
      - name: trace-transparent-header
        match:
          host: ["127.0.0.1"]
          path: ["/trace"]
        action: { type: direct }
        headers:
          request_set:
            X-Transparent-Test: enabled
YAML

  local backend_log="$LOG_DIR/transparent-h2c-backend.log"
  start_qpxd "$backend_cfg" "$TRANS_BACKEND_PORT" "$backend_log"
  local bpid="$LAST_PID"

  local proxy_log="$LOG_DIR/transparent-h2c-proxy.log"
  start_qpxd "$proxy_cfg" "$TRANS_PROXY_PORT" "$proxy_log"
  local qpid="$LAST_PID"

  local status
  status=$(curl -sS --http2-prior-knowledge --max-time 8 \
    -H "Host: 127.0.0.1:${TRANS_BACKEND_PORT}" \
    -o "$TMP_DIR/transparent-h2c.body" \
    -D "$TMP_DIR/transparent-h2c.headers" \
    -w '%{http_code}' \
    "http://127.0.0.1:${TRANS_PROXY_PORT}/trace")

  assert_eq "200" "$status" "transparent h2c status"
  assert_eq "H2TRACE!" "$(cat "$TMP_DIR/transparent-h2c.body")" "transparent h2c body"

  stop_pid "$qpid"
  stop_pid "$bpid"
}

run_reverse_tls_h2_suite() {
  echo "[H2-E2E] reverse tls h2"
  local cert="$TMP_DIR/rev-h2.crt"
  local key="$TMP_DIR/rev-h2.key"
  local backend_cfg="$TMP_DIR/rev-h2-backend.yaml"
  local proxy_cfg="$TMP_DIR/rev-h2-proxy.yaml"

  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$key" \
    -out "$cert" \
    -subj '/CN=reverse.local' \
    -days 1 >/dev/null 2>&1

  write_reverse_backend_config "$backend_cfg" "$REV_TLS_BACKEND_PORT" "H2TLS!" "/h2"

  cat >"$proxy_cfg" <<YAML
version: 1
state_dir: "${STATE_DIR}"
reverse:
  - name: rev-h2
    listen: "127.0.0.1:${REV_TLS_PROXY_PORT}"
    tls:
      certificates:
        - sni: "reverse.local"
          cert: "${cert}"
          key: "${key}"
    routes:
      - match:
          host: ["reverse.local"]
        upstreams: ["http://127.0.0.1:${REV_TLS_BACKEND_PORT}"]
YAML

  local backend_log="$LOG_DIR/reverse-tls-h2-backend.log"
  start_qpxd "$backend_cfg" "$REV_TLS_BACKEND_PORT" "$backend_log"
  local bpid="$LAST_PID"

  local proxy_log="$LOG_DIR/reverse-tls-h2-proxy.log"
  start_qpxd "$proxy_cfg" "$REV_TLS_PROXY_PORT" "$proxy_log"
  local qpid="$LAST_PID"

  local status
  status=$(curl -sS -k --http2 --max-time 8 --noproxy '*' \
    --resolve "reverse.local:${REV_TLS_PROXY_PORT}:127.0.0.1" \
    -o "$TMP_DIR/reverse-tls-h2.body" \
    -D "$TMP_DIR/reverse-tls-h2.headers" \
    -w '%{http_code}' \
    "https://reverse.local:${REV_TLS_PROXY_PORT}/h2")

  assert_eq "200" "$status" "reverse tls h2 status"
  assert_eq "H2TLS!" "$(cat "$TMP_DIR/reverse-tls-h2.body")" "reverse tls h2 body"

  stop_pid "$qpid"
  stop_pid "$bpid"
}

main() {
  require_cmd cargo
  require_cmd curl
  require_cmd nc
  require_cmd openssl

  echo "[H2-E2E] building qpxd"
  cargo build -q -p qpxd
  if [ ! -x "$QPXD_BIN" ]; then
    echo "missing built qpxd binary: $QPXD_BIN" >&2
    exit 1
  fi

  run_reverse_h2c_suite
  run_transparent_h2c_suite
  run_reverse_tls_h2_suite
  echo "[H2-E2E] all HTTP/2 checks passed"
}

main "$@"
