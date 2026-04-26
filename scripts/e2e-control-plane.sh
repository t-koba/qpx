#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QPXD_BIN="${QPXD_BIN:-$ROOT_DIR/target/debug/qpxd}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/qpx-control-plane.XXXXXX")"
CONFIG_FILE="$TMP_DIR/control-plane.yaml"
LOG_FILE="$TMP_DIR/qpxd.log"
STATE_DIR="$TMP_DIR/state"
PORT="${QPX_CONTROL_PLANE_PORT:-}"
RESTART_PORT="${QPX_CONTROL_PLANE_RESTART_PORT:-}"
PIDS=()

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
  if [ -f "$CONFIG_FILE" ]; then
    while IFS= read -r pid; do
      if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
        kill "$pid" >/dev/null 2>&1 || true
        wait "$pid" >/dev/null 2>&1 || true
      fi
    done < <(pgrep -f "$CONFIG_FILE" || true)
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
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
  local tries=0

  while [ "$tries" -lt 100 ]; do
    if port_open "$port"; then
      return 0
    fi
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "qpxd exited before opening port $port" >&2
      cat "$LOG_FILE" >&2 || true
      exit 1
    fi
    tries=$((tries + 1))
    sleep 0.1
  done

  echo "timeout waiting for port $port" >&2
  cat "$LOG_FILE" >&2 || true
  exit 1
}

wait_log_contains() {
  local needle="$1"
  local tries=0

  while [ "$tries" -lt 120 ]; do
    if grep -Fq "$needle" "$LOG_FILE" 2>/dev/null; then
      return 0
    fi
    tries=$((tries + 1))
    sleep 0.1
  done

  echo "missing expected log line: $needle" >&2
  cat "$LOG_FILE" >&2 || true
  exit 1
}

request_body() {
  curl -fsS --max-time 3 \
    -H 'Host: control.local' \
    "http://127.0.0.1:${PORT}/health"
}

wait_body() {
  local expected="$1"
  local tries=0
  local body=""

  while [ "$tries" -lt 120 ]; do
    body="$(request_body 2>/dev/null || true)"
    if [ "$body" = "$expected" ]; then
      return 0
    fi
    tries=$((tries + 1))
    sleep 0.1
  done

  echo "unexpected response body (expected=$expected actual=$body)" >&2
  cat "$LOG_FILE" >&2 || true
  exit 1
}

install_config() {
  local body="$1"
  local acceptors="$2"
  local tcp_backlog=4096
  local tmp_cfg="$TMP_DIR/control-plane.next.yaml"

  if [ "$acceptors" -gt 1 ]; then
    tcp_backlog=4097
  fi

  cat >"$tmp_cfg" <<EOF
state_dir: '$STATE_DIR'
runtime:
  acceptor_tasks_per_listener: $acceptors
  reuse_port: false
  tcp_backlog: $tcp_backlog
reverse:
- name: control
  listen: 127.0.0.1:$PORT
  routes:
  - name: health
    match:
      host:
      - control.local
      path:
      - /health
    local_response:
      status: 200
      body: $body
EOF

  if [ "$acceptors" -gt 1 ]; then
    cat >>"$tmp_cfg" <<EOF
- name: control-extra
  listen: 127.0.0.1:$RESTART_PORT
  routes:
  - name: health
    match:
      host:
      - control.local
      path:
      - /health
    local_response:
      status: 200
      body: $body
EOF
  fi

  mv "$tmp_cfg" "$CONFIG_FILE"
}

main() {
  require_cmd curl
  require_cmd grep
  require_cmd nc
  require_cmd pgrep
  require_cmd python3

  if [ -z "$PORT" ]; then
    PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
  fi
  if [ -z "$RESTART_PORT" ]; then
    RESTART_PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
  fi

  mkdir -p "$STATE_DIR"
  install_config OLD 1

  echo "[CONTROL] start qpxd"
  RUST_LOG=info "$QPXD_BIN" run --config "$CONFIG_FILE" >"$LOG_FILE" 2>&1 &
  local parent_pid=$!
  register_pid "$parent_pid"
  wait_port "$PORT" "$parent_pid"
  wait_body "OLD"

  echo "[CONTROL] hot reload in place"
  install_config RELOADED 1
  wait_log_contains "config reloaded"
  wait_body "RELOADED"

  echo "[CONTROL] hot reload with listener/reverse restart"
  install_config RESTARTED 2
  wait_log_contains "config reloaded; listener/reverse server set restarted"
  wait_body "RESTARTED"

  echo "[CONTROL] binary upgrade"
  "$QPXD_BIN" upgrade --pid "$parent_pid"

  local child_pid=""
  local tries=0
  while [ "$tries" -lt 120 ]; do
    child_pid="$(pgrep -f "$CONFIG_FILE" | grep -v "^${parent_pid}\$" | head -n1 || true)"
    if [ -n "$child_pid" ]; then
      break
    fi
    tries=$((tries + 1))
    sleep 0.1
  done

  if [ -z "$child_pid" ]; then
    echo "failed to locate upgraded child process" >&2
    cat "$LOG_FILE" >&2 || true
    exit 1
  fi
  register_pid "$child_pid"

  tries=0
  while kill -0 "$parent_pid" >/dev/null 2>&1; do
    if [ "$tries" -ge 120 ]; then
      echo "parent did not exit after binary upgrade" >&2
      cat "$LOG_FILE" >&2 || true
      exit 1
    fi
    tries=$((tries + 1))
    sleep 0.1
  done

  wait_body "RESTARTED"
  echo "[CONTROL] hot reload and binary upgrade e2e passed"
}

main "$@"
