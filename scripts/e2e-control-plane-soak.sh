#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QPXD_BIN="${QPXD_BIN:-$ROOT_DIR/target/debug/qpxd}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/qpx-control-plane-soak.XXXXXX")"
CONFIG_FILE="$TMP_DIR/control-plane.yaml"
LOG_FILE="$TMP_DIR/qpxd.log"
STATE_DIR="$TMP_DIR/state"
TRAFFIC_FILE="$TMP_DIR/traffic.log"
FAIL_FILE="$TMP_DIR/failures.log"
STOP_FILE="$TMP_DIR/stop"
PORT="${QPX_CONTROL_PLANE_PORT:-}"
PIDS=()

register_pid() {
  PIDS+=("$1")
}

cleanup() {
  touch "$STOP_FILE" 2>/dev/null || true
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
  curl -fsS --max-time 1 \
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
  local tmp_cfg="$TMP_DIR/control-plane.next.yaml"

  cat >"$tmp_cfg" <<EOF
state_dir: '$STATE_DIR'
runtime:
  acceptor_tasks_per_listener: $acceptors
  reuse_port: false
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

  mv "$tmp_cfg" "$CONFIG_FILE"
}

start_traffic_loop() {
  : >"$TRAFFIC_FILE"
  : >"$FAIL_FILE"
  (
    while [ ! -f "$STOP_FILE" ]; do
      if body="$(request_body 2>/dev/null)"; then
        printf '%s\n' "$body" >>"$TRAFFIC_FILE"
      else
        printf 'request_failed\n' >>"$FAIL_FILE"
      fi
      sleep 0.02
    done
  ) &
  register_pid "$!"
}

assert_soak_results() {
  if [ -s "$FAIL_FILE" ]; then
    echo "control-plane soak observed failed requests" >&2
    cat "$FAIL_FILE" >&2 || true
    cat "$LOG_FILE" >&2 || true
    exit 1
  fi

  local samples
  samples="$(wc -l <"$TRAFFIC_FILE" | tr -d ' ')"
  if [ "${samples:-0}" -lt 50 ]; then
    echo "control-plane soak captured too few responses: $samples" >&2
    cat "$TRAFFIC_FILE" >&2 || true
    exit 1
  fi

  local seen
  seen="$(sort -u "$TRAFFIC_FILE" | tr '\n' ' ')"
  case " $seen " in
    *" OLD "* ) ;;
    * ) echo "control-plane soak never observed OLD body" >&2; exit 1 ;;
  esac
  case " $seen " in
    *" RELOADED "* ) ;;
    * ) echo "control-plane soak never observed RELOADED body" >&2; exit 1 ;;
  esac
  case " $seen " in
    *" RESTARTED "* ) ;;
    * ) echo "control-plane soak never observed RESTARTED body" >&2; exit 1 ;;
  esac
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

  mkdir -p "$STATE_DIR"
  install_config OLD 1

  echo "[CONTROL-SOAK] start qpxd"
  RUST_LOG=info "$QPXD_BIN" run --config "$CONFIG_FILE" >"$LOG_FILE" 2>&1 &
  local parent_pid=$!
  register_pid "$parent_pid"
  wait_port "$PORT" "$parent_pid"
  wait_body "OLD"

  start_traffic_loop
  sleep 1

  echo "[CONTROL-SOAK] hot reload in place under load"
  install_config RELOADED 1
  wait_log_contains "config reloaded"
  wait_body "RELOADED"
  sleep 1

  echo "[CONTROL-SOAK] hot reload with restart under load"
  install_config RESTARTED 2
  wait_log_contains "config reloaded; listener/reverse server set restarted"
  wait_body "RESTARTED"
  sleep 1

  echo "[CONTROL-SOAK] binary upgrade under load"
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
  sleep 2

  touch "$STOP_FILE"
  sleep 0.1
  assert_soak_results
  echo "[CONTROL-SOAK] reload/upgrade under load e2e passed"
}

main "$@"
