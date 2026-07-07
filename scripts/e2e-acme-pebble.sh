#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QPXD_BIN="${QPXD_BIN:-$ROOT_DIR/target/debug/qpxd}"
TMP_PARENT="${QPX_ACME_PEBBLE_TMPDIR:-/private/tmp}"
if [ ! -d "$TMP_PARENT" ]; then
  TMP_PARENT="${TMPDIR:-/tmp}"
fi
TMP_DIR="$(mktemp -d "$TMP_PARENT/qpx-acme-pebble.XXXXXX")"
BIN_DIR="$TMP_DIR/bin"
LOG_DIR="$TMP_DIR/logs"
STATE_ROOT="$TMP_DIR/state"
mkdir -p "$BIN_DIR" "$LOG_DIR" "$STATE_ROOT"

PIDS=()

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

register_pid() {
  PIDS+=("$1")
}

pick_ports() {
  python3 - <<'PY'
import socket

sockets = []
try:
    for _ in range(8):
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.bind(("::1", 0))
        sockets.append(sock)
    print(" ".join(str(sock.getsockname()[1]) for sock in sockets))
finally:
    for sock in sockets:
        sock.close()
PY
}

download_pebble_binary() {
  local name="$1"
  local asset_prefix="$2"
  local output="$BIN_DIR/$name"
  local os arch platform url
  if command -v "$name" >/dev/null 2>&1; then
    command -v "$name"
    return
  fi
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os/$arch" in
    Linux/x86_64) platform="linux-amd64" ;;
    Darwin/arm64) platform="darwin-arm64" ;;
    Darwin/x86_64) platform="darwin-amd64" ;;
    *)
      echo "$name not found and automatic download is unsupported on $os/$arch" >&2
      exit 1
      ;;
  esac
  url="https://github.com/letsencrypt/pebble/releases/latest/download/${asset_prefix}-${platform}.tar.gz"
  curl -fsSL "$url" | tar xz -C "$BIN_DIR" --strip-components=3
  chmod +x "$output"
  printf '%s\n' "$output"
}

wait_for_url() {
  local name="$1"
  local url="$2"
  local pid="$3"
  local log_file="$4"
  local curl_args=("${@:5}")
  local tries=0
  while [ "$tries" -lt 150 ]; do
    if curl -fsS --max-time 2 "${curl_args[@]}" "$url" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "$name exited before becoming ready" >&2
      cat "$log_file" >&2 || true
      exit 1
    fi
    tries=$((tries + 1))
    sleep 0.2
  done
  echo "timeout waiting for $name at $url" >&2
  cat "$log_file" >&2 || true
  exit 1
}

wait_for_tcp() {
  local name="$1"
  local host="$2"
  local port="$3"
  local pid="$4"
  local log_file="$5"
  local tries=0
  while [ "$tries" -lt 150 ]; do
    if (echo >/dev/tcp/"$host"/"$port") >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "$name exited before opening $host:$port" >&2
      cat "$log_file" >&2 || true
      exit 1
    fi
    tries=$((tries + 1))
    sleep 0.2
  done
  echo "timeout waiting for $name at $host:$port" >&2
  cat "$log_file" >&2 || true
  exit 1
}

wait_for_cert() {
  local sni="$1"
  local state_dir="$2"
  local qpxd_pid="$3"
  local log_file="$4"
  local cert="$state_dir/acme/certs/$sni/cert.pem"
  local key="$state_dir/acme/certs/$sni/key.pem"
  local tries=0
  while [ "$tries" -lt 180 ]; do
    if [ -s "$cert" ] && [ -s "$key" ]; then
      openssl x509 -in "$cert" -noout -subject -issuer >/dev/null
      return 0
    fi
    if ! kill -0 "$qpxd_pid" >/dev/null 2>&1; then
      echo "qpxd exited before issuing ACME certificate for $sni" >&2
      cat "$log_file" >&2 || true
      exit 1
    fi
    tries=$((tries + 1))
    sleep 1
  done
  echo "timeout waiting for ACME certificate for $sni" >&2
  cat "$log_file" >&2 || true
  exit 1
}

stop_pid() {
  local pid="$1"
  if kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  fi
}

write_dns_hooks() {
  local management_port="$1"
  local set_hook="$TMP_DIR/dns-set.sh"
  local clear_hook="$TMP_DIR/dns-clear.sh"
  cat >"$set_hook" <<SH
#!/usr/bin/env bash
set -euo pipefail
curl -fsS -X POST -H 'Content-Type: application/json' \\
  --data "{\\"host\\":\\"_acme-challenge.\${QPX_ACME_DOMAIN}.\\",\\"value\\":\\"\${QPX_ACME_TXT_VALUE}\\"}" \\
  "http://127.0.0.1:${management_port}/set-txt" >/dev/null
SH
  cat >"$clear_hook" <<SH
#!/usr/bin/env bash
set -euo pipefail
curl -fsS -X POST -H 'Content-Type: application/json' \\
  --data "{\\"host\\":\\"_acme-challenge.\${QPX_ACME_DOMAIN}.\\",\\"value\\":\\"\\"}" \\
  "http://127.0.0.1:${management_port}/set-txt" >/dev/null
SH
  chmod +x "$set_hook" "$clear_hook"
  printf '%s %s\n' "$set_hook" "$clear_hook"
}

write_qpxd_config() {
  local config="$1"
  local state_dir="$2"
  local sni="$3"
  local challenge="$4"
  local pebble_port="$5"
  local http_port="$6"
  local tls_port="$7"
  local set_hook="${8:-}"
  local clear_hook="${9:-}"

  {
    cat <<YAML
state_dir: "$state_dir"
acme:
  enabled: true
  terms_of_service_agreed: true
  email: ops@example.invalid
  directory_url: "https://127.0.0.1:${pebble_port}/dir"
  challenge: "$challenge"
  renew_before_days: 30
YAML
    if [ "$challenge" = "http-01" ]; then
      printf '  http01_listen: "[::]:%s"\n' "$http_port"
    fi
    if [ "$challenge" = "dns-01" ]; then
      cat <<YAML
  dns_hook:
    set_command: "$set_hook"
    clear_command: "$clear_hook"
    propagation_wait_secs: 1
YAML
    fi
    cat <<YAML
edges:
- kind: reverse
  name: "acme-${challenge}"
  listen: "[::]:${tls_port}"
  tls:
    certificates:
    - sni: "$sni"
  routes:
  - match:
      host:
      - "$sni"
    target:
      type: local_response
      response:
        status: 200
        body: "ACME_OK"
YAML
  } >"$config"
}

run_case() {
  local challenge="$1"
  local sni="$2"
  local pebble_port="$3"
  local http_port="$4"
  local tls_port="$5"
  local set_hook="${6:-}"
  local clear_hook="${7:-}"
  local state_dir="$STATE_ROOT/$challenge"
  local config="$TMP_DIR/qpxd-$challenge.yaml"
  local log_file="$LOG_DIR/qpxd-$challenge.log"
  mkdir -p "$state_dir"
  write_qpxd_config "$config" "$state_dir" "$sni" "$challenge" "$pebble_port" "$http_port" "$tls_port" "$set_hook" "$clear_hook"
  QPX_ACME_ROOT_CERT="$TMP_DIR/pebble-ca.pem" QPX_STATE_DIR="$state_dir" "$QPXD_BIN" run --config "$config" >"$log_file" 2>&1 &
  local pid=$!
  register_pid "$pid"
  wait_for_cert "$sni" "$state_dir" "$pid" "$log_file"
  stop_pid "$pid"
  echo "[ACME-E2E] $challenge issued certificate for $sni"
}

require_cmd curl
require_cmd openssl
require_cmd python3

if [ ! -x "$QPXD_BIN" ]; then
  echo "missing qpxd binary: $QPXD_BIN" >&2
  exit 1
fi

PEBBLE_BIN="$(download_pebble_binary pebble pebble)"
CHALLTESTSRV_BIN="$(download_pebble_binary pebble-challtestsrv pebble-challtestsrv)"

read -r PEBBLE_PORT PEBBLE_MGMT_PORT CHALL_DNS_PORT CHALL_MGMT_PORT HTTP_PORT TLS_PORT CHALL_HTTP_PORT CHALL_TLS_PORT < <(pick_ports)

openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$TMP_DIR/pebble-ca.key" \
  -out "$TMP_DIR/pebble-ca.pem" \
  -subj "/CN=qpx pebble e2e root" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -keyout "$TMP_DIR/pebble.key" \
  -out "$TMP_DIR/pebble.csr" \
  -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" >/dev/null 2>&1
cat >"$TMP_DIR/pebble-server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:127.0.0.1,DNS:localhost
EOF
openssl x509 -req -days 2 \
  -in "$TMP_DIR/pebble.csr" \
  -CA "$TMP_DIR/pebble-ca.pem" \
  -CAkey "$TMP_DIR/pebble-ca.key" \
  -CAcreateserial \
  -out "$TMP_DIR/pebble.pem" \
  -extfile "$TMP_DIR/pebble-server.ext" >/dev/null 2>&1

cat >"$TMP_DIR/pebble-config.json" <<JSON
{
  "pebble": {
    "listenAddress": "127.0.0.1:${PEBBLE_PORT}",
    "managementListenAddress": "127.0.0.1:${PEBBLE_MGMT_PORT}",
    "certificate": "$TMP_DIR/pebble.pem",
    "privateKey": "$TMP_DIR/pebble.key",
    "httpPort": ${HTTP_PORT},
    "tlsPort": ${TLS_PORT},
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false,
    "domainBlocklist": [],
    "retryAfter": {
      "authz": 1,
      "order": 1
    }
  }
}
JSON

"$CHALLTESTSRV_BIN" \
  -management ":${CHALL_MGMT_PORT}" \
  -dnsserver ":${CHALL_DNS_PORT}" \
  -http01 ":${CHALL_HTTP_PORT}" \
  -tlsalpn01 ":${CHALL_TLS_PORT}" \
  -https01 "" \
  -doh "" >"$LOG_DIR/challtestsrv.log" 2>&1 &
CHALL_PID=$!
register_pid "$CHALL_PID"
wait_for_tcp "pebble-challtestsrv" "127.0.0.1" "$CHALL_MGMT_PORT" "$CHALL_PID" "$LOG_DIR/challtestsrv.log"

PEBBLE_VA_NOSLEEP=1 "$PEBBLE_BIN" \
  -config "$TMP_DIR/pebble-config.json" \
  -dnsserver "127.0.0.1:${CHALL_DNS_PORT}" \
  -strict >"$LOG_DIR/pebble.log" 2>&1 &
PEBBLE_PID=$!
register_pid "$PEBBLE_PID"
wait_for_url "pebble" "https://127.0.0.1:${PEBBLE_PORT}/dir" "$PEBBLE_PID" "$LOG_DIR/pebble.log" --cacert "$TMP_DIR/pebble-ca.pem"

read -r DNS_SET_HOOK DNS_CLEAR_HOOK < <(write_dns_hooks "$CHALL_MGMT_PORT")

run_case "http-01" "f3-http01.example.com" "$PEBBLE_PORT" "$HTTP_PORT" "$TLS_PORT"
run_case "tls-alpn-01" "f3-tlsalpn.example.com" "$PEBBLE_PORT" "$HTTP_PORT" "$TLS_PORT"
run_case "dns-01" "f3-dns01.example.com" "$PEBBLE_PORT" "$HTTP_PORT" "$TLS_PORT" "$DNS_SET_HOOK" "$DNS_CLEAR_HOOK"

echo "[ACME-E2E] all Pebble checks passed"
