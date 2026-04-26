#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/qpx-config-check.XXXXXX")"
RUSTLS_TARGET_DIR="${QPX_CONFIG_CHECK_TARGET_DIR:-$TMP_DIR/target-rustls}"
QPXD_BIN="$RUSTLS_TARGET_DIR/debug/qpxd"
QPXF_BIN="$RUSTLS_TARGET_DIR/debug/qpxf"
CERT_FILE="$TMP_DIR/sample.crt"
KEY_FILE="$TMP_DIR/sample.key"
RUNTIME_DIR="$TMP_DIR/runtime"
STATE_DIR="$TMP_DIR/state"
QPXF_SAMPLE_CGI_ROOT="$ROOT_DIR/config/usecases/12-ipc-gateway/assets/cgi"
QPXF_SAMPLE_WASM_MODULE="$ROOT_DIR/config/usecases/12-ipc-gateway/assets/wasm/echo.wat"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

generate_sample_cert() {
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days 1 \
    -subj "/CN=example.com" >/dev/null 2>&1
}

run_check() {
  local config_file="$1"
  echo "==> $config_file"
  env \
    LDAP_BIND_PASSWORD="sample-bind-password" \
    CACHE_GW_AUTH_HEADER="Bearer sample-token" \
    EDGE_JWT_HMAC_SECRET="sample-hs256-secret" \
    XDG_RUNTIME_DIR="$RUNTIME_DIR" \
    QPX_STATE_DIR="$STATE_DIR" \
    QPXF_UNIX_LISTEN="unix://$RUNTIME_DIR/qpxf.sock" \
    QPX_TLS_CERT="$CERT_FILE" \
    QPX_TLS_KEY="$KEY_FILE" \
    QPX_TLS_CERT_ALT="$CERT_FILE" \
    QPX_TLS_KEY_ALT="$KEY_FILE" \
    QPX_TLS_CLIENT_CA="$CERT_FILE" \
    "$QPXD_BIN" check --config "$config_file"
}

run_qpxf_check() {
  local config_file="$1"
  echo "==> $config_file"
  env \
    XDG_RUNTIME_DIR="$RUNTIME_DIR" \
    QPXF_UNIX_LISTEN="unix://$RUNTIME_DIR/qpxf.sock" \
    QPXF_SAMPLE_CGI_ROOT="$QPXF_SAMPLE_CGI_ROOT" \
    QPXF_SAMPLE_WASM_MODULE="$QPXF_SAMPLE_WASM_MODULE" \
    "$QPXF_BIN" check --config "$config_file"
}

main() {
  require_cmd cargo
  require_cmd find
  require_cmd openssl

  echo "[CONFIG] building qpxd and qpxf"
  cargo build -q -p qpxd -p qpxf --locked --target-dir "$RUSTLS_TARGET_DIR"

  if [ ! -x "$QPXD_BIN" ]; then
    echo "missing built qpxd binary: $QPXD_BIN" >&2
    exit 1
  fi
  if [ ! -x "$QPXF_BIN" ]; then
    echo "missing built qpxf binary: $QPXF_BIN" >&2
    exit 1
  fi

  generate_sample_cert
  mkdir -p "$RUNTIME_DIR"
  mkdir -p "$STATE_DIR"

  run_check "$ROOT_DIR/config/qpx.example.yaml"
  while IFS= read -r config_file; do
    run_check "$config_file"
  done < <(find "$ROOT_DIR/config/usecases" -name '*.yaml' ! -name 'qpxf*.yaml' ! -name '*-native-*.yaml' -print | sort)

  run_qpxf_check "$ROOT_DIR/config/usecases/12-ipc-gateway/qpxf.yaml"
  run_qpxf_check "$ROOT_DIR/config/usecases/12-ipc-gateway/qpxf-tcp.yaml"

  echo "[CONFIG] all qpxd/qpxf sample configs validated"
}

main "$@"
