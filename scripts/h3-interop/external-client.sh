#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT_DIR/scripts/lib/temp-dir.sh"
QPXD_BIN="${QPXD_BIN:?QPXD_BIN is required}"
CLIENT="${1:?client name is required}"
TMP_DIR="$(make_temp_dir qpx-h3-external)"
QPXD_PID=""
EXPECTED="qpx-h3-external-interop"
URL="https://localhost:18443/"

cleanup() {
  if [[ -n "$QPXD_PID" ]]; then kill "$QPXD_PID" 2>/dev/null || true; fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$TMP_DIR/key.pem" -out "$TMP_DIR/cert.pem" \
  -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' >/dev/null 2>&1
SPKI_HASH="$(openssl x509 -in "$TMP_DIR/cert.pem" -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary \
  | openssl base64 -A)"
mkdir -p "$TMP_DIR/state"
QPX_STATE_DIR="$TMP_DIR/state" QPX_TLS_CERT="$TMP_DIR/cert.pem" QPX_TLS_KEY="$TMP_DIR/key.pem" \
  "$QPXD_BIN" run -c "$ROOT_DIR/integration/h3/qpx.yaml" >"$TMP_DIR/qpxd.log" 2>&1 &
QPXD_PID=$!
sleep 1
if ! kill -0 "$QPXD_PID" 2>/dev/null; then
  cat "$TMP_DIR/qpxd.log" >&2
  exit 1
fi

case "$CLIENT" in
  aioquic)
    : "${AIOQUIC_DIR:?AIOQUIC_DIR is required}"
    mkdir -p "$TMP_DIR/aioquic-output"
    timeout 45 python3 "$AIOQUIC_DIR/examples/http3_client.py" --ca-certs "$TMP_DIR/cert.pem" \
      --output-dir "$TMP_DIR/aioquic-output" "$URL"
    cp "$TMP_DIR/aioquic-output/index.html" "$TMP_DIR/client.out"
    ;;
  curl)
    : "${CURL_HTTP3_BIN:?CURL_HTTP3_BIN is required}"
    timeout 45 "$CURL_HTTP3_BIN" --http3-only --cacert "$TMP_DIR/cert.pem" --silent --show-error "$URL" >"$TMP_DIR/client.out"
    ;;
  ngtcp2)
    : "${NGTCP2_CLIENT_BIN:?NGTCP2_CLIENT_BIN is required}"
    mkdir -p "$TMP_DIR/ngtcp2-output"
    timeout 45 "$NGTCP2_CLIENT_BIN" --exit-on-first-stream-close \
      --download="$TMP_DIR/ngtcp2-output" localhost 18443 "$URL"
    cp "$TMP_DIR/ngtcp2-output/index.html" "$TMP_DIR/client.out"
    ;;
  quiche)
    : "${QUICHE_CLIENT_BIN:?QUICHE_CLIENT_BIN is required}"
    if ! timeout 45 "$QUICHE_CLIENT_BIN" --no-verify "$URL" >"$TMP_DIR/client.out"; then
      cat "$TMP_DIR/qpxd.log" >&2
      exit 1
    fi
    ;;
  chromium)
    : "${CHROMIUM_BIN:?CHROMIUM_BIN is required}"
    timeout 45 "$CHROMIUM_BIN" --headless --disable-gpu --no-sandbox \
      --enable-quic --origin-to-force-quic-on=localhost:18443 \
      --ignore-certificate-errors-spki-list="$SPKI_HASH" --dump-dom "$URL" >"$TMP_DIR/client.out"
    ;;
  *)
    echo "unknown external H3 client: $CLIENT" >&2
    exit 2
    ;;
esac

if ! grep -q "$EXPECTED" "$TMP_DIR/client.out"; then
  cat "$TMP_DIR/client.out" >&2
  cat "$TMP_DIR/qpxd.log" >&2
  echo "$CLIENT did not receive the expected HTTP/3 response" >&2
  exit 1
fi
echo "$CLIENT HTTP/3 interop passed"
