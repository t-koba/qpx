#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/lib/temp-dir.sh"
QPXD_BIN="${QPXD_BIN:-$ROOT_DIR/target/debug/qpxd}"
CHROMIUM_BIN="${CHROMIUM_BIN:-}"
TMP_DIR="$(make_temp_dir qpx-browser-origin-e2e)"
QPXD_PID=""

cleanup() {
  if [[ -n "$QPXD_PID" ]] && kill -0 "$QPXD_PID" >/dev/null 2>&1; then
    kill "$QPXD_PID" >/dev/null 2>&1 || true
    wait "$QPXD_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

if [[ -z "$CHROMIUM_BIN" ]]; then
  for candidate in google-chrome chromium chromium-browser; do
    if command -v "$candidate" >/dev/null 2>&1; then
      CHROMIUM_BIN="$(command -v "$candidate")"
      break
    fi
  done
fi
if [[ -z "$CHROMIUM_BIN" ]]; then
  echo "a Chromium executable is required" >&2
  exit 1
fi

if [[ ! -x "$QPXD_BIN" ]]; then
  cargo build -q -p qpxd --locked
fi

mkdir -p "$TMP_DIR/state" "$TMP_DIR/chrome-profile"
QPX_STATE_DIR="$TMP_DIR/state" "$QPXD_BIN" run \
  --config "$ROOT_DIR/integration/browser-origin/qpx.yaml" >"$TMP_DIR/qpxd.log" 2>&1 &
QPXD_PID=$!

for port in 19480 19481 19482; do
  ready=false
  for _ in $(seq 1 100); do
    if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
      ready=true
      break
    fi
    if ! kill -0 "$QPXD_PID" >/dev/null 2>&1; then
      cat "$TMP_DIR/qpxd.log" >&2
      exit 1
    fi
    sleep 0.1
  done
  if [[ "$ready" != true ]]; then
    echo "timeout waiting for browser origin port $port" >&2
    cat "$TMP_DIR/qpxd.log" >&2
    exit 1
  fi
done

run_browser_case() {
  local port="$1"
  local expected="$2"
  local output="$TMP_DIR/browser-$port.html"
  set +e
  timeout 45 "$CHROMIUM_BIN" --headless=new --disable-gpu --no-sandbox \
    --disable-background-networking --disable-component-update --no-first-run \
    --user-data-dir="$TMP_DIR/chrome-profile-$port" \
    --virtual-time-budget=5000 --dump-dom "http://127.0.0.1:$port/" >"$output"
  local chrome_status=$?
  set -e
  if [[ "$chrome_status" -ne 0 && "$chrome_status" -ne 124 ]]; then
    cat "$output" >&2
    cat "$TMP_DIR/qpxd.log" >&2
    echo "browser origin case on port $port failed with status $chrome_status" >&2
    exit 1
  fi
  if ! grep -q "$expected" "$output"; then
    cat "$output" >&2
    cat "$TMP_DIR/qpxd.log" >&2
    echo "browser origin case on port $port did not produce $expected" >&2
    exit 1
  fi
}

run_browser_case 19480 CORS_ALLOWED_PASS
run_browser_case 19482 CORS_DENIED_PASS

page_headers="$TMP_DIR/page-headers.txt"
curl -fsS -D "$page_headers" -o /dev/null "http://127.0.0.1:19480/"
grep -qi '^content-security-policy:' "$page_headers"
grep -qi '^permissions-policy:' "$page_headers"
grep -qi '^cross-origin-opener-policy: same-origin' "$page_headers"
grep -qi '^x-content-type-options: nosniff' "$page_headers"
grep -qi '^origin-agent-cluster: ?1' "$page_headers"

allowed_status="$(curl -sS -o /dev/null -w '%{http_code}' -X PUT \
  -H 'Sec-Fetch-Site: same-site' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Dest: empty' \
  "http://127.0.0.1:19481/api/check")"
[[ "$allowed_status" == "200" ]]
missing_status="$(curl -sS -o /dev/null -w '%{http_code}' -X PUT \
  "http://127.0.0.1:19481/api/check")"
[[ "$missing_status" == "403" ]]

report_headers="$TMP_DIR/report-headers.txt"
report_status="$(curl -sS -D "$report_headers" -o /dev/null -w '%{http_code}' -X POST \
  -H 'Content-Type: application/reports+json' \
  --data '[{"type":"csp-violation","url":"http://127.0.0.1:19480/","body":{}}]' \
  "http://127.0.0.1:19481/reports")"
[[ "$report_status" == "204" ]]
grep -qi '^cache-control: no-store' "$report_headers"

invalid_report_status="$(curl -sS -o /dev/null -w '%{http_code}' -X POST \
  -H 'Content-Type: application/reports+json' \
  --data '[]' \
  "http://127.0.0.1:19481/reports")"
[[ "$invalid_report_status" == "400" ]]

echo "browser origin policy checks passed"
