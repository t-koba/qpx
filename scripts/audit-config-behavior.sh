#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/qpx-config-behavior.XXXXXX")"
TARGET_DIR="${QPX_CONFIG_BEHAVIOR_TARGET_DIR:-$ROOT_DIR/target}"
QPXD_BIN_FROM_ENV="${QPXD_BIN:-}"
QPXD_BIN="${QPXD_BIN_FROM_ENV:-$TARGET_DIR/debug/qpxd}"
CERT_FILE="$TMP_DIR/sample.crt"
KEY_FILE="$TMP_DIR/sample.key"
RUNTIME_DIR="$TMP_DIR/runtime"
STATE_DIR="$TMP_DIR/state"

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

run_qpxd() {
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
    "$QPXD_BIN" "$@"
}

assert_output_contains() {
  local label="$1"
  local output_file="$2"
  shift 2
  local pattern
  for pattern in "$@"; do
    if ! grep -Eq "$pattern" "$output_file"; then
      echo "config behavior audit failed: $label: missing pattern: $pattern" >&2
      echo "--- output ---" >&2
      sed -n '1,220p' "$output_file" >&2
      echo "--------------" >&2
      exit 1
    fi
  done
}

assert_qpxd_match() {
  local label="$1"
  local config="$2"
  local edge="$3"
  shift 3

  local -a command_args=()
  local -a patterns=()
  local reading_patterns=0
  local arg
  for arg in "$@"; do
    if [ "$arg" = "--expect" ]; then
      reading_patterns=1
      continue
    fi
    if [ "$reading_patterns" -eq 0 ]; then
      command_args+=("$arg")
    else
      patterns+=("$arg")
    fi
  done

  local output_file="$TMP_DIR/${label//[^A-Za-z0-9_.-]/_}.out"
  run_qpxd match --config "$ROOT_DIR/$config" --edge "$edge" "${command_args[@]}" >"$output_file"
  assert_output_contains "$label" "$output_file" "${patterns[@]}"
}

assert_qpxd_explain() {
  local label="$1"
  local config="$2"
  local edge="$3"
  local route="$4"
  shift 4

  local output_file="$TMP_DIR/${label//[^A-Za-z0-9_.-]/_}.out"
  if [ -n "$route" ]; then
    run_qpxd explain --config "$ROOT_DIR/$config" --edge "$edge" --route "$route" >"$output_file"
  else
    run_qpxd explain --config "$ROOT_DIR/$config" --edge "$edge" >"$output_file"
  fi
  assert_output_contains "$label" "$output_file" "$@"
}

main() {
  require_cmd cargo
  require_cmd grep
  require_cmd openssl
  require_cmd sed

  generate_sample_cert
  mkdir -p "$RUNTIME_DIR" "$STATE_DIR"

  if [ -z "$QPXD_BIN_FROM_ENV" ]; then
    cargo build -q -p qpxd --locked --features qpxd/auth-digest,qpxd/auth-ldap --target-dir "$TARGET_DIR"
  fi

  if [ ! -x "$QPXD_BIN" ]; then
    echo "missing qpxd binary: $QPXD_BIN" >&2
    exit 1
  fi

  assert_qpxd_match "example config blocks ad hosts with local response" \
    "config/qpx.example.yaml" "forward" \
    --src-ip 127.0.0.1 --host ads.doubleclick.net --method GET --path /ad.js \
    --expect '^rule: block-ads-with-local-page$' '^[[:space:]]+action: respond$' '^[[:space:]]+status: 403$'
  assert_qpxd_match "example config allows loopback direct by final rule" \
    "config/qpx.example.yaml" "forward" \
    --src-ip 127.0.0.1 --host example.org --method GET --path / \
    --expect '^rule: allow-loopback$' '^[[:space:]]+action: direct$'
  assert_qpxd_match "example config keeps non-loopback forward default deny" \
    "config/qpx.example.yaml" "forward" \
    --src-ip 203.0.113.10 --host example.org --method GET --path / \
    --expect '^rule: <default>$' '^[[:space:]]+action: block$'
  assert_qpxd_match "example config transparent loopback web stays direct" \
    "config/qpx.example.yaml" "transparent" \
    --src-ip 127.0.0.1 --host example.com --dst-port 443 --method GET --path / \
    --expect '^rule: allow-loopback-web$' '^[[:space:]]+action: direct$'
  assert_qpxd_match "example config reverse site routes example host" \
    "config/qpx.example.yaml" "site" \
    --host example.com --method GET --path / \
    --expect '^route: app$' '^[[:space:]]+type: upstream$' 'site-app-a' 'site-app-b'

  assert_qpxd_match "include forward fragment routes internal host directly" \
    "config/usecases/09-composition/include-forward.yaml" "include-forward" \
    --src-ip 127.0.0.1 --host app.internal.example --method GET --path / \
    --expect '^rule: include-direct-allow$' '^[[:space:]]+action: direct$'
  assert_qpxd_match "include forward fragment proxies loopback external host" \
    "config/usecases/09-composition/include-forward.yaml" "include-forward" \
    --src-ip 127.0.0.1 --host example.com --method GET --path / \
    --expect '^rule: include-allow-loopback-egress$' '^[[:space:]]+action: proxy$'
  assert_qpxd_match "include forward fragment denies non-loopback default" \
    "config/usecases/09-composition/include-forward.yaml" "include-forward" \
    --src-ip 203.0.113.10 --host example.com --method GET --path / \
    --expect '^rule: <default>$' '^[[:space:]]+action: block$'
  assert_qpxd_match "include transparent fragment routes internal app directly" \
    "config/usecases/09-composition/include-transparent-reverse.yaml" "include-transparent" \
    --src-ip 10.1.2.3 --host internal-app.example.com --dst-port 443 --method GET --path / \
    --expect '^rule: allow-internal-app$' '^[[:space:]]+action: direct$'
  assert_qpxd_match "include reverse fragment routes internal app to upstream" \
    "config/usecases/09-composition/include-transparent-reverse.yaml" "include-reverse" \
    --host internal-app.example.com --method GET --path / \
    --expect '^route: route\[0\]$' '^[[:space:]]+type: upstream$' 'http://10\.60\.0\.11:8080'

  assert_qpxd_match "forward minimal allows loopback" \
    "config/usecases/01-getting-started/forward-minimal.yaml" "minimal-forward" \
    --src-ip 127.0.0.1 --host example.com --method GET --path / \
    --expect '^rule: allow-loopback$' '^[[:space:]]+action: direct$'
  assert_qpxd_match "forward minimal blocks non-loopback by default" \
    "config/usecases/01-getting-started/forward-minimal.yaml" "minimal-forward" \
    --src-ip 203.0.113.10 --host example.com --method GET --path / \
    --expect '^rule: <default>$' '^[[:space:]]+action: block$'
  assert_qpxd_match "forward dev blocks known bad hosts" \
    "config/usecases/01-getting-started/forward-local-dev-direct.yaml" "forward-dev-direct" \
    --host bad.malware.test --method GET --path / \
    --expect '^rule: block-known-bad$' '^[[:space:]]+action: block$'
  assert_qpxd_match "forward dev defaults to direct" \
    "config/usecases/01-getting-started/forward-local-dev-direct.yaml" "forward-dev-direct" \
    --host example.com --method GET --path / \
    --expect '^rule: <default>$' '^[[:space:]]+action: direct$'

  assert_qpxd_match "selective TLS inspection inspects work SNI" \
    "config/usecases/02-secure-egress/forward-tls-inspection-selective.yaml" "selective-mitm-forward" \
    --src-ip 127.0.0.1 --sni api.work.example.com --method CONNECT \
    --expect '^rule: inspect-work-sites$' '^[[:space:]]+action: inspect$'
  assert_qpxd_match "selective TLS inspection bypasses banking SNI" \
    "config/usecases/02-secure-egress/forward-tls-inspection-selective.yaml" "selective-mitm-forward" \
    --src-ip 127.0.0.1 --sni portal.bank.example --method CONNECT \
    --expect '^rule: direct-banking-sites$' '^[[:space:]]+action: direct$'
  assert_qpxd_match "selective TLS inspection blocks known bad host" \
    "config/usecases/02-secure-egress/forward-tls-inspection-selective.yaml" "selective-mitm-forward" \
    --src-ip 127.0.0.1 --host c2.botnet.invalid --method GET --path / \
    --expect '^rule: block-known-bad$' '^[[:space:]]+action: block$'
  assert_qpxd_match "upstream chained forward proxies external traffic" \
    "config/usecases/02-secure-egress/forward-upstream-chain.yaml" "chained-forward" \
    --src-ip 127.0.0.1 --host example.com --method GET --path / \
    --expect '^rule: allow-loopback-via-upstream$' '^[[:space:]]+action: proxy$'

  assert_qpxd_match "reverse basic routes matching host to upstream" \
    "config/usecases/01-getting-started/reverse-basic-http.yaml" "reverse-basic" \
    --host app.example.com --method GET --path / \
    --expect '^route: route\[0\]$' '^[[:space:]]+type: upstream$' 'http://10\.10\.0\.11:8080'
  assert_qpxd_match "reverse basic does not route other host" \
    "config/usecases/01-getting-started/reverse-basic-http.yaml" "reverse-basic" \
    --host other.example.com --method GET --path / \
    --expect '^route: <no match>$'
  assert_qpxd_match "reverse SNI host exception config still routes tenant host" \
    "config/usecases/03-service-publishing/reverse-sni-host-exceptions.yaml" "reverse-sni-host-exceptions" \
    --host tenant-a.shared.example.com --method GET --path / \
    --expect '^route: tenant-a$' 'http://10\.70\.0\.21:8080'
  assert_qpxd_match "reverse TLS passthrough routes SNI to raw upstream" \
    "config/usecases/03-service-publishing/reverse-tls-passthrough-sni.yaml" "reverse-tls-passthrough" \
    --sni db.example.com --dst-port 443 \
    --expect '^route: tls_passthrough\[0\]$' '^[[:space:]]+type: tls_passthrough$' '10\.40\.0\.10:5432'
  assert_qpxd_match "reverse maintenance route returns local 503" \
    "config/usecases/06-local-response/reverse-maintenance.yaml" "reverse-maintenance" \
    --host app.example.com --method GET --path /maintenance/window \
    --expect '^route: route\[1\]$' '^[[:space:]]+type: local_response$' '^[[:space:]]+status: 503$'

  assert_qpxd_match "HTTP3 CONNECT-UDP sample chains corp traffic to upstream proxy" \
    "config/usecases/04-http3-and-masque/forward-http3-connect-udp.yaml" "forward-http3" \
    --host api.corp.example --method CONNECT \
    --expect '^rule: connect-udp-chain-corp$' '^[[:space:]]+action: proxy$' '^[[:space:]]+auth: on$'
  assert_qpxd_match "HTTP3 URI template sample allows loopback CONNECT" \
    "config/usecases/04-http3-and-masque/forward-http3-connect-udp-uri-template.yaml" "forward-http3-template" \
    --src-ip 127.0.0.1 --host target.example.com --method CONNECT \
    --expect '^rule: allow-loopback-connect-and-connect-udp$' '^[[:space:]]+action: direct$'
  assert_qpxd_explain "HTTP3 URI template is present in checked config" \
    "config/usecases/04-http3-and-masque/forward-http3-connect-udp-uri-template.yaml" "forward-http3-template" "" \
    '^[[:space:]]+kind: forward$' '^[[:space:]]+action: block$'

  assert_qpxd_explain "observability capture compiles to capture plan" \
    "config/usecases/07-observability-debug/observability-high-detail.yaml" "obs-forward" "" \
    '^[[:space:]]+capture_encrypted: on$' '^[[:space:]]+capture_plaintext: on$' \
    '^[[:space:]]+plaintext_headers: on$' '^[[:space:]]+plaintext_body: full$' \
    '^[[:space:]]+max_body_bytes: 16384$'
  assert_qpxd_explain "HTTP modules compile into request and response stages" \
    "config/usecases/07-observability-debug/http-modules-advanced.yaml" "modules-forward" "" \
    'cache_purge \(forward-cache-purge\)' 'subrequest \(request-authz\)' \
    'response_compression \(forward-compress\)' 'backend: module-cache'
  assert_qpxd_explain "reverse response policy compiles with weighted target" \
    "config/usecases/03-service-publishing/reverse-affinity-response-policy.yaml" "reverse-affinity-policy" "store-api" \
    '^[[:space:]]+type: weighted$' '^[[:space:]]+response_rules: on$' \
    '^[[:space:]]+count: 2$' '^[[:space:]]+backend$'
  assert_qpxd_explain "IPC gateway compiles shm target" \
    "config/usecases/12-ipc-gateway/qpx.yaml" "ipc-gateway" "function-executor" \
    '^[[:space:]]+type: ipc$' '^[[:space:]]+mode: shm$'
  assert_qpxd_explain "IPC TCP gateway compiles tcp target" \
    "config/usecases/12-ipc-gateway/qpx-tcp.yaml" "ipc-gateway-tcp" "function-executor" \
    '^[[:space:]]+type: ipc$' '^[[:space:]]+mode: tcp$'

  echo "[CONFIG] compiled behavior audit passed"
}

main "$@"
