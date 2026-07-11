#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QPXD_BIN="${QPXD_BIN:-$ROOT_DIR/target/debug/qpxd}"
KEYCLOAK_IMAGE="quay.io/keycloak/keycloak@sha256:98fab020a3a490aba0978f237e2a06cd0ea42bf149c6cf10f11c0aaf27728ff2"
CERBOS_IMAGE="ghcr.io/cerbos/cerbos@sha256:86f768368bbab30ceddd39e0e6df3d9ff8824c5f324af255a5573f0bddaae042"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/qpx-provider-e2e.XXXXXX")"
PIDS=()
CONTAINERS=()

cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  for container in "${CONTAINERS[@]}"; do docker rm -f "$container" >/dev/null 2>&1 || true; done
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

wait_http() {
  local url="$1"
  for _ in $(seq 1 120); do
    if curl -fsS "$url" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "endpoint did not become ready: $url" >&2
  return 1
}

wait_tcp() {
  local port="$1"
  for _ in $(seq 1 60); do
    if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "TCP listener did not become ready: $port" >&2
  return 1
}

start_origin() {
  python3 -m http.server 18090 --bind 127.0.0.1 --directory "$TMP_DIR" >"$TMP_DIR/origin.log" 2>&1 &
  PIDS+=("$!")
  wait_http http://127.0.0.1:18090/
}

start_qpx() {
  local config="$1" log="$2"
  QPX_STATE_DIR="$TMP_DIR/state-$log" "$QPXD_BIN" run -c "$config" >"$TMP_DIR/$log.log" 2>&1 &
  PIDS+=("$!")
}

test_keycloak() {
  local name="qpx-keycloak-ci-$RANDOM"
  CONTAINERS+=("$name")
  docker run -d --name "$name" --network host \
    -v "$ROOT_DIR/integration/providers/keycloak/realm.json:/opt/keycloak/data/import/realm.json:ro" \
    -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
    -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
    "$KEYCLOAK_IMAGE" start-dev --hostname=http://127.0.0.1:18081 --http-port=18081 --import-realm >/dev/null
  wait_http http://127.0.0.1:18081/realms/qpx-ci/.well-known/openid-configuration
  local token
  token="$(curl -fsS -X POST http://127.0.0.1:18081/realms/qpx-ci/protocol/openid-connect/token \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data 'grant_type=client_credentials&client_id=qpx-ci-client&client_secret=qpx-ci-secret' \
    | jq -er .access_token)"
  start_qpx "$ROOT_DIR/integration/providers/keycloak/qpx.yaml" keycloak-qpx
  wait_tcp 18082
  curl -fsS -x http://127.0.0.1:18082 -H "Authorization: Bearer $token" http://127.0.0.1:18090/ >/dev/null
  if curl -fsS -x http://127.0.0.1:18082 http://127.0.0.1:18090/ >/dev/null 2>&1; then
    echo "Keycloak resource server accepted an unauthenticated request" >&2
    return 1
  fi
}

test_cerbos() {
  local name="qpx-cerbos-ci-$RANDOM"
  CONTAINERS+=("$name")
  docker run -d --name "$name" --network host \
    -v "$ROOT_DIR/integration/providers/cerbos/conf.yaml:/conf.yaml:ro" \
    -v "$ROOT_DIR/integration/providers/cerbos/policies:/policies:ro" \
    "$CERBOS_IMAGE" server --config=/conf.yaml >/dev/null
  wait_http http://127.0.0.1:18083/_cerbos/health
  start_qpx "$ROOT_DIR/integration/providers/cerbos/qpx.yaml" cerbos-qpx
  wait_tcp 18084
  curl -fsS -x http://127.0.0.1:18084 http://127.0.0.1:18090/ >/dev/null
  if curl -fsS -X POST -x http://127.0.0.1:18084 http://127.0.0.1:18090/ >/dev/null 2>&1; then
    echo "Cerbos denied action was forwarded" >&2
    return 1
  fi
}

test_qid() {
  local qid_dir="${SISTER_QID_REPO_DIR:?SISTER_QID_REPO_DIR is required}"
  QPXD_BIN="$QPXD_BIN" bash "$qid_dir/examples/qpx-e2e/run.sh"
}

test_qid
start_origin
test_keycloak
test_cerbos
echo "provider-neutral integration matrix passed"
