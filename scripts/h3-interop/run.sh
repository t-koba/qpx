#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${QPX_H3_INTEROP_OUT_DIR:-$ROOT_DIR/target/interop}"
OUT_FILE="${QPX_H3_INTEROP_JSON:-$OUT_DIR/qpx-h3-matrix.json}"
REQUESTED="${1:-all}"
COMMIT="$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || printf unknown)"
TESTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
QLOG_AVAILABLE="no"
BACKENDS="${QPX_H3_INTEROP_BACKENDS:-h3 qpx_h3}"

if [[ -n "${QPX_QLOG_DIR:-}" && -d "${QPX_QLOG_DIR:-}" ]]; then
  QLOG_AVAILABLE="yes"
fi

json_escape() {
  printf '%s' "$1" \
    | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g'
}

record() {
  local backend="$1"
  local scenario="$2"
  local peer="$3"
  local result="$4"
  local limitation="$5"
  local command_or_test="$6"
  printf '  {"backend":"%s","scenario":"%s","peer_client":"%s","pass_fail":"%s","qlog_available":"%s","known_limitation":"%s","tested_commit":"%s","tested_at":"%s","command_or_test":"%s"}' \
    "$(json_escape "$backend")" \
    "$(json_escape "$scenario")" \
    "$(json_escape "$peer")" \
    "$(json_escape "$result")" \
    "$(json_escape "$QLOG_AVAILABLE")" \
    "$(json_escape "$limitation")" \
    "$(json_escape "$COMMIT")" \
    "$(json_escape "$TESTED_AT")" \
    "$(json_escape "$command_or_test")"
}

tool_result() {
  local tool="$1"
  if command -v "$tool" >/dev/null 2>&1; then
    printf pending
  else
    printf skipped
  fi
}

tool_limitation() {
  local tool="$1"
  if command -v "$tool" >/dev/null 2>&1; then
    printf 'manual interop execution required'
  else
    printf 'external tool not present'
  fi
}

repo_result() {
  if [[ "${QPX_H3_INTEROP_RUN_TESTS:-0}" == "1" ]]; then
    printf pending
  else
    printf pending
  fi
}

repo_limitation() {
  if [[ "${QPX_H3_INTEROP_RUN_TESTS:-0}" == "1" ]]; then
    printf 'run the listed cargo test and update result'
  else
    printf 'set QPX_H3_INTEROP_RUN_TESTS=1 to execute repository tests'
  fi
}

emit_records() {
  local first=1
  local backend
  for backend in $BACKENDS; do
    local feature
    case "$backend" in
      h3) feature="http3-backend-h3,tls-rustls" ;;
      qpx_h3) feature="http3-backend-qpx,tls-rustls" ;;
      *) echo "unknown backend: $backend" >&2; return 2 ;;
    esac
    local rows=(
      "$backend|curl HTTP/3|curl|$(tool_result curl)|$(tool_limitation curl)|QPX_H3_INTEROP_BACKENDS=$backend scripts/h3-interop/run.sh curl-http3"
      "$backend|Chromium WebTransport|chromium|$(tool_result chromium)|$(tool_limitation chromium)|QPX_H3_INTEROP_BACKENDS=$backend scripts/h3-interop/run.sh chromium-webtransport"
      "$backend|ngtcp2|ngtcp2|$(tool_result nghttp3-client)|$(tool_limitation nghttp3-client)|QPX_H3_INTEROP_BACKENDS=$backend scripts/h3-interop/run.sh ngtcp2"
      "$backend|quiche|quiche|$(tool_result quiche-client)|$(tool_limitation quiche-client)|QPX_H3_INTEROP_BACKENDS=$backend scripts/h3-interop/run.sh quiche"
      "$backend|gRPC over H3|repository e2e|$(repo_result)|$(repo_limitation)|cargo test -p qpxd --test h3_streaming_e2e --features $feature grpc"
      "$backend|SSE over H3|repository e2e|$(repo_result)|$(repo_limitation)|cargo test -p qpxd --test h3_streaming_e2e --features $feature sse"
      "$backend|CONNECT-UDP|repository e2e|$(repo_result)|$(repo_limitation)|cargo test -p qpxd --test forward_e2e --features $feature connect_udp"
      "$backend|MASQUE|repository e2e|$(repo_result)|$(repo_limitation)|cargo test -p qpxd --test forward_e2e --features $feature masque"
      "$backend|generic extended CONNECT|repository e2e|$(repo_result)|$(repo_limitation)|cargo test -p qpxd --test forward_e2e --features $feature extended"
      "$backend|trailers over H3|repository e2e|$(repo_result)|$(repo_limitation)|cargo test -p qpxd --test reverse_h3_e2e --features $feature trailers"
    )
  for row in "${rows[@]}"; do
    IFS='|' read -r backend scenario peer result limitation command_or_test <<<"$row"
    case "$REQUESTED" in
      all) ;;
      curl-http3) [[ "$scenario" == "curl HTTP/3" ]] || continue ;;
      chromium-webtransport) [[ "$scenario" == "Chromium WebTransport" ]] || continue ;;
      ngtcp2) [[ "$scenario" == "ngtcp2" ]] || continue ;;
      quiche) [[ "$scenario" == "quiche" ]] || continue ;;
      grpc-over-h3) [[ "$scenario" == "gRPC over H3" ]] || continue ;;
      sse-over-h3) [[ "$scenario" == "SSE over H3" ]] || continue ;;
      connect-udp) [[ "$scenario" == "CONNECT-UDP" ]] || continue ;;
      masque) [[ "$scenario" == "MASQUE" ]] || continue ;;
      extended-connect) [[ "$scenario" == "generic extended CONNECT" ]] || continue ;;
      trailers) [[ "$scenario" == "trailers over H3" ]] || continue ;;
      *) echo "unknown scenario: $REQUESTED" >&2; return 2 ;;
    esac
    if [[ "$first" -eq 0 ]]; then
      printf ',\n'
    fi
    record "$backend" "$scenario" "$peer" "$result" "$limitation" "$command_or_test"
    first=0
  done
  done
}

mkdir -p "$OUT_DIR"
{
  printf '[\n'
  emit_records
  printf '\n]\n'
} >"$OUT_FILE"

echo "wrote $OUT_FILE"
