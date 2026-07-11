#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${QPX_H3_INTEROP_OUT_DIR:-$ROOT_DIR/target/interop}"
OUT_FILE="${QPX_H3_INTEROP_JSON:-$OUT_DIR/qpx-h3-matrix.json}"
REQUESTED="${1:-all}"
BACKENDS="${QPX_H3_INTEROP_BACKENDS:-h3 qpx_h3}"
COMMIT="$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || printf unknown)"
TESTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TMP_ROWS="$(mktemp "${TMPDIR:-/tmp}/qpx-h3-rows.XXXXXX")"
trap 'rm -f "$TMP_ROWS"' EXIT

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g'
}

record_pass() {
  local backend="$1" scenario="$2" command="$3"
  printf '{"backend":"%s","scenario":"%s","peer_client":"repository contract","pass_fail":"pass","qlog_available":"no","known_limitation":"","tested_commit":"%s","tested_at":"%s","command_or_test":"%s"}\n' \
    "$(json_escape "$backend")" "$(json_escape "$scenario")" \
    "$(json_escape "$COMMIT")" "$(json_escape "$TESTED_AT")" \
    "$(json_escape "$command")" >>"$TMP_ROWS"
}

run_contract() {
  local backend="$1" scenario="$2" command="$3"
  echo "[h3-interop] $backend: $scenario"
  (cd "$ROOT_DIR" && bash -euo pipefail -c "$command")
  record_pass "$backend" "$scenario" "$command"
}

for backend in $BACKENDS; do
  case "$backend" in
    h3) features="http3-backend-h3,tls-rustls,mitm" ;;
    qpx_h3) features="http3-backend-qpx,tls-rustls,mitm" ;;
    *) echo "unknown backend: $backend" >&2; exit 2 ;;
  esac
  case "$REQUESTED" in
    all)
      run_contract "$backend" "H3 streaming" \
        "cargo test -p qpxd --test h3_streaming_e2e --locked --features $features -- --test-threads=1"
      run_contract "$backend" "CONNECT and WebTransport" \
        "cargo test -p qpxd --test forward_e2e --locked --features $features -- --test-threads=1"
      run_contract "$backend" "reverse H3" \
        "cargo test -p qpxd --test reverse_h3_e2e --locked --features $features -- --test-threads=1"
      ;;
    streaming)
      run_contract "$backend" "H3 streaming" \
        "cargo test -p qpxd --test h3_streaming_e2e --locked --features $features -- --test-threads=1"
      ;;
    connect)
      run_contract "$backend" "CONNECT and WebTransport" \
        "cargo test -p qpxd --test forward_e2e --locked --features $features -- --test-threads=1"
      ;;
    reverse)
      run_contract "$backend" "reverse H3" \
        "cargo test -p qpxd --test reverse_h3_e2e --locked --features $features -- --test-threads=1"
      ;;
    *) echo "unknown scenario: $REQUESTED" >&2; exit 2 ;;
  esac
done

mkdir -p "$OUT_DIR"
jq -s . "$TMP_ROWS" >"$OUT_FILE"
if ! jq -e 'length > 0 and all(.[]; .pass_fail == "pass")' "$OUT_FILE" >/dev/null; then
  echo "H3 interoperability matrix contains a non-pass result" >&2
  exit 1
fi
echo "wrote verified H3 matrix: $OUT_FILE"
