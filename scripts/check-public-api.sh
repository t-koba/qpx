#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo-public-api >/dev/null 2>&1 && ! cargo public-api --version >/dev/null 2>&1; then
  echo "cargo-public-api is required; install with: cargo install cargo-public-api --locked" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/qpx-public-api.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

check_crate() {
  local crate="$1"
  local expected="$2"
  local output="$tmpdir/${crate}.api"

  cargo public-api --manifest-path "$ROOT_DIR/$crate/Cargo.toml" -sss --color never >"$output"
  local actual
  actual="$(hash_file "$output")"
  if [[ "$actual" != "$expected" ]]; then
    {
      echo "public API fingerprint changed for ${crate}"
      echo "expected: ${expected}"
      echo "actual:   ${actual}"
      echo "Review the public API change. If it is intentional, update scripts/check-public-api.sh."
    } >&2
    return 1
  fi
}

case "$(uname -s)" in
  Darwin)
    qpx_core_api_hash=08e679eac4748b717ffe7fb4edcf71480143893bdf2adcbd3ebc650d8897371e
    qpx_h3_api_hash=400fc73c391d6a5963c922c2053bb7c18776d9ab5997762b7e2cac3a3b2376cb
    ;;
  *)
    qpx_core_api_hash=2e9baafa22d8981d7ab1b7adee05752857bfa7afe744c3f489417871e3906a8c
    qpx_h3_api_hash=cd9fcefc7ac1cb75406ab51a30de364be14e9ea72b243b850f43f03e649a211a
    ;;
esac

check_crate qpx-core "$qpx_core_api_hash"
check_crate qpx-auth c17be9a9eb26c0587c0425b1d2088ebe1ad09d5c7f43a00dc8677938ecf842c5
check_crate qpx-h3 "$qpx_h3_api_hash"
check_crate qpx-acme 437ee44d007ac282cf2216fa00cb602dfd1a0daf6846f62376fa6cb35831442a
check_crate qpx-observability ab86004ce9ece7bc97870c59e049d1feb9f9e85a5817002d8f9d1c02ee514a37
