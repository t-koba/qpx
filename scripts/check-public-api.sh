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

check_crate qpx-core 58a9a25dbfd9fc94349a0707c23f03cba3d0ec50569e515f4b21348c6ba68afa
check_crate qpx-auth c17be9a9eb26c0587c0425b1d2088ebe1ad09d5c7f43a00dc8677938ecf842c5
check_crate qpx-h3 d8be4f46e894aee75742bd9c4978aa18da20e65b2967be9ab8c108e34a38a975
check_crate qpx-acme dd10ddb8f525aea913e5e5f6d89d03ca853292e164de2620dbf6f4e359c62f48
check_crate qpx-observability ec6221c7735dc149f7c7bc413e1a25f0600db2edea2c7e93e6b272faa2f244d5
