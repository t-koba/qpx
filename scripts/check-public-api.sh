#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/lib/temp-dir.sh"

if ! command -v cargo-public-api >/dev/null 2>&1 && ! cargo public-api --version >/dev/null 2>&1; then
  echo "cargo-public-api 0.52.0 is required; install with: cargo install cargo-public-api --version 0.52.0 --locked" >&2
  exit 1
fi
if [ "$(cargo public-api --version)" != "cargo-public-api 0.52.0" ]; then
  echo "cargo-public-api 0.52.0 is required" >&2
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

tmpdir="$(make_temp_dir qpx-public-api)"
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
    qpx_core_api_hash=d6d3412e7c07e276b300ec5efc65b294b2d3ba9dea1178638a2c357abe794101
    qpx_h3_api_hash=400fc73c391d6a5963c922c2053bb7c18776d9ab5997762b7e2cac3a3b2376cb
    ;;
  *)
    qpx_core_api_hash=4a2ae77412aa933b76a6e35b8ecc8a6d48a91d3f4101d7041d450977e1bcce38
    qpx_h3_api_hash=cd9fcefc7ac1cb75406ab51a30de364be14e9ea72b243b850f43f03e649a211a
    ;;
esac

check_crate qpx-core "$qpx_core_api_hash"
check_crate qpx-auth c17be9a9eb26c0587c0425b1d2088ebe1ad09d5c7f43a00dc8677938ecf842c5
check_crate qpx-h3 "$qpx_h3_api_hash"
check_crate qpx-acme 437ee44d007ac282cf2216fa00cb602dfd1a0daf6846f62376fa6cb35831442a
check_crate qpx-observability 14acc450f63cf0605cf69c863f347f25c9c8dc30edfbcf702f9b795aa5bf0701
