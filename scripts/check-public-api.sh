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
    qpx_core_api_hash=b35bc1d6ded69d594addf0248294584da6ee5c66ba8369626234c5bef55735e2
    qpx_h3_api_hash=d8be4f46e894aee75742bd9c4978aa18da20e65b2967be9ab8c108e34a38a975
    ;;
  *)
    qpx_core_api_hash=5ae66e29b639c0ee2a522510776bc29d4f97bdef3c4e08d7fd1b2069e0a40fac
    qpx_h3_api_hash=540781e2e1344a18d82194b31634b84a509c5d6182d6d7e9abe1d2455e50c654
    ;;
esac

check_crate qpx-core "$qpx_core_api_hash"
check_crate qpx-auth c17be9a9eb26c0587c0425b1d2088ebe1ad09d5c7f43a00dc8677938ecf842c5
check_crate qpx-h3 "$qpx_h3_api_hash"
check_crate qpx-acme dd10ddb8f525aea913e5e5f6d89d03ca853292e164de2620dbf6f4e359c62f48
check_crate qpx-observability 8e652f42356370411b6e746bcdd70610d35d63c71978b8ff33c327a1feecdaa4
