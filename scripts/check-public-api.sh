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
    qpx_core_api_hash=afd4263749c5a42d340752298f4db9c0c3b07c039658beb1b3bb1958442f66b6
    qpx_h3_api_hash=dbcdbf4cbf5bec53cb9518144ee1bfaa7c2893b0ade0d0af4b91b69bd390153b
    ;;
  *)
    qpx_core_api_hash=6e8f17363a28460d4ca85fc814a3d860dec88fa71613624b49a64da0fb084885
    qpx_h3_api_hash=dbcdbf4cbf5bec53cb9518144ee1bfaa7c2893b0ade0d0af4b91b69bd390153b
    ;;
esac

check_crate qpx-core "$qpx_core_api_hash"
check_crate qpx-auth c17be9a9eb26c0587c0425b1d2088ebe1ad09d5c7f43a00dc8677938ecf842c5
check_crate qpx-h3 "$qpx_h3_api_hash"
check_crate qpx-acme 437ee44d007ac282cf2216fa00cb602dfd1a0daf6846f62376fa6cb35831442a
check_crate qpx-observability 155c776fab2df14c461ce87ed53681da4bec411c871bc2b9328f1f6f3bd7cbb2
