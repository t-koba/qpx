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

# qpx-core exposes opaque owner-backed request/header carriers, policy/Vary operations
# and closed configured transfer/expansion effects; keep the fingerprint gate strict.
check_crate qpx-core 2e07159b628ca74564c471cc60f914cbd7eff3dc861d961d1877b4e3016996dc
check_crate qpx-auth 7ec39677db4cf2709526b71d89f3eaac1cf469f38109ab8ef0bb5b4cfda29ca3
check_crate qpx-h3 01aecfccd1ef9f622ca8a78e2a6859d06b73060d2e18159ec59a4305523f0d61
check_crate qpx-acme 437ee44d007ac282cf2216fa00cb602dfd1a0daf6846f62376fa6cb35831442a
check_crate qpx-observability baa66d20c029936bb98c25b9d2925d50eebfa6bba9e2698bb18c19454f1610a2
