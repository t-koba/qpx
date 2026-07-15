#!/usr/bin/env bash

make_temp_dir() {
  local prefix="${1:?temporary directory prefix is required}"
  local logical_root="${TMPDIR:-/tmp}"
  local physical_root
  physical_root="$(cd "$logical_root" && pwd -P)" || {
    echo "failed to resolve temporary directory root: $logical_root" >&2
    return 1
  }
  mktemp -d "$physical_root/${prefix}.XXXXXX"
}
