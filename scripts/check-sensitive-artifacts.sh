#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

common_excludes=(
  --hidden
  --glob '!.git/**'
  --glob '!target/**'
  --glob '!.claude/**'
  --glob '!.qpx/**'
  --glob '!**/.qpx/**'
  --glob '!scripts/check-sensitive-artifacts.sh'
)

failed=0

check_rg() {
  local label="$1"
  local pattern="$2"
  if rg -n "${common_excludes[@]}" "$pattern" .; then
    echo "sensitive-artifacts: found ${label}" >&2
    failed=1
  fi
}

check_find() {
  local label="$1"
  shift
  local output
  output="$(
    find . \
      -path './.git' -prune -o \
      -path './target' -prune -o \
      -path './.claude' -prune -o \
      -path './.qpx' -prune -o \
      -path './qpxd/.qpx' -prune -o \
      "$@" -print
  )"
  if [[ -n "${output}" ]]; then
    printf '%s\n' "${output}"
    echo "sensitive-artifacts: found ${label}" >&2
    failed=1
  fi
}

check_rg "developer-local absolute paths" '/Users/|/home/[^/[:space:]]+/|/var/folders/|/private/var/'
check_rg "private key material" 'BEGIN (RSA |EC |OPENSSH |PRIVATE )?KEY|PRIVATE KEY'
check_rg "common high-entropy service tokens" 'AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{36,}|xox[baprs]-[A-Za-z0-9-]+'

check_find "local runtime directories" -type d \( -name '.qpx' -o -name '.claude' \)
check_find "local runtime files" -type f \( \
  -name '*.pid' -o \
  -name '*.log' -o \
  -name '*.sock' -o \
  -name '*.key' -o \
  -name '*.p12' -o \
  -name '*.pcap' -o \
  -name '*.pcapng' -o \
  -name '.env' -o \
  -name '*~' \
\)

if [[ "${failed}" -ne 0 ]]; then
  exit 1
fi
