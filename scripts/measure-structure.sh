#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

DEFAULT_FILES=(
  "qpxd/src/forward/h3_connect.rs"
  "qpxd/src/reverse/transport.rs"
  "qpx-core/src/config/validate.rs"
  "qpxd/src/forward/connect.rs"
  "qpxd/src/reverse/router.rs"
  "qpxd/src/transparent/udp_path.rs"
  "qpxd/src/forward/request.rs"
  "qpx-core/src/config/types/mod.rs"
  "qpxd/src/runtime.rs"
  "qpxd/src/upstream/origin.rs"
)

if [ "$#" -gt 0 ]; then
  FILES=("$@")
else
  FILES=("${DEFAULT_FILES[@]}")
fi

strip_inline_tests() {
  local file="$1"
  awk '
    function brace_delta(line, tmp, opens, closes) {
      tmp = line
      sub(/\/\/.*/, "", tmp)
      opens = gsub(/\{/, "{", tmp)
      closes = gsub(/\}/, "}", tmp)
      return opens - closes
    }
    {
      if (!skip && $0 ~ /^[[:space:]]*#\[cfg\(test\)\][[:space:]]*mod tests[[:space:]]*\{[[:space:]]*$/) {
        skip = 1
        depth = 1
        next
      }
      if (!skip && $0 ~ /^[[:space:]]*#\[cfg\(test\)\][[:space:]]*$/) {
        pending = 1
        next
      }
      if (pending && $0 ~ /^[[:space:]]*mod tests[[:space:]]*\{[[:space:]]*$/) {
        skip = 1
        depth = 1
        pending = 0
        next
      }
      if (pending) {
        pending = 0
        print $0
        next
      }
      if (skip) {
        depth += brace_delta($0)
        if (depth <= 0) {
          skip = 0
          depth = 0
        }
        next
      }
      print $0
    }
  ' "$file"
}

count_code_lines() {
  awk '
    /^[[:space:]]*$/ { next }
    {
      line = $0
      sub(/^[[:space:]]+/, "", line)
      if (in_block) {
        if (line ~ /\*\//) {
          in_block = 0
        }
        next
      }
      if (line ~ /^\/\//) {
        next
      }
      if (line ~ /^\/\*/) {
        if (line !~ /\*\//) {
          in_block = 1
        }
        next
      }
      count++
    }
    END {
      print count + 0
    }
  '
}

printf "%-42s %8s\n" "file" "code_loc"
for relative in "${FILES[@]}"; do
  absolute="${ROOT_DIR}/${relative}"
  if [ ! -f "$absolute" ]; then
    printf "%-42s %8s\n" "$relative" "missing"
    continue
  fi
  code_loc="$(strip_inline_tests "$absolute" | count_code_lines)"
  printf "%-42s %8s\n" "$relative" "$code_loc"
done
