#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ "$#" -gt 0 ]; then
  FILES=("$@")
else
  mapfile -t FILES < <(cut -f1 "${ROOT_DIR}/xtask/loc-budgets.tsv" | grep -v '^$')
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
