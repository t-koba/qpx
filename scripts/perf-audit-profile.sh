#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE_DIR="${QPX_PERF_PROFILE_DIR:-$ROOT_DIR/target/perf/profiles}"
PROFILE_JSON="${QPX_PERF_PROFILE_JSON:-$ROOT_DIR/target/perf/perf-audit-profile-summary.jsonl}"
PROFILE_EVENTS="${QPX_PERF_PROFILE_EVENTS:-$ROOT_DIR/target/perf/perf-audit-profile-events.jsonl}"
PROFILE_REQUESTS="${QPX_PERF_PROFILE_REQUESTS:-32}"
PROFILE_CONCURRENCY="${QPX_PERF_PROFILE_CONCURRENCY:-4}"

mkdir -p "$PROFILE_DIR" "$(dirname "$PROFILE_JSON")"
: >"$PROFILE_JSON"
: >"$PROFILE_EVENTS"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

json_escape() {
  python3 -c 'import json, sys; print(json.dumps(sys.argv[1]))' "$1"
}

test_binary_from_messages() {
  local messages="$1"
  python3 - "$messages" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    for line in handle:
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        profile = message.get("profile") or {}
        executable = message.get("executable")
        if profile.get("test") is True and executable:
            print(executable)
            sys.exit(0)
sys.exit(1)
PY
}

build_test_binary() {
  local test_name="$1"
  local features="$2"
  local messages="$PROFILE_DIR/${test_name}.cargo-messages.jsonl"
  if [ -n "$features" ]; then
    cargo test -p qpxd --release --test "$test_name" --locked --features "$features" --no-run --message-format=json >"$messages"
  else
    cargo test -p qpxd --release --test "$test_name" --locked --no-run --message-format=json >"$messages"
  fi
  test_binary_from_messages "$messages"
}

annotate_callgrind_outputs() {
  local target="$1"
  local filter="$2"
  local commit="${GITHUB_SHA:-unknown}"
  local file instructions annotated cmd_line failed
  failed=0
  while IFS= read -r file; do
    if ! grep -q '^events:' "$file"; then
      echo "callgrind output missing events: ${file}" >&2
      failed=1
      continue
    fi
    instructions="$(awk '/^summary:/ { print $2; exit }' "$file")"
    instructions="${instructions:-0}"
    if ! [[ "$instructions" =~ ^[0-9]+$ ]] || [ "$instructions" -le 0 ]; then
      echo "callgrind output has no instructions: ${file}" >&2
      failed=1
      continue
    fi
    cmd_line="$(awk -F':  ' '/^cmd:/ { print $2; exit }' "$file")"
    cmd_line="${cmd_line:-unknown}"
    annotated="${file}.annotated.txt"
    if ! callgrind_annotate --threshold=99 "$file" >"$annotated" 2>"${annotated}.err"; then
      echo "callgrind_annotate failed for ${file}" >&2
      cat "${annotated}.err" >&2 || true
      failed=1
      continue
    fi
    printf '{"bench":"callgrind_hot_path_profile","target":%s,"filter":%s,"command":%s,"instructions":%s,"callgrind_file":%s,"annotated_file":%s,"commit":%s}\n' \
      "$(json_escape "$target")" \
      "$(json_escape "$filter")" \
      "$(json_escape "$cmd_line")" \
      "$instructions" \
      "$(json_escape "${file#"$ROOT_DIR"/}")" \
      "$(json_escape "${annotated#"$ROOT_DIR"/}")" \
      "$(json_escape "$commit")" >>"$PROFILE_JSON"
  done < <(find "$PROFILE_DIR" -type f -name "callgrind.${target}.${filter}.*.out" | sort)
  return "$failed"
}

run_profile() {
  local test_name="$1"
  local filter="$2"
  local features="${3:-}"
  local filter_slug="$filter"
  local test_bin
  filter_slug="${filter_slug:-all}"
  filter_slug="${filter_slug//[^A-Za-z0-9_.-]/_}"
  test_bin="$(build_test_binary "$test_name" "$features")"
  echo "profiling ${test_name} ${filter_slug}" >&2
  rm -f "$PROFILE_DIR/callgrind.${test_name}.${filter_slug}."*.out \
    "$PROFILE_DIR/callgrind.${test_name}.${filter_slug}."*.out.annotated.txt \
    "$PROFILE_DIR/callgrind.${test_name}.${filter_slug}."*.out.annotated.txt.err
  QPX_PERF_PROFILE=1 \
  QPX_PERF_PROFILE_REQUESTS="$PROFILE_REQUESTS" \
  QPX_PERF_PROFILE_CONCURRENCY="$PROFILE_CONCURRENCY" \
  QPX_PERF_SMOKE_JSON="$PROFILE_EVENTS" \
  valgrind \
    --tool=callgrind \
    --trace-children=yes \
    --child-silent-after-fork=yes \
    --callgrind-out-file="$PROFILE_DIR/callgrind.${test_name}.${filter_slug}.%p.out" \
    "$test_bin" ${filter:+"$filter"} --nocapture --test-threads=1
  annotate_callgrind_outputs "$test_name" "$filter_slug"
}

require_cmd callgrind_annotate
require_cmd cargo
require_cmd python3
require_cmd valgrind

run_profile "perf_smoke" ""
run_profile "perf_smoke" "reverse_http3" "http3-backend-h3"
run_profile "perf_smoke" "reverse_http3" "http3-backend-qpx"
run_profile "advanced_transport_perf" "" "http3-backend-qpx,mitm"
