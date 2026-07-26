#!/usr/bin/env bash
set -euo pipefail

MIN_CORES="${QPX_PERF_MIN_CORES:-4}"
MIN_MEM_MB="${QPX_PERF_MIN_MEM_MB:-15360}"
REQUIRE_CAPACITY="${QPX_PERF_REQUIRE_CAPACITY:-1}"
OUT_JSON="${QPX_PERF_RUNNER_JSON:-target/perf/runner.jsonl}"

mkdir -p "$(dirname "$OUT_JSON")"

cpu_count() {
  if command -v nproc >/dev/null 2>&1; then
    nproc
  elif command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.ncpu
  else
    echo 1
  fi
}

mem_mb() {
  if [ -r /proc/meminfo ]; then
    awk '/^MemTotal:/ { print int($2 / 1024); exit }' /proc/meminfo
  elif command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.memsize | awk '{ print int($1 / 1024 / 1024) }'
  else
    echo 0
  fi
}

cores="$(cpu_count)"
memory_mb="$(mem_mb)"
runner_name="${RUNNER_NAME:-unknown}"
runner_os="${RUNNER_OS:-unknown}"
runner_arch="${RUNNER_ARCH:-unknown}"
runner_environment="${RUNNER_ENVIRONMENT:-unknown}"
commit="${GITHUB_SHA:-unknown}"

printf '{"bench":"perf_runner_capacity","runner_name":"%s","runner_os":"%s","runner_arch":"%s","runner_environment":"%s","cpu_cores":%s,"memory_mb":%s,"min_cpu_cores":%s,"min_memory_mb":%s,"commit":"%s"}\n' \
  "$runner_name" "$runner_os" "$runner_arch" "$runner_environment" "$cores" "$memory_mb" "$MIN_CORES" "$MIN_MEM_MB" "$commit" >"$OUT_JSON"

if [ "$cores" -lt "$MIN_CORES" ] || [ "$memory_mb" -lt "$MIN_MEM_MB" ]; then
  echo "perf runner is below target capacity: cores=${cores}/${MIN_CORES} memory_mib=${memory_mb}/${MIN_MEM_MB}" >&2
  if [ "$REQUIRE_CAPACITY" = "1" ] || [ "$REQUIRE_CAPACITY" = "true" ]; then
    exit 1
  fi
fi
