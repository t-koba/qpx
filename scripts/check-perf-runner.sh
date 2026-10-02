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

python3 - "$OUT_JSON" "$cores" "$memory_mb" "$MIN_CORES" "$MIN_MEM_MB" \
  "$runner_name" "$runner_os" "$runner_arch" "$runner_environment" "$commit" <<'PY'
import json
import os
import platform
from pathlib import Path
import subprocess
import sys
import time

out, cores, memory, min_cores, min_memory, name, system, arch, environment, commit = sys.argv[1:11]
record = {
    "bench": "perf_runner_capacity",
    "runner_name": name, "runner_os": system, "runner_arch": arch,
    "runner_environment": environment, "cpu_cores": int(cores),
    "memory_mb": int(memory), "min_cpu_cores": int(min_cores),
    "min_memory_mb": int(min_memory), "commit": commit,
    "kernel": platform.release(), "machine": platform.machine(),
    "image_os": os.environ.get("ImageOS"),
    "image_version": os.environ.get("ImageVersion"),
    "recorded_at_unix": time.time(),
    "rustc": subprocess.check_output(["rustc", "-Vv"], text=True).strip(),
    "cargo": subprocess.check_output(["cargo", "--version"], text=True).strip(),
}
if Path("/proc/cpuinfo").exists():
    record["cpu_models"] = sorted({line.split(":", 1)[1].strip()
                                   for line in Path("/proc/cpuinfo").read_text().splitlines()
                                   if line.startswith("model name")})
Path(out).write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
PY

if [ "$cores" -lt "$MIN_CORES" ] || [ "$memory_mb" -lt "$MIN_MEM_MB" ]; then
  echo "perf runner is below target capacity: cores=${cores}/${MIN_CORES} memory_mib=${memory_mb}/${MIN_MEM_MB}" >&2
  if [ "$REQUIRE_CAPACITY" = "1" ] || [ "$REQUIRE_CAPACITY" = "true" ]; then
    exit 1
  fi
fi
