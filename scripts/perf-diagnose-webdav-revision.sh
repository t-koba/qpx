#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ "$(uname -s)" != Linux ]; then
  echo "WebDAV revision comparison requires Linux resource accounting" >&2
  exit 1
fi
BASELINE_BIN="${QPX_PERF_BASELINE_BIN:?baseline binary is required}"
BASELINE_SHA="${QPX_PERF_BASELINE_SHA:?baseline commit is required}"
CURRENT_BIN="${QPXD_BIN:-$ROOT_DIR/target/release/qpxd}"
CURRENT_SHA="${GITHUB_SHA:-$(git -C "$ROOT_DIR" rev-parse HEAD)}"
for binary in "$BASELINE_BIN" "$CURRENT_BIN"; do
  if [ ! -x "$binary" ]; then
    echo "WebDAV revision comparison binary is not executable: $binary" >&2
    exit 1
  fi
done
mkdir -p "$ROOT_DIR/target/perf/profiles"
profile_dir="$(mktemp -d "$ROOT_DIR/target/perf/profiles/webdav-pair.XXXXXX")"
python3 - "$ROOT_DIR" "$profile_dir" "$BASELINE_BIN" "$BASELINE_SHA" "$CURRENT_BIN" "$CURRENT_SHA" <<'PY_MANIFEST'
import hashlib
import json
from pathlib import Path
import re
import sys
root, output, baseline, baseline_sha, current, current_sha = sys.argv[1:]
output = Path(output)
if any(re.fullmatch(r"[0-9a-f]{40}", value) is None for value in (baseline_sha, current_sha)):
    raise SystemExit("WebDAV revision comparison requires exact commit identities")
objectives = json.loads((Path(root) / "perf/origin-cache-performance-objectives.json").read_text())
objectives["lanes"] = [lane for lane in objectives["lanes"] if lane["bench"] == "origin_webdav_http1"]
if len(objectives["lanes"]) != 2 or {lane["body_bytes"] for lane in objectives["lanes"]} != {1024, 1048576}:
    raise SystemExit("WebDAV revision objectives lack the complete existing workload")
(output / "objectives.json").write_text(json.dumps(objectives, indent=2) + "\n")
for lane in objectives["lanes"]:
    if lane["body_bytes"] == 1048576:
        lane["max_p99_latency_ratio"] = min(
            lane.get("max_p99_latency_ratio", objectives["defaults"]["max_p99_latency_ratio"]), 1.0)
(output / "goal-objectives.json").write_text(json.dumps(objectives, indent=2) + "\n")
manifest = {
    "measurement": "webdav_same_runner_revision_comparison_v1",
    "replaces_required_gate": False, "sampling_order": "baseline_then_current",
    "required_body_bytes": [1024, 1048576], "required_samples_per_role": 3,
    "diagnostic_instrumentation": False,
    "binaries": {name: {"path": path, "commit": commit,
                         "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest()}
                 for name, path, commit in (("baseline", baseline, baseline_sha),
                                           ("current", current, current_sha))},
}
(output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
PY_MANIFEST
failed=0
for revision in baseline current; do
  binary="$BASELINE_BIN"
  sha="$BASELINE_SHA"
  if [ "$revision" = current ]; then
    binary="$CURRENT_BIN"
    sha="$CURRENT_SHA"
  fi
  directory="$profile_dir/$revision"
  mkdir "$directory"
  if ! env GITHUB_SHA="$sha" QPXD_BIN="$binary" \
    QPX_PROXY_COMPARE_THREAD_DIAGNOSTICS=0 \
    QPX_PROXY_COMPARE_PROXY_FILTER=qpxd-webdav,apache-webdav \
    QPX_PROXY_COMPARE_BODY_SIZES="1024 1048576" \
    QPX_PROXY_COMPARE_DURATION_SECONDS=10 QPX_PROXY_COMPARE_CONCURRENCY=64 \
    QPX_PROXY_COMPARE_THREADS=2 QPX_PROXY_COMPARE_WRK_TIMEOUT=30s \
    QPX_PROXY_COMPARE_CALLGRIND_DIAGNOSTICS=0 \
    QPX_PROXY_COMPARE_SAMPLE_ATTEMPTS=3 QPX_PROXY_COMPARE_LOG_DIR="$directory/logs" \
    QPX_PROXY_COMPARE_WEBDAV_QPXD_ENV="MALLOC_ARENA_MAX=2 MALLOC_TRIM_THRESHOLD_=134217728" \
    python3 "$ROOT_DIR/scripts/perf-evaluate.py" "$revision WebDAV revision comparison" -- \
    bash "$ROOT_DIR/scripts/perf-audit-proxy-compare.sh" "$directory/comparison.jsonl"; then
    failed=1
  fi
  if ! python3 "$ROOT_DIR/scripts/perf-evaluate.py" "$revision WebDAV measurement quality" -- \
    bash "$ROOT_DIR/scripts/check-origin-cache-performance.sh" "$directory/comparison.jsonl" \
    "$profile_dir/objectives.json" measurement-quality; then
    failed=1
  fi
  if [ "$revision" = current ]; then
    if ! python3 "$ROOT_DIR/scripts/perf-evaluate.py" "current WebDAV existing acceptance" -- \
      bash "$ROOT_DIR/scripts/check-origin-cache-performance.sh" "$directory/comparison.jsonl" \
      "$profile_dir/objectives.json"; then
      failed=1
    fi
    if ! python3 "$ROOT_DIR/scripts/perf-evaluate.py" "current WebDAV tail latency goal" -- \
      bash "$ROOT_DIR/scripts/check-origin-cache-performance.sh" "$directory/comparison.jsonl" \
      "$profile_dir/goal-objectives.json"; then
      failed=1
    fi
  fi
done
exit "$failed"
