#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ "$(uname -s)" != Linux ]; then
  echo "origin/cache revision comparison requires Linux resource accounting" >&2
  exit 1
fi
BASELINE_BIN="${QPX_PERF_BASELINE_BIN:?baseline binary is required}"
BASELINE_SHA="${QPX_PERF_BASELINE_SHA:?baseline commit is required}"
CURRENT_BIN="${QPXD_BIN:-$ROOT_DIR/target/release/qpxd}"
CURRENT_SHA="${GITHUB_SHA:-$(git -C "$ROOT_DIR" rev-parse HEAD)}"
revision_order="${QPX_PERF_REVISION_ORDER:-baseline-current}"
workload="${QPX_PERF_REVISION_WORKLOAD:-webdav}"
case "$workload" in
  webdav) proxies=qpxd-webdav,apache-webdav; body_sizes="1024 1048576" ;;
  cache) proxies=qpxd-cache,nginx-cache,qpxd-feature-rich,nginx-feature-rich; body_sizes=1024 ;;
  *) echo "unsupported origin/cache revision workload: $workload" >&2; exit 2 ;;
esac
case "$revision_order" in
  baseline-current) revisions=(baseline current) ;;
  current-baseline) revisions=(current baseline) ;;
  *) echo "unsupported origin/cache revision order: $revision_order" >&2; exit 2 ;;
esac
for binary in "$BASELINE_BIN" "$CURRENT_BIN"; do
  if [ ! -x "$binary" ]; then
    echo "origin/cache revision comparison binary is not executable: $binary" >&2
    exit 1
  fi
done
mkdir -p "$ROOT_DIR/target/perf/profiles"
profile_dir="$(mktemp -d "$ROOT_DIR/target/perf/profiles/${workload}-pair.XXXXXX")"
python3 - "$ROOT_DIR" "$profile_dir" "$BASELINE_BIN" "$BASELINE_SHA" "$CURRENT_BIN" "$CURRENT_SHA" "$revision_order" "$workload" <<'PY_MANIFEST'
import hashlib
import json
from pathlib import Path
import re
import sys
root, output, baseline, baseline_sha, current, current_sha, order, workload = sys.argv[1:]
output = Path(output)
if any(re.fullmatch(r"[0-9a-f]{40}", value) is None for value in (baseline_sha, current_sha)):
    raise SystemExit("origin/cache revision comparison requires exact commit identities")
objectives = json.loads((Path(root) / "perf/origin-cache-performance-objectives.json").read_text())
required = ({("origin_webdav_http1", 1024), ("origin_webdav_http1", 1048576)}
            if workload == "webdav" else
            {("proxy_cache_hit_http1", 1024), ("proxy_cache_miss_http1", 1024),
             ("feature_rich_cache_hit_http1", 1024)})
objectives["lanes"] = [lane for lane in objectives["lanes"]
                       if (lane["bench"], lane["body_bytes"]) in required]
if len(objectives["lanes"]) != len(required) or {(lane["bench"], lane["body_bytes"]) for lane in objectives["lanes"]} != required:
    raise SystemExit("origin/cache revision objectives lack the complete workload")
(output / "objectives.json").write_text(json.dumps(objectives, indent=2) + "\n")
for lane in objectives["lanes"]:
    if workload == "webdav" and lane["body_bytes"] == 1048576:
        lane["max_p99_latency_ratio"] = min(
            lane.get("max_p99_latency_ratio", objectives["defaults"]["max_p99_latency_ratio"]), 1.0)
    elif workload == "cache" and lane["bench"] != "proxy_cache_hit_http1":
        for metric in ("min_throughput_ratio", "min_cpu_efficiency_ratio"):
            lane[metric] = max(lane.get(metric, objectives["defaults"][metric]), 1.0)
        for metric in ("max_p99_latency_ratio", "max_scheduler_queue_delay_ratio"):
            lane[metric] = min(lane.get(metric, objectives["defaults"][metric]), 1.0)
(output / "goal-objectives.json").write_text(json.dumps(objectives, indent=2) + "\n")
manifest = {
    "measurement": "origin_cache_same_runner_revision_comparison_v3",
    "workload": workload,
    "replaces_required_gate": False, "sampling_order": order.split("-"),
    "required_lanes": [{"bench": bench, "body_bytes": size} for bench, size in sorted(required)],
    "required_body_bytes": sorted({size for _, size in required}), "required_samples_per_role": 3,
    "diagnostic_instrumentation": False,
    "binaries": {name: {"path": path, "commit": commit,
                         "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest()}
                 for name, path, commit in (("baseline", baseline, baseline_sha),
                                           ("current", current, current_sha))},
}
(output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
PY_MANIFEST
failed=0
for revision in "${revisions[@]}"; do
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
    QPX_PROXY_COMPARE_PROXY_FILTER="$proxies" \
    QPX_PROXY_COMPARE_BODY_SIZES="$body_sizes" \
    QPX_PROXY_COMPARE_DURATION_SECONDS=10 QPX_PROXY_COMPARE_CONCURRENCY=64 \
    QPX_PROXY_COMPARE_THREADS=2 QPX_PROXY_COMPARE_WRK_TIMEOUT=30s \
    QPX_PROXY_COMPARE_CALLGRIND_DIAGNOSTICS=0 \
    QPX_PROXY_COMPARE_SAMPLE_ATTEMPTS=3 QPX_PROXY_COMPARE_LOG_DIR="$directory/logs" \
    QPX_PROXY_COMPARE_WEBDAV_QPXD_ENV="MALLOC_ARENA_MAX=2 MALLOC_TRIM_THRESHOLD_=134217728" \
    python3 "$ROOT_DIR/scripts/perf-evaluate.py" "$revision $workload revision comparison" -- \
    bash "$ROOT_DIR/scripts/perf-audit-proxy-compare.sh" "$directory/comparison.jsonl"; then
    failed=1
  fi
  if ! python3 "$ROOT_DIR/scripts/perf-evaluate.py" "$revision $workload measurement quality" -- \
    bash "$ROOT_DIR/scripts/check-origin-cache-performance.sh" "$directory/comparison.jsonl" \
    "$profile_dir/objectives.json" measurement-quality; then
    failed=1
  fi
  if [ "$revision" = current ]; then
    if ! python3 "$ROOT_DIR/scripts/perf-evaluate.py" "current $workload existing acceptance" -- \
      bash "$ROOT_DIR/scripts/check-origin-cache-performance.sh" "$directory/comparison.jsonl" \
      "$profile_dir/objectives.json"; then
      failed=1
    fi
    if ! python3 "$ROOT_DIR/scripts/perf-evaluate.py" "current $workload performance goals" -- \
      bash "$ROOT_DIR/scripts/check-origin-cache-performance.sh" "$directory/comparison.jsonl" \
      "$profile_dir/goal-objectives.json"; then
      failed=1
    fi
  fi
done
exit "$failed"
