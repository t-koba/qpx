#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_JSON="${1:-${QPX_CRITERION_JSON:-$ROOT_DIR/target/perf/perf-audit-criterion.jsonl}}"
CRITERION_DIR="${QPX_CRITERION_DIR:-$ROOT_DIR/target/criterion}"

mkdir -p "$(dirname "$OUT_JSON")"

python3 - "$CRITERION_DIR" "$OUT_JSON" "${GITHUB_SHA:-unknown}" <<'PY'
import json
import pathlib
import sys

criterion_dir = pathlib.Path(sys.argv[1])
out_path = pathlib.Path(sys.argv[2])
commit = sys.argv[3]

estimate_files = sorted(criterion_dir.glob("**/new/estimates.json"))
if not estimate_files:
    raise SystemExit(f"missing Criterion estimates under {criterion_dir}")

with out_path.open("w", encoding="utf-8") as out:
    for estimate_path in estimate_files:
        with estimate_path.open("r", encoding="utf-8") as handle:
            estimates = json.load(handle)
        rel_parts = estimate_path.relative_to(criterion_dir).parts[:-2]
        if not rel_parts:
            continue
        record = {
            "bench": "criterion_streaming_throughput",
            "benchmark_id": "/".join(rel_parts),
            "group": rel_parts[0],
            "parameter": "/".join(rel_parts[1:]) or None,
            "mean_ns": estimates["mean"]["point_estimate"],
            "mean_lower_ns": estimates["mean"]["confidence_interval"]["lower_bound"],
            "mean_upper_ns": estimates["mean"]["confidence_interval"]["upper_bound"],
            "median_ns": estimates["median"]["point_estimate"],
            "median_lower_ns": estimates["median"]["confidence_interval"]["lower_bound"],
            "median_upper_ns": estimates["median"]["confidence_interval"]["upper_bound"],
            "std_dev_ns": estimates["std_dev"]["point_estimate"],
            "commit": commit,
        }
        out.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
PY
