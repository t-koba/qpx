#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JSONL="${1:-${QPX_ALLOCATION_PROFILE_JSON:-}}"
BUDGET="${2:-${QPX_ALLOCATION_BUDGET:-$ROOT_DIR/perf/allocation-budget.json}}"

if [ -z "$JSONL" ] || [ -z "$BUDGET" ]; then
  echo "usage: scripts/check-allocation-budget.sh <allocation-jsonl> [budget-json]" >&2
  exit 2
fi

python3 - "$JSONL" "$BUDGET" <<'PY'
import json
import math
import sys

jsonl_path, budget_path = sys.argv[1:3]


def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)


with open(budget_path, "r", encoding="utf-8") as handle:
    budget = json.load(handle)

if budget.get("schema_version") != 1:
    fail("unsupported allocation budget schema")

bench = budget.get("bench")
if not isinstance(bench, str) or not bench:
    fail("allocation budget bench must be a non-empty string")

records = []
with open(jsonl_path, "r", encoding="utf-8") as handle:
    for line_number, line in enumerate(handle, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            fail(f"{jsonl_path}:{line_number}: invalid JSON: {exc}")
        if record.get("bench") == bench:
            records.append(record)

if len(records) != 1:
    fail(f"expected exactly one allocation profile for {bench}, found {len(records)}")

record = records[0]


def positive_number(source, field):
    try:
        value = float(source[field])
    except (KeyError, TypeError, ValueError):
        fail(f"missing numeric {field}")
    if not math.isfinite(value) or value <= 0:
        fail(f"{field} must be a positive finite number")
    return value


alloc_bytes = positive_number(record, "alloc_bytes_per_request")
alloc_count = positive_number(record, "alloc_count_per_request")
max_bytes = positive_number(budget, "max_alloc_bytes_per_request")
max_count = positive_number(budget, "max_alloc_count_per_request")

failures = []
if alloc_bytes > max_bytes:
    failures.append(
        f"allocation byte budget exceeded: {alloc_bytes:.3f} > {max_bytes:.3f} bytes/request"
    )
if alloc_count > max_count:
    failures.append(
        f"allocation count budget exceeded: {alloc_count:.3f} > {max_count:.3f} allocations/request"
    )
if failures:
    for failure in failures:
        print(failure, file=sys.stderr)
    sys.exit(1)

print(
    "allocation budget ok: "
    f"{alloc_bytes:.3f}/{max_bytes:.3f} bytes/request, "
    f"{alloc_count:.3f}/{max_count:.3f} allocations/request"
)
PY
