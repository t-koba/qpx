#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="compare"
THRESHOLD=""

usage() {
  cat >&2 <<'USAGE'
usage:
  scripts/compare-proxy-baseline.sh [--threshold 0.10] <proxy-jsonl> [baseline-json]
  scripts/compare-proxy-baseline.sh --generate-baseline [--threshold 0.10] <proxy-jsonl> <baseline-json>
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --generate-baseline)
      MODE="generate"
      shift
      ;;
    --threshold)
      if [ "$#" -lt 2 ]; then
        usage
        exit 2
      fi
      THRESHOLD="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "unknown option: $1" >&2
      usage
      exit 2
      ;;
    *)
      break
      ;;
  esac
done

JSONL="${1:-${QPX_PROXY_COMPARE_JSON:-}}"
BASELINE="${2:-${QPX_PROXY_COMPARE_BASELINE:-$ROOT_DIR/perf/baseline-proxy-compare.json}}"

if [ -z "$JSONL" ] || [ -z "$BASELINE" ]; then
  usage
  exit 2
fi

python3 - "$MODE" "$JSONL" "$BASELINE" "$THRESHOLD" <<'PY'
import json
import math
import os
import sys
from collections import defaultdict

MODE, JSONL_PATH, BASELINE_PATH, THRESHOLD_ARG = sys.argv[1:5]
BENCH = "proxy_compare_http1_reverse"
METRIC = "qpxd_requests_per_sec / direct-backend_requests_per_sec"
DEFAULT_THRESHOLD = 0.10


def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def load_jsonl(path):
    records = []
    with open(path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                records.append(json.loads(stripped))
            except json.JSONDecodeError as exc:
                fail(f"{path}:{line_number}: invalid JSON: {exc}")
    return records


def parse_threshold(value, fallback):
    if value == "":
        return fallback
    try:
        threshold = float(value)
    except ValueError:
        fail(f"invalid threshold: {value}")
    if not math.isfinite(threshold) or threshold < 0 or threshold >= 1:
        fail("threshold must be in the range [0, 1)")
    return threshold


def number(record, field):
    try:
        value = float(record[field])
    except (KeyError, TypeError, ValueError):
        fail(f"record for proxy {record.get('proxy', '<missing>')} is missing numeric {field}")
    if not math.isfinite(value) or value <= 0:
        fail(f"{field} must be a positive finite number")
    return value


def lane_key(record):
    try:
        return (
            record["bench"],
            int(record["requests"]),
            int(record["concurrency"]),
            int(record["body_bytes"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        fail(f"invalid proxy comparison record shape: {exc}")


def collect_ratios(records):
    grouped = defaultdict(dict)
    for record in records:
        if record.get("bench") != BENCH:
            continue
        proxy = record.get("proxy")
        if proxy not in {"direct-backend", "qpxd"}:
            continue
        grouped[lane_key(record)][proxy] = record

    ratios = []
    for key in sorted(grouped):
        proxies = grouped[key]
        if "direct-backend" not in proxies or "qpxd" not in proxies:
            fail(f"missing direct-backend or qpxd record for lane {key}")
        direct_rps = number(proxies["direct-backend"], "requests_per_sec")
        qpxd_rps = number(proxies["qpxd"], "requests_per_sec")
        ratio = qpxd_rps / direct_rps
        bench, requests, concurrency, body_bytes = key
        ratios.append(
            {
                "bench": bench,
                "requests": requests,
                "concurrency": concurrency,
                "body_bytes": body_bytes,
                "baseline_ratio": round(ratio, 6),
                "qpxd_requests_per_sec": qpxd_rps,
                "direct_backend_requests_per_sec": direct_rps,
                "source_commit": proxies["qpxd"].get("commit", "unknown"),
            }
        )

    if not ratios:
        fail(f"no {BENCH} qpxd/direct-backend records found in {JSONL_PATH}")
    return ratios


def baseline_key(entry):
    try:
        return (
            entry["bench"],
            int(entry["requests"]),
            int(entry["concurrency"]),
            int(entry["body_bytes"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        fail(f"invalid baseline shape: {exc}")


records = load_jsonl(JSONL_PATH)

if MODE == "generate":
    threshold = parse_threshold(THRESHOLD_ARG, DEFAULT_THRESHOLD)
    baseline = {
        "schema_version": 1,
        "metric": METRIC,
        "degradation_threshold": threshold,
        "baselines": collect_ratios(records),
    }
    os.makedirs(os.path.dirname(os.path.abspath(BASELINE_PATH)), exist_ok=True)
    with open(BASELINE_PATH, "w", encoding="utf-8") as handle:
        json.dump(baseline, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"wrote proxy baseline: {BASELINE_PATH}")
    sys.exit(0)

if MODE != "compare":
    fail(f"unknown mode: {MODE}")

with open(BASELINE_PATH, "r", encoding="utf-8") as handle:
    baseline = json.load(handle)

if baseline.get("schema_version") != 1:
    fail("unsupported proxy baseline schema")
if baseline.get("metric") != METRIC:
    fail("proxy baseline metric does not match this checker")

threshold = parse_threshold(THRESHOLD_ARG, float(baseline.get("degradation_threshold", DEFAULT_THRESHOLD)))
current = {baseline_key(entry): entry for entry in collect_ratios(records)}
failures = []

for entry in baseline.get("baselines", []):
    key = baseline_key(entry)
    current_entry = current.get(key)
    if current_entry is None:
        failures.append(f"missing current proxy comparison lane {key}")
        continue
    baseline_ratio = number(entry, "baseline_ratio")
    current_ratio = number(current_entry, "baseline_ratio")
    required_ratio = baseline_ratio * (1.0 - threshold)
    if current_ratio + 1e-12 < required_ratio:
        failures.append(
            "proxy baseline regression for "
            f"{key}: current ratio {current_ratio:.6f} < required {required_ratio:.6f} "
            f"(baseline {baseline_ratio:.6f}, threshold {threshold:.2%})"
        )
    else:
        print(
            "proxy baseline ok for "
            f"{key}: current ratio {current_ratio:.6f}, required {required_ratio:.6f}"
        )

if failures:
    for failure in failures:
        print(failure, file=sys.stderr)
    sys.exit(1)
PY
