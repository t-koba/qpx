#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JSONL="${1:-${QPX_PROXY_COMPARE_JSON:-}}"
OBJECTIVES="${2:-${QPX_ORIGIN_CACHE_PERFORMANCE_OBJECTIVES:-$ROOT_DIR/perf/origin-cache-performance-objectives.json}}"

if [ -z "$JSONL" ]; then
  echo "usage: scripts/check-origin-cache-performance.sh <proxy-jsonl> [objectives-json]" >&2
  exit 2
fi

python3 - "$JSONL" "$OBJECTIVES" <<'PY'
import json
import math
import sys

JSONL_PATH, OBJECTIVES_PATH = sys.argv[1:3]


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        fail(f"failed to load {path}: {error}")


def load_jsonl(path):
    records = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as error:
                    fail(f"{path}:{line_number}: invalid JSON: {error}")
    except OSError as error:
        fail(f"failed to load {path}: {error}")
    return records


def number(container, field, context):
    try:
        value = float(container[field])
    except (KeyError, TypeError, ValueError):
        fail(f"{context} is missing positive numeric {field}")
    if not math.isfinite(value) or value <= 0:
        fail(f"{context} has invalid {field}: {value}")
    return value


def nonnegative_number(container, field, context):
    try:
        value = float(container[field])
    except (KeyError, TypeError, ValueError):
        fail(f"{context} is missing non-negative numeric {field}")
    if not math.isfinite(value) or value < 0:
        fail(f"{context} has invalid {field}: {value}")
    return value


def lower_is_better_ratio(current, reference):
    if reference == 0:
        return 1.0 if current == 0 else sys.float_info.max
    return current / reference


def nonnegative_integer(container, field, context):
    try:
        value = int(container[field])
    except (KeyError, TypeError, ValueError):
        fail(f"{context} is missing non-negative integer {field}")
    if value < 0:
        fail(f"{context} has invalid {field}: {value}")
    return value


def require_record(record, context):
    if record.get("valid") is not True:
        fail(f"{context} is marked invalid")
    if record.get("benchmark_schema_version") != 4:
        fail(f"{context} uses unsupported benchmark schema")
    if record.get("resource_measurement") != "sampled_workload_peak_v1":
        fail(f"{context} uses unsupported resource measurement")
    if record.get("aggregation") != "conservative_median_per_metric":
        fail(f"{context} uses unsupported aggregation")
    if record.get("sampling_order") != "round_robin_interleaved":
        fail(f"{context} was not interleaved")
    if record.get("sample_spread_basis") != "tightest_valid_majority":
        fail(f"{context} does not use majority spread")
    execution_model = record.get("execution_model")
    if execution_model not in ("async-io", "thread-per-request"):
        fail(f"{context} has unsupported execution model: {execution_model}")
    if nonnegative_integer(record, "role_workers", context) == 0:
        fail(f"{context} has no role workers")
    if record.get("kernel_resource_metrics") is not True:
        fail(f"{context} is missing Linux kernel resource metrics")
    if context.startswith("proxy_cache_miss_http1/") and record.get("cache_writeback_verified") is not True:
        fail(f"{context} did not verify durable cache writeback")
    rss_baseline_kb = nonnegative_integer(record, "rss_baseline_kb", context)
    if rss_baseline_kb == 0:
        fail(f"{context} has no RSS baseline measurement")
    rss_peak_kb = nonnegative_integer(record, "rss_peak_kb", context)
    if rss_peak_kb == 0:
        fail(f"{context} has no peak RSS measurement")
    rss_growth_kb = nonnegative_integer(record, "rss_growth_kb", context)
    fd_baseline = nonnegative_integer(record, "fd_baseline", context)
    if fd_baseline == 0:
        fail(f"{context} has no FD baseline measurement")
    fd_peak = nonnegative_integer(record, "fd_peak", context)
    if fd_peak == 0:
        fail(f"{context} has no peak FD measurement")
    fd_growth = nonnegative_integer(record, "fd_growth", context)
    if rss_peak_kb < rss_baseline_kb or rss_growth_kb != rss_peak_kb - rss_baseline_kb:
        fail(f"{context} has inconsistent RSS measurements")
    if fd_peak < fd_baseline or fd_growth != fd_peak - fd_baseline:
        fail(f"{context} has inconsistent FD measurements")
    attempts = nonnegative_integer(record, "sample_attempts", context)
    valid_samples = nonnegative_integer(record, "valid_samples", context)
    if attempts == 0 or valid_samples < attempts // 2 + 1 or valid_samples > attempts:
        fail(f"{context} lacks a majority of valid samples")
    requests = nonnegative_integer(record, "requests", context)
    completed = nonnegative_integer(record, "complete_requests", context)
    if requests == 0 or requests != completed:
        fail(f"{context} did not complete every request")
    for field in (
        "connect_errors",
        "write_errors",
        "timeout_errors",
        "non_2xx_responses",
        "bad_length_responses",
        "cache_result_errors",
    ):
        if nonnegative_integer(record, field, context) != 0:
            fail(f"{context} has non-zero {field}")
    read_errors = nonnegative_integer(record, "read_errors", context)
    max_read_error_rate_ppm = nonnegative_integer(
        record, "max_read_error_rate_ppm", context
    )
    if read_errors * 1_000_000 > completed * max_read_error_rate_ppm:
        fail(f"{context} exceeds the bounded read-error rate")
    failed_requests = nonnegative_integer(record, "failed_requests", context)
    if failed_requests != read_errors:
        fail(f"{context} has inconsistent failed request accounting")
    if str(record.get("status_before")) != "200" or str(record.get("status_after")) != "200":
        fail(f"{context} failed status probes")
    spread = record.get("sample_spread")
    if not isinstance(spread, dict):
        fail(f"{context} is missing sample_spread")
    for field in (
        "requests_per_sec_ratio",
        "latency_p99_ratio",
        "requests_per_cpu_second_ratio",
    ):
        if number(spread, field, context) < 1.0:
            fail(f"{context} has invalid {field}")


objectives = load_json(OBJECTIVES_PATH)
if objectives.get("schema_version") != 2:
    fail("unsupported origin/cache objectives schema")
if objectives.get("metric") != "multi_axis_origin_cache_dominance":
    fail("origin/cache objectives metric does not match this checker")
if objectives.get("resource_measurement") != "sampled_workload_peak_v1":
    fail("origin/cache resource measurement does not match this checker")
defaults = objectives.get("defaults")
lanes = objectives.get("lanes")
if not isinstance(defaults, dict) or not isinstance(lanes, list) or not lanes:
    fail("origin/cache objectives require defaults and at least one lane")

records = load_jsonl(JSONL_PATH)
indexed = {}
for record in records:
    try:
        key = (record["bench"], int(record["body_bytes"]), record["proxy"])
    except (KeyError, TypeError, ValueError):
        continue
    if key in indexed:
        fail(f"duplicate performance record for {key}")
    indexed[key] = record

results = []
for lane in lanes:
    try:
        bench = lane["bench"]
        body_bytes = int(lane["body_bytes"])
        qpx_name = lane["qpx"]
        reference_name = lane["reference"]
    except (KeyError, TypeError, ValueError) as error:
        fail(f"invalid origin/cache objective lane: {error}")
    qpx = indexed.get((bench, body_bytes, qpx_name))
    reference = indexed.get((bench, body_bytes, reference_name))
    if qpx is None or reference is None:
        fail(
            f"missing origin/cache records for {bench}/{body_bytes}: "
            f"{qpx_name}, {reference_name}"
        )
    qpx_context = f"{bench}/{body_bytes}/{qpx_name}"
    reference_context = f"{bench}/{body_bytes}/{reference_name}"
    require_record(qpx, qpx_context)
    require_record(reference, reference_context)
    expected_profile = lane.get("workload_profile")
    if not isinstance(expected_profile, str) or not expected_profile:
        fail(f"objective {bench}/{body_bytes} is missing workload_profile")
    if qpx.get("workload_profile") != expected_profile:
        fail(f"{qpx_context} uses unexpected workload profile")
    if reference.get("workload_profile") != expected_profile:
        fail(f"{reference_context} uses unexpected workload profile")
    for field in (
        "duration_seconds",
        "threads",
        "concurrency",
        "sample_attempts",
        "benchmark_schema_version",
        "sampling_order",
        "sample_spread_basis",
        "aggregation",
    ):
        if qpx.get(field) != reference.get(field):
            fail(f"{bench}/{body_bytes} disagrees on {field}")

    qpx_model = qpx["execution_model"]
    reference_model = reference["execution_model"]
    qpx_workers = nonnegative_integer(qpx, "role_workers", qpx_context)
    reference_workers = nonnegative_integer(
        reference, "role_workers", reference_context
    )
    if qpx_model == reference_model:
        if qpx_workers != reference_workers:
            fail(f"{bench}/{body_bytes} disagrees on async I/O worker count")
    elif bench == "origin_webdav_http1":
        if qpx_model != "async-io" or reference_model != "thread-per-request":
            fail(f"{bench}/{body_bytes} has unexpected execution models")
        qpx_blocking_workers = nonnegative_integer(
            qpx, "blocking_workers", qpx_context
        )
        if qpx_blocking_workers < qpx_workers:
            fail(f"{bench}/{body_bytes} has fewer blocking than async workers")
    else:
        fail(f"{bench}/{body_bytes} compares incompatible execution models")

    expected_workers = {
        "qpx_role_workers": qpx_workers,
        "reference_role_workers": reference_workers,
    }
    if bench == "origin_webdav_http1":
        expected_workers["qpx_blocking_workers"] = qpx_blocking_workers
    for field, actual in expected_workers.items():
        if field in lane and nonnegative_integer(lane, field, f"objective {bench}/{body_bytes}") != actual:
            fail(f"{bench}/{body_bytes} disagrees on objective {field}")

    throughput_ratio = number(qpx, "requests_per_sec", qpx_context) / number(
        reference, "requests_per_sec", reference_context
    )
    cpu_ratio = number(qpx, "requests_per_cpu_second", qpx_context) / number(
        reference, "requests_per_cpu_second", reference_context
    )
    p99_ratio = number(qpx, "latency_p99_ms", qpx_context) / number(
        reference, "latency_p99_ms", reference_context
    )
    rss_peak_ratio = lower_is_better_ratio(
        nonnegative_number(qpx, "rss_peak_kb", qpx_context),
        nonnegative_number(reference, "rss_peak_kb", reference_context),
    )
    fd_peak_ratio = lower_is_better_ratio(
        nonnegative_number(qpx, "fd_peak", qpx_context),
        nonnegative_number(reference, "fd_peak", reference_context),
    )
    scheduler_queue_delay_ratio = lower_is_better_ratio(
        nonnegative_number(qpx, "scheduler_queue_delay_us_per_request", qpx_context),
        nonnegative_number(
            reference, "scheduler_queue_delay_us_per_request", reference_context
        ),
    )
    dominance = (throughput_ratio * cpu_ratio / p99_ratio) ** (1.0 / 3.0)

    def objective(name):
        return number(lane if name in lane else defaults, name, f"objective {bench}/{body_bytes}")

    # Per-lane policy floors. Each floor equals the current evidence-based
    # objective so objectives can only be tightened, never weakened, without
    # changing this table.
    policy_floor = {
        ("proxy_cache_miss_http1", 1024): {
            "min_throughput_ratio": 0.65,
            "min_cpu_efficiency_ratio": 0.5,
            "max_p99_latency_ratio": 7.5,
            "min_dominance_score": 0.37,
            "max_rss_peak_ratio": 1.0,
            "max_fd_peak_ratio": 1.0,
            "max_scheduler_queue_delay_ratio": 2.6,
        },
        ("proxy_cache_hit_http1", 1024): {
            "min_throughput_ratio": 1.25,
            "min_cpu_efficiency_ratio": 1.25,
            "max_p99_latency_ratio": 0.8,
            "min_dominance_score": 1.25,
            "max_rss_peak_ratio": 1.0,
            "max_fd_peak_ratio": 1.0,
            "max_scheduler_queue_delay_ratio": 1.0,
        },
        ("proxy_cache_hit_http1", 1048576): {
            "min_throughput_ratio": 1.0,
            "min_cpu_efficiency_ratio": 1.1,
            "max_p99_latency_ratio": 1.15,
            "min_dominance_score": 1.1,
            "max_rss_peak_ratio": 1.0,
            "max_fd_peak_ratio": 1.0,
            "max_scheduler_queue_delay_ratio": 1.0,
        },
        ("feature_rich_cache_hit_http1", 1024): {
            "min_throughput_ratio": 0.85,
            "min_cpu_efficiency_ratio": 0.75,
            "max_p99_latency_ratio": 1.0,
            "min_dominance_score": 0.9,
            "max_rss_peak_ratio": 1.0,
            "max_fd_peak_ratio": 1.0,
            "max_scheduler_queue_delay_ratio": 1.0,
        },
        ("feature_rich_cache_hit_http1", 1048576): {
            "min_throughput_ratio": 1.0,
            "min_cpu_efficiency_ratio": 1.05,
            "max_p99_latency_ratio": 1.15,
            "min_dominance_score": 1.1,
            "max_rss_peak_ratio": 1.1,
            "max_fd_peak_ratio": 1.0,
            "max_scheduler_queue_delay_ratio": 1.0,
        },
        ("origin_local_http1", 1024): {
            "min_throughput_ratio": 1.25,
            "min_cpu_efficiency_ratio": 1.25,
            "max_p99_latency_ratio": 0.8,
            "min_dominance_score": 1.25,
            "max_rss_peak_ratio": 1.06,
            "max_fd_peak_ratio": 1.0,
            "max_scheduler_queue_delay_ratio": 1.0,
        },
        ("origin_webdav_http1", 1024): {
            "min_throughput_ratio": 1.1,
            "min_cpu_efficiency_ratio": 1.25,
            "max_p99_latency_ratio": 0.8,
            "min_dominance_score": 1.25,
            "max_rss_peak_ratio": 1.0,
            "max_fd_peak_ratio": 1.0,
            "max_scheduler_queue_delay_ratio": 1.0,
        },
        ("origin_webdav_http1", 1048576): {
            "min_throughput_ratio": 1.0,
            "min_cpu_efficiency_ratio": 1.5,
            "max_p99_latency_ratio": 6.0,
            "min_dominance_score": 0.82,
            "max_rss_peak_ratio": 1.0,
            "max_fd_peak_ratio": 1.0,
            "max_scheduler_queue_delay_ratio": 1.0,
        },
    }[(bench, body_bytes)]

    for name in ("min_throughput_ratio", "min_cpu_efficiency_ratio", "min_dominance_score"):
        if objective(name) < policy_floor[name]:
            fail(f"objective {bench}/{body_bytes} weakens {name}")
    if objective("max_p99_latency_ratio") > policy_floor["max_p99_latency_ratio"]:
        fail(f"objective {bench}/{body_bytes} weakens max_p99_latency_ratio")
    for name in (
        "max_rss_peak_ratio",
        "max_fd_peak_ratio",
        "max_scheduler_queue_delay_ratio",
    ):
        if objective(name) > policy_floor[name]:
            fail(f"objective {bench}/{body_bytes} weakens {name}")

    failures = []
    if throughput_ratio < objective("min_throughput_ratio"):
        failures.append(f"throughput ratio {throughput_ratio:.3f}")
    if cpu_ratio < objective("min_cpu_efficiency_ratio"):
        failures.append(f"CPU-efficiency ratio {cpu_ratio:.3f}")
    if p99_ratio > objective("max_p99_latency_ratio"):
        failures.append(f"p99 ratio {p99_ratio:.3f}")
    if dominance < objective("min_dominance_score"):
        failures.append(f"dominance score {dominance:.3f}")
    if rss_peak_ratio > objective("max_rss_peak_ratio"):
        failures.append(f"RSS peak ratio {rss_peak_ratio:.3f}")
    if fd_peak_ratio > objective("max_fd_peak_ratio"):
        failures.append(f"FD peak ratio {fd_peak_ratio:.3f}")
    if scheduler_queue_delay_ratio > objective("max_scheduler_queue_delay_ratio"):
        failures.append(f"scheduler queue-delay ratio {scheduler_queue_delay_ratio:.3f}")
    qpx_spread = qpx["sample_spread"]
    reference_spread = reference["sample_spread"]
    for field in ("requests_per_sec_ratio", "requests_per_cpu_second_ratio"):
        if number(qpx_spread, field, qpx_context) > objective("max_qpx_sample_spread_ratio"):
            failures.append(f"qpx {field} is unstable")
        if number(reference_spread, field, reference_context) > objective(
            "max_reference_sample_spread_ratio"
        ):
            failures.append(f"reference {field} is unstable")
    result = {
        "bench": bench,
        "body_bytes": body_bytes,
        "qpx": qpx_name,
        "reference": reference_name,
        "qpx_execution_model": qpx_model,
        "qpx_workers": qpx_workers,
        "reference_execution_model": reference_model,
        "reference_workers": reference_workers,
        "throughput_ratio": round(throughput_ratio, 6),
        "cpu_efficiency_ratio": round(cpu_ratio, 6),
        "p99_latency_ratio": round(p99_ratio, 6),
        "dominance_score": round(dominance, 6),
        "rss_peak_ratio": round(rss_peak_ratio, 6),
        "fd_peak_ratio": round(fd_peak_ratio, 6),
        "scheduler_queue_delay_ratio": round(scheduler_queue_delay_ratio, 6),
    }
    print(json.dumps(result, sort_keys=True))
    results.append((bench, body_bytes, failures))

failed = [(bench, body, failures) for bench, body, failures in results if failures]
if failed:
    for bench, body, failures in failed:
        print(f"{bench}/{body} failed: {', '.join(failures)}", file=sys.stderr)
    raise SystemExit(1)
PY
