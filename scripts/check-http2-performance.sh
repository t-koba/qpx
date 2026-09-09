#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JSONL="${1:-${QPX_HTTP2_COMPARE_JSON:-}}"
OBJECTIVES="${2:-${QPX_HTTP2_PERFORMANCE_OBJECTIVES:-$ROOT_DIR/perf/http2-performance-objectives.json}}"

if [ -z "$JSONL" ]; then
  echo "usage: scripts/check-http2-performance.sh <http2-jsonl> [objectives-json]" >&2
  exit 2
fi

python3 - "$JSONL" "$OBJECTIVES" <<'PY'
import json
import math
import sys

JSONL_PATH, OBJECTIVES_PATH = sys.argv[1:3]
BENCH = "proxy_compare_http2_reverse"
PROXIES = ("direct-backend", "qpxd", "nginx")


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


def positive_number(record, field, owner="record"):
    try:
        value = float(record[field])
    except (KeyError, TypeError, ValueError):
        fail(f"{owner} is missing numeric {field}")
    if not math.isfinite(value) or value <= 0:
        fail(f"{owner} field {field} must be a positive finite number")
    return value


def nonnegative_number(record, field, owner="record"):
    try:
        value = float(record[field])
    except (KeyError, TypeError, ValueError):
        fail(f"{owner} is missing numeric {field}")
    if not math.isfinite(value) or value < 0:
        fail(f"{owner} field {field} must be a non-negative finite number")
    return value


def lower_is_better_ratio(current, reference):
    if reference == 0:
        return 1.0 if current == 0 else sys.float_info.max
    return current / reference


def nonnegative_int(record, field, owner="record"):
    try:
        value = int(record[field])
    except (KeyError, TypeError, ValueError):
        fail(f"{owner} is missing integer {field}")
    if value < 0:
        fail(f"{owner} field {field} must be non-negative")
    return value


def nested_number(record, container, field, owner):
    nested = record.get(container)
    if not isinstance(nested, dict):
        fail(f"{owner} is missing object {container}")
    return positive_number(nested, field, owner)


def positive_int(record, field, owner="record"):
    value = record.get(field)
    if not isinstance(value, int) or value <= 0:
        fail(f"{owner} {field} must be a positive integer")
    return value


def positive_int_list(config, field):
    values = config.get(field)
    if not isinstance(values, list) or not values:
        fail(f"HTTP/2 objectives must declare non-empty {field}")
    if any(not isinstance(value, int) or value <= 0 for value in values):
        fail(f"HTTP/2 objective {field} must contain positive integers")
    if len(values) != len(set(values)):
        fail(f"HTTP/2 objective {field} must not contain duplicates")
    return tuple(values)


with open(OBJECTIVES_PATH, "r", encoding="utf-8") as handle:
    objectives = json.load(handle)
if objectives.get("schema_version") != 3:
    fail("unsupported HTTP/2 performance objectives schema")
if objectives.get("metric") != "multi_axis_total_system_http2_dominance":
    fail("HTTP/2 performance metric does not match this checker")
if objectives.get("resource_measurement") != "sampled_workload_peak_v1":
    fail("HTTP/2 performance objectives use an unsupported resource measurement")

limits = objectives.get("defaults", {})
limit_fields = (
    "min_lane_throughput_ratio",
    "min_lane_total_cpu_efficiency_ratio",
    "max_lane_mean_latency_ratio",
    "max_lane_p99_latency_ratio",
    "max_lane_latency_ratio",
    "min_lane_dominance_score",
    "min_aggregate_dominance_score",
    "max_qpx_throughput_sample_spread_ratio",
    "max_qpx_cpu_sample_spread_ratio",
    "max_reference_throughput_sample_spread_ratio",
    "max_reference_cpu_sample_spread_ratio",
    "max_lane_total_rss_peak_ratio",
    "max_lane_total_fd_peak_ratio",
    "max_lane_scheduler_queue_delay_ratio",
)
for field in limit_fields:
    positive_number(limits, field, "HTTP/2 objectives")

required_body_bytes = positive_int_list(objectives, "required_body_bytes")
required_streams = positive_int_list(objectives, "required_max_concurrent_streams")
required_lanes = {
    (body_bytes, max_streams)
    for body_bytes in required_body_bytes
    for max_streams in required_streams
}

# Per-lane objective overrides; lanes without an entry use the defaults.
lane_overrides = {}
for lane in objectives.get("lanes", []):
    key = (positive_int(lane, "body_bytes", "HTTP/2 lane"), positive_int(lane, "max_concurrent_streams", "HTTP/2 lane"))
    for field in limit_fields:
        if field in lane:
            lane_overrides.setdefault(key, {})[field] = positive_number(lane, field, "HTTP/2 lane")


def lane_limit(field, key):
    overrides = lane_overrides.get(key)
    if overrides is not None and field in overrides:
        return overrides[field]
    return positive_number(limits, field, "HTTP/2 objectives")

records = {}
with open(JSONL_PATH, "r", encoding="utf-8") as handle:
    for line_number, line in enumerate(handle, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError as exc:
            fail(f"{JSONL_PATH}:{line_number}: invalid JSON: {exc}")
        if record.get("bench") != BENCH or record.get("proxy") not in PROXIES:
            continue
        proxy = record["proxy"]
        body_bytes = nonnegative_int(record, "body_bytes", proxy)
        max_streams = nonnegative_int(record, "max_concurrent_streams", proxy)
        if body_bytes == 0 or max_streams == 0:
            fail(f"HTTP/2 record for {proxy} has an empty workload")
        key = (body_bytes, max_streams, proxy)
        owner = f"HTTP/2 record {key}"
        if key in records:
            fail(f"duplicate {owner}")
        if record.get("valid") is not True:
            fail(f"{owner} is marked invalid")
        attempts = nonnegative_int(record, "sample_attempts", owner)
        valid_samples = nonnegative_int(record, "valid_samples", owner)
        if attempts == 0 or valid_samples > attempts or valid_samples < attempts // 2 + 1:
            fail(f"{owner} lacks a majority of valid samples")
        if record.get("aggregation") != "conservative_median_per_metric":
            fail(f"{owner} uses an unsupported aggregation")
        if record.get("sampling_order") != "round_robin_interleaved":
            fail(f"{owner} uses an unsupported sampling order")
        if nonnegative_int(record, "benchmark_schema_version", owner) != 7:
            fail(f"{owner} uses an unsupported benchmark schema")
        if record.get("resource_measurement") != "sampled_workload_peak_v1":
            fail(f"{owner} uses an unsupported resource measurement")
        if record.get("kernel_resource_metrics") is not True:
            fail(f"{owner} is missing Linux kernel resource metrics")
        concurrency = nonnegative_int(record, "concurrency", owner)
        client_threads = nonnegative_int(record, "client_threads", owner)
        server_workers = nonnegative_int(record, "server_workers", owner)
        if concurrency == 0 or client_threads == 0 or server_workers == 0 or client_threads > concurrency:
            fail(f"{owner} has an invalid client saturation configuration")
        requests = nonnegative_int(record, "requests", owner)
        started = nonnegative_int(record, "started_requests", owner)
        complete = nonnegative_int(record, "complete_requests", owner)
        succeeded = nonnegative_int(record, "succeeded_requests", owner)
        if requests == 0 or requests != started or requests != complete or requests != succeeded:
            fail(f"{owner} did not complete every request")
        if nonnegative_int(record, "failed_requests", owner) != 0:
            fail(f"{owner} contains failed requests")
        if nonnegative_int(record, "non_2xx_responses", owner) != 0:
            fail(f"{owner} contains non-2xx responses")
        if nonnegative_int(record, "calibration_requests", owner) == 0:
            fail(f"{owner} has an empty calibration workload")
        if nonnegative_int(record, "benchmark_request_count", owner) != requests:
            fail(f"{owner} benchmark request count does not match completed requests")
        for field in (
            "calibration_duration_ms",
            "requests_per_sec",
            "requests_per_cpu_second",
            "requests_per_total_cpu_second",
            "mean_time_per_request_ms",
            "latency_p99_ms",
            "latency_max_ms",
            "cpu_ms",
            "backend_cpu_ms",
            "total_cpu_ms",
            "rss_baseline_kb",
            "rss_peak_kb",
            "backend_rss_baseline_kb",
            "backend_rss_peak_kb",
            "total_rss_peak_kb",
            "fd_baseline",
            "fd_peak",
            "backend_fd_baseline",
            "backend_fd_peak",
            "total_fd_peak",
        ):
            positive_number(record, field, owner)
        if positive_number(record, "total_cpu_ms", owner) < positive_number(record, "cpu_ms", owner):
            fail(f"{owner} total CPU excludes the measured proxy or direct backend")
        if positive_number(record, "total_cpu_ms", owner) < positive_number(record, "backend_cpu_ms", owner):
            fail(f"{owner} total CPU excludes the measured backend")
        for baseline_field, peak_field, growth_field in (
            ("rss_baseline_kb", "rss_peak_kb", "rss_growth_kb"),
            ("backend_rss_baseline_kb", "backend_rss_peak_kb", "backend_rss_growth_kb"),
            ("fd_baseline", "fd_peak", "fd_growth"),
            ("backend_fd_baseline", "backend_fd_peak", "backend_fd_growth"),
        ):
            baseline = positive_number(record, baseline_field, owner)
            peak = positive_number(record, peak_field, owner)
            growth = nonnegative_number(record, growth_field, owner)
            if peak < baseline or growth != peak - baseline:
                fail(f"{owner} has inconsistent {growth_field}")
        if proxy == "direct-backend":
            expected_total_rss_peak = positive_number(record, "rss_peak_kb", owner)
            expected_total_rss_growth = nonnegative_number(record, "rss_growth_kb", owner)
            expected_total_fd_peak = positive_number(record, "fd_peak", owner)
            expected_total_fd_growth = nonnegative_number(record, "fd_growth", owner)
        else:
            expected_total_rss_peak = positive_number(record, "rss_peak_kb", owner) + positive_number(
                record, "backend_rss_peak_kb", owner
            )
            expected_total_rss_growth = nonnegative_number(
                record, "rss_growth_kb", owner
            ) + nonnegative_number(record, "backend_rss_growth_kb", owner)
            expected_total_fd_peak = positive_number(record, "fd_peak", owner) + positive_number(
                record, "backend_fd_peak", owner
            )
            expected_total_fd_growth = nonnegative_number(
                record, "fd_growth", owner
            ) + nonnegative_number(record, "backend_fd_growth", owner)
        if positive_number(record, "total_rss_peak_kb", owner) != expected_total_rss_peak:
            fail(f"{owner} has inconsistent total_rss_peak_kb")
        if nonnegative_number(record, "total_rss_growth_kb", owner) != expected_total_rss_growth:
            fail(f"{owner} has inconsistent total_rss_growth_kb")
        if positive_number(record, "total_fd_peak", owner) != expected_total_fd_peak:
            fail(f"{owner} has inconsistent total_fd_peak")
        if nonnegative_number(record, "total_fd_growth", owner) != expected_total_fd_growth:
            fail(f"{owner} has inconsistent total_fd_growth")
        for field in (
            "requests_per_sec_ratio",
            "requests_per_cpu_second_ratio",
            "requests_per_total_cpu_second_ratio",
            "mean_time_per_request_ms_ratio",
        ):
            if nested_number(record, "sample_spread", field, owner) < 1.0:
                fail(f"{owner} has an invalid {field}")
        records[key] = record

if not records:
    fail(f"no {BENCH} records found in {JSONL_PATH}")

failures = []
lane_scores = []
for body_bytes, max_streams in sorted(required_lanes):
    missing = [
        proxy
        for proxy in PROXIES
        if (body_bytes, max_streams, proxy) not in records
    ]
    if missing:
        fail(
            f"missing HTTP/2 records for {body_bytes} bytes and m={max_streams}: "
            f"{', '.join(missing)}"
        )
    direct = records[(body_bytes, max_streams, "direct-backend")]
    qpx = records[(body_bytes, max_streams, "qpxd")]
    nginx = records[(body_bytes, max_streams, "nginx")]
    for field in (
        "target_duration_seconds",
        "concurrency",
        "client_threads",
        "server_workers",
        "max_concurrent_streams",
        "sample_attempts",
        "sampling_order",
        "aggregation",
        "benchmark_schema_version",
        "resource_measurement",
    ):
        if len({direct.get(field), qpx.get(field), nginx.get(field)}) != 1:
            fail(f"HTTP/2 records for {body_bytes} bytes and m={max_streams} disagree on {field}")

    throughput_ratio = positive_number(qpx, "requests_per_sec") / positive_number(
        nginx, "requests_per_sec"
    )
    total_cpu_ratio = positive_number(qpx, "requests_per_total_cpu_second") / positive_number(
        nginx, "requests_per_total_cpu_second"
    )
    mean_ratio = positive_number(qpx, "mean_time_per_request_ms") / positive_number(
        nginx, "mean_time_per_request_ms"
    )
    p99_ratio = positive_number(qpx, "latency_p99_ms") / positive_number(
        nginx, "latency_p99_ms"
    )
    maximum_ratio = positive_number(qpx, "latency_max_ms") / positive_number(
        nginx, "latency_max_ms"
    )
    total_rss_peak_ratio = positive_number(qpx, "total_rss_peak_kb") / positive_number(
        nginx, "total_rss_peak_kb"
    )
    total_fd_peak_ratio = positive_number(qpx, "total_fd_peak") / positive_number(
        nginx, "total_fd_peak"
    )
    scheduler_queue_delay_ratio = lower_is_better_ratio(
        nonnegative_number(qpx, "scheduler_queue_delay_us_per_request"),
        nonnegative_number(nginx, "scheduler_queue_delay_us_per_request"),
    )
    lane_score = (
        throughput_ratio
        * total_cpu_ratio
        / mean_ratio
        / p99_ratio
        / maximum_ratio
    ) ** 0.2
    lane_scores.append(lane_score)

    checks = (
        ("throughput ratio", throughput_ratio, "min_lane_throughput_ratio", "min"),
        ("total CPU efficiency ratio", total_cpu_ratio, "min_lane_total_cpu_efficiency_ratio", "min"),
        ("mean latency ratio", mean_ratio, "max_lane_mean_latency_ratio", "max"),
        ("p99 latency ratio", p99_ratio, "max_lane_p99_latency_ratio", "max"),
        ("maximum latency ratio", maximum_ratio, "max_lane_latency_ratio", "max"),
        ("lane dominance score", lane_score, "min_lane_dominance_score", "min"),
        ("total RSS peak ratio", total_rss_peak_ratio, "max_lane_total_rss_peak_ratio", "max"),
        ("total FD peak ratio", total_fd_peak_ratio, "max_lane_total_fd_peak_ratio", "max"),
        ("scheduler queue-delay ratio", scheduler_queue_delay_ratio, "max_lane_scheduler_queue_delay_ratio", "max"),
    )
    for label, current, field, direction in checks:
        objective = lane_limit(field, (body_bytes, max_streams))
        if direction == "min" and current + 1e-12 < objective:
            failures.append(
                f"HTTP/2 {body_bytes}-byte m={max_streams} {label} "
                f"{current:.6f} < objective {objective:.6f}"
            )
        if direction == "max" and current > objective + 1e-12:
            failures.append(
                f"HTTP/2 {body_bytes}-byte m={max_streams} {label} "
                f"{current:.6f} > objective {objective:.6f}"
            )

    for proxy, record in (("direct-backend", direct), ("qpxd", qpx), ("nginx", nginx)):
        if proxy == "qpxd":
            throughput_limit = lane_limit(
                "max_qpx_throughput_sample_spread_ratio", (body_bytes, max_streams)
            )
            cpu_limit = lane_limit(
                "max_qpx_cpu_sample_spread_ratio", (body_bytes, max_streams)
            )
        else:
            throughput_limit = lane_limit(
                "max_reference_throughput_sample_spread_ratio", (body_bytes, max_streams)
            )
            cpu_limit = lane_limit(
                "max_reference_cpu_sample_spread_ratio", (body_bytes, max_streams)
            )
        throughput_spread = nested_number(
            record, "sample_spread", "requests_per_sec_ratio", proxy
        )
        cpu_spread = nested_number(
            record, "sample_spread", "requests_per_total_cpu_second_ratio", proxy
        )
        if throughput_spread > throughput_limit + 1e-12:
            failures.append(
                f"HTTP/2 {body_bytes}-byte m={max_streams} {proxy} throughput sample spread "
                f"{throughput_spread:.6f} > objective {throughput_limit:.6f}"
            )
        if cpu_spread > cpu_limit + 1e-12:
            failures.append(
                f"HTTP/2 {body_bytes}-byte m={max_streams} {proxy} total CPU sample spread "
                f"{cpu_spread:.6f} > objective {cpu_limit:.6f}"
            )

    print(
        f"HTTP/2 {body_bytes} bytes m={max_streams}: throughput={throughput_ratio:.3f}, "
        f"total-CPU={total_cpu_ratio:.3f}, mean={mean_ratio:.3f}, "
        f"p99={p99_ratio:.3f}, max={maximum_ratio:.3f}, dominance={lane_score:.3f}"
        f", RSS={total_rss_peak_ratio:.3f}, FD={total_fd_peak_ratio:.3f}, "
        f"queue={scheduler_queue_delay_ratio:.3f}"
    )

aggregate_score = math.prod(lane_scores) ** (1.0 / len(lane_scores))
aggregate_objective = positive_number(
    limits, "min_aggregate_dominance_score", "HTTP/2 objectives"
)
print(f"HTTP/2 aggregate dominance={aggregate_score:.3f}")
if aggregate_score + 1e-12 < aggregate_objective:
    failures.append(
        f"HTTP/2 aggregate dominance score {aggregate_score:.6f} "
        f"< objective {aggregate_objective:.6f}"
    )

if failures:
    for failure in failures:
        print(failure, file=sys.stderr)
    raise SystemExit(1)
PY
