#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JSONL="${1:-${QPX_STREAMING_COMPARE_JSON:-}}"
OBJECTIVES="${2:-${QPX_STREAMING_PERFORMANCE_OBJECTIVES:-$ROOT_DIR/perf/streaming-performance-objectives.json}}"

if [ -z "$JSONL" ]; then
  echo "usage: scripts/check-streaming-performance.sh <streaming-jsonl> [objectives-json]" >&2
  exit 2
fi

python3 - "$JSONL" "$OBJECTIVES" <<'PY'
import json
import math
import sys

JSONL_PATH, OBJECTIVES_PATH = sys.argv[1:3]
BENCH = "proxy_compare_http1_streaming_reverse"


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


def positive_number(record, field):
    try:
        value = float(record[field])
    except (KeyError, TypeError, ValueError):
        fail(f"record for {record.get('proxy', '<missing>')} is missing numeric {field}")
    if not math.isfinite(value) or value <= 0:
        fail(f"{field} must be a positive finite number")
    return value


def nonnegative_number(record, field):
    try:
        value = float(record[field])
    except (KeyError, TypeError, ValueError):
        fail(f"record for {record.get('proxy', '<missing>')} is missing numeric {field}")
    if not math.isfinite(value) or value < 0:
        fail(f"{field} must be a non-negative finite number")
    return value


def lower_is_better_ratio(current, reference):
    if reference == 0:
        return 1.0 if current == 0 else sys.float_info.max
    return current / reference


def nonnegative_int(record, field):
    try:
        value = int(record[field])
    except (KeyError, TypeError, ValueError):
        fail(f"record for {record.get('proxy', '<missing>')} is missing integer {field}")
    if value < 0:
        fail(f"{field} must be non-negative")
    return value


def nested_number(record, container, field):
    nested = record.get(container)
    if not isinstance(nested, dict):
        fail(f"record for {record.get('proxy', '<missing>')} is missing object {container}")
    return positive_number(nested, field)


def ratio_limit(config, field):
    try:
        value = float(config[field])
    except (KeyError, TypeError, ValueError):
        fail(f"streaming objectives are missing numeric {field}")
    if not math.isfinite(value) or value <= 0:
        fail(f"streaming objective {field} must be a positive finite number")
    return value


with open(OBJECTIVES_PATH, "r", encoding="utf-8") as handle:
    objectives = json.load(handle)
if objectives.get("schema_version") != 2:
    fail("unsupported streaming performance objectives schema")
if objectives.get("metric") != "multi_axis_total_system_streaming_dominance":
    fail("streaming performance metric does not match this checker")

external_proxies = tuple(objectives.get("external_proxies", ()))
if not external_proxies:
    fail("streaming objectives must declare external proxies")
required_proxies = ("direct-backend", "qpxd", *external_proxies)

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
        if record.get("bench") != BENCH or record.get("proxy") not in required_proxies:
            continue
        read_mode = record.get("read_mode")
        if read_mode not in {"fast", "slow"}:
            fail(f"record for {record.get('proxy', '<missing>')} has invalid read mode")
        key = (read_mode, record["proxy"])
        if key in records:
            fail(f"duplicate streaming performance record for {key}")
        if record.get("valid") is not True:
            fail(f"streaming performance record for {key} is marked invalid")
        attempts = nonnegative_int(record, "sample_attempts")
        valid_samples = nonnegative_int(record, "valid_samples")
        if attempts == 0 or valid_samples > attempts or valid_samples < attempts // 2 + 1:
            fail(f"streaming performance record for {key} lacks a majority of valid samples")
        if record.get("aggregation") != "conservative_median_per_metric":
            fail(f"streaming performance record for {key} uses an unsupported aggregation")
        if record.get("sampling_order") != "round_robin_interleaved":
            fail(f"streaming performance record for {key} uses an unsupported sampling order")
        if nonnegative_int(record, "benchmark_schema_version") != 4:
            fail(f"streaming performance record for {key} uses an unsupported benchmark schema")
        if record.get("kernel_resource_metrics") is not True:
            fail(f"streaming performance record for {key} is missing Linux kernel resource metrics")
        stream_bytes = nonnegative_int(record, "stream_bytes")
        chunk_bytes = nonnegative_int(record, "chunk_bytes")
        transfers = nonnegative_int(record, "transfers")
        received_bytes = nonnegative_int(record, "bytes")
        observation_bytes = nonnegative_int(record, "gap_observation_bytes")
        observations = nonnegative_int(record, "chunk_observations")
        if stream_bytes == 0 or chunk_bytes == 0 or transfers == 0:
            fail(f"streaming performance record for {key} has an empty workload")
        expected_transfers = 1 if read_mode == "slow" else None
        if expected_transfers is not None and transfers != expected_transfers:
            fail(f"streaming performance record for {key} must use one slow transfer")
        if received_bytes != stream_bytes * transfers:
            fail(f"streaming performance record for {key} did not receive the complete body")
        if observation_bytes != chunk_bytes:
            fail(f"streaming performance record for {key} did not use fixed byte observations")
        expected_observations = max(0, stream_bytes // chunk_bytes - 1) * transfers
        if observations != expected_observations:
            fail(
                f"streaming performance record for {key} has {observations} observations; "
                f"expected {expected_observations}"
            )
        for field in (
            "total_ms",
            "first_byte_ms",
            "p99_chunk_gap_ms",
            "max_chunk_gap_ms",
            "requests_per_total_cpu_second",
            "cpu_ms",
            "backend_cpu_ms",
            "total_cpu_ms",
            "total_rss_peak_kb",
            "total_fd_peak",
        ):
            positive_number(record, field)
        if positive_number(record, "total_cpu_ms") < positive_number(record, "cpu_ms"):
            fail(f"streaming performance record for {key} excludes proxy CPU from total CPU")
        if positive_number(record, "total_cpu_ms") < positive_number(record, "backend_cpu_ms"):
            fail(f"streaming performance record for {key} excludes backend CPU from total CPU")
        for field in (
            "total_ms_ratio",
            "requests_per_cpu_second_ratio",
            "requests_per_total_cpu_second_ratio",
            "p99_chunk_gap_ms_ratio",
        ):
            if nested_number(record, "sample_spread", field) < 1.0:
                fail(f"streaming performance record for {key} has an invalid {field}")
        records[key] = record

for read_mode in ("fast", "slow"):
    missing = [proxy for proxy in required_proxies if (read_mode, proxy) not in records]
    if missing:
        fail(f"missing {read_mode} streaming records for: {', '.join(missing)}")
    dimensions = {
        (
            record["stream_bytes"],
            record["chunk_bytes"],
            record["transfers"],
            record["gap_observation_bytes"],
        )
        for (mode, _proxy), record in records.items()
        if mode == read_mode
    }
    if len(dimensions) != 1:
        fail(f"{read_mode} streaming records do not share one workload")

fast = {proxy: records[("fast", proxy)] for proxy in required_proxies}
leader_name = min(external_proxies, key=lambda name: positive_number(fast[name], "total_ms"))
leader = fast[leader_name]
qpx_fast = fast["qpxd"]
direct_fast = fast["direct-backend"]

throughput_ratio = positive_number(leader, "total_ms") / positive_number(qpx_fast, "total_ms")
direct_efficiency_ratio = positive_number(direct_fast, "total_ms") / positive_number(qpx_fast, "total_ms")
qpx_cpu_efficiency = positive_number(qpx_fast, "requests_per_total_cpu_second")
leader_cpu_efficiency = positive_number(leader, "requests_per_total_cpu_second")
total_cpu_efficiency_ratio = qpx_cpu_efficiency / leader_cpu_efficiency
first_byte_ratio = positive_number(qpx_fast, "first_byte_ms") / positive_number(leader, "first_byte_ms")
p99_gap_ratio = positive_number(qpx_fast, "p99_chunk_gap_ms") / positive_number(leader, "p99_chunk_gap_ms")
max_gap_ratio = positive_number(qpx_fast, "max_chunk_gap_ms") / positive_number(leader, "max_chunk_gap_ms")
total_rss_peak_ratio = positive_number(qpx_fast, "total_rss_peak_kb") / positive_number(
    leader, "total_rss_peak_kb"
)
total_fd_peak_ratio = positive_number(qpx_fast, "total_fd_peak") / positive_number(
    leader, "total_fd_peak"
)
scheduler_queue_delay_ratio = lower_is_better_ratio(
    nonnegative_number(qpx_fast, "scheduler_queue_delay_us_per_transfer"),
    nonnegative_number(leader, "scheduler_queue_delay_us_per_transfer"),
)
dominance_score = (
    throughput_ratio * total_cpu_efficiency_ratio / first_byte_ratio / p99_gap_ratio
) ** 0.25

fast_objectives = objectives.get("fast", {})
fast_checks = (
    ("throughput ratio", throughput_ratio, ratio_limit(fast_objectives, "min_throughput_ratio"), "min"),
    ("direct efficiency ratio", direct_efficiency_ratio, ratio_limit(fast_objectives, "min_direct_efficiency_ratio"), "min"),
    ("total CPU efficiency ratio", total_cpu_efficiency_ratio, ratio_limit(fast_objectives, "min_total_cpu_efficiency_ratio"), "min"),
    ("first-byte ratio", first_byte_ratio, ratio_limit(fast_objectives, "max_first_byte_ratio"), "max"),
    ("p99 gap ratio", p99_gap_ratio, ratio_limit(fast_objectives, "max_p99_gap_ratio"), "max"),
    ("maximum gap ratio", max_gap_ratio, ratio_limit(fast_objectives, "max_gap_ratio"), "max"),
    ("dominance score", dominance_score, ratio_limit(fast_objectives, "min_dominance_score"), "min"),
    ("total RSS peak ratio", total_rss_peak_ratio, ratio_limit(fast_objectives, "max_total_rss_peak_ratio"), "max"),
    ("total FD peak ratio", total_fd_peak_ratio, ratio_limit(fast_objectives, "max_total_fd_peak_ratio"), "max"),
    ("scheduler queue-delay ratio", scheduler_queue_delay_ratio, ratio_limit(fast_objectives, "max_scheduler_queue_delay_ratio"), "max"),
)

failures = []
stability_objectives = objectives.get("stability", {})
frontier_ratio = ratio_limit(stability_objectives, "competitive_frontier_total_ratio")
stability_records = {
    ("fast", "qpxd"),
    ("slow", "qpxd"),
    ("fast", "direct-backend"),
    ("slow", "direct-backend"),
    ("fast", leader_name),
}
leader_total = positive_number(leader, "total_ms")
for proxy in external_proxies:
    if positive_number(fast[proxy], "total_ms") <= leader_total * frontier_ratio:
        stability_records.add(("fast", proxy))
for key in sorted(stability_records):
    record = records[key]
    if key[1] == "qpxd":
        max_total_sample_spread_ratio = ratio_limit(
            stability_objectives, "max_qpx_total_sample_spread_ratio"
        )
    else:
        max_total_sample_spread_ratio = ratio_limit(
            stability_objectives, "max_reference_total_sample_spread_ratio"
        )
    total_spread = nested_number(record, "sample_spread", "total_ms_ratio")
    if total_spread > max_total_sample_spread_ratio + 1e-12:
        failures.append(
            f"streaming {key} total-time sample spread {total_spread:.6f} "
            f"> objective {max_total_sample_spread_ratio:.6f}"
        )
for name, current, objective, direction in fast_checks:
    if direction == "min" and current + 1e-12 < objective:
        failures.append(f"fast streaming {name} {current:.6f} < objective {objective:.6f}")
    if direction == "max" and current > objective + 1e-12:
        failures.append(f"fast streaming {name} {current:.6f} > objective {objective:.6f}")

qpx_slow = records[("slow", "qpxd")]
direct_slow = records[("slow", "direct-backend")]
slow_ratios = {
    "max_total_time_ratio": positive_number(qpx_slow, "total_ms") / positive_number(direct_slow, "total_ms"),
    "max_first_byte_ratio": positive_number(qpx_slow, "first_byte_ms") / positive_number(direct_slow, "first_byte_ms"),
    "max_p99_gap_ratio": positive_number(qpx_slow, "p99_chunk_gap_ms") / positive_number(direct_slow, "p99_chunk_gap_ms"),
    "max_gap_ratio": positive_number(qpx_slow, "max_chunk_gap_ms") / positive_number(direct_slow, "max_chunk_gap_ms"),
    "max_total_rss_peak_ratio": positive_number(qpx_slow, "total_rss_peak_kb") / positive_number(direct_slow, "total_rss_peak_kb"),
    "max_total_fd_peak_ratio": positive_number(qpx_slow, "total_fd_peak") / positive_number(direct_slow, "total_fd_peak"),
    "max_scheduler_queue_delay_ratio": lower_is_better_ratio(
        nonnegative_number(qpx_slow, "scheduler_queue_delay_us_per_transfer"),
        nonnegative_number(direct_slow, "scheduler_queue_delay_us_per_transfer"),
    ),
}
slow_objectives = objectives.get("slow", {})
for field, current in slow_ratios.items():
    objective = ratio_limit(slow_objectives, field)
    if current > objective + 1e-12:
        failures.append(f"slow streaming {field} {current:.6f} > objective {objective:.6f}")

print(
    "streaming performance: "
    f"leader={leader_name}, throughput={throughput_ratio:.3f}, "
    f"direct-efficiency={direct_efficiency_ratio:.3f}, total-CPU={total_cpu_efficiency_ratio:.3f}, "
    f"first-byte={first_byte_ratio:.3f}, p99-gap={p99_gap_ratio:.3f}, "
    f"max-gap={max_gap_ratio:.3f}, dominance={dominance_score:.3f}"
    f", RSS={total_rss_peak_ratio:.3f}, FD={total_fd_peak_ratio:.3f}, "
    f"queue={scheduler_queue_delay_ratio:.3f}"
)
print(
    "streaming backpressure: "
    + ", ".join(f"{name}={value:.3f}" for name, value in slow_ratios.items())
)

if failures:
    for failure in failures:
        print(failure, file=sys.stderr)
    raise SystemExit(1)
PY
