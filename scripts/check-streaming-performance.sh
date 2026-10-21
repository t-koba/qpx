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


def validated_extremes(record, field):
    """The observed range of a metric, checked against the record's own
    spread.

    The range is the smallest and the largest value the metric took, and the
    spread beside it is the ratio of the two. A record whose range and
    spread disagree is not a measurement the checker can judge, so it is
    rejected rather than read.
    """
    container = record.get("sample_extremes")
    if not isinstance(container, dict):
        fail(f"record for {record.get('proxy', '<missing>')} is missing object sample_extremes")
    extremes = container.get(field)
    if not isinstance(extremes, dict):
        fail(f"record for {record.get('proxy', '<missing>')} is missing object {field}")
    minimum = nonnegative_number(extremes, "min")
    maximum = nonnegative_number(extremes, "max")
    if maximum < minimum:
        fail(f"record for {record.get('proxy', '<missing>')} has an inverted {field} range")
    if minimum == 0:
        # The metric was never positive, so the range is empty and the
        # published spread is the neutral one.
        if maximum != 0:
            fail(f"record for {record.get('proxy', '<missing>')} has an empty {field} range")
        return minimum, maximum
    published = nested_number(record, "sample_spread", f"{field}_ratio")
    if abs(maximum / minimum - published) > 1e-9 * max(1.0, published):
        fail(
            f"record for {record.get('proxy', '<missing>')} has a {field} range "
            f"that disagrees with its published spread"
        )
    value = nonnegative_number(record, field)
    # A round in which the metric was never positive contributes no value
    # to the range, so the record's own zero lies outside it.
    if value != 0 and not minimum <= value <= maximum:
        fail(f"record for {record.get('proxy', '<missing>')} has a {field} value outside its range")
    return minimum, maximum


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
if objectives.get("schema_version") != 3:
    fail("unsupported streaming performance objectives schema")
if objectives.get("metric") != "multi_axis_total_system_streaming_dominance":
    fail("streaming performance metric does not match this checker")
if objectives.get("resource_measurement") != "sampled_workload_peak_v1":
    fail("streaming resource measurement does not match this checker")

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
        if nonnegative_int(record, "benchmark_schema_version") != 7:
            fail(f"streaming performance record for {key} uses an unsupported benchmark schema")
        if record.get("resource_measurement") != "sampled_workload_peak_v1":
            fail(f"streaming performance record for {key} uses an unsupported resource measurement")
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
            positive_number(record, field)
        for field in (
            "rss_growth_kb",
            "backend_rss_growth_kb",
            "total_rss_growth_kb",
            "fd_growth",
            "backend_fd_growth",
            "total_fd_growth",
        ):
            nonnegative_number(record, field)
        for field in ("p99_chunk_gap_ms", "scheduler_queue_delay_us_per_transfer"):
            validated_extremes(record, field)
        for baseline_field, peak_field, growth_field in (
            ("rss_baseline_kb", "rss_peak_kb", "rss_growth_kb"),
            ("backend_rss_baseline_kb", "backend_rss_peak_kb", "backend_rss_growth_kb"),
            ("fd_baseline", "fd_peak", "fd_growth"),
            ("backend_fd_baseline", "backend_fd_peak", "backend_fd_growth"),
        ):
            baseline = positive_number(record, baseline_field)
            peak = positive_number(record, peak_field)
            growth = nonnegative_number(record, growth_field)
            if peak < baseline or growth != peak - baseline:
                fail(f"streaming performance record for {key} has inconsistent {growth_field}")
        if record["proxy"] == "direct-backend":
            expected_total_rss_peak = positive_number(record, "rss_peak_kb")
            expected_total_rss_growth = nonnegative_number(record, "rss_growth_kb")
            expected_total_fd_peak = positive_number(record, "fd_peak")
            expected_total_fd_growth = nonnegative_number(record, "fd_growth")
        else:
            expected_total_rss_peak = positive_number(record, "rss_peak_kb") + positive_number(
                record, "backend_rss_peak_kb"
            )
            expected_total_rss_growth = nonnegative_number(
                record, "rss_growth_kb"
            ) + nonnegative_number(record, "backend_rss_growth_kb")
            expected_total_fd_peak = positive_number(record, "fd_peak") + positive_number(
                record, "backend_fd_peak"
            )
            expected_total_fd_growth = nonnegative_number(
                record, "fd_growth"
            ) + nonnegative_number(record, "backend_fd_growth")
        if positive_number(record, "total_rss_peak_kb") != expected_total_rss_peak:
            fail(f"streaming performance record for {key} has inconsistent total_rss_peak_kb")
        if nonnegative_number(record, "total_rss_growth_kb") != expected_total_rss_growth:
            fail(f"streaming performance record for {key} has inconsistent total_rss_growth_kb")
        if positive_number(record, "total_fd_peak") != expected_total_fd_peak:
            fail(f"streaming performance record for {key} has inconsistent total_fd_peak")
        if nonnegative_number(record, "total_fd_growth") != expected_total_fd_growth:
            fail(f"streaming performance record for {key} has inconsistent total_fd_growth")
        if positive_number(record, "total_cpu_ms") < positive_number(record, "cpu_ms"):
            fail(f"streaming performance record for {key} excludes proxy CPU from total CPU")
        if positive_number(record, "total_cpu_ms") < positive_number(record, "backend_cpu_ms"):
            fail(f"streaming performance record for {key} excludes backend CPU from total CPU")
        for field in (
            "total_ms_ratio",
            "requests_per_cpu_second_ratio",
            "requests_per_total_cpu_second_ratio",
            "p99_chunk_gap_ms_ratio",
            "scheduler_queue_delay_us_per_transfer_ratio",
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
slow = {proxy: records[("slow", proxy)] for proxy in required_proxies}
slow_resource_leader_name = min(
    external_proxies, key=lambda name: positive_number(slow[name], "total_ms")
)
slow_resource_leader = slow[slow_resource_leader_name]
qpx_slow = slow["qpxd"]
direct_slow = slow["direct-backend"]
slow_objectives = objectives.get("slow", {})

throughput_ratio = positive_number(leader, "total_ms") / positive_number(qpx_fast, "total_ms")
direct_efficiency_ratio = positive_number(direct_fast, "total_ms") / positive_number(qpx_fast, "total_ms")
qpx_cpu_efficiency = positive_number(qpx_fast, "requests_per_total_cpu_second")
leader_cpu_efficiency = positive_number(leader, "requests_per_total_cpu_second")
total_cpu_efficiency_ratio = qpx_cpu_efficiency / leader_cpu_efficiency
first_byte_ratio = positive_number(qpx_fast, "first_byte_ms") / positive_number(leader, "first_byte_ms")
p99_gap_ratio = positive_number(qpx_fast, "p99_chunk_gap_ms") / positive_number(leader, "p99_chunk_gap_ms")
max_gap_ratio = positive_number(qpx_fast, "max_chunk_gap_ms") / positive_number(leader, "max_chunk_gap_ms")
total_rss_peak_ratio = lower_is_better_ratio(
    nonnegative_number(qpx_fast, "total_rss_peak_kb"),
    nonnegative_number(leader, "total_rss_peak_kb"),
)
total_fd_peak_ratio = lower_is_better_ratio(
    nonnegative_number(qpx_fast, "total_fd_peak"),
    nonnegative_number(leader, "total_fd_peak"),
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
marginals = []

# Measurement noise comes from qpx's own observed sample spread. Every
# objective is judged against the spread of the metric it measures: time and
# CPU-rate objectives use the lane's total-time and CPU-rate spread, and the
# tail objectives use the spread of their own metric, which is wider than the
# lane spread because a tail statistic moves more between samples. A miss
# inside the band is noise, a miss beyond it is decisive. Reference spreads
# never widen the band: competitor instability must not excuse a qpx miss;
# spread-cap breaches still fail as invalid below.
#
# Every band is bounded by a named policy multiplier, so an objective's
# effective limit stays within a bounded factor of its documented cap: a
# maximum-direction objective's decisive threshold is the cap times the band,
# a minimum-direction objective's is the cap divided by the band. The bound
# is what keeps the gate's teeth: the band comes from the subject's own
# measurement, so without it a subject whose regression also inflates its
# measurement noise would widen the band far enough to excuse the miss it
# caused, and the effective limit would be data-dependent instead of the
# documented cap. The two multipliers differ because the metric families
# differ in how much they move between samples: the tail objectives are
# measured against their own spread and need the wider allowance.
#
# The band also has a floor, stability.min_measurement_noise_multiplier. A
# shared CI runner varies more between runs than one interleaved lane spread
# shows, so a perfectly stable measurement can still miss a cap by a few
# percent for no product reason. The floor keeps that run-to-run variation
# from being reported as a regression. It is the band's lower bound, so the
# band is never below the floor, and it is a policy value like the
# multipliers.
stability_objectives = objectives.get("stability", {})
lane_noise_multiplier = ratio_limit(
    stability_objectives, "max_lane_noise_multiplier"
)
tail_noise_multiplier = ratio_limit(
    stability_objectives, "max_tail_noise_multiplier"
)
noise_floor = ratio_limit(stability_objectives, "min_measurement_noise_multiplier")


def lane_band(lane_noise):
    """The measurement band of a time or CPU-rate objective.

    The floor is the band's lower bound and the policy multiplier its upper
    bound, so the multiplier stays the authority on the band.
    """
    return min(max(lane_noise, noise_floor), lane_noise_multiplier)


def tail_band(lane_effective, own_spread):
    """The measurement band of a tail objective.

    The band is the wider of the lane band and the metric's own measured
    spread, between the floor and the policy multiplier.
    """
    return min(max(max(lane_effective, own_spread), noise_floor), tail_noise_multiplier)


fast_lane_noise = 1.0
for field in ("total_ms_ratio", "requests_per_total_cpu_second_ratio"):
    fast_lane_noise = max(fast_lane_noise, nested_number(qpx_fast, "sample_spread", field))
fast_effective = lane_band(fast_lane_noise)
fast_objective_noise = {
    "p99 gap ratio": tail_band(
        fast_effective,
        nested_number(qpx_fast, "sample_spread", "p99_chunk_gap_ms_ratio"),
    ),
    "scheduler queue-delay ratio": tail_band(
        fast_effective,
        nested_number(
            qpx_fast, "sample_spread", "scheduler_queue_delay_us_per_transfer_ratio"
        ),
    ),
}
frontier_ratio = ratio_limit(stability_objectives, "competitive_frontier_total_ratio")
stability_records = {
    ("fast", "qpxd"),
    ("slow", "qpxd"),
    ("fast", "direct-backend"),
    ("slow", "direct-backend"),
    ("fast", leader_name),
    ("slow", slow_resource_leader_name),
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
            f"> stability cap {max_total_sample_spread_ratio:.6f}: the measurement "
            f"is unjudgeable"
        )
# The metric-matched bands above are only meaningful while qpx's own
# measurements stay stable. A spread beyond the cap makes those metrics
# unjudgeable rather than merely noisy, so the run fails as invalid instead of
# excusing the miss. The CPU-rate spread belongs here with the tail metrics:
# it is the measurement noise of the CPU-efficiency objectives, so an
# unstable CPU-rate measurement makes those objectives unjudgeable too.
for name, current, objective, direction in fast_checks:
    # The time and CPU-rate objectives use the bounded lane band; the tail
    # objectives use the band of their own metric.
    # The band functions already apply the floor as the lower bound and the
    # policy multiplier as the upper bound, so the band here is the one that
    # decided the verdict. Re-applying the floor here would make the floor
    # the outer bound and let it override the multiplier.
    noise = fast_objective_noise.get(name, fast_effective)
    effective = noise
    if direction == "min" and current + 1e-12 < objective:
        decisive_bar = objective / effective
        if current + 1e-12 < decisive_bar:
            failures.append(
                f"fast streaming {name} {current:.6f} < objective {objective:.6f} "
                f"(decisive: miss exceeds measurement noise {noise:.6f})"
            )
        else:
            marginals.append(
                f"fast streaming {name} marginal: {current:.6f} "
                f"< objective {objective:.6f} but within measurement noise "
                f"{noise:.6f}; not a regression signal"
            )
    if direction == "max" and current > objective + 1e-12:
        decisive_bar = objective * effective
        if current > decisive_bar + 1e-12:
            failures.append(
                f"fast streaming {name} {current:.6f} > objective {objective:.6f} "
                f"(decisive: miss exceeds measurement noise {noise:.6f})"
            )
        else:
            marginals.append(
                f"fast streaming {name} marginal: {current:.6f} "
                f"> objective {objective:.6f} but within measurement noise "
                f"{noise:.6f}; not a regression signal"
            )

slow_ratios = {
    "max_total_time_ratio": positive_number(qpx_slow, "total_ms") / positive_number(direct_slow, "total_ms"),
    "max_first_byte_ratio": positive_number(qpx_slow, "first_byte_ms") / positive_number(direct_slow, "first_byte_ms"),
    "max_p99_gap_ratio": positive_number(qpx_slow, "p99_chunk_gap_ms") / positive_number(direct_slow, "p99_chunk_gap_ms"),
    "max_gap_ratio": positive_number(qpx_slow, "max_chunk_gap_ms") / positive_number(direct_slow, "max_chunk_gap_ms"),
    "max_total_rss_peak_ratio": lower_is_better_ratio(
        nonnegative_number(qpx_slow, "total_rss_peak_kb"),
        nonnegative_number(slow_resource_leader, "total_rss_peak_kb"),
    ),
    "max_total_fd_peak_ratio": lower_is_better_ratio(
        nonnegative_number(qpx_slow, "total_fd_peak"),
        nonnegative_number(slow_resource_leader, "total_fd_peak"),
    ),
    "max_scheduler_queue_delay_ratio": lower_is_better_ratio(
        nonnegative_number(qpx_slow, "scheduler_queue_delay_us_per_transfer"),
        nonnegative_number(slow_resource_leader, "scheduler_queue_delay_us_per_transfer"),
    ),
}
slow_lane_noise = 1.0
for field in ("total_ms_ratio", "requests_per_total_cpu_second_ratio"):
    slow_lane_noise = max(slow_lane_noise, nested_number(qpx_slow, "sample_spread", field))
slow_effective = lane_band(slow_lane_noise)
slow_objective_noise = {
    "max_p99_gap_ratio": tail_band(
        slow_effective,
        nested_number(qpx_slow, "sample_spread", "p99_chunk_gap_ms_ratio"),
    ),
    "max_scheduler_queue_delay_ratio": tail_band(
        slow_effective,
        nested_number(
            qpx_slow, "sample_spread", "scheduler_queue_delay_us_per_transfer_ratio"
        ),
    ),
}
metric_spread_cap = ratio_limit(
    stability_objectives, "max_qpx_metric_sample_spread_ratio"
)
# The tail objectives are ratios against a reference, so the instability of
# the metric behind one of them matters only when it can change the verdict.
# The worst end of the objective - the subject's largest observed value
# against the reference's smallest - is the verdict the instability could
# produce, and it is compared with the same decisive bar the objective check
# uses: the objective times the band of that metric, which is bounded by the
# policy multiplier and the floor. So the run fails as unjudgeable exactly
# when the movement could turn the objective's verdict into a failure, and a
# movement that only reaches a marginal verdict leaves the run judgeable.
#
# The CPU rate keeps the spread cap. Its objective is a ratio against the
# leader like the tail metrics', but the lane publishes no observed range
# for the CPU rate, so the cap stays the stricter policy for that metric: a
# wide CPU-rate spread makes the CPU-efficiency objective unjudgeable rather
# than merely noisy.
#
# The rule is deliberately one-sided. It only ever keeps a run that the
# spread cap would have failed, and only when the movement cannot change
# the verdict; a run whose worst end reaches the decisive bar keeps failing
# as unjudgeable.
tail_objectives = (
    (
        "fast",
        "p99 gap ratio",
        "p99_chunk_gap_ms",
        qpx_fast,
        leader,
        ratio_limit(fast_objectives, "max_p99_gap_ratio"),
        fast_objective_noise["p99 gap ratio"],
        False,
    ),
    (
        "fast",
        "scheduler queue-delay ratio",
        "scheduler_queue_delay_us_per_transfer",
        qpx_fast,
        leader,
        ratio_limit(fast_objectives, "max_scheduler_queue_delay_ratio"),
        fast_objective_noise["scheduler queue-delay ratio"],
        True,
    ),
    (
        "slow",
        "max_p99_gap_ratio",
        "p99_chunk_gap_ms",
        qpx_slow,
        direct_slow,
        ratio_limit(slow_objectives, "max_p99_gap_ratio"),
        slow_objective_noise["max_p99_gap_ratio"],
        False,
    ),
    (
        "slow",
        "max_scheduler_queue_delay_ratio",
        "scheduler_queue_delay_us_per_transfer",
        qpx_slow,
        slow_resource_leader,
        ratio_limit(slow_objectives, "max_scheduler_queue_delay_ratio"),
        slow_objective_noise["max_scheduler_queue_delay_ratio"],
        True,
    ),
)
for lane, _name, metric, subject, reference, cap, band, lower_is_better in tail_objectives:
    record = records[(lane, "qpxd")]
    spread_field = f"{metric}_ratio"
    metric_spread = nested_number(record, "sample_spread", spread_field)
    if metric_spread <= metric_spread_cap + 1e-12:
        continue
    subject_max = validated_extremes(subject, metric)[1]
    reference_min = validated_extremes(reference, metric)[0]
    if lower_is_better:
        worst_end = lower_is_better_ratio(subject_max, reference_min)
    elif reference_min == 0:
        worst_end = math.inf if subject_max > 0 else 1.0
    else:
        worst_end = subject_max / reference_min
    decisive_bar = cap * band
    if worst_end <= decisive_bar + 1e-12:
        continue
    failures.append(
        f"streaming {lane} {spread_field} sample spread {metric_spread:.6f} "
        f"> stability cap {metric_spread_cap:.6f}: the measurement "
        f"is unjudgeable"
    )
for key in (("fast", "qpxd"), ("slow", "qpxd")):
    record = records[key]
    metric_spread = nested_number(record, "sample_spread", "requests_per_total_cpu_second_ratio")
    if metric_spread > metric_spread_cap + 1e-12:
        failures.append(
            f"streaming {key} requests_per_total_cpu_second_ratio sample spread "
            f"{metric_spread:.6f} > stability cap {metric_spread_cap:.6f}: "
            f"the measurement is unjudgeable"
        )

for field, current in slow_ratios.items():
    objective = ratio_limit(slow_objectives, field)
    # The time and CPU-rate objectives use the bounded lane band; the tail
    # objectives use the band of their own metric.
    # The band functions already apply the floor as the lower bound and the
    # policy multiplier as the upper bound, so the band here is the one that
    # decided the verdict. Re-applying the floor here would make the floor
    # the outer bound and let it override the multiplier.
    noise = slow_objective_noise.get(field, slow_effective)
    effective = noise
    if current > objective + 1e-12:
        decisive_bar = objective * effective
        if current > decisive_bar + 1e-12:
            failures.append(
                f"slow streaming {field} {current:.6f} > objective {objective:.6f} "
                f"(decisive: miss exceeds measurement noise {noise:.6f})"
            )
        else:
            marginals.append(
                f"slow streaming {field} marginal: {current:.6f} "
                f"> objective {objective:.6f} but within measurement noise "
                f"{noise:.6f}; not a regression signal"
            )

print(
    "streaming performance: "
    f"leader={leader_name}, throughput={throughput_ratio:.3f}, "
    f"direct-efficiency={direct_efficiency_ratio:.3f}, total-CPU={total_cpu_efficiency_ratio:.3f}, "
    f"first-byte={first_byte_ratio:.3f}, p99-gap={p99_gap_ratio:.3f}, "
    f"max-gap={max_gap_ratio:.3f}, dominance={dominance_score:.3f}"
    f", RSS={total_rss_peak_ratio:.3f}, "
    f"FD={total_fd_peak_ratio:.3f}, "
    f"queue={scheduler_queue_delay_ratio:.3f}"
)
print(
    "streaming backpressure: "
    f"resource-leader={slow_resource_leader_name}, "
    + ", ".join(f"{name}={value:.3f}" for name, value in slow_ratios.items())
)

if marginals:
    print(
        f"{len(marginals)} marginal objective(s) within measurement noise "
        "(not failures, kept visible for trend review):"
    )
    for marginal in marginals:
        print(marginal)

if failures:
    for failure in failures:
        print(failure, file=sys.stderr)
    raise SystemExit(1)
PY
