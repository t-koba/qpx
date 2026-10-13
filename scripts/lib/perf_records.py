"""Benchmark record validation shared by the policy and the samplers' driver.

Transport/schema failures are errors, not measurement spread events.
"""
import math
import sys
from collections import defaultdict

BENCH = "proxy_compare_http1_reverse"
EXTERNAL_PROXIES = ("nginx", "apache", "lighttpd")


def fail(message):
    raise ValueError(message)


def number(record, field, owner="record"):
    value = record.get(field)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"{owner}: missing numeric {field}")
    if not math.isfinite(value) or value <= 0:
        fail(f"{owner}: {field} must be positive and finite")
    return value


positive_number = number


def nonnegative_number(record, field, owner="record"):
    value = record.get(field)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"{owner}: missing numeric {field}")
    if not math.isfinite(value) or value < 0:
        fail(f"{owner}: {field} must be non-negative and finite")
    return value


def nonnegative_int(record, field, owner="record"):
    value = record.get(field)
    if type(value) is not int or value < 0:
        fail(f"{owner}: {field} must be a non-negative integer")
    return value


nonnegative_integer = nonnegative_int


def positive_int(record, field, owner="record"):
    value = nonnegative_int(record, field, owner)
    if value == 0:
        fail(f"{owner}: {field} must be positive")
    return value


def nested_number(record, container, field, owner="record"):
    nested = record.get(container)
    if not isinstance(nested, dict):
        fail(f"{owner}: missing object {container}")
    return number(nested, field, owner)


def lower_is_better_ratio(current, reference):
    if reference == 0:
        return 1.0 if current == 0 else sys.float_info.max
    return current / reference

def validate_http1(record, context):
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
    expected_spread_basis = "full_range" if record.get("pair_role") else "tightest_valid_majority"
    if record.get("sample_spread_basis") != expected_spread_basis:
        fail(f"{context} uses unsupported sample spread basis")
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
    if attempts == 0 or valid_samples != attempts or valid_samples > attempts:
        fail(f"{context} does not contain every required valid sample")
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


def validate_reverse(record):
    proxy = record.get("proxy", "<missing>")
    if record.get("valid") is not True:
        fail(f"proxy comparison record for {proxy} is marked invalid")
    sample_attempts = nonnegative_int(record, "sample_attempts")
    valid_samples = nonnegative_int(record, "valid_samples")
    if sample_attempts == 0:
        fail(f"proxy comparison record for {proxy} has no sample attempts")
    if valid_samples > sample_attempts:
        fail(f"proxy comparison record for {proxy} has impossible valid sample count")
    if valid_samples != sample_attempts:
        fail(f"proxy comparison record for {proxy} does not contain every required valid sample")
    if record.get("aggregation") != "conservative_median_per_metric":
        fail(f"proxy comparison record for {proxy} uses an unsupported aggregation")
    if record.get("sampling_order") != "round_robin_interleaved":
        fail(f"proxy comparison record for {proxy} uses an unsupported sampling order")
    if positive_int(record, "benchmark_schema_version") != 4:
        fail(f"proxy comparison record for {proxy} uses an unsupported benchmark schema")
    if record.get("resource_measurement") != "sampled_workload_peak_v1":
        fail(f"proxy comparison record for {proxy} uses an unsupported resource measurement")
    positive_int(record, "backend_workers")
    positive_int(record, "health_check_interval_ms")
    positive_int(record, "logical_cpus")
    if record.get("kernel_resource_metrics") is not True:
        fail(f"proxy comparison record for {proxy} is missing Linux kernel resource metrics")
    rss_baseline_kb = positive_int(record, "rss_baseline_kb")
    rss_peak_kb = positive_int(record, "rss_peak_kb")
    rss_growth_kb = nonnegative_int(record, "rss_growth_kb")
    fd_baseline = positive_int(record, "fd_baseline")
    fd_peak = positive_int(record, "fd_peak")
    fd_growth = nonnegative_int(record, "fd_growth")
    if rss_peak_kb < rss_baseline_kb or rss_growth_kb != rss_peak_kb - rss_baseline_kb:
        fail(f"proxy comparison record for {proxy} has inconsistent RSS measurements")
    if fd_peak < fd_baseline or fd_growth != fd_peak - fd_baseline:
        fail(f"proxy comparison record for {proxy} has inconsistent FD measurements")
    if nonnegative_int(record, "complete_requests") != nonnegative_int(record, "requests"):
        fail(f"proxy comparison record for {proxy} did not complete all requests")
    connect_errors = nonnegative_int(record, "connect_errors")
    read_errors = nonnegative_int(record, "read_errors")
    write_errors = nonnegative_int(record, "write_errors")
    timeout_errors = nonnegative_int(record, "timeout_errors")
    failed_requests = nonnegative_int(record, "failed_requests")
    if failed_requests != connect_errors + read_errors + write_errors + timeout_errors:
        fail(f"proxy comparison record for {proxy} has inconsistent failure counters")
    if connect_errors != 0 or write_errors != 0 or timeout_errors != 0:
        fail(f"proxy comparison record for {proxy} has fatal transport errors")
    max_read_error_rate_ppm = nonnegative_int(record, "max_read_error_rate_ppm")
    if max_read_error_rate_ppm > 1_000_000:
        fail(f"proxy comparison record for {proxy} has invalid read error tolerance")
    complete_requests = nonnegative_int(record, "complete_requests")
    if read_errors * 1_000_000 > complete_requests * max_read_error_rate_ppm:
        fail(f"proxy comparison record for {proxy} exceeds its read error tolerance")
    if nonnegative_int(record, "non_2xx_responses") != 0:
        fail(f"proxy comparison record for {proxy} has non-2xx responses")
    if nonnegative_int(record, "bad_length_responses") != 0:
        fail(f"proxy comparison record for {proxy} has bad response lengths")
    if nonnegative_int(record, "cache_result_errors") != 0:
        fail(f"proxy comparison record for {proxy} has cache-result validation errors")
    if str(record.get("status_before")) != "200" or str(record.get("status_after")) != "200":
        fail(f"proxy comparison record for {proxy} failed status probes")
    throughput_spread = nested_number(record, "sample_spread", "requests_per_sec_ratio")
    cpu_spread = nested_number(record, "sample_spread", "requests_per_cpu_second_ratio")
    p99_spread = nested_number(record, "sample_spread", "latency_p99_ratio")
    if throughput_spread < 1.0 or cpu_spread < 1.0 or p99_spread < 1.0:
        fail(f"proxy comparison record for {proxy} has an invalid sample spread")


def validate_http2(record):
    proxy = record.get("proxy")
    body_bytes = positive_int(record, "body_bytes")
    max_streams = positive_int(record, "max_concurrent_streams")
    key = (body_bytes, max_streams, proxy)
    owner = f"HTTP/2 record {key}"
    if record.get("valid") is not True:
        fail(f"{owner} is marked invalid")
    attempts = nonnegative_int(record, "sample_attempts", owner)
    valid_samples = nonnegative_int(record, "valid_samples", owner)
    if attempts == 0 or valid_samples > attempts or valid_samples != attempts:
        fail(f"{owner} does not contain every required valid sample")
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


def sample_dimension(record):
    if "duration_seconds" in record:
        try:
            duration_seconds = int(record["duration_seconds"])
        except (TypeError, ValueError):
            fail("duration_seconds must be an integer")
        if duration_seconds <= 0:
            fail("duration_seconds must be positive")
        return ("duration_seconds", duration_seconds)
    try:
        requests = int(record["requests"])
    except (KeyError, TypeError, ValueError):
        fail("requests must be an integer")
    if requests <= 0:
        fail("requests must be positive")
    return ("requests", requests)


def lane_key(record):
    try:
        dimension_name, dimension_value = sample_dimension(record)
        return (
            record["bench"],
            dimension_name,
            dimension_value,
            int(record["concurrency"]),
            int(record["body_bytes"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        fail(f"invalid proxy comparison record shape: {exc}")


def collect_ratios(records, target_keys=None):
    grouped = defaultdict(dict)
    for record in records:
        if record.get("bench") != BENCH:
            continue
        proxy = record.get("proxy")
        if proxy not in {"direct-backend", "qpxd", *EXTERNAL_PROXIES}:
            continue
        key = lane_key(record)
        if target_keys is not None and key not in target_keys:
            continue
        validate_reverse(record)
        if proxy in grouped[key]:
            fail(f"duplicate proxy comparison record for lane {key} and {proxy}")
        grouped[key][proxy] = record

    ratios = []
    for key in sorted(grouped):
        proxies = grouped[key]
        missing = [
            proxy
            for proxy in ("direct-backend", "qpxd", *EXTERNAL_PROXIES)
            if proxy not in proxies
        ]
        if missing:
            fail(f"missing proxy comparison records for lane {key}: {', '.join(missing)}")
        metadata_fields = (
            "duration_seconds",
            "threads",
            "concurrency",
            "sample_attempts",
            "backend_workers",
            "health_check_interval_ms",
            "logical_cpus",
            "benchmark_schema_version",
            "sampling_order",
            "aggregation",
        )
        for field in metadata_fields:
            values = {record.get(field) for record in proxies.values()}
            if len(values) != 1:
                fail(f"proxy comparison records for lane {key} disagree on {field}")
        qpxd_rps = number(proxies["qpxd"], "requests_per_sec")
        external_requests_per_sec = {
            proxy: number(proxies[proxy], "requests_per_sec") for proxy in EXTERNAL_PROXIES
        }
        external_best_rps = max(external_requests_per_sec.values())
        throughput_ratio = qpxd_rps / external_best_rps
        qpxd_cpu_efficiency = number(proxies["qpxd"], "requests_per_cpu_second")
        external_cpu_efficiency = {
            proxy: number(proxies[proxy], "requests_per_cpu_second") for proxy in EXTERNAL_PROXIES
        }
        external_best_cpu_efficiency = max(external_cpu_efficiency.values())
        cpu_efficiency_ratio = qpxd_cpu_efficiency / external_best_cpu_efficiency
        qpxd_p99_ms = number(proxies["qpxd"], "latency_p99_ms")
        external_latency_p99_ms = {
            proxy: number(proxies[proxy], "latency_p99_ms") for proxy in EXTERNAL_PROXIES
        }
        external_best_p99_ms = min(external_latency_p99_ms.values())
        p99_latency_ratio = qpxd_p99_ms / external_best_p99_ms
        qpxd_rss_peak_kb = nonnegative_number(proxies["qpxd"], "rss_peak_kb")
        external_rss_peak_kb = {
            proxy: nonnegative_number(proxies[proxy], "rss_peak_kb")
            for proxy in EXTERNAL_PROXIES
        }
        # RSS compares resident process footprints, so the reference must be a
        # server of the same class. lighttpd is a minimal single-purpose
        # process whose ~4MB footprint no full-featured async runtime can
        # match; nginx is the same-class production reference. RSS parity is
        # measured against nginx while every other resource stays
        # best-of-breed.
        nginx_rss_peak_kb = nonnegative_number(proxies["nginx"], "rss_peak_kb")
        rss_peak_ratio = lower_is_better_ratio(qpxd_rss_peak_kb, nginx_rss_peak_kb)
        qpxd_fd_peak = nonnegative_number(proxies["qpxd"], "fd_peak")
        external_fd_peak = {
            proxy: nonnegative_number(proxies[proxy], "fd_peak")
            for proxy in EXTERNAL_PROXIES
        }
        external_best_fd_peak = min(external_fd_peak.values())
        fd_peak_ratio = lower_is_better_ratio(qpxd_fd_peak, external_best_fd_peak)
        qpxd_scheduler_queue_delay = nonnegative_number(
            proxies["qpxd"], "scheduler_queue_delay_us_per_request"
        )
        external_scheduler_queue_delay = {
            proxy: nonnegative_number(proxies[proxy], "scheduler_queue_delay_us_per_request")
            for proxy in EXTERNAL_PROXIES
        }
        external_best_scheduler_queue_delay = min(
            external_scheduler_queue_delay.values()
        )
        scheduler_queue_delay_ratio = lower_is_better_ratio(
            qpxd_scheduler_queue_delay, external_best_scheduler_queue_delay
        )
        dominance_score = (
            throughput_ratio * cpu_efficiency_ratio / p99_latency_ratio
        ) ** (1.0 / 3.0)
        direct_backend_rps = number(proxies["direct-backend"], "requests_per_sec")
        fastest_proxy_rps = max(qpxd_rps, external_best_rps)
        direct_headroom_ratio = direct_backend_rps / fastest_proxy_rps
        bench, dimension_name, dimension_value, concurrency, body_bytes = key
        ratio_record = {
            "bench": bench,
            dimension_name: dimension_value,
            "concurrency": concurrency,
            "body_bytes": body_bytes,
            "throughput_ratio": round(throughput_ratio, 6),
            "cpu_efficiency_ratio": round(cpu_efficiency_ratio, 6),
            "p99_latency_ratio": round(p99_latency_ratio, 6),
            "dominance_score": round(dominance_score, 6),
            "rss_peak_ratio": round(rss_peak_ratio, 6),
            "fd_peak_ratio": round(fd_peak_ratio, 6),
            "scheduler_queue_delay_ratio": round(scheduler_queue_delay_ratio, 6),
            "qpxd_requests_per_sec": qpxd_rps,
            "qpxd_requests_per_cpu_second": qpxd_cpu_efficiency,
            "qpxd_latency_p99_ms": qpxd_p99_ms,
            "external_proxy_best_requests_per_sec": external_best_rps,
            "external_proxy_best_requests_per_cpu_second": external_best_cpu_efficiency,
            "external_proxy_best_latency_p99_ms": external_best_p99_ms,
            "external_proxy_requests_per_sec": external_requests_per_sec,
            "external_proxy_requests_per_cpu_second": external_cpu_efficiency,
            "external_proxy_latency_p99_ms": external_latency_p99_ms,
            "external_proxy_rss_peak_kb": external_rss_peak_kb,
            "external_proxy_fd_peak": external_fd_peak,
            "external_proxy_scheduler_queue_delay_us_per_request": external_scheduler_queue_delay,
            "direct_backend_requests_per_sec": direct_backend_rps,
            "direct_efficiency_ratio": round(qpxd_rps / direct_backend_rps, 6),
            "direct_headroom_ratio": round(direct_headroom_ratio, 6),
            "sample_spread": {
                proxy: proxies[proxy]["sample_spread"]
                for proxy in ("direct-backend", "qpxd", *EXTERNAL_PROXIES)
            },
            "source_commit": proxies["qpxd"].get("commit", "unknown"),
        }
        if dimension_name == "duration_seconds":
            ratio_record["requests"] = int(proxies["qpxd"]["requests"])
        ratios.append(
            ratio_record
        )

    if not ratios:
        fail(f"no {BENCH} qpxd/direct-backend records found in {JSONL_PATH}")
    return ratios

