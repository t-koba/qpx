#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="compare"
THRESHOLD=""

usage() {
  cat >&2 <<'USAGE'
usage:
  scripts/compare-proxy-baseline.sh [--threshold 0.10] <proxy-jsonl> [baseline-json] [objectives-json]
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
OBJECTIVES="${3:-${QPX_PROXY_PERFORMANCE_OBJECTIVES:-$ROOT_DIR/perf/proxy-performance-objectives.json}}"

if [ -z "$JSONL" ] || [ -z "$BASELINE" ]; then
  usage
  exit 2
fi

python3 - "$MODE" "$JSONL" "$BASELINE" "$OBJECTIVES" "$THRESHOLD" <<'PY'
import json
import math
import os
import sys
from collections import defaultdict

MODE, JSONL_PATH, BASELINE_PATH, OBJECTIVES_PATH, THRESHOLD_ARG = sys.argv[1:6]
BENCH = "proxy_compare_http1_reverse"
METRIC = "multi_axis_proxy_dominance"
DEFAULT_THRESHOLD = 0.05
EXTERNAL_PROXIES = ("nginx", "apache", "lighttpd")


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


def nonnegative_number(record, field):
    try:
        value = float(record[field])
    except (KeyError, TypeError, ValueError):
        fail(f"record for proxy {record.get('proxy', '<missing>')} is missing numeric {field}")
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
        fail(f"record for proxy {record.get('proxy', '<missing>')} is missing integer {field}")
    if value < 0:
        fail(f"{field} must be non-negative")
    return value


def positive_int(record, field):
    value = nonnegative_int(record, field)
    if value == 0:
        fail(f"{field} must be positive")
    return value


def nested_number(record, container, field):
    nested = record.get(container)
    if not isinstance(nested, dict):
        fail(
            f"record for proxy {record.get('proxy', '<missing>')} "
            f"is missing object {container}"
        )
    return number(nested, field)


def require_valid_sample(record):
    proxy = record.get("proxy", "<missing>")
    if record.get("valid") is not True:
        fail(f"proxy comparison record for {proxy} is marked invalid")
    sample_attempts = nonnegative_int(record, "sample_attempts")
    valid_samples = nonnegative_int(record, "valid_samples")
    if sample_attempts == 0:
        fail(f"proxy comparison record for {proxy} has no sample attempts")
    if valid_samples > sample_attempts:
        fail(f"proxy comparison record for {proxy} has impossible valid sample count")
    if valid_samples < sample_attempts // 2 + 1:
        fail(f"proxy comparison record for {proxy} lacks a majority of valid samples")
    if record.get("aggregation") != "conservative_median_per_metric":
        fail(f"proxy comparison record for {proxy} uses an unsupported aggregation")
    if record.get("sampling_order") != "round_robin_interleaved":
        fail(f"proxy comparison record for {proxy} uses an unsupported sampling order")
    if positive_int(record, "benchmark_schema_version") != 3:
        fail(f"proxy comparison record for {proxy} uses an unsupported benchmark schema")
    positive_int(record, "backend_workers")
    positive_int(record, "health_check_interval_ms")
    positive_int(record, "logical_cpus")
    if record.get("kernel_resource_metrics") is not True:
        fail(f"proxy comparison record for {proxy} is missing Linux kernel resource metrics")
    positive_int(record, "fd_peak")
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
    nested_number(record, "sample_spread", "latency_p99_ratio")
    if throughput_spread < 1.0 or cpu_spread < 1.0:
        fail(f"proxy comparison record for {proxy} has an invalid sample spread")


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
        require_valid_sample(record)
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
        qpxd_rss_peak_kb = number(proxies["qpxd"], "rss_peak_kb")
        external_rss_peak_kb = {
            proxy: number(proxies[proxy], "rss_peak_kb") for proxy in EXTERNAL_PROXIES
        }
        external_best_rss_peak_kb = min(external_rss_peak_kb.values())
        rss_peak_ratio = qpxd_rss_peak_kb / external_best_rss_peak_kb
        qpxd_fd_peak = number(proxies["qpxd"], "fd_peak")
        external_fd_peak = {
            proxy: number(proxies[proxy], "fd_peak") for proxy in EXTERNAL_PROXIES
        }
        external_best_fd_peak = min(external_fd_peak.values())
        fd_peak_ratio = qpxd_fd_peak / external_best_fd_peak
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


def baseline_key(entry):
    try:
        dimension_name, dimension_value = sample_dimension(entry)
        return (
            entry["bench"],
            dimension_name,
            dimension_value,
            int(entry["concurrency"]),
            int(entry["body_bytes"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        fail(f"invalid baseline shape: {exc}")


records = load_jsonl(JSONL_PATH)

if MODE == "generate":
    threshold = parse_threshold(THRESHOLD_ARG, DEFAULT_THRESHOLD)
    baselines = collect_ratios(records)
    baseline = {
        "schema_version": 3,
        "metric": METRIC,
        "degradation_threshold": threshold,
        "baselines": baselines,
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

if baseline.get("schema_version") != 3:
    fail("unsupported proxy baseline schema")
if baseline.get("metric") != METRIC:
    fail("proxy baseline metric does not match this checker")

with open(OBJECTIVES_PATH, "r", encoding="utf-8") as handle:
    objectives = json.load(handle)
if objectives.get("schema_version") != 1:
    fail("unsupported proxy performance objectives schema")
if objectives.get("metric") != METRIC:
    fail("proxy performance objectives metric does not match this checker")
objective_defaults = objectives.get("defaults", {})
min_throughput_ratio = number(objective_defaults, "min_throughput_ratio")
min_cpu_ratio = number(objective_defaults, "min_cpu_efficiency_ratio")
max_p99_ratio = number(objective_defaults, "max_p99_latency_ratio")
min_dominance_score = number(objective_defaults, "min_dominance_score")
max_throughput_sample_spread_ratio = number(
    objective_defaults, "max_throughput_sample_spread_ratio"
)
max_cpu_sample_spread_ratio = number(
    objective_defaults, "max_cpu_sample_spread_ratio"
)
max_rss_peak_ratio = number(objective_defaults, "max_rss_peak_ratio")
max_fd_peak_ratio = number(objective_defaults, "max_fd_peak_ratio")
max_scheduler_queue_delay_ratio = number(
    objective_defaults, "max_scheduler_queue_delay_ratio"
)

threshold = parse_threshold(THRESHOLD_ARG, float(baseline.get("degradation_threshold", DEFAULT_THRESHOLD)))
baseline_entries = baseline.get("baselines", [])
target_keys = {baseline_key(entry) for entry in baseline_entries}
current = {baseline_key(entry): entry for entry in collect_ratios(records, target_keys)}
failures = []

for entry in baseline_entries:
    key = baseline_key(entry)
    current_entry = current.get(key)
    if current_entry is None:
        failures.append(f"missing current proxy comparison lane {key}")
        continue
    baseline_throughput_ratio = number(entry, "throughput_ratio")
    current_throughput_ratio = number(current_entry, "throughput_ratio")
    required_throughput_ratio = baseline_throughput_ratio * (1.0 - threshold)
    if current_throughput_ratio + 1e-12 < required_throughput_ratio:
        failures.append(
            "proxy baseline regression for "
            f"{key}: current throughput ratio {current_throughput_ratio:.6f} "
            f"< required {required_throughput_ratio:.6f} "
            f"(baseline {baseline_throughput_ratio:.6f}, threshold {threshold:.2%})"
        )
    else:
        print(
            "proxy baseline ok for "
            f"{key}: current throughput ratio {current_throughput_ratio:.6f}, "
            f"required {required_throughput_ratio:.6f}"
        )
    baseline_cpu_ratio = number(entry, "cpu_efficiency_ratio")
    current_cpu_ratio = number(current_entry, "cpu_efficiency_ratio")
    required_cpu_ratio = baseline_cpu_ratio * (1.0 - threshold)
    if current_cpu_ratio + 1e-12 < required_cpu_ratio:
        failures.append(
            "proxy CPU efficiency regression for "
            f"{key}: current ratio {current_cpu_ratio:.6f} < required {required_cpu_ratio:.6f} "
            f"(baseline {baseline_cpu_ratio:.6f}, threshold {threshold:.2%})"
        )
    baseline_p99_ratio = number(entry, "p99_latency_ratio")
    current_p99_ratio = number(current_entry, "p99_latency_ratio")
    allowed_p99_ratio = baseline_p99_ratio * (1.0 + threshold)
    if current_p99_ratio > allowed_p99_ratio + 1e-12:
        failures.append(
            "proxy p99 latency regression for "
            f"{key}: current ratio {current_p99_ratio:.6f} > allowed {allowed_p99_ratio:.6f} "
            f"(baseline {baseline_p99_ratio:.6f}, threshold {threshold:.2%})"
        )
    baseline_dominance_score = number(entry, "dominance_score")
    current_dominance_score = number(current_entry, "dominance_score")
    required_dominance_score = baseline_dominance_score * (1.0 - threshold)
    if current_dominance_score + 1e-12 < required_dominance_score:
        failures.append(
            "proxy dominance score regression for "
            f"{key}: current score {current_dominance_score:.6f} "
            f"< required {required_dominance_score:.6f} "
            f"(baseline {baseline_dominance_score:.6f}, threshold {threshold:.2%})"
        )
    if current_throughput_ratio + 1e-12 < min_throughput_ratio:
        failures.append(
            "proxy throughput dominance objective failed for "
            f"{key}: current ratio {current_throughput_ratio:.6f} "
            f"< objective {min_throughput_ratio:.6f}"
        )
    if current_cpu_ratio + 1e-12 < min_cpu_ratio:
        failures.append(
            "proxy CPU efficiency dominance objective failed for "
            f"{key}: current ratio {current_cpu_ratio:.6f} < objective {min_cpu_ratio:.6f}"
        )
    if current_p99_ratio > max_p99_ratio + 1e-12:
        failures.append(
            "proxy p99 latency dominance objective failed for "
            f"{key}: current ratio {current_p99_ratio:.6f} > objective {max_p99_ratio:.6f}"
        )
    if current_dominance_score + 1e-12 < min_dominance_score:
        failures.append(
            "proxy aggregate dominance objective failed for "
            f"{key}: current score {current_dominance_score:.6f} "
            f"< objective {min_dominance_score:.6f}"
        )
    current_rss_peak_ratio = number(current_entry, "rss_peak_ratio")
    if current_rss_peak_ratio > max_rss_peak_ratio + 1e-12:
        failures.append(
            "proxy RSS peak dominance objective failed for "
            f"{key}: current ratio {current_rss_peak_ratio:.6f} "
            f"> objective {max_rss_peak_ratio:.6f}"
        )
    current_fd_peak_ratio = number(current_entry, "fd_peak_ratio")
    if current_fd_peak_ratio > max_fd_peak_ratio + 1e-12:
        failures.append(
            "proxy FD peak dominance objective failed for "
            f"{key}: current ratio {current_fd_peak_ratio:.6f} "
            f"> objective {max_fd_peak_ratio:.6f}"
        )
    current_scheduler_queue_delay_ratio = number(
        current_entry, "scheduler_queue_delay_ratio"
    )
    if current_scheduler_queue_delay_ratio > max_scheduler_queue_delay_ratio + 1e-12:
        failures.append(
            "proxy scheduler queue-delay dominance objective failed for "
            f"{key}: current ratio {current_scheduler_queue_delay_ratio:.6f} "
            f"> objective {max_scheduler_queue_delay_ratio:.6f}"
        )
    for proxy, spread in current_entry["sample_spread"].items():
        throughput_spread = number(spread, "requests_per_sec_ratio")
        cpu_spread = number(spread, "requests_per_cpu_second_ratio")
        if throughput_spread > max_throughput_sample_spread_ratio + 1e-12:
            failures.append(
                "proxy benchmark throughput sample spread objective failed for "
                f"{key} and {proxy}: current ratio {throughput_spread:.6f} "
                f"> objective {max_throughput_sample_spread_ratio:.6f}"
            )
        if cpu_spread > max_cpu_sample_spread_ratio + 1e-12:
            failures.append(
                "proxy benchmark CPU sample spread objective failed for "
                f"{key} and {proxy}: current ratio {cpu_spread:.6f} "
                f"> objective {max_cpu_sample_spread_ratio:.6f}"
            )

if failures:
    for failure in failures:
        print(failure, file=sys.stderr)
    sys.exit(1)
PY
