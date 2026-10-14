"""Validity first; independent paired regressions; competitive reports.

Exit 1 is a hard error/regression (or a controlled competitive miss).
INCONCLUSIVE measurements remain visible but are non-blocking. Only RETRYABLE_INVALID permits another measurement.
"""
import json
import math
import os
import re
from pathlib import Path

from perf_records import (
    collect_ratios, fail, lower_is_better_ratio, nonnegative_number, number,
    positive_int, validate_http1, validate_http2, validate_reverse,
)

ROOT = Path(__file__).resolve().parents[2]
FILES = {
    "http2": ("http2-performance-objectives.json", 3, "multi_axis_total_system_http2_dominance"),
    "origin": ("origin-cache-performance-objectives.json", 2, "multi_axis_origin_cache_dominance"),
    "proxy": ("proxy-performance-objectives.json", 2, "multi_axis_proxy_dominance"),
}


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        fail(f"{path}: expected a JSON object")
    return value


def load_jsonl(path, validate_records=True):
    """Load records, optionally deferring role-aware measurement validation."""
    records = []
    seen = set()
    with open(path, encoding="utf-8") as handle:
        for index, line in enumerate(handle, 1):
            if not line.strip():
                continue
            record = json.loads(line)
            if not isinstance(record, dict):
                fail(f"{path}:{index}: expected a record object")
            if not all(isinstance(record.get(f), str) and record[f] for f in ("bench", "proxy")):
                fail(f"{path}:{index}: missing benchmark identity")
            positive_int(record, "body_bytes")
            key = (record["bench"], record["body_bytes"], record.get("max_concurrent_streams"), record["proxy"], record.get("pair_role"))
            if key in seen:
                fail(f"{path}:{index}: duplicate record {key}")
            seen.add(key)
            if validate_records:
                if record["bench"] == "proxy_compare_http2_reverse":
                    validate_http2(record)
                else:
                    validate_http1(record, record["bench"] + "/" + record["proxy"])
            records.append(record)
    if not records:
        fail(f"{path}: no measurements")
    return records


def write_json(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def write_jsonl(path, records):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in records))


def assessment():
    mode = os.environ.get("QPX_PERF_ASSESSMENT", "shared")
    if mode not in ("shared", "controlled"):
        fail("QPX_PERF_ASSESSMENT must be shared or controlled")
    return mode


def objectives(kind, path=None):
    filename, schema, metric = FILES[kind]
    config = load_json(path or ROOT / "perf" / filename)
    if (config.get("schema_version") != schema or config.get("metric") != metric
            or config.get("resource_measurement") != "sampled_workload_peak_v1"):
        fail(f"unsupported {kind} objectives schema/metric/resource measurement")
    defaults = config.get("defaults")
    if not isinstance(defaults, dict):
        fail("objectives require defaults")
    for field in defaults:
        if field.startswith(("min_", "max_")):
            number(defaults, field)
    policy = config.get("ci_policy", {})
    if (policy.get("schema_version") != 1 or policy.get("max_attempts") != 3
            or policy.get("pair_samples") != 3
            or policy.get("shared_competitive") != "report_only"
            or policy.get("scheduler_queue_delay") != "diagnostic_only"):
        fail("unsupported or missing CI measurement policy")
    pin = policy.get("previous_release", {})
    if not re.fullmatch(r"[0-9a-f]{40}", pin.get("sha", "")) or not pin.get("tag"):
        fail("previous release must be pinned by tag and full commit SHA")
    tolerances = policy.get("paired_regression", {})
    for field in ("min_throughput_ratio", "min_cpu_efficiency_ratio", "max_p99_latency_ratio"):
        number(tolerances, field)
    if (tolerances["min_throughput_ratio"] > 1 or tolerances["min_cpu_efficiency_ratio"] > 1
            or tolerances["max_p99_latency_ratio"] < 1):
        fail("paired tolerances must allow an equal pair")
    lanes = []
    if kind == "http2":
        dimensions = []
        for field in ("required_body_bytes", "required_max_concurrent_streams"):
            values = config.get(field)
            if (not isinstance(values, list) or not values
                    or any(type(v) is not int or v <= 0 for v in values)
                    or len(set(values)) != len(values)):
                fail(f"invalid required dimension {field}")
            dimensions.append(values)
        overrides = {}
        for entry in config.get("lanes", []):
            key = (positive_int(entry, "body_bytes"), positive_int(entry, "max_concurrent_streams"))
            if key in overrides:
                fail(f"duplicate HTTP/2 objective lane {key}")
            overrides[key] = entry
        for size in dimensions[0]:
            for streams in dimensions[1]:
                lanes.append({"bench": "proxy_compare_http2_reverse", "body_bytes": size,
                              "max_concurrent_streams": streams, "qpx": "qpxd",
                              "references": ["direct-backend", "nginx"],
                              **overrides.get((size, streams), {})})
    else:
        for entry in config.get("lanes", []):
            positive_int(entry, "body_bytes")
            if kind == "proxy":
                entry = {"bench": "proxy_compare_http1_reverse", "qpx": "qpxd",
                         "references": ["direct-backend", "nginx", "apache", "lighttpd"], **entry}
            else:
                if not all(isinstance(entry.get(k), str) and entry[k] for k in ("bench", "qpx", "reference", "workload_profile")):
                    fail("invalid origin/cache objective lane")
                entry = {**entry, "references": [entry["reference"]]}
            lanes.append(entry)
    if not lanes:
        fail("objectives require lanes")
    names = set()
    for lane in lanes:
        compatibility = lane.get("pair_compatibility")
        if compatibility is not None:
            if (not isinstance(compatibility, dict)
                    or type(compatibility.get("applicable")) is not bool
                    or compatibility.get("previous_sha") != pin["sha"]
                    or not isinstance(compatibility.get("reason"), str)
                    or not compatibility["reason"].strip()):
                fail("invalid or stale lane pair compatibility")
        lane.update(kind=kind, policy=policy, limits={**defaults, **lane})
        lane["name"] = f'{lane["bench"]}/{lane["body_bytes"]}'
        if kind == "http2":
            lane["name"] += f'/m={lane["max_concurrent_streams"]}'
        if lane["name"] in names:
            fail(f'duplicate objective lane {lane["name"]}')
        names.add(lane["name"])
        for key, value in lane["limits"].items():
            if key.startswith(("min_", "max_")):
                number(lane["limits"], key)
    return config, lanes


def matches(record, lane):
    return (record.get("bench") == lane["bench"] and record.get("body_bytes") == lane["body_bytes"]
            and (lane["kind"] != "http2" or record.get("max_concurrent_streams") == lane["max_concurrent_streams"]))


def validate(record, lane):
    if lane["kind"] == "http2":
        validate_http2(record)
    else:
        validate_http1(record, lane["name"] + "/" + str(record.get("proxy")))
        if lane["kind"] == "proxy":
            validate_reverse(record)
        if lane["kind"] == "origin" and record.get("workload_profile") != lane["workload_profile"]:
            fail(f'{lane["name"]}: unexpected workload profile')
    positive_int(record, "body_bytes")
    if lane["kind"] != "http2":
        for field in ("duration_seconds", "threads", "concurrency", "backend_workers", "health_check_interval_ms", "logical_cpus"):
            positive_int(record, field)
        if record["threads"] > record["concurrency"]:
            fail("client threads exceed concurrency")
        if record["max_read_error_rate_ppm"] > 1_000_000:
            fail("invalid read error ceiling")
        if record.get("proxy") == lane["qpx"]:
            if record["execution_model"] != "async-io":
                fail("unexpected qpx execution model")
            for field in ("role_workers", "blocking_workers"):
                expected = lane.get(f"qpx_{field}")
                if expected is not None and record.get(field) != expected:
                    fail(f"unexpected qpx {field}")
    for field in ("requests_per_sec", "requests_per_cpu_second", "latency_p99_ms"):
        number(record, field)
    # A negative/missing diagnostic is malformed data, not a performance miss.
    nonnegative_number(record, "scheduler_queue_delay_us_per_request")


def spread_limits(lane, qpx):
    limits = lane["limits"]
    if lane["kind"] == "http2":
        role = "qpx" if qpx else "reference"
        return {"requests_per_sec_ratio": number(limits, f"max_{role}_throughput_sample_spread_ratio"),
                "requests_per_total_cpu_second_ratio": number(limits, f"max_{role}_cpu_sample_spread_ratio"),
                "latency_p99_ratio": number(limits, f"max_{role}_p99_sample_spread_ratio")}
    if lane["kind"] == "origin":
        role = "qpx" if qpx else "reference"
        return {"requests_per_sec_ratio": number(limits, f"max_{role}_sample_spread_ratio"),
                "requests_per_cpu_second_ratio": number(limits, f"max_{role}_sample_spread_ratio"),
                "latency_p99_ratio": number(limits, "max_p99_sample_spread_ratio")}
    return {"requests_per_sec_ratio": number(limits, "max_throughput_sample_spread_ratio"),
            "requests_per_cpu_second_ratio": number(limits, "max_cpu_sample_spread_ratio"),
            "latency_p99_ratio": number(limits, "max_p99_sample_spread_ratio")}


def consistent(records, lane, paired, same_role=False):
    fields = ["sample_attempts", "sampling_order", "aggregation", "benchmark_schema_version", "resource_measurement", "concurrency"]
    if lane["kind"] == "http2":
        fields += ["target_duration_seconds", "client_threads", "server_workers", "max_concurrent_streams"]
    else:
        fields += ["duration_seconds", "threads", "backend_workers", "health_check_interval_ms", "logical_cpus", "sample_spread_basis", "workload_profile"]
    if same_role:
        fields += ["proxy"]
    if paired or same_role:
        fields += ["role_workers", "blocking_workers", "execution_model", "toolchain", "runner", "pair_order"]
    for field in fields:
        if any(r.get(field) != records[0].get(field) for r in records[1:]):
            fail(f'{lane["name"]}: records disagree on {field}')
    if lane["kind"] == "origin" and not paired and not same_role and len(records) == 2:
        qpx, ref = records
        for record, role in ((qpx, "qpx"), (ref, "reference")):
            for field in ("role_workers", "blocking_workers"):
                expected = lane.get(f"{role}_{field}")
                if expected is not None and record.get(field) != expected:
                    fail(f'{lane["name"]}: unexpected {role} {field}')
        if qpx["execution_model"] == ref["execution_model"]:
            if qpx["role_workers"] != ref["role_workers"]:
                fail("origin/cache async worker counts differ")
        elif (lane["bench"] != "origin_webdav_http1" or qpx["execution_model"] != "async-io"
              or ref["execution_model"] != "thread-per-request"):
            fail("incompatible origin/cache execution models")


def validate_pair_record(record, lane):
    if record.get("proxy") != lane["qpx"]:
        fail("paired regression requires two qpx lanes")
    deltas = record.get("paired_metric_ratios")
    if not isinstance(deltas, list) or len(deltas) != lane["policy"]["pair_samples"]:
        fail("pair is missing per-round metric deltas")
    for delta in deltas:
        if not isinstance(delta, dict):
            fail("invalid paired delta record")
        for metric in ("throughput_ratio", "cpu_efficiency_ratio", "p99_latency_ratio"):
            number(delta, metric)
    for field, width in (("source_sha", 40), ("binary_sha256", 64)):
        if not re.fullmatch(f"[0-9a-f]{{{width}}}", record.get(field, "")):
            fail(f"pair is missing {field}")
    for field in ("toolchain", "runner"):
        if not isinstance(record.get(field), str) or not record[field]:
            fail(f"pair is missing {field}")
    if record.get("pair_order") != [["current", "previous"], ["previous", "current"], ["current", "previous"]]:
        fail("pair was not measured in the required alternating order")
    if record.get("sample_attempts") != lane["policy"]["pair_samples"]:
        fail("pair is missing its required samples")


def pair_identity(records, lane):
    for record in records:
        validate_pair_record(record, lane)
    if len(records) == 1:
        return
    if len(records) != 2:
        fail("pair requires one current and one previous qpx record")
    if records[0]["paired_metric_ratios"] != records[1]["paired_metric_ratios"]:
        fail("pair disagrees on per-round deltas")
    if records[1]["source_sha"] != lane["policy"]["previous_release"]["sha"]:
        fail("previous pair identity does not match the pinned release")


def paired_not_applicable(lane, mode=None):
    """Only explicitly declared, pin-bound incompatibility can skip a pair."""
    compatibility = lane.get("pair_compatibility", {})
    if compatibility.get("applicable") is False:
        return {"lane": lane["name"], "assessment": "paired", "mode": mode or assessment(),
                "status": "NOT_APPLICABLE", "reason": compatibility["reason"],
                "previous_sha": compatibility["previous_sha"]}
    return None


class RetryableInvalid(ValueError):
    """A sampler's parsed reference-side transient invalid sample (exit 75)."""


class InconclusiveReference(ValueError):
    """A comparison reference supplied no valid measurement for its lane."""


class InconclusiveCandidate(ValueError):
    """A candidate sample cannot support its declared comparison lane."""


def evaluate(records, lane, paired=False, mode=None, baseline=None):
    mode = mode or assessment()
    if paired:
        skipped = paired_not_applicable(lane, mode)
        if skipped:
            return skipped
    names = ["current", "previous"] if paired else [lane["qpx"], *lane["references"]]
    selected = {}
    invalid_references = {}
    for record in records:
        if matches(record, lane):
            key = record.get("pair_role") if paired else record.get("proxy")
            if key in names:
                if key in selected or key in invalid_references:
                    fail(f'{lane["name"]}: duplicate record {key}')
                try:
                    validate(record, lane)
                except (ValueError, KeyError, TypeError) as error:
                    is_reference = key == "previous" if paired else key != lane["qpx"]
                    if not is_reference:
                        raise
                    invalid_references[key] = str(error)
                    continue
                selected[key] = record
    missing = set(names) - set(selected) - set(invalid_references)
    result = {"lane": lane["name"], "assessment": "paired" if paired else "competitive", "mode": mode}
    candidate_key = "current" if paired else lane["qpx"]
    if candidate_key not in selected:
        fail(f'{lane["name"]}: missing candidate qpx measurement')
    candidate_spread_issues = []
    for field, cap in spread_limits(lane, True).items():
        spread = number(selected[candidate_key].get("sample_spread", {}), field)
        if spread < 1:
            fail(f"invalid spread {field}: {spread}")
        if spread > cap + 1e-12:
            candidate_spread_issues.append(f"{candidate_key} {field} {spread:.6f} > cap {cap:.6f}")
    available = [selected[name] for name in names if name in selected]
    consistent(available, lane, paired)
    if paired:
        # The current sample carries an independently checkable pair identity;
        # missing previous data must not conceal malformed candidate metadata.
        pair_identity([selected[candidate_key]], lane)
        if "previous" in missing or "previous" in invalid_references:
            reference_issue = invalid_references.get("previous", "pinned reference qpx measurement is missing")
            return {**result, "status": "INCONCLUSIVE", "reasons": [reference_issue, *candidate_spread_issues],
                    "unmeasured": True}
    else:
        reference_issues = [f"{name}: {invalid_references[name]}" for name in names
                            if name in invalid_references]
        reference_issues.extend(f"{name}: missing measurement" for name in names if name in missing)
        if reference_issues:
            return {**result, "status": "INCONCLUSIVE", "reasons": [*reference_issues, *candidate_spread_issues],
                    "unmeasured": True}
    group = [selected[n] for n in names]
    if paired:
        pair_identity(group, lane)
    reasons = []
    invalid_names = set()
    for index, record in enumerate(group):
        for field, cap in spread_limits(lane, paired or index == 0).items():
            spread = number(record.get("sample_spread", {}), field)
            if spread < 1:
                fail(f"invalid spread {field}: {spread}")
            if spread > cap + 1e-12:
                invalid_names.add(names[index])
                reasons.append(f"{names[index]} {field} {spread:.6f} > cap {cap:.6f}")
    if reasons:
        # Never remeasure an unstable candidate: only reference-side invalidity
        # may trigger a retry, since candidate variance can itself be a regression.
        candidate = "current" if paired else lane["qpx"]
        status = "INCONCLUSIVE" if candidate in invalid_names else "RETRYABLE_INVALID"
        return {**result, "status": status, "reasons": reasons}
    current = group[0]
    references = group[1:]
    if not paired and lane["kind"] == "proxy":
        references = [r for r in references if r["proxy"] != "direct-backend"]
    cpu = "requests_per_total_cpu_second" if lane["kind"] == "http2" else "requests_per_cpu_second"
    ratios = {"throughput_ratio": number(current, "requests_per_sec") / max(number(r, "requests_per_sec") for r in references),
              "cpu_efficiency_ratio": number(current, cpu) / max(number(r, cpu) for r in references),
              "p99_latency_ratio": number(current, "latency_p99_ms") / min(number(r, "latency_p99_ms") for r in references)}
    misses = []
    def check(metric, limit, direction):
        value = ratios[metric]
        if (direction == "min" and value + 1e-12 < limit) or (direction == "max" and value > limit + 1e-12):
            misses.append(f"{metric} {value:.6f} {'<' if direction == 'min' else '>'} {limit:.6f}")
    if paired:
        deltas = current.get("paired_metric_ratios")
        if not isinstance(deltas, list) or len(deltas) != lane["policy"]["pair_samples"]:
            fail("pair is missing per-round metric deltas")
        for metric in ratios:
            ratios[metric] = sorted(number(delta, metric) for delta in deltas)[len(deltas) // 2]
        limits = lane["policy"]["paired_regression"]
        for metric, field, direction in (("throughput_ratio", "min_throughput_ratio", "min"),
                                         ("cpu_efficiency_ratio", "min_cpu_efficiency_ratio", "min"),
                                         ("p99_latency_ratio", "max_p99_latency_ratio", "max")):
            check(metric, number(limits, field), direction)
        return {**result, "status": "REGRESSED" if misses else "PASSED", "ratios": ratios,
                "misses": misses, "per_round_ratios": deltas, "identities": {n: {f: r[f] for f in ("source_sha", "binary_sha256", "toolchain", "runner")} for n, r in zip(names, group)}}
    limits = lane["limits"]
    if lane["kind"] == "http2":
        # The direct backend is a validity/control lane, not the competitor.
        ref = selected["nginx"]
        ratios.update(throughput_ratio=number(current, "requests_per_sec") / number(ref, "requests_per_sec"),
                      cpu_efficiency_ratio=number(current, cpu) / number(ref, cpu),
                      p99_latency_ratio=number(current, "latency_p99_ms") / number(ref, "latency_p99_ms"))
        ratios["mean_latency_ratio"] = number(current, "mean_time_per_request_ms") / number(ref, "mean_time_per_request_ms")
        ratios["max_latency_ratio"] = number(current, "latency_max_ms") / number(ref, "latency_max_ms")
        ratios["dominance_score"] = (ratios["throughput_ratio"] * ratios["cpu_efficiency_ratio"] / ratios["p99_latency_ratio"] / ratios["mean_latency_ratio"] / ratios["max_latency_ratio"]) ** .2
        fields = [("throughput_ratio", "min_lane_throughput_ratio", "min"), ("cpu_efficiency_ratio", "min_lane_total_cpu_efficiency_ratio", "min"),
                  ("p99_latency_ratio", "max_lane_p99_latency_ratio", "max"), ("mean_latency_ratio", "max_lane_mean_latency_ratio", "max"),
                  ("max_latency_ratio", "max_lane_latency_ratio", "max"), ("dominance_score", "min_lane_dominance_score", "min")]
        rss, fd = "total_rss_peak_kb", "total_fd_peak"
        resources = [("rss_peak_ratio", "max_lane_total_rss_peak_ratio", "max"), ("fd_peak_ratio", "max_lane_total_fd_peak_ratio", "max")]
    else:
        ref = references[0]
        ratios["dominance_score"] = (ratios["throughput_ratio"] * ratios["cpu_efficiency_ratio"] / ratios["p99_latency_ratio"]) ** (1 / 3)
        fields = [("throughput_ratio", "min_throughput_ratio", "min"), ("cpu_efficiency_ratio", "min_cpu_efficiency_ratio", "min"),
                  ("p99_latency_ratio", "max_p99_latency_ratio", "max"), ("dominance_score", "min_dominance_score", "min")]
        rss, fd = "rss_peak_kb", "fd_peak"
        resources = [("rss_peak_ratio", "max_rss_peak_ratio", "max"), ("fd_peak_ratio", "max_fd_peak_ratio", "max")]
    for metric, field in (("rss_peak_ratio", rss), ("fd_peak_ratio", fd)):
        ratios[metric] = number(current, field) / min(number(r, field) for r in references if r["proxy"] != "direct-backend")
    if lane["kind"] == "proxy":
        ratios["rss_peak_ratio"] = number(current, rss) / number(selected["nginx"], rss)
    for metric, field, direction in fields + resources:
        check(metric, number(limits, field), direction)
    diagnostic = lower_is_better_ratio(nonnegative_number(current, "scheduler_queue_delay_us_per_request"), nonnegative_number(ref, "scheduler_queue_delay_us_per_request"))
    historical = None
    if baseline is not None:
        historical = historical_comparison(records, lane, baseline)
        misses += historical["misses"]
    return {**result, "status": "OBJECTIVE_MISS" if mode == "controlled" and misses else "REPORT_ONLY",
            "ratios": ratios, "misses": misses, "historical": historical,
            "diagnostics": {"scheduler_queue_delay_ratio": diagnostic}}


def load_baseline(path):
    config = load_json(path)
    if (config.get("schema_version") != 4 or config.get("metric") != "multi_axis_proxy_dominance"
            or config.get("resource_measurement") != "sampled_workload_peak_v1"
            or config.get("shared_assessment") != "report_only"):
        fail("unsupported proxy baseline policy/schema")
    threshold = config.get("degradation_threshold")
    if type(threshold) not in (int, float) or not math.isfinite(threshold) or not 0 <= threshold < 1:
        fail("invalid historical degradation threshold")
    entries = config.get("baselines")
    if not isinstance(entries, list) or not entries:
        fail("baseline is missing lanes")
    seen = set()
    for entry in entries:
        key = (entry.get("bench"), positive_int(entry, "body_bytes"))
        if key in seen:
            fail("duplicate historical lane")
        seen.add(key)
        for field in ("throughput_ratio", "cpu_efficiency_ratio", "p99_latency_ratio", "dominance_score",
                      "qpxd_requests_per_sec", "qpxd_requests_per_cpu_second", "qpxd_latency_p99_ms"):
            number(entry, field)
        for field in ("concurrency", "duration_seconds"):
            positive_int(entry, field)
    return config


def historical_comparison(records, lane, baseline):
    entry = next((e for e in baseline["baselines"] if e["bench"] == lane["bench"] and e["body_bytes"] == lane["body_bytes"]), None)
    if entry is None:
        fail(f'{lane["name"]}: missing historical baseline')
    current = collect_ratios([r for r in records if matches(r, lane)])[0]
    for field in ("duration_seconds", "concurrency"):
        if current.get(field) != entry.get(field):
            fail(f"historical workload disagrees on {field}")
    misses = []
    deltas = {}
    threshold = baseline["degradation_threshold"]
    for field in ("throughput_ratio", "cpu_efficiency_ratio", "p99_latency_ratio", "dominance_score",
                  "qpxd_requests_per_sec", "qpxd_requests_per_cpu_second", "qpxd_latency_p99_ms"):
        ratio = number(current, field) / number(entry, field)
        deltas[field] = ratio
        if ("latency" in field and ratio > 1 + threshold) or ("latency" not in field and ratio < 1 - threshold):
            misses.append(f"historical {field} delta {ratio:.6f} misses {threshold:.1%} objective")
    return {"deltas": deltas, "misses": misses}


def exit_code(results):
    allowed = {"PASSED", "REGRESSED", "REPORT_ONLY", "OBJECTIVE_MISS", "INCONCLUSIVE",
               "RETRYABLE_INVALID", "NOT_APPLICABLE", "ERROR"}
    if not results or any(r.get("status") not in allowed or r["status"] in ("ERROR", "REGRESSED", "OBJECTIVE_MISS")
                          for r in results):
        return 1
    return 0


def summary(results):
    code = exit_code(results)
    inconclusive = any(r["status"] in ("INCONCLUSIVE", "RETRYABLE_INVALID") for r in results)
    status = "FAILED" if code == 1 else "INCONCLUSIVE" if inconclusive else "COMPLETE"
    return {"status": status,
            "coverage": {"declared": len(results), "required": sum(r["status"] != "NOT_APPLICABLE" for r in results),
                         "not_applicable": [f'{r["lane"]}:{r["assessment"]}' for r in results if r["status"] == "NOT_APPLICABLE"],
                         "valid": sum(r["status"] in ("PASSED", "REGRESSED", "OBJECTIVE_MISS", "REPORT_ONLY") for r in results),
                         "unmeasured": [f'{r["lane"]}:{r["assessment"]}' for r in results if r["status"] in ("INCONCLUSIVE", "RETRYABLE_INVALID", "ERROR")]},
            "results": results}


def bounded_measure(lane, paired, measure, artifact_dir, mode=None, baseline=None):
    """Retry invalid reference samples only; candidate instability stays inconclusive."""
    assessment_name = "paired" if paired else "competitive"
    if paired:
        skipped = paired_not_applicable(lane, mode)
        if skipped:
            write_json(Path(artifact_dir) / "result.json", skipped)
            return skipped
    for attempt in range(1, lane["policy"]["max_attempts"] + 1):
        directory = Path(artifact_dir) / f"attempt-{attempt}"
        directory.mkdir(parents=True, exist_ok=False)
        try:
            records = measure(lane, paired, directory)
            write_jsonl(directory / "measurements.jsonl", records)
            result = evaluate(records, lane, paired, mode, baseline)
        except InconclusiveReference as error:
            result = {"lane": lane["name"], "assessment": assessment_name,
                      "status": "INCONCLUSIVE", "reasons": [str(error)], "unmeasured": True}
        except InconclusiveCandidate as error:
            result = {"lane": lane["name"], "assessment": assessment_name,
                      "status": "INCONCLUSIVE", "reasons": [str(error)], "unmeasured": True}
        except RetryableInvalid as error:
            result = {"lane": lane["name"], "assessment": assessment_name,
                      "status": "RETRYABLE_INVALID", "reasons": [str(error)]}
        except (ValueError, KeyError, TypeError, OSError) as error:
            result = {"lane": lane["name"], "assessment": assessment_name, "status": "ERROR", "error": str(error)}
        result["attempt"] = attempt
        write_json(directory / "result.json", result)
        if result["status"] != "RETRYABLE_INVALID":
            return result
    return {**result, "status": "INCONCLUSIVE", "unmeasured": True, "attempts_exhausted": attempt}


def http2_aggregate(config, results):
    competitive = [r for r in results if r["assessment"] == "competitive"]
    expected = len(config["required_body_bytes"]) * len(config["required_max_concurrent_streams"])
    result = {"lane": "http2/aggregate", "assessment": "competitive", "mode": assessment()}
    if len(competitive) != expected or any("ratios" not in r for r in competitive):
        return {**result, "status": "INCONCLUSIVE", "reason": "aggregate requires every valid competitive lane"}
    score = math.prod(r["ratios"]["dominance_score"] for r in competitive) ** (1 / expected)
    objective = number(config["defaults"], "min_aggregate_dominance_score")
    miss = score + 1e-12 < objective
    return {**result, "status": "OBJECTIVE_MISS" if assessment() == "controlled" and miss else "REPORT_ONLY",
            "dominance_score": score, "objective": objective, "misses": ["aggregate dominance objective missed"] if miss else []}
