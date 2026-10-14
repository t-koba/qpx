#!/usr/bin/env python3
"""Run the in-job validity/regression policy or check recorded measurements."""
import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from perf_policy import (
    ROOT,
    InconclusiveReference,
    RetryableInvalid,
    assessment,
    bounded_measure,
    consistent,
    evaluate,
    exit_code,
    http2_aggregate,
    load_baseline,
    load_jsonl,
    matches,
    objectives,
    summary,
    validate,
    write_json,
    write_jsonl,
)
from perf_records import collect_ratios, fail, number

ORDER = [["current", "previous"], ["previous", "current"], ["current", "previous"]]


def aggregate(samples, lane):
    # Every single sample is functionally validated before aggregation. No
    # failed/crashed/wrong-response sample can be discarded as an outlier.
    for record in samples:
        validate(record, lane)
    consistent(samples, lane, False, same_role=True)
    record = dict(samples[0])
    spread = dict(record["sample_spread"])
    for field in ("requests_per_sec", "requests_per_cpu_second", "requests_per_total_cpu_second",
                  "latency_p99_ms", "mean_time_per_request_ms", "latency_max_ms"):
        if field not in record:
            continue
        values = sorted(number(s, field) for s in samples)
        record[field] = values[len(values) // 2]
        spread_field = {"latency_p99_ms": "latency_p99_ratio", "mean_time_per_request_ms": "mean_time_per_request_ms_ratio"}.get(field, field + "_ratio")
        spread[spread_field] = values[-1] / values[0]
    record.update(sample_attempts=len(samples), valid_samples=len(samples), sample_spread=spread)
    return record


def cache_writeback_log_status(log_path):
    """Detect failed cache writes and response body length errors in one log."""
    try:
        if not log_path.is_file():
            raise ValueError("required qpxd-cache log is missing")
        failure_count = 0
        response_body_length_failure_count = 0
        body_length_errors = (
            "response body ended before declared content-length was satisfied",
            "response body exceeded declared content-length",
        )
        with log_path.open(encoding="utf-8") as log:
            for line_number, line in enumerate(log, 1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as error:
                    raise ValueError(f"malformed qpxd-cache JSON log at line {line_number}") from error
                if not isinstance(event, dict):
                    raise ValueError(f"qpxd-cache log entry at line {line_number} is not an object")
                message = event.get("message")
                if isinstance(message, str) and message.startswith("cache writeback failed"):
                    failure_count += 1
                error_text = event.get("error")
                if any(
                    isinstance(value, str) and any(error in value for error in body_length_errors)
                    for value in (message, error_text)
                ):
                    response_body_length_failure_count += 1
    except (OSError, ValueError) as error:
        return {
            "status": "unestablished",
            "failure_count": None,
            "response_body_length_failure_count": None,
            "detail": str(error),
        }
    if failure_count:
        status = "writeback_failure_observed"
    elif response_body_length_failure_count:
        status = "response_body_length_failure_observed"
    else:
        status = "no_cache_miss_response_failure_logged"
    return {
        "status": status,
        "failure_count": failure_count,
        "response_body_length_failure_count": response_body_length_failure_count,
        "detail": None,
    }


class Sampler:
    def __init__(self, previous_bin, previous_sha):
        self.binaries = {"current": Path(os.environ.get("QPXD_BIN", ROOT / "target/release/qpxd")).resolve(),
                         "previous": Path(previous_bin).resolve()}
        self.identities = {}
        toolchain = subprocess.check_output(["rustc", "-Vv"], text=True).strip()
        runner = os.environ.get("GITHUB_RUN_ID", "local") + ":" + os.environ.get("GITHUB_JOB", "local") + ":" + os.environ.get("RUNNER_NAME", "local")
        for role, path in self.binaries.items():
            if not path.is_file() or not os.access(path, os.X_OK):
                fail(f"missing executable {role} qpxd binary")
            self.identities[role] = {"source_sha": previous_sha if role == "previous" else subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                                     "binary_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                     "toolchain": toolchain, "runner": runner}

    def _validate_cache_writeback_admission_metric(self, directory, records):
        """Require the candidate's scrape to establish zero admission rejects."""
        validation = {"status": "unestablished", "rejections": None}
        if len(records) != 1:
            validation["detail"] = "paired cache-miss sampler did not return exactly one record"
        else:
            value = records[0].get("cache_writeback_admission_rejections")
            if type(value) is not int or value < 0:
                validation["detail"] = "cache writeback admission rejection metric is missing or malformed"
            elif value != 0:
                validation.update(status="rejection_observed", rejections=value)
                validation["detail"] = "cache writeback admission rejection metric is nonzero"
            else:
                validation.update(status="zero_rejections_observed", rejections=0, detail=None)
        write_json(directory / "cache-writeback-admission-validation.json", validation)
        if validation["status"] != "zero_rejections_observed":
            fail(
                "cache writeback admission validity unestablished "
                f"({validation['detail']}); see cache-writeback-admission-validation.json"
            )

    def _validate_cache_writeback_log(self, directory, role):
        log_relative_path = Path("logs/qpxd-cache.log")
        validation = cache_writeback_log_status(directory / log_relative_path)
        validation.update({
            "log": str(log_relative_path),
            "scope": "full qpxd-cache log for this sampler invocation, including setup and verification",
            "limitation": "absence of logged errors does not prove every asynchronous write completed or no unlogged body-length mismatch occurred; candidate admission rejections are validated separately, while the pinned reference does not export that counter",
        })
        write_json(directory / "cache-writeback-validation.json", validation)
        if validation["status"] == "no_cache_miss_response_failure_logged":
            return
        if validation["status"] == "writeback_failure_observed":
            reason = f"cache writeback failure observed ({validation['failure_count']} event(s))"
        elif validation["status"] == "response_body_length_failure_observed":
            reason = (
                "cache-miss response body length failure observed "
                f"({validation['response_body_length_failure_count']} event(s))"
            )
        else:
            reason = f"cache writeback validity unestablished ({validation['detail']})"
        reason += "; see logs/qpxd-cache.log and cache-writeback-validation.json"
        if role == "previous":
            raise InconclusiveReference(f"pinned reference {reason}")
        fail(reason)

    def sample(self, lane, role, paired, directory):
        directory.mkdir(parents=True, exist_ok=False)
        env = os.environ.copy()
        env["QPXD_BIN"] = str(self.binaries[role])
        prefix = "QPX_HTTP2_COMPARE_" if lane["kind"] == "http2" else "QPX_PROXY_COMPARE_"
        env.update({prefix + "BODY_SIZES": str(lane["body_bytes"]),
                    prefix + "SAMPLE_ATTEMPTS": "1" if paired else "3",
                    prefix + "MIN_VALID_SAMPLES": "1" if paired else "3",
                    prefix + "PROXY_FILTER": lane["qpx"] if paired else ",".join([lane["qpx"], *lane["references"]]),
                    prefix + "LOG_DIR": str(directory / "logs")})
        if lane["kind"] == "http2":
            if not paired:
                env[prefix + "PROXY_FILTER"] = "direct-backend,qpxd,nginx"
            env[prefix + "MAX_CONCURRENT_STREAMS_VALUES"] = str(lane["max_concurrent_streams"])
        else:
            env[prefix + "BENCH_FILTER"] = lane["bench"]
            env[prefix + "MISS_SAMPLE_ATTEMPTS"] = "1" if paired else "3"
            if (
                paired
                and role == "current"
                and lane.get("bench") == "proxy_cache_miss_http1"
                and lane.get("qpx") == "qpxd-cache"
            ):
                env[prefix + "CACHE_ADMISSION_METRICS_PORT"] = "19093"
        out = directory / "samples.jsonl"
        script = ROOT / "scripts" / ("perf-audit-http2-compare.sh" if lane["kind"] == "http2" else "perf-audit-proxy-compare.sh")
        with (directory / "command.log").open("w") as log:
            process = subprocess.run([str(script), str(out)], env=env, stdout=log, stderr=subprocess.STDOUT)
        if lane.get("bench") == "proxy_cache_miss_http1" and lane.get("qpx") == "qpxd-cache":
            # Validate the collected log after the sampler has shut down so
            # late background-write failures are not hidden by MISS headers or
            # the single post-sample sentinel.
            self._validate_cache_writeback_log(directory, role)
        if process.returncode == 75 and not paired and role == "current":
            raise RetryableInvalid(f"reference sample invalid; see {directory.name}/command.log (sampler exit 75)")
        if process.returncode and role == "previous":
            message = f"sampler exited {process.returncode}; see {directory.name}/command.log (not retryable)"
            raise InconclusiveReference(f"pinned reference measurement unavailable: {message}")
        if process.returncode and not paired and role == "current":
            try:
                records = load_jsonl(out, validate_records=False)
                result = evaluate(records, lane, mode="shared")
            except (ValueError, KeyError, TypeError, OSError):
                fail(
                    f"sampler exited {process.returncode}; candidate measurement invalid or unavailable; "
                    f"see {directory.name}/command.log"
                )
            if result["status"] == "INCONCLUSIVE":
                reasons = result.get("reasons", [])
                if any(reason.startswith(lane["qpx"] + " ") for reason in reasons):
                    return records  # Preserve a candidate-spread diagnosis for evaluate().
                details = "; ".join(reasons) or "comparison has no valid reference lane"
                raise InconclusiveReference(
                    f"competitive sampler exited {process.returncode}: {details}; "
                    f"see {directory.name}/command.log and samples.jsonl"
                )
            fail(f"sampler exited {process.returncode}; see {directory.name}/command.log (not retryable)")
        if process.returncode:
            fail(f"sampler exited {process.returncode}; see {directory.name}/command.log (not retryable)")
        try:
            records = load_jsonl(out, validate_records=False)
            for record in records:
                if not matches(record, lane):
                    fail(f"sampler returned an unexpected workload for {lane['name']}")
        except (ValueError, KeyError, TypeError, OSError) as error:
            if role == "previous":
                raise InconclusiveReference(f"pinned reference measurement invalid: {error}") from error
            raise
        if (
            paired
            and role == "current"
            and lane.get("bench") == "proxy_cache_miss_http1"
            and lane.get("qpx") == "qpxd-cache"
        ):
            self._validate_cache_writeback_admission_metric(directory, records)
        return records

    def __call__(self, lane, paired, directory):
        if not paired:
            return self.sample(lane, "current", False, directory / "competitive")
        samples = {role: [] for role in self.binaries}
        for index, roles in enumerate(ORDER, 1):
            for role in roles:
                records = self.sample(lane, role, True, directory / f"round-{index}-{role}")
                if len(records) != 1 or records[0]["proxy"] != lane["qpx"]:
                    fail("paired sampler did not return exactly one qpx lane")
                samples[role].append(records[0])
        aggregated = {}
        for role in ("current", "previous"):
            try:
                aggregated[role] = aggregate(samples[role], lane)
            except (ValueError, KeyError, TypeError, OSError) as error:
                if role == "previous":
                    raise InconclusiveReference(f"pinned reference measurement invalid: {error}") from error
                raise
        cpu = "requests_per_total_cpu_second" if lane["kind"] == "http2" else "requests_per_cpu_second"
        deltas = [{"throughput_ratio": number(c, "requests_per_sec") / number(p, "requests_per_sec"),
                   "cpu_efficiency_ratio": number(c, cpu) / number(p, cpu),
                   "p99_latency_ratio": number(c, "latency_p99_ms") / number(p, "latency_p99_ms")}
                  for c, p in zip(samples["current"], samples["previous"])]
        return [{**aggregated[role], **self.identities[role], "pair_role": role, "pair_order": ORDER, "sample_spread_basis": "full_range", "paired_metric_ratios": deltas} for role in ("current", "previous")]


def run(args):
    kinds = ("proxy", "origin") if args.suite == "proxy" else ("http2",)
    configs_lanes = [objectives(k) for k in kinds]
    policies = [config["ci_policy"] for config, _ in configs_lanes]
    if any(policy != policies[0] for policy in policies):
        fail("suite policies disagree")
    policy = policies[0]
    if args.previous_sha != policy["previous_release"]["sha"]:
        fail("previous binary build SHA does not match the pinned release")
    mode = assessment()
    sampler = Sampler(args.previous_bin, args.previous_sha)
    baseline = load_baseline(ROOT / "perf/baseline-proxy-compare.json") if args.suite == "proxy" else None
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    results = []
    accepted = {"paired": [], "competitive": []}
    for _, lanes in configs_lanes:
        for lane in lanes:
            for paired in (True, False):
                name = "paired" if paired else "competitive"
                result = bounded_measure(lane, paired, sampler, out / lane["name"] / name, mode,
                                         baseline if lane["kind"] == "proxy" and not paired else None)
                results.append(result)
                if result["status"] in ("PASSED", "REGRESSED", "REPORT_ONLY", "OBJECTIVE_MISS"):
                    attempt_file = out / lane["name"] / name / f'attempt-{result["attempt"]}' / "measurements.jsonl"
                    accepted[name] += load_jsonl(attempt_file)
                write_json(out / "summary.json", summary(results))
    if args.suite == "http2":
        results.append(http2_aggregate(configs_lanes[0][0], results))
    for name, records in accepted.items():
        write_jsonl(out / f"accepted-{name}.jsonl", records)
    report = summary(results)
    write_json(out / "summary.json", report)
    print(json.dumps(report, indent=2))
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a") as handle:
            handle.write(f"## {args.suite} performance: {report['status']}\n\n````json\n{json.dumps(report, indent=2)}\n````\n")
    return exit_code(results)


def check(args):
    config, lanes = objectives(args.kind, args.objectives)
    records = load_jsonl(args.jsonl, validate_records=False)
    baseline = load_baseline(args.baseline) if args.baseline else None
    results = []
    for lane in lanes:
        try:
            results.append(evaluate(records, lane, args.paired, baseline=baseline))
        except (ValueError, KeyError, TypeError) as error:
            results.append({"lane": lane["name"], "assessment": "paired" if args.paired else "competitive", "status": "ERROR", "error": str(error)})
    if args.kind == "http2" and not args.paired:
        results.append(http2_aggregate(config, results))
    print(json.dumps(summary(results), indent=2))
    return exit_code(results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    checker = sub.add_parser("check")
    checker.add_argument("kind", choices=("proxy", "origin", "http2"))
    checker.add_argument("jsonl")
    checker.add_argument("--objectives")
    checker.add_argument("--baseline")
    checker.add_argument("--paired", action="store_true")
    runner = sub.add_parser("run")
    runner.add_argument("suite", choices=("proxy", "http2"))
    runner.add_argument("out")
    runner.add_argument("--previous-bin", required=True)
    runner.add_argument("--previous-sha", required=True)
    generate = sub.add_parser("generate")
    generate.add_argument("jsonl")
    generate.add_argument("baseline")
    generate.add_argument("--threshold", type=float, default=.05)
    args = parser.parse_args()
    try:
        if args.command == "run":
            return run(args)
        if args.command == "check":
            return check(args)
        if not math_is_threshold(args.threshold):
            fail("threshold must be finite and in [0, 1)")
        write_json(args.baseline, {"schema_version": 4, "metric": "multi_axis_proxy_dominance",
                                  "resource_measurement": "sampled_workload_peak_v1", "shared_assessment": "report_only",
                                  "degradation_threshold": args.threshold, "baselines": collect_ratios(load_jsonl(args.jsonl))})
        return 0
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "ERROR", "error": str(error)}), file=sys.stderr)
        return 1


def math_is_threshold(value):
    return 0 <= value < 1  # NaN and infinities are rejected by these comparisons.


if __name__ == "__main__":
    sys.exit(main())
