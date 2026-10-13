#!/usr/bin/env python3
"""Small JSONL fixture demo; no benchmarks or network. Artifacts are retained."""
import copy
import ctypes
import ctypes.util
import importlib.util
import json
import re
import shlex
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))
from perf_policy import (bounded_measure, evaluate, exit_code, load_jsonl,
                         objectives, summary, write_json, write_jsonl)

ARTIFACTS = ROOT / "target/perf/policy-fixtures"
ORDER = [["current", "previous"], ["previous", "current"], ["current", "previous"]]
SPEC = importlib.util.spec_from_file_location("driver", ROOT / "scripts/perf-audit-policy.py")
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


def shell_function(script, name):
    """Run the real shell functions without starting servers or requiring tools."""
    source = (ROOT / "scripts" / script).read_text()
    return re.search(r"(?ms)^" + re.escape(name) + r"\(\) \{.*?^\}$", source).group()


def fixture_sampler(lane):
    sampler = object.__new__(DRIVER.Sampler)
    sampler.binaries = {"current": ROOT / "target/fixture-current", "previous": ROOT / "target/fixture-previous"}
    sampler.identities = {r: {"source_sha": "a" * 40 if r == "current" else lane["policy"]["previous_release"]["sha"],
                               "binary_sha256": str(i + 1) * 64, "toolchain": "fixture", "runner": "fixture"}
                          for i, r in enumerate(sampler.binaries)}
    return sampler


def record(lane, proxy):
    result = dict(bench=lane["bench"], body_bytes=lane["body_bytes"], proxy=proxy,
                  valid=True, sample_attempts=3, valid_samples=3,
                  aggregation="conservative_median_per_metric", sampling_order="round_robin_interleaved",
                  sample_spread_basis="tightest_valid_majority", benchmark_schema_version=4,
                  resource_measurement="sampled_workload_peak_v1", kernel_resource_metrics=True,
                  execution_model="async-io", role_workers=lane.get("qpx_role_workers", 1),
                  blocking_workers=lane.get("qpx_blocking_workers"), backend_workers=3,
                  health_check_interval_ms=5000, logical_cpus=4,
                  duration_seconds=10, target_duration_seconds=10, threads=2, concurrency=64,
                  client_threads=2, server_workers=4, requests=100, complete_requests=100,
                  started_requests=100, succeeded_requests=100, benchmark_request_count=100,
                  calibration_requests=100, calibration_duration_ms=2000,
                  requests_per_sec=100, requests_per_cpu_second=100, requests_per_total_cpu_second=50,
                  mean_time_per_request_ms=1, latency_p99_ms=1, latency_max_ms=2,
                  cpu_ms=1000, backend_cpu_ms=1000, total_cpu_ms=2000,
                  rss_baseline_kb=100, rss_peak_kb=120, rss_growth_kb=20,
                  backend_rss_baseline_kb=100, backend_rss_peak_kb=120, backend_rss_growth_kb=20,
                  total_rss_peak_kb=240, total_rss_growth_kb=40,
                  fd_baseline=10, fd_peak=12, fd_growth=2,
                  backend_fd_baseline=10, backend_fd_peak=12, backend_fd_growth=2,
                  total_fd_peak=24, total_fd_growth=4,
                  scheduler_queue_delay_us_per_request=1,
                  connect_errors=0, read_errors=0, write_errors=0, timeout_errors=0,
                  failed_requests=0, non_2xx_responses=0, bad_length_responses=0, cache_result_errors=0,
                  cache_writeback_verified=True, max_read_error_rate_ppm=1000,
                  status_before="200", status_after="200",
                  workload_profile=lane.get("workload_profile", "minimal_proxy_v1"),
                  sample_spread={f: 1.0 for f in ("requests_per_sec_ratio", "requests_per_cpu_second_ratio", "requests_per_total_cpu_second_ratio", "latency_p99_ratio", "mean_time_per_request_ms_ratio")})
    if lane["kind"] == "http2":
        result.update(benchmark_schema_version=7, max_concurrent_streams=lane["max_concurrent_streams"])
        if proxy == "direct-backend":
            result.update(total_rss_peak_kb=120, total_rss_growth_kb=20, total_fd_peak=12, total_fd_growth=2)
    if proxy in ("apache", "apache-webdav"):
        result["execution_model"] = "thread-per-request"
    if proxy in lane["references"]:
        result["role_workers"] = lane.get("reference_role_workers", result["role_workers"])
    return result


def pair(lane, throughput=1.0, cpu=1.0, p99=1.0, spread=1.0, invalid_role="current"):
    current, previous = [record(lane, lane["qpx"]) for _ in range(2)]
    current["requests_per_sec"] *= throughput
    current["requests_per_cpu_second"] *= cpu
    current["requests_per_total_cpu_second"] *= cpu
    current["latency_p99_ms"] *= p99
    deltas = [{"throughput_ratio": throughput, "cpu_efficiency_ratio": cpu, "p99_latency_ratio": p99}] * 3
    for index, (role, r) in enumerate(zip(("current", "previous"), (current, previous))):
        r.update(pair_role=role, pair_order=ORDER, sample_spread_basis="full_range", paired_metric_ratios=deltas,
                 source_sha="a" * 40 if role == "current" else lane["policy"]["previous_release"]["sha"],
                 binary_sha256=str(index + 1) * 64, toolchain="fixture-rustc", runner="fixture-runner")
        if role == invalid_role:
            r["sample_spread"]["requests_per_sec_ratio"] = spread
    return [current, previous]


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.directory = ARTIFACTS / self._testMethodName
        self.directory.mkdir(parents=True)
        self.lanes = [lane for kind in ("proxy", "origin", "http2") for lane in objectives(kind)[1]]
        self.pair_lanes = [lane for lane in self.lanes if lane.get("pair_compatibility", {}).get("applicable", True)]

    def measure(self, lane, attempts, name="lane", paired=True):
        calls = []
        def fixture_measure(_lane, _paired, directory):
            calls.append(directory)
            payload = attempts[len(calls) - 1]
            source = directory / "fixture.jsonl"
            if isinstance(payload, str):
                source.write_text(payload)
            else:
                write_jsonl(source, payload)
            return load_jsonl(source)
        result = bounded_measure(lane, paired, fixture_measure, self.directory / name, mode="shared")
        write_json(self.directory / (name + "-summary.json"), summary([result]))
        self.assertEqual(len(calls), result.get("attempt", 0))
        for directory in calls:
            self.assertTrue((directory / "result.json").is_file())
            self.assertTrue((directory / "fixture.jsonl").is_file())
        return result, len(calls)

    def test_equal_pairs_and_competitive_misses_are_reports(self):
        for index, lane in enumerate(self.lanes):
            with self.subTest(lane=lane["name"]):
                equal, count = self.measure(lane, [pair(lane)], str(index))
                self.assertEqual((equal["status"], count), ("PASSED", 1) if lane in self.pair_lanes else ("NOT_APPLICABLE", 0))
                competitive = [record(lane, p) for p in [lane["qpx"], *lane["references"]]]
                competitive[0]["requests_per_sec"] /= 10
                competitive[0]["scheduler_queue_delay_us_per_request"] = 1e9
                write_jsonl(self.directory / f"competitive-{index}.jsonl", competitive)
                report = evaluate(load_jsonl(self.directory / f"competitive-{index}.jsonl"), lane, mode="shared")
                self.assertEqual(report["status"], "REPORT_ONLY")
                self.assertTrue(report["misses"])
                self.assertEqual(exit_code([equal, report]), 0)
                self.assertEqual(evaluate(competitive, lane, mode="controlled")["status"], "OBJECTIVE_MISS")

    def test_independent_metric_regressions_never_retry(self):
        for index, lane in enumerate(self.pair_lanes):
            for metric, value in (("throughput", .94), ("cpu", .94), ("p99", 1.11)):
                with self.subTest(lane=lane["name"], metric=metric):
                    # A tempting second equal attempt must never be reached.
                    bad = pair(lane, **{metric: value})
                    result, count = self.measure(lane, [bad, pair(lane)], f"{index}-{metric}")
                    self.assertEqual((result["status"], count, exit_code([result])), ("REGRESSED", 1, 1))

    def test_only_invalid_pinned_reference_spread_is_retried(self):
        for index, lane in enumerate(self.pair_lanes):
            candidate_invalid = pair(lane, throughput=.5, spread=2000, invalid_role="current")
            result = evaluate(candidate_invalid, lane, True)
            self.assertEqual(result["status"], "INCONCLUSIVE")
            self.assertNotIn("ratios", result)
            # Candidate variance can itself be a regression; a later attractive
            # sample must not erase this inconclusive measurement.
            candidate, count = self.measure(
                lane, [candidate_invalid, pair(lane)], f"{index}-candidate-inconclusive"
            )
            self.assertEqual((candidate["status"], count, exit_code([candidate])), ("INCONCLUSIVE", 1, 75))

            reference_invalid = pair(lane, throughput=.5, spread=2000, invalid_role="previous")
            result = evaluate(reference_invalid, lane, True)
            self.assertEqual(result["status"], "RETRYABLE_INVALID")
            self.assertNotIn("ratios", result)
            valid, count = self.measure(
                lane, [reference_invalid, pair(lane)], f"{index}-reference-recovered"
            )
            self.assertEqual((valid["status"], count), ("PASSED", 2))
            bad, count = self.measure(
                lane, [reference_invalid, pair(lane, p99=1.2), pair(lane)], f"{index}-reference-bad"
            )
            self.assertEqual((bad["status"], count), ("REGRESSED", 2))
            exhausted, count = self.measure(
                lane, [reference_invalid] * 3, f"{index}-reference-exhausted"
            )
            self.assertEqual((exhausted["status"], count, exit_code([exhausted])), ("INCONCLUSIVE", 3, 75))
            self.assertEqual(summary([exhausted])["coverage"]["valid"], 0)
            self.assertTrue(summary([exhausted])["coverage"]["unmeasured"])

    def test_regression_survives_another_inconclusive_lane(self):
        bad, _ = self.measure(self.lanes[0], [pair(self.lanes[0], p99=1.2)], "bad")
        invalid, _ = self.measure(self.lanes[1], [pair(self.lanes[1], spread=2000)] * 3, "invalid")
        report = summary([bad, invalid])
        write_json(self.directory / "mixed-summary.json", report)
        self.assertEqual((report["status"], exit_code([bad, invalid])), ("FAILED", 1))
        self.assertEqual(report["coverage"]["valid"], 1)

    def test_missing_corrupt_wrong_response_and_schema_are_errors(self):
        lane = self.lanes[0]
        broken = pair(lane, spread=2000)
        broken[1]["bad_length_responses"] = 1  # error outranks spread, no retry
        malformed = pair(lane)
        malformed[0]["requests_per_sec"] = "NaN"
        schema = pair(lane)
        schema[0]["benchmark_schema_version"] = 999
        for index, payload in enumerate(([pair(lane)[0]], "{bad-json\n", broken, malformed, schema, "[]\n", "")):
            result, count = self.measure(lane, [payload, pair(lane)], str(index))
            self.assertEqual((result["status"], count, exit_code([result])), ("ERROR", 1, 1))
        for index, payload in enumerate((pair(lane) * 2, pair(lane))):
            if index == 1:
                payload[1]["source_sha"] = "b" * 40
            result, _ = self.measure(lane, [payload], f"identity-{index}")
            self.assertEqual(result["status"], "ERROR")

    def test_competitive_candidate_spread_is_not_retried_but_reference_spread_is(self):
        for index, lane in enumerate(self.lanes):
            valid = [record(lane, p) for p in [lane["qpx"], *lane["references"]]]
            candidate_invalid = copy.deepcopy(valid)
            candidate_invalid[0]["sample_spread"]["requests_per_sec_ratio"] = 2000
            result, count = self.measure(
                lane, [candidate_invalid, valid], f"{index}-candidate", paired=False
            )
            self.assertEqual((result["status"], count, exit_code([result])), ("INCONCLUSIVE", 1, 75))

            reference_invalid = copy.deepcopy(valid)
            reference_invalid[-1]["sample_spread"]["requests_per_sec_ratio"] = 2000
            result, count = self.measure(
                lane, [reference_invalid, valid], f"{index}-reference", paired=False
            )
            self.assertEqual((result["status"], count), ("REPORT_ONLY", 2))

    def test_public_checker_entrypoints_and_historical_reports(self):
        for kind, script in (("proxy", "compare-proxy-baseline.sh"), ("origin", "check-origin-cache-performance.sh"), ("http2", "check-http2-performance.sh")):
            lanes = objectives(kind)[1]
            records = [record(lane, p) for lane in lanes for p in [lane["qpx"], *lane["references"]]]
            source = self.directory / f"{kind}.jsonl"
            write_jsonl(source, records)
            process = subprocess.run([str(ROOT / "scripts" / script), str(source)], text=True, capture_output=True)
            self.assertEqual(process.returncode, 0, process.stderr + process.stdout)
            self.assertEqual(json.loads(process.stdout)["status"], "COMPLETE")
            source.write_text("{bad-json\n")
            self.assertEqual(subprocess.run([str(ROOT / "scripts" / script), str(source)], capture_output=True).returncode, 1)
        # An absent file is an error, never a spread event.
        process = subprocess.run([str(ROOT / "scripts/check-http2-performance.sh"), str(self.directory / "missing")], capture_output=True)
        self.assertEqual(process.returncode, 1)

    def test_scheduler_queue_delay_never_gates_controlled_assessment(self):
        for lane in self.lanes:
            records = [record(lane, p) for p in [lane["qpx"], *lane["references"]]]
            qpx = records[0]
            qpx.update(requests_per_sec=10000, requests_per_cpu_second=10000,
                       requests_per_total_cpu_second=10000, latency_p99_ms=.001,
                       mean_time_per_request_ms=.001, latency_max_ms=.001,
                       scheduler_queue_delay_us_per_request=1e9)
            report = evaluate(records, lane, mode="controlled")
            self.assertEqual(report["status"], "REPORT_ONLY")
            self.assertEqual(report["misses"], [])
            self.assertGreater(report["diagnostics"]["scheduler_queue_delay_ratio"], 1)

    def test_pair_sampler_interleaves_and_records_every_round(self):
        # Includes origin-local, hit and miss: three samples of one qpx role
        # must not be unpacked or worker-checked as a qpx/reference pair.
        for lane in self.pair_lanes:
            with self.subTest(lane=lane["name"]):
                sampler = fixture_sampler(lane)
                calls = []
                def singleton(lane, role, paired, directory):
                    calls.append(role)
                    result = record(lane, lane["qpx"])
                    result.update(sample_attempts=1, valid_samples=1)
                    return [result]
                sampler.sample = singleton
                records = sampler(lane, True, self.directory)
                self.assertEqual(calls, [r for round_ in ORDER for r in round_])
                self.assertEqual(evaluate(records, lane, True)["status"], "PASSED")
                self.assertEqual(len(records[0]["paired_metric_ratios"]), 3)

    def test_origin_same_role_aggregation_still_checks_consistency(self):
        lane = objectives("origin")[1][0]
        samples = [record(lane, lane["qpx"]) for _ in range(3)]
        self.assertEqual(DRIVER.aggregate(samples, lane)["valid_samples"], 3)
        for field, value in (("concurrency", 32), ("role_workers", 4), ("blocking_workers", 99),
                             ("proxy", lane["references"][0]), ("execution_model", "thread-per-request")):
            broken = copy.deepcopy(samples)
            broken[-1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                DRIVER.aggregate(broken, lane)
        # Competitive checks remain distinct and still reject worker mismatch.
        competitive = [record(lane, p) for p in [lane["qpx"], *lane["references"]]]
        competitive[1]["role_workers"] += 1
        with self.assertRaises(ValueError):
            evaluate(competitive, lane)

    def test_not_applicable_pairs_only_skip_declared_pin_bound_lanes(self):
        skipped_lanes = [lane for lane in self.lanes if lane not in self.pair_lanes]
        self.assertEqual([(lane["bench"], lane["body_bytes"]) for lane in skipped_lanes],
                         [(bench, size) for bench in ("origin_webdav_http1", "feature_rich_cache_hit_http1")
                          for size in (1024, 1048576)])
        results = []
        for index, lane in enumerate(skipped_lanes):
            skipped, count = self.measure(lane, [], str(index))
            self.assertEqual((skipped["status"], count), ("NOT_APPLICABLE", 0))
            self.assertTrue(skipped["reason"])
            self.assertEqual(skipped["previous_sha"], lane["policy"]["previous_release"]["sha"])
            self.assertEqual(evaluate([], lane, True), skipped)
            self.assertTrue((self.directory / str(index) / "result.json").is_file())
            valid = [record(lane, p) for p in [lane["qpx"], *lane["references"]]]
            competitive, count = self.measure(lane, [valid], f"competitive-{index}", paired=False)
            self.assertEqual((competitive["status"], count), ("REPORT_ONLY", 1))
            results += [skipped, competitive]
        report = summary(results)
        self.assertEqual(report["status"], "COMPLETE")
        self.assertEqual((report["coverage"]["declared"], report["coverage"]["required"], report["coverage"]["valid"]), (8, 4, 4))
        self.assertEqual(len(report["coverage"]["not_applicable"]), 4)
        self.assertEqual(report["coverage"]["unmeasured"], [])
        config = json.loads((ROOT / "perf/origin-cache-performance-objectives.json").read_text())
        for index, changes in enumerate(({"previous_sha": "a" * 40}, {"applicable": "false"}, {"reason": ""})):
            broken = copy.deepcopy(config)
            broken["lanes"][1]["pair_compatibility"].update(changes)
            path = self.directory / f"bad-compatibility-{index}.json"
            write_json(path, broken)
            with self.assertRaises(ValueError):
                objectives("origin", path)

    def test_sampler_exit_75_retries_only_competitive_not_qpx_pairs(self):
        for kind in ("proxy", "http2"):
            lane = objectives(kind)[1][0]
            sampler = fixture_sampler(lane)
            for status, paired, expected, attempts in ((75, False, "INCONCLUSIVE", 3), (1, False, "ERROR", 1),
                                                      (75, True, "ERROR", 1), (1, True, "ERROR", 1)):
                with patch.object(DRIVER.subprocess, "run", return_value=SimpleNamespace(returncode=status)) as run:
                    result = bounded_measure(lane, paired, sampler, self.directory / f"{kind}-{status}-{paired}")
                self.assertEqual((result["status"], run.call_count), (expected, attempts))
                self.assertEqual(exit_code([result]), 75 if expected == "INCONCLUSIVE" else 1)
            # Neither previous nor current qpx can request a functional retry.
            for role in ("current", "previous"):
                with patch.object(DRIVER.subprocess, "run", return_value=SimpleNamespace(returncode=75)):
                    with self.assertRaises(ValueError) as error:
                        sampler.sample(lane, role, True, self.directory / f"{kind}-{role}")
                self.assertNotIsInstance(error.exception, DRIVER.RetryableInvalid)
            calls = []
            def invalid_then_valid(command, **kwargs):
                calls.append(command)
                if len(calls) == 1:
                    return SimpleNamespace(returncode=75)
                write_jsonl(command[-1], [record(lane, p) for p in [lane["qpx"], *lane["references"]]])
                return SimpleNamespace(returncode=0)
            with patch.object(DRIVER.subprocess, "run", side_effect=invalid_then_valid):
                result = bounded_measure(lane, False, sampler, self.directory / f"{kind}-recovered")
            self.assertEqual((result["status"], len(calls), result["attempt"]), ("REPORT_ONLY", 2, 2))

    def test_both_qpx_roles_functional_failures_never_retry(self):
        for kind in ("proxy", "http2"):
            lane = objectives(kind)[1][0]
            for role in (0, 1):
                invalid = pair(lane)
                invalid[role]["non_2xx_responses"] = 1
                result, count = self.measure(lane, [invalid, pair(lane)], f"{kind}-{role}")
                self.assertEqual((result["status"], count), ("ERROR", 1))

class SamplerScriptTests(unittest.TestCase):
    """Execute real sampler functions with deterministic tool/proc fixtures."""
    def setUp(self):
        self.directory = ARTIFACTS / self._testMethodName
        self.directory.mkdir(parents=True)

    def shell(self, script, functions, command, name, prelude=""):
        directory = self.directory / name
        directory.mkdir()
        source = "set -euo pipefail\n" + "\n".join(shell_function(script, f) for f in functions)
        source += f"\nROOT_DIR={shlex.quote(str(ROOT))}\nTMP_DIR={shlex.quote(str(directory))}\n"
        source += '''
OUT_JSON="$TMP_DIR/samples.jsonl"
LOG_DIR="$TMP_DIR"
STATE_DIR="$TMP_DIR"
SAMPLE_ATTEMPTS=1 MIN_VALID_SAMPLES=1 MAX_READ_ERROR_RATE_PPM=1000
THREADS=2 CONCURRENCY=64 CLIENT_THREADS=2 SERVER_WORKERS=4 DURATION_SECONDS=10
MAX_CONCURRENT_STREAMS=100 MULTIPLEX_CONCURRENCY=1 MULTIPLEX_CLIENT_THREADS=1
CALIBRATION_BYTES=16 CALIBRATION_MIN_DURATION_MS=2000 TARGET_DURATION_SECONDS=10
PROFILE_QPXD_SECONDS=0 PROFILE_SECONDS=0 PROFILE_PROXY="" TLS_HOST=localhost
WRK_TIMEOUT=30s BENCH_FILTER="" LAST_TIMED_PROXY="" HOST_HEADER=bench.local
WARMUP_COOLDOWN_SECONDS=0 REPEATED_PROXY_SETTLE_SECONDS=0
body_profile() { echo short; }
proxy_selected() { return 0; }
sleep() { :; }
process_tree_cpu_ms() {
  local n=0
  [ ! -f "$TMP_DIR/cpu" ] || n="$(cat "$TMP_DIR/cpu")"
  n=$((n + 100)); echo "$n" >"$TMP_DIR/cpu"; echo "$n"
}
process_tree_status_kb() { echo 100; }
process_tree_fd_count() { echo 10; }
process_tree_scheduler_run_delay_ns() { echo 0; }
process_tree_io_counter() { echo 0; }
monitor_process_tree_rss_peak() { echo "$3" >"$2"; }
monitor_process_tree_fd_peak() { echo "$3" >"$2"; }
peak_growth() { echo 0; }
expect_status_ok() { return 0; }
safe_probe_status() { echo 200; }
compact_feature_rich_access_log() { :; }
settle_feature_rich_log_compaction() { :; }
drain_feature_rich_access_log() { :; }
dump_benchmark_logs() { :; }
'''
        source += prelude + "\n" + command + "\n"
        (directory / "fixture.sh").write_text(source)
        process = subprocess.run(["bash", str(directory / "fixture.sh")], capture_output=True, text=True)
        (directory / "command.log").write_text(process.stdout + process.stderr)
        return process, directory

    def h2_sample(self, proxy, name, malformed=None, clean=False):
        requests, success, errors = (3615, 3615 if clean else 3614, 0 if clean else 1)
        sample = (f"finished in 10s, 361.50 req/s\n"
                  f"requests: {requests} total, {requests} started, {requests} done, {success} succeeded, 0 failed, {errors} errored, 0 timeout\n"
                  f"status codes: {success} 2xx, 0 3xx, 0 4xx, 0 5xx\n"
                  "time for request: 1ms 3ms 2ms\n")
        if malformed == "timing":
            sample = sample.replace("time for request:", "missing:")
        sample_path = self.directory / (name + ".h2load")
        sample_path.write_text(sample)
        latency_path = self.directory / (name + ".tsv")
        latency_path.write_text("0\t200\t2000\n" * success + ("0\t0\t3000\n" if errors else ""))
        if malformed == "latency":
            latency_path.write_text("not-a-latency-row\n")
        prelude = f'''
h2load() {{
  local arg measured=""
  for arg in "$@"; do
    case "$arg" in --log-file=*) measured="${{arg#--log-file=}}" ;; esac
  done
  if [ -n "$measured" ]; then
    cp {shlex.quote(str(latency_path))} "$measured"
    cat {shlex.quote(str(sample_path))}
  else
    printf 'finished in 2s, 2 req/s\nrequests: 4 total, 4 started, 4 done, 4 succeeded, 0 failed, 0 errored, 0 timeout\n'
  fi
}}
'''
        return self.shell("perf-audit-http2-compare.sh", ("parse_h2load", "parse_h2load_calibration", "run_one"),
                          f"run_one {proxy} 1234 99999 99998 4", name, prelude)[0]

    def test_h2_reference_invalid_is_retryable_but_qpx_and_malformed_are_errors(self):
        for proxy in ("nginx", "direct-backend", "qpxd"):
            with self.subTest(proxy=proxy):
                process = self.h2_sample(proxy, proxy)
                self.assertEqual(process.returncode, 1 if proxy == "qpxd" else 75, process.stderr)
        for malformed in ("latency", "timing"):
            process = self.h2_sample("nginx", malformed, malformed=malformed)
            self.assertEqual(process.returncode, 1, process.stderr)
        process = self.h2_sample("nginx", "clean", clean=True)
        self.assertEqual(process.returncode, 0, process.stderr)

    def proxy_sample(self, proxy, name, read_errors=18, changes=None, cache_header="", cache_result=""):
        metrics = dict(qpx_complete_requests=9302, qpx_summary_requests=9302, qpx_non_2xx_responses=0,
                       qpx_bad_length_responses=0, qpx_first_bad_length_status=None,
                       qpx_first_bad_length_bytes=None, qpx_cache_result_errors=0, qpx_requests_per_sec=930.2,
                       qpx_transfer_kbytes_per_sec=100, qpx_latency_p50_ms=1, qpx_latency_p90_ms=1,
                       qpx_latency_p95_ms=1, qpx_latency_p99_ms=1, qpx_latency_p999_ms=1)
        metrics.update(changes or {})
        sample_path = self.directory / (name + ".wrk")
        sample_path.write_text(f"Latency 1.00ms 1ms 1ms\nSocket errors: connect 0, read {read_errors}, write 0, timeout 0\n"
                               + "".join(f"{key} {value}\n" for key, value in metrics.items() if value is not None))
        prelude = f"wrk() {{ cat {shlex.quote(str(sample_path))}; }}\nexpect_cache_hit() {{ :; }}\n"
        return self.shell("perf-audit-proxy-compare.sh", ("extract_metric", "read_error_rate_allowed", "json_number_or_null", "run_one"),
                          f"run_one proxy_cache_miss_http1 {proxy} 1234 reverse /bench-4 bench.local 4 99999 {shlex.quote(cache_header)} {shlex.quote(cache_result)}",
                          name, prelude)

    def test_proxy_reference_read_overrun_is_retryable_not_qpx_or_wrong_response(self):
        for proxy in ("apache", "nginx", "qpxd", "qpxd-cache"):
            process, _ = self.proxy_sample(proxy, proxy)
            self.assertEqual(process.returncode, 1 if proxy.startswith("qpxd") else 75, process.stderr)
        for key, value in (("qpx_bad_length_responses", 1), ("qpx_cache_result_errors", 1), ("qpx_non_2xx_responses", 1),
                           ("qpx_complete_requests", 9301), ("qpx_requests_per_sec", "NaN"),
                           ("qpx_bad_length_responses", None), ("qpx_summary_requests", "bad")):
            name = f"{key}-{value}"
            process, _ = self.proxy_sample("apache", name, changes={key: value})
            self.assertEqual(process.returncode, 1, process.stderr)
        process, _ = self.proxy_sample(
            "apache", "bad-length-diagnostics", read_errors=0,
            changes={"qpx_bad_length_responses": 1, "qpx_first_bad_length_status": 200,
                     "qpx_first_bad_length_bytes": 0}
        )
        self.assertEqual(process.returncode, 1, process.stderr)
        self.assertIn("qpx_first_bad_length_status 200", process.stderr)
        self.assertIn("qpx_first_bad_length_bytes 0", process.stderr)
        # Keep the existing 1000ppm ceiling: 9/9302 allowed, 10/9302 invalid.
        for read_errors, expected in ((9, 0), (10, 75)):
            process, _ = self.proxy_sample("apache", str(read_errors), read_errors=read_errors)
            self.assertEqual(process.returncode, expected, process.stderr)

    def test_qpx_cache_hit_probe_accepts_both_header_generations(self):
        for index, (proxy, header, expected) in enumerate((
                ("qpxd-cache", "Cache-Status: qpx; hit; ttl=60", 0),
                ("qpxd-cache", "X-Qpx-Cache: HIT", 0),
                ("qpxd-feature-rich", "x-qpx-cache: hit", 0),
                ("qpxd-cache", "X-Qpx-Cache: MISS", 1),
                ("qpxd-cache", "Cache-Status: qpx; fwd=uri-miss", 1),
                ("qpxd-cache", "X-Qpx-Cache: HITISH", 1),
                ("nginx-cache", "X-Qpx-Cache: HIT", 1),
                ("nginx-cache", "X-Cache-Status: HIT", 0))):
            prelude = f'''
curl() {{
  while [ "$1" != -D ]; do shift; done
  printf '%s\\r\\n' {shlex.quote(header)} >"$2"
}}
'''
            process, _ = self.shell("perf-audit-proxy-compare.sh", ("expect_cache_hit",),
                                    f"expect_cache_hit {proxy} 1234 '^x-cache-status:.*hit' /bench-4", str(index), prelude)
            self.assertEqual(process.returncode, expected, process.stderr)

    def test_cache_miss_lua_validates_both_headers_and_body(self):
        # wrk embeds LuaJIT. Exercise the actual generated Lua, not a Python
        # imitation; loading its library avoids starting a load generator.
        library = ctypes.util.find_library("luajit-5.1")
        if not library:
            self.skipTest("LuaJIT library (provided by wrk) is not installed")
        lua = ctypes.CDLL(library)
        lua.luaL_newstate.restype = ctypes.c_void_p
        lua.luaL_openlibs.argtypes = [ctypes.c_void_p]
        lua.luaL_loadstring.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lua.lua_pcall.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int]
        lua.lua_tolstring.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
        lua.lua_tolstring.restype = ctypes.c_char_p
        lua.lua_close.argtypes = [ctypes.c_void_p]
        process, directory = self.proxy_sample("qpxd-cache", "lua", read_errors=0, cache_header="cache-status", cache_result="miss")
        self.assertEqual(process.returncode, 0, process.stderr)
        generated = next(directory.glob("*.lua")).read_text()
        tests = '''
local function check(headers, body, status, errors, lengths, non200)
  init({})
  response(status, headers, body)
  assert(cache_result_errors == errors, "cache result")
  assert(bad_length == lengths, "body length")
  assert(non_200 == non200, "HTTP status")
end
check({["Cache-Status"]="qpx; fwd=uri-miss"}, "abcd", 200, 0, 0, 0)
check({["X-Qpx-Cache"]="MISS"}, "abcd", 200, 0, 0, 0)
check({["x-qpx-cache"]=" miss "}, "abcd", 200, 0, 0, 0)
check({["X-Qpx-Cache"]="HIT"}, "abcd", 200, 1, 0, 0)
check({["X-Qpx-Cache"]="MISSISH"}, "abcd", 200, 1, 0, 0)
check({}, "abcd", 200, 1, 0, 0)
check({["X-Qpx-Cache"]="MISS"}, "bad-body", 200, 0, 1, 0)
assert(first_bad_length_status == 200, "first bad status")
assert(first_bad_length_bytes == 8, "first bad body bytes")
check({["X-Qpx-Cache"]="MISS"}, "abcd", 500, 0, 0, 1)
'''
        state = lua.luaL_newstate()
        try:
            lua.luaL_openlibs(state)
            code = (generated + tests).encode()
            status = lua.luaL_loadstring(state, code) or lua.lua_pcall(state, 0, 0, 0)
            message = lua.lua_tolstring(state, -1, None) if status else b""
            self.assertEqual(status, 0, message)
        finally:
            lua.lua_close(state)

    def test_h2_shared_config_omits_unexpressible_runtime_key(self):
        prelude = '''
QPXD_TLS_FORMAT=pem QPX_PORT=1234 BACKEND_PORT=1235
QPXD_BIN=true
register_pid() { :; }
wait_https() { wait "$3"; }
'''
        process, directory = self.shell("perf-audit-http2-compare.sh", ("start_qpxd_h2",),
                                        "start_qpxd_h2", "config", prelude)
        self.assertEqual(process.returncode, 0, process.stderr)
        config = (directory / "qpxd-h2.yaml").read_text()
        self.assertNotIn("upstream_max_idle_connections_per_origin", config)
        self.assertIn("upstream_proxy_max_concurrent_per_endpoint: 2048", config)


if __name__ == "__main__":
    if ARTIFACTS.exists():
        shutil.rmtree(ARTIFACTS)
    ARTIFACTS.mkdir(parents=True)
    print(f"Fixture artifacts: {ARTIFACTS.relative_to(ROOT)}", flush=True)
    unittest.main(verbosity=2)
