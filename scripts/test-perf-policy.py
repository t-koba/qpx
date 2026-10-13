#!/usr/bin/env python3
"""Small JSONL fixture demo; no benchmarks or network. Artifacts are retained."""
import copy
import importlib.util
import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))
from perf_policy import (bounded_measure, evaluate, exit_code, load_jsonl,
                         objectives, summary, write_json, write_jsonl)

ARTIFACTS = ROOT / "target/perf/policy-fixtures"
ORDER = [["current", "previous"], ["previous", "current"], ["current", "previous"]]


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
        self.assertEqual(len(calls), result["attempt"])
        for directory in calls:
            self.assertTrue((directory / "result.json").is_file())
            self.assertTrue((directory / "fixture.jsonl").is_file())
        return result, len(calls)

    def test_equal_pairs_and_competitive_misses_are_reports(self):
        for index, lane in enumerate(self.lanes):
            with self.subTest(lane=lane["name"]):
                equal, count = self.measure(lane, [pair(lane)], str(index))
                self.assertEqual((equal["status"], count), ("PASSED", 1))
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
        for index, lane in enumerate(self.lanes):
            for metric, value in (("throughput", .94), ("cpu", .94), ("p99", 1.11)):
                with self.subTest(lane=lane["name"], metric=metric):
                    # A tempting second equal attempt must never be reached.
                    bad = pair(lane, **{metric: value})
                    result, count = self.measure(lane, [bad, pair(lane)], f"{index}-{metric}")
                    self.assertEqual((result["status"], count, exit_code([result])), ("REGRESSED", 1, 1))

    def test_invalid_then_first_valid_and_exhaustion(self):
        for index, lane in enumerate(self.lanes):
            for role in ("current", "previous"):
                invalid = pair(lane, throughput=.5, spread=2000, invalid_role=role)
                # Invalid measurement must not even evaluate the bad performance.
                result = evaluate(invalid, lane, True)
                self.assertEqual(result["status"], "RETRYABLE_INVALID")
                self.assertNotIn("ratios", result)
                valid, count = self.measure(lane, [invalid, pair(lane)], f"{index}-{role}-equal")
                self.assertEqual((valid["status"], count), ("PASSED", 2))
                bad, count = self.measure(lane, [invalid, pair(lane, p99=1.2), pair(lane)], f"{index}-{role}-bad")
                self.assertEqual((bad["status"], count), ("REGRESSED", 2))
                exhausted, count = self.measure(lane, [invalid] * 3, f"{index}-{role}-exhausted")
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

    def test_competitive_reference_spread_is_retryable_not_passed(self):
        for index, lane in enumerate(self.lanes):
            valid = [record(lane, p) for p in [lane["qpx"], *lane["references"]]]
            invalid = copy.deepcopy(valid)
            invalid[-1]["sample_spread"]["requests_per_sec_ratio"] = 2000
            result, count = self.measure(lane, [invalid, valid], str(index), paired=False)
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
        # Exercise the real pair orchestrator with a synthetic singleton sampler.
        spec = importlib.util.spec_from_file_location("driver", ROOT / "scripts/perf-audit-policy.py")
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        lane = self.lanes[0]
        sampler = object.__new__(driver.Sampler)
        sampler.binaries = {"current": None, "previous": None}
        sampler.identities = {r: {"source_sha": "a" * 40 if r == "current" else lane["policy"]["previous_release"]["sha"],
                                   "binary_sha256": str(i + 1) * 64, "toolchain": "fixture", "runner": "fixture"} for i, r in enumerate(sampler.binaries)}
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
        records[0]["latency_p99_ms"] = 1.2
        # The real sampler's per-round deltas, rather than cross-round best-of.
        self.assertEqual(len(records[0]["paired_metric_ratios"]), 3)


if __name__ == "__main__":
    if ARTIFACTS.exists():
        shutil.rmtree(ARTIFACTS)
    ARTIFACTS.mkdir(parents=True)
    print(f"Fixture artifacts: {ARTIFACTS.relative_to(ROOT)}", flush=True)
    unittest.main(verbosity=2)
