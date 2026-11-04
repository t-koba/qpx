#!/usr/bin/env python3
"""Streaming gate fixture demo; no benchmarks, servers, or network."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts/check-streaming-performance.sh"
OBJECTIVES = ROOT / "perf/streaming-performance-objectives.json"
BENCH = "proxy_compare_http1_streaming_reverse"
STREAM_BYTES = 262144
CHUNK_BYTES = 65536
FAST_TRANSFERS = 8
SLOW_TRANSFERS = 1


def with_extremes(record):
    """The observed range of the metrics the checker judges by range.

    The range is derived from the record's own value and the published
    spread, so a synthetic record carries a range that agrees with the
    spread the checker reads beside it.
    """
    extremes = {}
    for field in (
        "p99_chunk_gap_ms",
        "requests_per_total_cpu_second",
        "scheduler_queue_delay_us_per_transfer",
    ):
        value = float(record[field])
        root = float(record["sample_spread"][f"{field}_ratio"]) ** 0.5
        extremes[field] = {"min": value / root, "max": value * root}
    record["sample_extremes"] = extremes
    return record


def build(proxy, mode, **overrides):
    """One aggregate streaming record that satisfies the gate's own invariants."""
    transfers = FAST_TRANSFERS if mode == "fast" else SLOW_TRANSFERS
    record = {
        "bench": BENCH,
        "commit": "a" * 40,
        "proxy": proxy,
        "read_mode": mode,
        "valid": True,
        "sample_attempts": 3,
        "valid_samples": 3,
        "aggregation": "conservative_median_per_metric",
        "sampling_order": "round_robin_interleaved",
        "benchmark_schema_version": 8,
        "resource_measurement": "sampled_workload_peak_v1",
        "kernel_resource_metrics": True,
        "stream_bytes": STREAM_BYTES,
        "chunk_bytes": CHUNK_BYTES,
        "gap_observation_bytes": CHUNK_BYTES,
        "transfers": transfers,
        "bytes": STREAM_BYTES * transfers,
        "chunk_observations": (STREAM_BYTES // CHUNK_BYTES - 1) * transfers,
        "total_ms": 100.0,
        "first_byte_ms": 1.0,
        "p50_chunk_gap_ms": 0.02,
        "p95_chunk_gap_ms": 0.05,
        "p99_chunk_gap_ms": 0.1,
        "max_chunk_gap_ms": 1.0,
        "requests_per_cpu_second": 10.0,
        "requests_per_total_cpu_second": 5.0,
        "cpu_ms": 100,
        "backend_cpu_ms": 100,
        "total_cpu_ms": 200,
        "rss_kb": 1000,
        "rss_baseline_kb": 1000,
        "rss_peak_kb": 1000,
        "rss_growth_kb": 0,
        "backend_rss_baseline_kb": 1000,
        "backend_rss_peak_kb": 1000,
        "backend_rss_growth_kb": 0,
        "fd_baseline": 10,
        "fd_peak": 10,
        "fd_growth": 0,
        "backend_fd_baseline": 10,
        "backend_fd_peak": 10,
        "backend_fd_growth": 0,
        "total_scheduler_run_delay_ns": 1000000,
        "scheduler_queue_delay_us_per_transfer": 100.0,
        "sample_spread": {
            "total_ms_ratio": 1.0,
            "requests_per_cpu_second_ratio": 1.0,
            "requests_per_total_cpu_second_ratio": 1.0,
            "p99_chunk_gap_ms_ratio": 1.0,
            "scheduler_queue_delay_us_per_transfer_ratio": 1.0,
        },
    }
    spread = overrides.pop("sample_spread", None)
    record.update(overrides)
    if spread is not None:
        record["sample_spread"].update(spread)
    with_extremes(record)
    if proxy == "direct-backend":
        record["total_rss_peak_kb"] = record["rss_peak_kb"]
        record["total_rss_growth_kb"] = record["rss_growth_kb"]
        record["total_fd_peak"] = record["fd_peak"]
        record["total_fd_growth"] = record["fd_growth"]
    else:
        record["total_rss_peak_kb"] = record["rss_peak_kb"] + record["backend_rss_peak_kb"]
        record["total_rss_growth_kb"] = (
            record["rss_growth_kb"] + record["backend_rss_growth_kb"]
        )
        record["total_fd_peak"] = record["fd_peak"] + record["backend_fd_peak"]
        record["total_fd_growth"] = record["fd_growth"] + record["backend_fd_growth"]
    return record


FAST_LANE = {
    "direct-backend": build(
        "direct-backend",
        "fast",
        total_ms=230.0,
        first_byte_ms=0.52,
        p99_chunk_gap_ms=0.05,
        max_chunk_gap_ms=0.96,
        requests_per_total_cpu_second=34.0,
        cpu_ms=230,
        backend_cpu_ms=230,
        total_cpu_ms=230,
        rss_baseline_kb=19556,
        rss_peak_kb=19556,
        backend_rss_baseline_kb=19556,
        backend_rss_peak_kb=19556,
        fd_baseline=12,
        fd_peak=12,
        scheduler_queue_delay_us_per_transfer=240.0,
    ),
    "qpxd": build(
        "qpxd",
        "fast",
        total_ms=320.0,
        first_byte_ms=0.64,
        p99_chunk_gap_ms=0.1,
        max_chunk_gap_ms=1.88,
        requests_per_total_cpu_second=20.0,
        cpu_ms=140,
        backend_cpu_ms=260,
        total_cpu_ms=400,
        rss_baseline_kb=12000,
        rss_peak_kb=12000,
        backend_rss_baseline_kb=19556,
        backend_rss_peak_kb=19556,
        fd_baseline=12,
        fd_peak=15,
        fd_growth=3,
        backend_fd_baseline=12,
        backend_fd_peak=12,
        scheduler_queue_delay_us_per_transfer=3000.0,
    ),
    "lighttpd": build(
        "lighttpd",
        "fast",
        total_ms=600.0,
        first_byte_ms=49.0,
        p99_chunk_gap_ms=0.045,
        max_chunk_gap_ms=2.27,
        requests_per_total_cpu_second=10.8,
        cpu_ms=520,
        backend_cpu_ms=220,
        total_cpu_ms=740,
        rss_baseline_kb=3052,
        rss_peak_kb=3052,
        backend_rss_baseline_kb=19556,
        backend_rss_peak_kb=19556,
        fd_baseline=11,
        fd_peak=15,
        fd_growth=4,
        backend_fd_baseline=12,
        backend_fd_peak=12,
        scheduler_queue_delay_us_per_transfer=3943.0,
    ),
    "apache": build(
        "apache",
        "fast",
        total_ms=1100.0,
        first_byte_ms=49.0,
        p99_chunk_gap_ms=0.787,
        max_chunk_gap_ms=3.65,
        requests_per_total_cpu_second=7.08,
        cpu_ms=950,
        backend_cpu_ms=220,
        total_cpu_ms=1130,
        rss_baseline_kb=25512,
        rss_peak_kb=26036,
        rss_growth_kb=524,
        backend_rss_baseline_kb=19488,
        backend_rss_peak_kb=19504,
        backend_rss_growth_kb=16,
        fd_baseline=61,
        fd_peak=65,
        fd_growth=4,
        backend_fd_baseline=11,
        backend_fd_peak=11,
        scheduler_queue_delay_us_per_transfer=38311.0,
    ),
    "nginx": build(
        "nginx",
        "fast",
        total_ms=1400.0,
        first_byte_ms=1.29,
        p99_chunk_gap_ms=0.68,
        max_chunk_gap_ms=3.57,
        requests_per_total_cpu_second=4.88,
        cpu_ms=1440,
        backend_cpu_ms=200,
        total_cpu_ms=1640,
        rss_baseline_kb=11236,
        rss_peak_kb=11236,
        backend_rss_baseline_kb=19556,
        backend_rss_peak_kb=19556,
        fd_baseline=20,
        fd_peak=21,
        fd_growth=1,
        backend_fd_baseline=12,
        backend_fd_peak=12,
        scheduler_queue_delay_us_per_transfer=18328.0,
    ),
}

SLOW_LANE = {
    "direct-backend": build(
        "direct-backend",
        "slow",
        total_ms=1751.0,
        first_byte_ms=1.234,
        p99_chunk_gap_ms=1.16,
        max_chunk_gap_ms=1.36,
        requests_per_total_cpu_second=50.0,
        cpu_ms=20,
        backend_cpu_ms=20,
        total_cpu_ms=20,
        rss_baseline_kb=19472,
        rss_peak_kb=19480,
        rss_growth_kb=8,
        backend_rss_baseline_kb=19472,
        backend_rss_peak_kb=19472,
        fd_baseline=12,
        fd_peak=13,
        fd_growth=1,
        backend_fd_baseline=12,
        backend_fd_peak=12,
        scheduler_queue_delay_us_per_transfer=57.0,
    ),
    "qpxd": build(
        "qpxd",
        "slow",
        total_ms=1785.0,
        first_byte_ms=1.77,
        p99_chunk_gap_ms=1.343,
        max_chunk_gap_ms=1.61,
        requests_per_total_cpu_second=16.667,
        cpu_ms=20,
        backend_cpu_ms=30,
        total_cpu_ms=60,
        rss_baseline_kb=18228,
        rss_peak_kb=18228,
        backend_rss_baseline_kb=19472,
        backend_rss_peak_kb=19472,
        fd_baseline=17,
        fd_peak=20,
        fd_growth=3,
        backend_fd_baseline=12,
        backend_fd_peak=12,
        scheduler_queue_delay_us_per_transfer=2673.0,
    ),
    "lighttpd": build(
        "lighttpd",
        "slow",
        total_ms=1900.0,
        first_byte_ms=54.9,
        p99_chunk_gap_ms=1.326,
        max_chunk_gap_ms=1.70,
        requests_per_total_cpu_second=9.09,
        cpu_ms=70,
        backend_cpu_ms=30,
        total_cpu_ms=100,
        rss_baseline_kb=3120,
        rss_peak_kb=3120,
        backend_rss_baseline_kb=19476,
        backend_rss_peak_kb=19476,
        fd_baseline=11,
        fd_peak=15,
        fd_growth=4,
        backend_fd_baseline=12,
        backend_fd_peak=12,
        scheduler_queue_delay_us_per_transfer=12560.0,
    ),
    "apache": build(
        "apache",
        "slow",
        total_ms=1800.0,
        first_byte_ms=3.66,
        p99_chunk_gap_ms=2.015,
        max_chunk_gap_ms=3.76,
        requests_per_total_cpu_second=9.09,
        cpu_ms=80,
        backend_cpu_ms=30,
        total_cpu_ms=100,
        rss_baseline_kb=26160,
        rss_peak_kb=26236,
        rss_growth_kb=76,
        backend_rss_baseline_kb=19476,
        backend_rss_peak_kb=19480,
        backend_rss_growth_kb=4,
        fd_baseline=61,
        fd_peak=62,
        fd_growth=1,
        backend_fd_baseline=12,
        backend_fd_peak=12,
        scheduler_queue_delay_us_per_transfer=21135.0,
    ),
    "nginx": build(
        "nginx",
        "slow",
        total_ms=1850.0,
        first_byte_ms=2.12,
        p99_chunk_gap_ms=1.285,
        max_chunk_gap_ms=3.55,
        requests_per_total_cpu_second=9.09,
        cpu_ms=80,
        backend_cpu_ms=20,
        total_cpu_ms=100,
        rss_baseline_kb=11236,
        rss_peak_kb=11236,
        backend_rss_baseline_kb=19476,
        backend_rss_peak_kb=19476,
        fd_baseline=20,
        fd_peak=21,
        fd_growth=1,
        backend_fd_baseline=12,
        backend_fd_peak=12,
        scheduler_queue_delay_us_per_transfer=15791.0,
    ),
}


def lane(base, **overrides):
    """A copy of a healthy lane with one record replaced."""
    updated = copy.deepcopy(base)
    for proxy, values in overrides.items():
        record = copy.deepcopy(updated[proxy])
        spread = values.pop("sample_spread", None)
        record.update(values)
        if spread is not None:
            record["sample_spread"].update(spread)
        with_extremes(record)
        if record["proxy"] == "direct-backend":
            record["total_rss_peak_kb"] = record["rss_peak_kb"]
            record["total_rss_growth_kb"] = record["rss_growth_kb"]
            record["total_fd_peak"] = record["fd_peak"]
            record["total_fd_growth"] = record["fd_growth"]
        else:
            record["total_rss_peak_kb"] = record["rss_peak_kb"] + record["backend_rss_peak_kb"]
            record["total_rss_growth_kb"] = (
                record["rss_growth_kb"] + record["backend_rss_growth_kb"]
            )
            record["total_fd_peak"] = record["fd_peak"] + record["backend_fd_peak"]
            record["total_fd_growth"] = record["fd_growth"] + record["backend_fd_growth"]
        updated[proxy] = record
    return updated


def reference_report(fast_median=1.0, slow_median=1.0, fast_rounds=3, slow_rounds=3):
    """A sibling streaming-compare-reference.json with a paired queue median."""

    def mode(median, rounds):
        return {
            "paired_rounds": rounds,
            "metrics": {
                "scheduler_queue_delay_us_per_transfer": {
                    "paired_rounds": rounds,
                    "median_current_over_reference": median,
                    "min_current_over_reference": median,
                    "max_current_over_reference": median,
                    "median_difference": 0.0,
                },
            },
        }

    return {
        "comparison": "current_build_versus_pinned_previous_release",
        "source_sha": "a" * 40,
        "reference_source_sha": "b" * 40,
        "sample_attempts": 3,
        "workload": {"stream_bytes": STREAM_BYTES, "chunk_bytes": CHUNK_BYTES,
                     "fast_transfers": FAST_TRANSFERS, "slow_read_delay_ms": "1"},
        "complete_modes": {"fast": True, "slow": True},
        "current_proxy": "qpxd",
        "reference_proxy": "qpxd-previous",
        "read_modes": {
            "fast": mode(fast_median, fast_rounds),
            "slow": mode(slow_median, slow_rounds),
        },
    }


class StreamingGateTest(unittest.TestCase):
    def run_gate(self, fast=None, slow=None, objectives=None, reference="default", confirmations=None):
        fast = FAST_LANE if fast is None else fast
        slow = SLOW_LANE if slow is None else slow
        if reference == "default":
            reference = reference_report()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "streaming.jsonl"
            records = list(fast.values()) + list(slow.values())
            with path.open("w", encoding="utf-8") as handle:
                for record in records:
                    handle.write(json.dumps(record, sort_keys=True) + "\n")
            if reference is not None:
                with (Path(directory) / "streaming-compare-reference.json").open(
                    "w", encoding="utf-8"
                ) as handle:
                    json.dump(reference, handle, sort_keys=True)
                    handle.write("\n")
            for mode, confirmation in (confirmations or {}).items():
                conf_dir = Path(directory) / "paired-confirmation" / mode
                conf_dir.mkdir(parents=True)
                (conf_dir / "streaming-compare-reference.json").write_text(
                    json.dumps(confirmation) if confirmation != "invalid" else "{"
                )
            result = subprocess.run(
                [str(CHECKER), str(path), str(objectives or OBJECTIVES)],
                capture_output=True,
                text=True,
                check=False,
                env={**{k: v for k, v in os.environ.items()
                        if k not in ("GITHUB_SHA", "QPX_PREVIOUS_SOURCE_SHA")},
                     "GITHUB_SHA": "a" * 40,
                     "QPX_PREVIOUS_SOURCE_SHA": "b" * 40},
            )

            evidence = Path(directory) / "streaming-compare-confirmation.json"
            result.confirmation = json.loads(evidence.read_text()) if evidence.exists() else None
            return result

    def test_confirmation_clear_retains_first_miss(self):
        result = self.run_gate(reference=reference_report(fast_median=2.082473),
                               confirmations={"fast": reference_report()})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("unconfirmed_misses", result.stdout)
        self.assertEqual(result.confirmation["fast"]["unconfirmed_misses"][0]
                         ["median_current_over_reference"], 2.082473)

    def test_confirmation_repeated_same_mode_miss_fails(self):
        result = self.run_gate(reference=reference_report(slow_median=2),
                               confirmations={"slow": reference_report(slow_median=1.5)})
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.confirmation["slow"]["status"], "REGRESSED")

    def test_confirmation_clear_cannot_clear_the_other_mode(self):
        result = self.run_gate(reference=reference_report(fast_median=2, slow_median=2),
                               confirmations={"fast": reference_report()})
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.confirmation["fast"]["status"], "PASSED")
        self.assertEqual(result.confirmation["slow"]["status"], "REGRESSED")

    def test_unusable_confirmations_never_clear_a_miss(self):
        invalids = [None, "invalid", [], reference_report(fast_rounds=0),
                    reference_report(fast_median=float("nan")),
                    reference_report(fast_rounds=2)]
        for field, value in (("source_sha", "c" * 40),
                             ("reference_source_sha", "c" * 40),
                             ("reference_source_sha", "unknown"),
                             ("complete_modes", {"fast": False}),
                             ("current_proxy", "nginx"),
                             ("workload", {}), ("sample_attempts", 1)):
            report = reference_report()
            report[field] = value
            invalids.append(report)
        for invalid in invalids:
            with self.subTest(confirmation=invalid):
                result = self.run_gate(reference=reference_report(fast_median=2),
                                       confirmations={"fast": invalid})
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertNotIn("unconfirmed_misses", result.stdout)

    def test_confirmation_cannot_rescue_an_inconclusive_first_pass(self):
        for first in (None, reference_report(fast_rounds=0),
                      reference_report(fast_median=2, fast_rounds=2)):
            result = self.run_gate(reference=first, confirmations={"fast": reference_report()})
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_incomplete_first_pair_fails_even_when_its_median_is_below_objective(self):
        incomplete = [
            reference_report(fast_median=1.0, fast_rounds=2),
            reference_report(slow_median=1.0, slow_rounds=2),
        ]
        incomplete[1]["complete_modes"]["slow"] = False
        for report in incomplete:
            with self.subTest(report=report):
                result = self.run_gate(reference=report)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("incomplete", result.stderr)

    def test_first_report_must_match_the_current_and_pinned_sources(self):
        report = reference_report()
        report["source_sha"] = "c" * 40
        result = self.run_gate(reference=report)
        self.assertEqual(result.returncode, 1)
        self.assertIn("source_sha identity mismatch", result.stderr)

    def test_confirmation_cannot_clear_a_mixed_source_aggregate(self):
        result = self.run_gate(lane(FAST_LANE, qpxd={"commit": "c" * 40}),
                               reference=reference_report(fast_median=2),
                               confirmations={"fast": reference_report()})
        self.assertEqual(result.returncode, 1)
        self.assertIn("source_sha identity mismatch", result.stderr)

    def test_confirmation_does_not_clear_other_metric_failures(self):
        result = self.run_gate(lane(FAST_LANE, qpxd={"total_ms": 10000}),
                               reference=reference_report(fast_median=2),
                               confirmations={"fast": reference_report()})
        self.assertEqual(result.returncode, 1)
        self.assertIn("unconfirmed_misses", result.stdout)
        self.assertIn("fast streaming throughput ratio", result.stderr)

    def run_gate_with_policy(self, stability, fast=None, slow=None, reference="default"):
        """Runs the gate against a copy of the policy with `stability` replaced."""
        if reference == "default":
            reference = reference_report()
        with tempfile.TemporaryDirectory() as directory:
            policy = json.loads(OBJECTIVES.read_text(encoding="utf-8"))
            policy["stability"].update(stability)
            path = Path(directory) / "objectives.json"
            path.write_text(json.dumps(policy), encoding="utf-8")
            if reference is not None:
                ref_path = Path(directory) / "streaming-compare-reference.json"
            else:
                ref_path = None
            # The checker reads the reference next to the JSONL, so stage
            # both files in one directory instead of delegating to run_gate.
            jsonl_path = Path(directory) / "streaming.jsonl"
            records = list((FAST_LANE if fast is None else fast).values()) + list(
                (SLOW_LANE if slow is None else slow).values()
            )
            with jsonl_path.open("w", encoding="utf-8") as handle:
                for record in records:
                    handle.write(json.dumps(record, sort_keys=True) + "\n")
            if ref_path is not None:
                with ref_path.open("w", encoding="utf-8") as handle:
                    json.dump(reference, handle, sort_keys=True)
                    handle.write("\n")
            # Point the checker at a staging directory holding both files by
            # nesting the JSONL one level down would break the sibling lookup,
            # so both live directly in the temporary directory.
            return subprocess.run(
                [str(CHECKER), str(jsonl_path), str(path)],
                capture_output=True,
                text=True,
                check=False,
                env={**{k: v for k, v in os.environ.items()
                        if k not in ("GITHUB_SHA", "QPX_PREVIOUS_SOURCE_SHA")},
                     "GITHUB_SHA": "a" * 40,
                     "QPX_PREVIOUS_SOURCE_SHA": "b" * 40},
            )

    def run_gate_with_reference(self, reference):
        """Runs the gate against the healthy lanes plus one reference record."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "streaming.jsonl"
            records = list(FAST_LANE.values()) + list(SLOW_LANE.values()) + [reference]
            with path.open("w", encoding="utf-8") as handle:
                for record in records:
                    handle.write(json.dumps(record, sort_keys=True) + "\n")
            with (Path(directory) / "streaming-compare-reference.json").open(
                "w", encoding="utf-8"
            ) as handle:
                json.dump(reference_report(), handle, sort_keys=True)
                handle.write("\n")
            return subprocess.run(
                [str(CHECKER), str(path), str(OBJECTIVES)],
                capture_output=True,
                text=True,
                check=False,
                env={**{k: v for k, v in os.environ.items()
                        if k not in ("GITHUB_SHA", "QPX_PREVIOUS_SOURCE_SHA")},
                     "GITHUB_SHA": "a" * 40,
                     "QPX_PREVIOUS_SOURCE_SHA": "b" * 40},
            )

    def test_the_reference_build_record_is_not_a_gate_input(self):
        """A JSONL reference-build record is not a gate input; the sibling report is."""
        reference = build("qpxd-previous", "fast", total_ms=400.0)
        result = self.run_gate_with_reference(reference)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_an_unusable_reference_build_record_does_not_fail_the_gate(self):
        """A JSONL reference record no gate could judge is still not an input."""
        reference = build("qpxd-previous", "fast", total_ms=0.0, cpu_ms=0)
        result = self.run_gate_with_reference(reference)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_healthy_lane_passes_without_marginals(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("marginal", result.stdout)

    def test_external_queue_ratio_is_visible_while_the_paired_verdict_passes(self):
        """A 10x qpx-vs-external queue ratio passes while the paired median holds.

        The external ratio is the noise case: competitors move between runs,
        so it stays visible for trend review and never fails the gate. The
        enforced verdict is the paired current-vs-pinned median below.
        """
        result = self.run_gate(
            lane(
                FAST_LANE,
                qpxd={"scheduler_queue_delay_us_per_transfer": 38311.0},
            )
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("queue=", result.stdout)
        self.assertNotIn("paired scheduler queue-delay ratio", result.stderr)

    def test_slow_external_queue_ratio_is_visible_while_the_paired_verdict_passes(self):
        """The slow lane also reports its external queue ratio without gating."""
        result = self.run_gate(
            slow=lane(
                SLOW_LANE,
                qpxd={"scheduler_queue_delay_us_per_transfer": 100000.0},
            )
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("max_scheduler_queue_delay_ratio=", result.stdout)
        self.assertNotIn("paired scheduler queue-delay ratio", result.stderr)

    def test_paired_fast_queue_ratio_above_cap_fails(self):
        """A paired fast queue median of 1.5 exceeds the fixed 1.25 tolerance."""
        result = self.run_gate(reference=reference_report(fast_median=1.5))
        self.assertEqual(result.returncode, 1)
        self.assertIn("paired scheduler queue-delay ratio", result.stderr)
        self.assertIn("1.500000 > objective 1.250000", result.stderr)
        self.assertIn("paired current-vs-pinned median", result.stderr)

    def test_paired_slow_queue_ratio_above_cap_fails(self):
        """A paired slow queue median of 1.5 exceeds the fixed 1.25 tolerance."""
        result = self.run_gate(reference=reference_report(slow_median=1.5))
        self.assertEqual(result.returncode, 1)
        self.assertIn("paired scheduler queue-delay ratio", result.stderr)
        self.assertIn("1.500000 > objective 1.250000", result.stderr)

    def test_missing_reference_report_fails(self):
        """Without the reference report the paired verdict fails, never passes."""
        result = self.run_gate(reference=None)
        self.assertEqual(result.returncode, 1)
        self.assertIn("reference report is missing", result.stderr)
        self.assertIn("requires the reference report", result.stderr)

    def test_missing_paired_queue_metric_fails(self):
        """A reference without the queue metric fails instead of passing silently."""
        report = reference_report()
        del report["read_modes"]["fast"]["metrics"][
            "scheduler_queue_delay_us_per_transfer"
        ]
        result = self.run_gate(reference=report)
        self.assertEqual(result.returncode, 1)
        self.assertIn("is missing fast scheduler_queue_delay_us_per_transfer", result.stderr)

    def test_paired_queue_without_rounds_fails(self):
        """paired_rounds == 0 fails instead of passing with no evidence."""
        result = self.run_gate(reference=reference_report(fast_rounds=0))
        self.assertEqual(result.returncode, 1)
        self.assertIn("no paired rounds", result.stderr)

    def test_paired_queue_rounds_must_be_an_integer(self):
        """A JSON bool is not a round count, even though True == 1."""
        result = self.run_gate(reference=reference_report(fast_rounds=True))
        self.assertEqual(result.returncode, 1)
        self.assertIn("no paired rounds", result.stderr)

    def test_noisy_tail_measurement_is_reported_as_noise(self):
        """A tail miss inside its own measurement spread is not a regression."""
        result = self.run_gate(
            lane(
                FAST_LANE,
                qpxd={
                    "p99_chunk_gap_ms": 0.182083,
                    "scheduler_queue_delay_us_per_transfer": 29216.16,
                    "sample_spread": {
                        "p99_chunk_gap_ms_ratio": 1.797179,
                        "scheduler_queue_delay_us_per_transfer_ratio": 1.4576,
                        "total_ms_ratio": 1.163375,
                    },
                },
            )
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("fast streaming p99 gap ratio marginal", result.stdout)
        self.assertIn("queue=", result.stdout)
        self.assertNotIn("scheduler queue-delay ratio", result.stdout)

    def test_tail_noise_band_is_bounded_by_the_policy_multiplier(self):
        """A wide measured spread must not widen the band past the policy limit.

        The band comes from the subject's own measurement, so without a bound
        a subject whose regression also inflates its noise could excuse the
        miss it caused. The policy multiplier is that bound.
        """
        result = self.run_gate(
            lane(
                FAST_LANE,
                qpxd={
                    # Twice the leader's gap and twice its cap.
                    "p99_chunk_gap_ms": 0.045 * 2.0 * 3.2,
                    "sample_spread": {"p99_chunk_gap_ms_ratio": 2.0},
                },
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("fast streaming p99 gap ratio", result.stderr)
        self.assertIn("decisive", result.stderr)
        # The band is the policy multiplier, not the measured spread.
        self.assertNotIn("within measurement noise", result.stdout)

    def test_time_objective_band_is_bounded_by_the_policy_multiplier(self):
        """A wide lane spread must not widen the time band past the policy limit.

        The band comes from the subject's own measurement, so without a bound
        a subject whose regression also inflates its measurement noise would
        excuse the miss it caused.
        """
        result = self.run_gate(
            lane(
                FAST_LANE,
                qpxd={
                    # Slower than the leader, and slower than the direct backend.
                    "total_ms": 700.0,
                    "sample_spread": {"total_ms_ratio": 2.4},
                },
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("fast streaming throughput ratio", result.stderr)
        self.assertIn("decisive", result.stderr)
        # The throughput miss is no longer excused by the subject's own noise.
        self.assertNotIn("fast streaming throughput ratio marginal", result.stdout)

    def test_cpu_rate_spread_cannot_widen_the_lane_band_past_the_policy_limit(self):
        """A wide CPU-rate spread must not widen the band of a lane objective.

        The lane band takes the wider of the total-time and CPU-rate spreads,
        so the CPU-rate input can widen it just as the total-time input can.
        The bound has to hold for both, otherwise a subject whose regression
        inflates its CPU-rate measurement excuses the miss it caused.
        """
        result = self.run_gate(
            lane(
                FAST_LANE,
                qpxd={
                    # Slower than the leader and than the direct backend, so
                    # the throughput and CPU-efficiency objectives both miss.
                    "total_ms": 700.0,
                    "requests_per_total_cpu_second": 5.0,
                    "sample_spread": {
                        # Only the CPU-rate spread is wide; the total-time
                        # spread stays stable, so the CPU-rate input is the
                        # only thing that could widen the band.
                        "requests_per_total_cpu_second_ratio": 2.4,
                    },
                },
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("fast streaming throughput ratio", result.stderr)
        self.assertIn("decisive", result.stderr)
        # The CPU-rate miss is no longer excused by the subject's own noise.
        self.assertNotIn(
            "fast streaming total CPU efficiency ratio marginal", result.stdout
        )
        self.assertIn(
            "fast streaming total CPU efficiency ratio", result.stderr
        )

    def test_a_stable_measurement_is_excused_only_within_the_noise_floor(self):
        """A stable measurement may exceed the cap by no more than the floor.

        A shared CI runner varies more between runs than one interleaved lane
        spread shows, so a perfectly stable measurement can still miss a cap
        by a few percent for no product reason. The floor is that allowance,
        and it is the only slack a stable measurement gets.
        """
        leader_p99 = FAST_LANE["lighttpd"]["p99_chunk_gap_ms"]
        cap = 3.2
        result = self.run_gate(
            lane(
                FAST_LANE,
                qpxd={"p99_chunk_gap_ms": leader_p99 * cap * 1.02},
            )
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("fast streaming p99 gap ratio marginal", result.stdout)

    def test_the_policy_multiplier_wins_over_the_noise_floor(self):
        """The multiplier is the band's upper bound, even above the floor.

        The floor is a lower bound on the band, so a policy whose floor
        exceeds the multiplier must not let the floor decide the verdict.
        """
        # The slow lane's qpxd total time is 1.4x the direct backend's, so
        # max_total_time_ratio is 1.400 against the objective 1.03.
        slow = lane(SLOW_LANE, qpxd={"total_ms": SLOW_LANE["direct-backend"]["total_ms"] * 1.4})
        result = self.run_gate_with_policy(
            {"min_measurement_noise_multiplier": 1.5},
            slow=slow,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("slow streaming max_total_time_ratio", result.stderr)
        self.assertIn("decisive", result.stderr)
        # The band that decided the verdict is the multiplier, so that is what
        # the message reports.
        self.assertIn("measurement noise 1.250000", result.stderr)

    def test_a_stable_measurement_beyond_the_noise_floor_fails(self):
        """Past the floor, a stable measurement's miss is decisive."""
        leader_p99 = FAST_LANE["lighttpd"]["p99_chunk_gap_ms"]
        cap = 3.2
        result = self.run_gate(
            lane(
                FAST_LANE,
                qpxd={"p99_chunk_gap_ms": leader_p99 * cap * 1.06},
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("fast streaming p99 gap ratio", result.stderr)
        self.assertIn("decisive", result.stderr)

    def test_tail_band_still_follows_a_measured_spread_below_the_policy_limit(self):
        """Below the policy bound, the measured spread still sets the band."""
        result = self.run_gate(
            lane(
                FAST_LANE,
                qpxd={
                    "p99_chunk_gap_ms": 0.045 * 3.2 * 1.15,
                    "sample_spread": {"p99_chunk_gap_ms_ratio": 1.2},
                },
            )
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("fast streaming p99 gap ratio marginal", result.stdout)

    def test_a_tail_miss_beyond_the_policy_multiplier_fails(self):
        """A miss past the policy band is decisive however noisy the spread is."""
        result = self.run_gate(
            lane(
                FAST_LANE,
                qpxd={
                    "p99_chunk_gap_ms": 0.045 * 3.2 * 1.6,
                    "sample_spread": {"p99_chunk_gap_ms_ratio": 2.5},
                },
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("fast streaming p99 gap ratio", result.stderr)
        self.assertIn("decisive", result.stderr)

    def test_stable_tail_measurement_still_fails(self):
        """The same miss on a stable measurement stays a decisive failure."""
        result = self.run_gate(
            lane(
                FAST_LANE,
                qpxd={"p99_chunk_gap_ms": 0.182083},
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("fast streaming p99 gap ratio", result.stderr)
        self.assertIn("decisive", result.stderr)

    def test_reference_spread_never_widens_the_band(self):
        result = self.run_gate(
            lane(
                FAST_LANE,
                qpxd={"p99_chunk_gap_ms": 0.182083},
                lighttpd={"sample_spread": {"p99_chunk_gap_ms_ratio": 2.4}},
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("fast streaming p99 gap ratio", result.stderr)
        self.assertIn("decisive", result.stderr)

    def test_time_objectives_keep_the_lane_band(self):
        """A noisy tail must not widen the band of the throughput objective."""
        result = self.run_gate(
            lane(
                FAST_LANE,
                qpxd={
                    "total_ms": 900.0,
                    "sample_spread": {"p99_chunk_gap_ms_ratio": 1.797179},
                },
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("fast streaming throughput ratio", result.stderr)
        self.assertIn("decisive", result.stderr)

    def test_unstable_tail_measurement_is_invalid(self):
        """A worst end that reaches the decisive bar makes the run invalid."""
        result = self.run_gate(
            lane(FAST_LANE, qpxd={"sample_spread": {"p99_chunk_gap_ms_ratio": 5.0}})
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("p99_chunk_gap_ms_ratio sample spread", result.stderr)

    def test_an_unstable_tail_measurement_that_only_reaches_a_marginal_stays_valid(self):
        """A worst end inside the decisive bar cannot turn the verdict into a
        failure, so the measurement stays judgeable.

        The slow p99 gap moves three-fold, so its worst end is 2.07 against an
        objective of 1.5, but the decisive bar of that objective is 2.25: no
        observed end of the metric could have produced a failure, so the run
        is not invalid.
        """
        result = self.run_gate(
            slow=lane(SLOW_LANE, qpxd={"sample_spread": {"p99_chunk_gap_ms_ratio": 3.2}})
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("unjudgeable", result.stderr)

    def test_an_unstable_tail_measurement_that_cannot_miss_stays_valid(self):
        """An unstable metric whose worst end still meets the objective is
        judgeable, so the movement does not fail the run.

        The measurement moved, but every sample it took met the objective:
        the movement cannot change the verdict, so the run is not invalid.
        This is the false red the streaming assessment produced on a shared
        runner, where a metric of a few milliseconds moved several-fold
        while the objective it judges was met with a wide margin.
        """
        result = self.run_gate(
            slow=lane(
                SLOW_LANE,
                qpxd={
                    "sample_spread": {
                        "scheduler_queue_delay_us_per_transfer_ratio": 3.5,
                    },
                },
            )
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("unjudgeable", result.stderr)

    def test_a_range_that_disagrees_with_the_spread_is_rejected(self):
        """A record whose range and spread disagree is not judgeable."""
        fast = lane(FAST_LANE)
        fast["qpxd"]["sample_extremes"]["p99_chunk_gap_ms"] = {"min": 0.01, "max": 0.5}
        result = self.run_gate(fast)
        self.assertEqual(result.returncode, 1)
        self.assertIn("disagrees with its published spread", result.stderr)

    def test_unstable_cpu_rate_measurement_is_invalid(self):
        """A CPU-rate spread whose worst end reaches the decisive bar makes
        the run invalid.

        The lane's CPU rate is 20.0 against the leader's 10.8, so a spread
        of 3.5 puts the subject's worst end at 20.0 / sqrt(3.5) = 10.69
        against the leader's 10.8: a ratio of 0.990, below the decisive
        bar of 1.25 / 1.25 = 1.0. The movement could turn the
        CPU-efficiency verdict into a failure, so the run is unjudgeable.
        """
        result = self.run_gate(
            lane(
                FAST_LANE,
                qpxd={"sample_spread": {"requests_per_total_cpu_second_ratio": 3.5}},
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("requests_per_total_cpu_second_ratio sample spread", result.stderr)
        self.assertIn("the CPU rate's worst end", result.stderr)

    def test_an_unstable_cpu_rate_that_cannot_change_the_verdict_stays_valid(self):
        """A CPU-rate spread whose worst end stays above the decisive bar
        leaves the run judgeable.

        A spread of 3.2 puts the subject's worst end at 20.0 / sqrt(3.2) =
        11.18 against the leader's 10.8: a ratio of 1.035, above the
        decisive bar of 1.25 / 1.25 = 1.0, so no observed end of the CPU
        rate could have produced a failure and the movement cannot excuse
        a miss.
        """
        result = self.run_gate(
            lane(
                FAST_LANE,
                qpxd={"sample_spread": {"requests_per_total_cpu_second_ratio": 3.2}},
            )
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("unjudgeable", result.stderr)

    def test_an_unstable_slow_cpu_rate_is_invalid(self):
        """The slow lane has no CPU-rate objective, so the cap stays there."""
        result = self.run_gate(
            slow=lane(
                SLOW_LANE,
                qpxd={"sample_spread": {"requests_per_total_cpu_second_ratio": 3.5}},
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "streaming ('slow', 'qpxd') requests_per_total_cpu_second_ratio sample spread",
            result.stderr,
        )

    def test_a_record_without_the_cpu_rate_range_is_rejected(self):
        """The record that the checker judges by range must carry the range."""
        fast = lane(FAST_LANE)
        del fast["qpxd"]["sample_extremes"]["requests_per_total_cpu_second"]
        result = self.run_gate(fast)
        self.assertEqual(result.returncode, 1)
        self.assertIn("requests_per_total_cpu_second", result.stderr)

    def test_a_cpu_rate_range_that_disagrees_with_the_spread_is_rejected(self):
        fast = lane(FAST_LANE)
        fast["qpxd"]["sample_extremes"]["requests_per_total_cpu_second"] = {
            "min": 1.0,
            "max": 100.0,
        }
        result = self.run_gate(fast)
        self.assertEqual(result.returncode, 1)
        self.assertIn("disagrees with its published spread", result.stderr)

    def test_stable_cpu_rate_measurement_stays_valid(self):
        result = self.run_gate(
            lane(
                FAST_LANE,
                qpxd={"sample_spread": {"requests_per_total_cpu_second_ratio": 2.5}},
            )
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_queue_delay_spread_is_rejected(self):
        fast = lane(FAST_LANE)
        del fast["qpxd"]["sample_spread"]["scheduler_queue_delay_us_per_transfer_ratio"]
        result = self.run_gate(fast)
        self.assertEqual(result.returncode, 1)
        self.assertIn("scheduler_queue_delay_us_per_transfer_ratio", result.stderr)

    def test_old_record_schema_is_rejected(self):
        fast = lane(FAST_LANE)
        fast["qpxd"]["benchmark_schema_version"] = 7
        result = self.run_gate(fast)
        self.assertEqual(result.returncode, 1)
        self.assertIn("unsupported benchmark schema", result.stderr)

    def test_slow_tail_measurement_uses_its_own_spread(self):
        result = self.run_gate(
            slow=lane(
                SLOW_LANE,
                qpxd={
                    "p99_chunk_gap_ms": 2.0,
                    "sample_spread": {"p99_chunk_gap_ms_ratio": 1.4},
                },
            )
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("slow streaming max_p99_gap_ratio marginal", result.stdout)

    def test_slow_tail_miss_on_a_stable_measurement_fails(self):
        result = self.run_gate(slow=lane(SLOW_LANE, qpxd={"p99_chunk_gap_ms": 2.0}))
        self.assertEqual(result.returncode, 1)
        self.assertIn("slow streaming max_p99_gap_ratio", result.stderr)
        self.assertIn("decisive", result.stderr)


if __name__ == "__main__":
    sys.exit(unittest.main())
