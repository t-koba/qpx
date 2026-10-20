#!/usr/bin/env python3
"""Streaming gate fixture demo; no benchmarks, servers, or network."""
import copy
import json
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


def build(proxy, mode, **overrides):
    """One aggregate streaming record that satisfies the gate's own invariants."""
    transfers = FAST_TRANSFERS if mode == "fast" else SLOW_TRANSFERS
    record = {
        "bench": BENCH,
        "proxy": proxy,
        "read_mode": mode,
        "valid": True,
        "sample_attempts": 3,
        "valid_samples": 3,
        "aggregation": "conservative_median_per_metric",
        "sampling_order": "round_robin_interleaved",
        "benchmark_schema_version": 6,
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


class StreamingGateTest(unittest.TestCase):
    def run_gate(self, fast=None, slow=None):
        fast = FAST_LANE if fast is None else fast
        slow = SLOW_LANE if slow is None else slow
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "streaming.jsonl"
            records = list(fast.values()) + list(slow.values())
            with path.open("w", encoding="utf-8") as handle:
                for record in records:
                    handle.write(json.dumps(record, sort_keys=True) + "\n")
            return subprocess.run(
                [str(CHECKER), str(path), str(OBJECTIVES)],
                capture_output=True,
                text=True,
                check=False,
            )

    def test_healthy_lane_passes_without_marginals(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("marginal", result.stdout)

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
        self.assertIn("fast streaming scheduler queue-delay ratio marginal", result.stdout)

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
                    # Twice the leader's gap and delay, and twice both caps.
                    "p99_chunk_gap_ms": 0.045 * 2.0 * 3.2,
                    "scheduler_queue_delay_us_per_transfer": 3943.0 * 2.0 * 6.0,
                    "sample_spread": {
                        "p99_chunk_gap_ms_ratio": 2.0,
                        "scheduler_queue_delay_us_per_transfer_ratio": 2.0,
                    },
                },
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("fast streaming p99 gap ratio", result.stderr)
        self.assertIn("decisive", result.stderr)
        self.assertIn("fast streaming scheduler queue-delay ratio", result.stderr)
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
                qpxd={
                    "p99_chunk_gap_ms": 0.182083,
                    "scheduler_queue_delay_us_per_transfer": 29216.16,
                },
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("fast streaming p99 gap ratio", result.stderr)
        self.assertIn("decisive", result.stderr)
        self.assertIn("fast streaming scheduler queue-delay ratio", result.stderr)

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
        result = self.run_gate(
            lane(FAST_LANE, qpxd={"sample_spread": {"p99_chunk_gap_ms_ratio": 3.5}})
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("p99_chunk_gap_ms_ratio sample spread", result.stderr)

    def test_unstable_cpu_rate_measurement_is_invalid(self):
        result = self.run_gate(
            lane(
                FAST_LANE,
                qpxd={"sample_spread": {"requests_per_total_cpu_second_ratio": 3.5}},
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("requests_per_total_cpu_second_ratio sample spread", result.stderr)

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
        fast["qpxd"]["benchmark_schema_version"] = 5
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
