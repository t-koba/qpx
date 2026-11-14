#!/usr/bin/env python3
"""Paired-build comparison fixtures; no benchmarks, servers, or network."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

import streaming_reference  # noqa: E402


def record(proxy, read_mode, round_number, **overrides):
    """One per-round streaming record."""
    payload = {
        "proxy": proxy,
        "read_mode": read_mode,
        "sample_round": round_number,
        "valid": True,
        "total_ms": 100.0,
        "requests_per_cpu_second": 10.0,
        "p99_chunk_gap_ms": 1.0,
        "scheduler_queue_delay_us_per_transfer": 100.0,
    }
    payload.update(overrides)
    return payload


class PairedComparisonTest(unittest.TestCase):
    def test_pairs_only_the_rounds_both_builds_measured(self):
        records = [
            record("qpxd", "fast", 1, total_ms=110.0),
            record("qpxd-previous", "fast", 1, total_ms=100.0),
            record("qpxd", "fast", 2, total_ms=120.0),
            record("qpxd-previous", "fast", 2, total_ms=100.0),
            record("qpxd", "fast", 3, total_ms=130.0),
        ]
        report = streaming_reference.compare(records)
        fast = report["read_modes"]["fast"]
        self.assertEqual(fast["paired_rounds"], 2)
        total = fast["metrics"]["total_ms"]
        self.assertEqual(total["paired_rounds"], 2)
        self.assertAlmostEqual(total["median_current_over_reference"], 1.15)
        self.assertAlmostEqual(total["min_current_over_reference"], 1.10)
        self.assertAlmostEqual(total["max_current_over_reference"], 1.20)
        self.assertAlmostEqual(total["median_difference"], 15.0)

    def test_reports_the_cpu_rate_and_the_tail_gap(self):
        records = [
            record("qpxd", "fast", 1, requests_per_cpu_second=8.0, p99_chunk_gap_ms=2.0),
            record("qpxd-previous", "fast", 1, requests_per_cpu_second=10.0, p99_chunk_gap_ms=1.0),
        ]
        report = streaming_reference.compare(records)
        metrics = report["read_modes"]["fast"]["metrics"]
        self.assertAlmostEqual(
            metrics["requests_per_cpu_second"]["median_current_over_reference"], 0.8
        )
        self.assertAlmostEqual(
            metrics["p99_chunk_gap_ms"]["median_current_over_reference"], 2.0
        )

    def test_reports_the_paired_queue_delay_with_median_and_rounds(self):
        records = [
            record("qpxd", "fast", 1, scheduler_queue_delay_us_per_transfer=110.0),
            record("qpxd-previous", "fast", 1, scheduler_queue_delay_us_per_transfer=100.0),
            record("qpxd", "fast", 2, scheduler_queue_delay_us_per_transfer=130.0),
            record("qpxd-previous", "fast", 2, scheduler_queue_delay_us_per_transfer=100.0),
        ]
        report = streaming_reference.compare(records)
        queue = report["read_modes"]["fast"]["metrics"][
            "scheduler_queue_delay_us_per_transfer"
        ]
        self.assertEqual(queue["paired_rounds"], 2)
        self.assertAlmostEqual(queue["median_current_over_reference"], 1.2)
        self.assertAlmostEqual(queue["min_current_over_reference"], 1.1)
        self.assertAlmostEqual(queue["max_current_over_reference"], 1.3)

    def test_reports_proxy_and_backend_queue_delay_components(self):
        records = [
            record(
                "qpxd", "fast", 1,
                scheduler_queue_delay_us_per_transfer=25.0,
                proxy_scheduler_queue_delay_us_per_transfer=20.0,
                backend_scheduler_queue_delay_us_per_transfer=5.0,
            ),
            record(
                "qpxd-previous", "fast", 1,
                scheduler_queue_delay_us_per_transfer=15.0,
                proxy_scheduler_queue_delay_us_per_transfer=10.0,
                backend_scheduler_queue_delay_us_per_transfer=5.0,
            ),
            record(
                "qpxd", "fast", 2,
                scheduler_queue_delay_us_per_transfer=45.0,
                proxy_scheduler_queue_delay_us_per_transfer=30.0,
                backend_scheduler_queue_delay_us_per_transfer=15.0,
            ),
            record(
                "qpxd-previous", "fast", 2,
                scheduler_queue_delay_us_per_transfer=20.0,
                proxy_scheduler_queue_delay_us_per_transfer=15.0,
                backend_scheduler_queue_delay_us_per_transfer=5.0,
            ),
        ]
        report = streaming_reference.compare(records)
        fast = report["read_modes"]["fast"]
        self.assertEqual(report["enforced_metric"], "scheduler_queue_delay_us_per_transfer")
        self.assertAlmostEqual(
            fast["metrics"]["proxy_scheduler_queue_delay_us_per_transfer"]
            ["median_current_over_reference"], 2.0
        )
        self.assertAlmostEqual(
            fast["metrics"]["backend_scheduler_queue_delay_us_per_transfer"]
            ["median_current_over_reference"], 2.0
        )
        self.assertAlmostEqual(
            fast["metrics"]["scheduler_queue_delay_us_per_transfer"]
            ["median_current_over_reference"], (25.0 / 15.0 + 45.0 / 20.0) / 2.0
        )

    def test_a_missing_reference_leaves_the_report_empty(self):
        records = [record("qpxd", "fast", 1)]
        report = streaming_reference.compare(records)
        self.assertEqual(report["read_modes"]["fast"]["paired_rounds"], 0)
        self.assertNotIn("total_ms", report["read_modes"]["fast"]["metrics"])
        self.assertEqual(
            report["enforced_metric"], "scheduler_queue_delay_us_per_transfer"
        )
        self.assertNotIn("gate", report)

    def test_records_without_a_round_number_are_not_paired(self):
        records = [
            record("qpxd", "fast", 1),
            record("qpxd-previous", "fast", 1),
            {"proxy": "qpxd", "read_mode": "fast", "valid": True, "total_ms": 100.0},
            {
                "proxy": "qpxd-previous",
                "read_mode": "fast",
                "valid": True,
                "total_ms": 100.0,
            },
        ]
        report = streaming_reference.compare(records)
        self.assertEqual(report["read_modes"]["fast"]["paired_rounds"], 1)

    def test_a_zero_reference_value_is_skipped(self):
        records = [
            record("qpxd", "fast", 1, total_ms=100.0),
            record("qpxd-previous", "fast", 1, total_ms=0.0),
        ]
        report = streaming_reference.compare(records)
        self.assertNotIn("total_ms", report["read_modes"]["fast"]["metrics"])

    def test_the_read_modes_are_reported_separately(self):
        records = [
            record("qpxd", "fast", 1, total_ms=110.0),
            record("qpxd-previous", "fast", 1, total_ms=100.0),
            record("qpxd", "slow", 1, total_ms=90.0),
            record("qpxd-previous", "slow", 1, total_ms=100.0),
        ]
        report = streaming_reference.compare(records)
        self.assertAlmostEqual(
            report["read_modes"]["fast"]["metrics"]["total_ms"][
                "median_current_over_reference"
            ],
            1.1,
        )
        self.assertAlmostEqual(
            report["read_modes"]["slow"]["metrics"]["total_ms"][
                "median_current_over_reference"
            ],
            0.9,
        )

    def test_load_records_keeps_only_valid_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "raw.jsonl"
            with path.open("w", encoding="utf-8") as handle:
                handle.write(json.dumps(record("qpxd", "fast", 1)) + "\n")
                handle.write(
                    json.dumps(record("qpxd", "fast", 2, valid=False)) + "\n"
                )
                handle.write("\n")
            records = streaming_reference.load_records(path)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["sample_round"], 1)

    def test_the_summary_names_the_enforced_paired_verdict(self):
        records = [
            record("qpxd", "fast", 1, total_ms=110.0),
            record("qpxd-previous", "fast", 1, total_ms=100.0),
        ]
        summary = streaming_reference.format_summary(
            streaming_reference.compare(records)
        )
        self.assertIn("qpxd-previous", summary)
        self.assertIn("paired scheduler queue-delay verdict enforced", summary)
        self.assertNotIn("not a gate", summary)
        self.assertIn("1 paired rounds", summary)


if __name__ == "__main__":
    unittest.main()
