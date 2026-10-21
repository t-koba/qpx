#!/usr/bin/env python3
"""Committed fixtures for the paired streaming measurement; no servers, no network.

The lane's pairing has two halves: the plan that owns the round's identity
and the order inside the pair, and the library that holds that plan while
the lane measures. These fixtures exercise both halves and the record they
produce, so a pairing that no longer holds - a pair whose members no longer
share a round, a pair measured in a fixed order, or a record that carries a
round of its own - fails here instead of leaving the lane with a silently
degraded report.
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

import streaming_pair  # noqa: E402
import streaming_records  # noqa: E402
import streaming_reference  # noqa: E402

BASH = shutil.which("bash") or "bash"

SAMPLE = json.dumps(
    {
        "proxy": "qpxd",
        "read_mode": "fast",
        "valid": True,
        "total_ms": 100.0,
        "requests_per_cpu_second": 10.0,
        "p99_chunk_gap_ms": 1.0,
    }
)

REFERENCE_SAMPLE = json.dumps(
    {
        "proxy": "qpxd-previous",
        "read_mode": "fast",
        "valid": True,
        "total_ms": 100.0,
        "requests_per_cpu_second": 10.0,
        "p99_chunk_gap_ms": 1.0,
    }
)

# The lane's own shell half, driven with a stub measurement: it reports the
# proxy, the round the plan produced and the read mode of every member.
APPLY_ROUNDS = """
set -euo pipefail
source "$1/scripts/lib/streaming_pair.sh"
run_one() { printf '%s %s %s\\n' "$1" "$STREAMING_PAIR_ROUND" "$4"; }
PREVIOUS_REFERENCE_AVAILABLE="$3"
QPX_PORT=18381
QPXD_PID=1
PREVIOUS_PORT=18385
PREVIOUS_QPXD_PID=2
for round in $2; do
  streaming_begin_round "$round"
  run_qpxd_pair fast
done
"""

# The lane's own record writing, driven over the rounds it measures.
WRITE_RECORDS = """
set -euo pipefail
source "$1/scripts/lib/streaming_pair.sh"
OUT_JSON="$2"
STREAM_BYTES=1024
CHUNK_BYTES=64
SAMPLE_ATTEMPTS=1
for round in $3; do
  streaming_begin_round "$round"
  streaming_write_round_record "$OUT_JSON" "$4" "$STREAM_BYTES" "$CHUNK_BYTES" \\
    "$SAMPLE_ATTEMPTS" "1" "commit"
  streaming_write_round_record "$OUT_JSON" "$5" "$STREAM_BYTES" "$CHUNK_BYTES" \\
    "$SAMPLE_ATTEMPTS" "1" "commit"
done
"""

# A lane that measures without beginning a round has no round to carry.
MEASURE_WITHOUT_A_ROUND = """
set -euo pipefail
source "$1/scripts/lib/streaming_pair.sh"
run_one() { printf '%s %s %s\\n' "$1" "$STREAMING_PAIR_ROUND" "$4"; }
PREVIOUS_REFERENCE_AVAILABLE=true
QPX_PORT=18381
QPXD_PID=1
PREVIOUS_PORT=18385
PREVIOUS_QPXD_PID=2
run_qpxd_pair fast
"""


def run_bash(script, arguments):
    """Runs one of the lane's shell halves and returns its result."""
    return subprocess.run(
        [BASH, "-c", script, "streaming-pair-fixture", *arguments],
        capture_output=True,
        text=True,
        check=False,
    )


def measure_rounds(rounds, reference_available="true"):
    """Measures the given rounds through the lane's own pairing shell."""
    result = run_bash(
        APPLY_ROUNDS,
        [str(ROOT), " ".join(str(number) for number in rounds), reference_available],
    )
    if result.returncode != 0:
        raise AssertionError(f"the pairing fixture failed: {result.stderr.strip()}")
    measured = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        proxy, round_number, read_mode = line.split()
        measured.append((proxy, int(round_number), read_mode))
    return measured


class PairPlanTest(unittest.TestCase):
    def test_the_plan_carries_the_round_it_measures(self):
        for number in (1, 2, 3, 7):
            self.assertEqual(streaming_pair.plan(number)["round"], number)

    def test_the_order_inside_the_pair_alternates_between_rounds(self):
        orders = [streaming_pair.plan(number)["members"] for number in (1, 2, 3, 4)]
        self.assertEqual(orders[0], ["qpxd", "qpxd-previous"])
        self.assertEqual(orders[1], ["qpxd-previous", "qpxd"])
        self.assertEqual(orders[2], ["qpxd", "qpxd-previous"])
        self.assertEqual(orders[3], ["qpxd-previous", "qpxd"])

    def test_without_a_reference_only_the_current_build_is_measured(self):
        the_plan = streaming_pair.plan(2, reference_available=False)
        self.assertEqual(the_plan["members"], ["qpxd"])

    def test_a_round_must_be_a_positive_integer(self):
        for number in (0, -1, "1", 1.5, None):
            with self.assertRaises(ValueError):
                streaming_pair.plan(number)


class PairApplicationTest(unittest.TestCase):
    def test_both_members_of_a_pair_carry_the_plan_round(self):
        measured = measure_rounds([1, 2, 3, 4])
        self.assertEqual(len(measured), 8)
        for index in range(0, len(measured), 2):
            first, second = measured[index], measured[index + 1]
            self.assertEqual(first[1], second[1])

    def test_the_measured_order_alternates_between_rounds(self):
        measured = measure_rounds([1, 2, 3, 4])
        self.assertEqual(
            [entry[0] for entry in measured],
            [
                "qpxd",
                "qpxd-previous",
                "qpxd-previous",
                "qpxd",
                "qpxd",
                "qpxd-previous",
                "qpxd-previous",
                "qpxd",
            ],
        )
        self.assertEqual([entry[1] for entry in measured], [1, 1, 2, 2, 3, 3, 4, 4])

    def test_without_a_reference_the_current_build_is_measured_alone(self):
        self.assertEqual(
            measure_rounds([1, 2], reference_available="false"),
            [("qpxd", 1, "fast"), ("qpxd", 2, "fast")],
        )

    def test_measuring_without_a_begun_round_fails_loudly(self):
        result = run_bash(MEASURE_WITHOUT_A_ROUND, [str(ROOT)])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no round was begun", result.stderr)


class LaneRecordTest(unittest.TestCase):
    def test_the_record_carries_the_round_the_plan_produced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.jsonl"
            result = run_bash(
                WRITE_RECORDS,
                [str(ROOT), str(path), "3 4", SAMPLE, REFERENCE_SAMPLE],
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            written = [
                json.loads(line)
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(
                [record["sample_round"] for record in written], [3, 3, 4, 4]
            )

    def test_the_records_of_a_round_pair_on_the_round_the_plan_produced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.jsonl"
            result = run_bash(
                WRITE_RECORDS,
                [str(ROOT), str(path), "1 2", SAMPLE, REFERENCE_SAMPLE],
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = streaming_reference.compare(
                streaming_reference.load_records(path)
            )
            self.assertEqual(report["read_modes"]["fast"]["paired_rounds"], 2)


class RoundRecordTest(unittest.TestCase):
    def write_record(self, path, proxy, sample_round):
        sample = json.dumps(
            {
                "proxy": proxy,
                "read_mode": "fast",
                "valid": True,
                "total_ms": 100.0,
                "requests_per_cpu_second": 10.0,
                "p99_chunk_gap_ms": 1.0,
            }
        )
        streaming_records.write_round_record(
            path, sample, 1024, 64, 1, 1, "commit", sample_round
        )

    def test_the_record_carries_the_round_the_report_pairs_on(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.jsonl"
            the_plan = streaming_pair.plan(3)
            self.write_record(path, "qpxd", the_plan["round"])
            self.write_record(path, "qpxd-previous", the_plan["round"])
            written = [
                json.loads(line)
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual([record["sample_round"] for record in written], [3, 3])
            report = streaming_reference.compare(
                streaming_reference.load_records(path)
            )
            self.assertEqual(report["read_modes"]["fast"]["paired_rounds"], 1)

    def test_records_of_different_rounds_do_not_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.jsonl"
            self.write_record(path, "qpxd", 3)
            self.write_record(path, "qpxd-previous", 4)
            report = streaming_reference.compare(
                streaming_reference.load_records(path)
            )
            self.assertEqual(report["read_modes"]["fast"]["paired_rounds"], 0)


if __name__ == "__main__":
    unittest.main()
