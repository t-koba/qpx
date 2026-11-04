#!/usr/bin/env python3
"""Exercise the real comparator orchestration with stub process/transfer I/O."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))
import streaming_confirmation

FIXTURES = runpy.run_path(str(ROOT / "scripts/test-streaming-performance.py"))

# Only process startup, command discovery and the transfer are stubbed. The
# script's round planner, raw record writer, aggregation, report and recursive
# pair-only confirmation paths execute unchanged, without servers or network.
STUBS = r'''
require_cmd() { echo "require $1 $PAIR_ONLY_MODE" >>"$TRACE"; }
start_streaming_backend() { :; }
start_qpxd() { :; }
start_previous_qpxd() { :; }
start_nginx() { echo nginx >>"$TRACE"; }
start_apache() { echo apache >>"$TRACE"; }
start_lighttpd() { echo lighttpd >>"$TRACE"; }
run_one() {
  echo "sample $1 $4 $STREAMING_PAIR_ROUND $PAIR_ONLY_MODE" >>"$TRACE"
  sample="$(python3 - "$SAMPLES" "$1" "$4" "$PAIR_ONLY_MODE" <<'SAMPLE'
import json, os, sys
path, proxy, mode, confirmation = sys.argv[1:]
record = json.load(open(path))[mode]["qpxd" if proxy == "qpxd-previous" else proxy]
record["proxy"] = proxy
ratio = float(os.environ["CONFIRM_RATIO"] if confirmation else os.environ[mode.upper() + "_RATIO"])
record["scheduler_queue_delay_us_per_transfer"] = 100 * (ratio if proxy == "qpxd" else 1)
print(json.dumps(record))
SAMPLE
)"
  streaming_write_round_record "$OUT_JSON" "$sample" "$STREAM_BYTES" \
    "$CHUNK_BYTES" "$SAMPLE_ATTEMPTS" 1 "$CURRENT_SOURCE_SHA"
}
'''


class ComparatorConfirmationTest(unittest.TestCase):
    def run_comparator(self, fast="2", slow="1", confirmation="1", pair_only="", previous=True, attempts=1):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        scripts = root / "scripts"
        scripts.mkdir()
        shutil.copytree(ROOT / "scripts/lib", scripts / "lib", ignore=shutil.ignore_patterns("__pycache__"))
        (root / "perf").mkdir()
        shutil.copy(ROOT / "perf/streaming-performance-objectives.json", root / "perf")
        source = (ROOT / "scripts/perf-audit-streaming-compare.sh").read_text()
        comparator = scripts / "perf-audit-streaming-compare.sh"
        comparator.write_text(source.replace("require_cmd curl\n", STUBS + "\nrequire_cmd curl\n"))
        samples = root / "samples.json"
        samples.write_text(json.dumps({"fast": FIXTURES["FAST_LANE"], "slow": FIXTURES["SLOW_LANE"]}))
        out = root / "out"
        out.mkdir()
        env = {k: v for k, v in os.environ.items() if not k.startswith("QPX_")}
        env.update(GITHUB_SHA="a" * 40, QPXD_BIN=shutil.which("true"),
                   QPX_PREVIOUS_BIN=shutil.which("true") if previous else str(root / "missing"),
                   QPX_PREVIOUS_SOURCE_SHA="b" * 40, QPX_STREAMING_COMPARE_BYTES="262144",
                   QPX_STREAMING_COMPARE_SAMPLE_ATTEMPTS=str(attempts),
                   QPX_STREAMING_COMPARE_PAIR_ONLY_MODE=pair_only,
                   QPX_STREAMING_COMPARE_APACHE_BIN="unused",
                   QPX_STREAMING_COMPARE_LOG_DIR=str(out / "logs"),
                   TRACE=str(root / "trace"), SAMPLES=str(samples), FAST_RATIO=fast,
                   SLOW_RATIO=slow, CONFIRM_RATIO=confirmation)
        result = subprocess.run(["bash", str(comparator), str(out / "measurements.jsonl")],
                                env=env, text=True, capture_output=True)
        trace = (root / "trace").read_text().splitlines()
        return result, out, trace

    def test_only_the_initially_missed_mode_gets_one_paired_confirmation(self):
        result, out, trace = self.run_comparator(attempts=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        confirmation = out / "paired-confirmation/fast"
        first = json.loads((out / "streaming-compare-reference.json").read_text())
        second = json.loads((confirmation / "streaming-compare-reference.json").read_text())
        self.assertEqual(first["source_sha"], second["source_sha"])
        self.assertEqual(first["reference_source_sha"], second["reference_source_sha"])
        self.assertEqual(first["sample_attempts"], second["sample_attempts"])
        self.assertTrue(first["complete_modes"]["fast"])
        self.assertTrue(second["complete_modes"]["fast"])
        self.assertFalse((out / "paired-confirmation/slow").exists())
        self.assertTrue((out / "streaming-compare-raw.jsonl").is_file())
        archive = out / "logs/paired-confirmation/fast"
        for filename in (
            "measurements.jsonl",
            "streaming-compare-raw.jsonl",
            "streaming-compare-reference.json",
            "run.log",
        ):
            with self.subTest(artifact=filename):
                self.assertEqual((confirmation / filename).read_bytes(),
                                 (archive / filename).read_bytes())
        self.assertEqual(trace.count("nginx"), 1)
        self.assertEqual(trace.count("apache"), 1)
        self.assertEqual(trace.count("lighttpd"), 1)
        raw = [json.loads(line) for line in (confirmation / "streaming-compare-raw.jsonl").read_text().splitlines()]
        self.assertEqual([(r["proxy"], r["sample_round"]) for r in raw], [
            ("qpxd", 1), ("qpxd-previous", 1),
        ])
        self.assertTrue(all(r["read_mode"] == "fast" for r in raw))

    def test_both_first_mode_misses_get_separate_reports(self):
        result, out, trace = self.run_comparator(slow="2")
        self.assertEqual(result.returncode, 0, result.stderr)
        for mode in ("fast", "slow"):
            self.assertTrue((out / "paired-confirmation" / mode / "streaming-compare-raw.jsonl").exists())
        self.assertEqual(sum(line.startswith("sample") for line in trace), 16)

    def test_pair_only_needs_no_external_proxy_commands_or_measurements(self):
        for mode in ("fast", "slow"):
            with self.subTest(mode=mode):
                result, out, trace = self.run_comparator(pair_only=mode, attempts=3)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(any(name in " ".join(trace) for name in ("nginx", "apache", "lighttpd", "direct-backend")))
                self.assertEqual(sum(line.startswith("sample") for line in trace), 6)
                raw = [json.loads(line) for line in
                       (out / "streaming-compare-raw.jsonl").read_text().splitlines()]
                self.assertEqual([(r["proxy"], r["sample_round"]) for r in raw], [
                    ("qpxd", 1), ("qpxd-previous", 1),
                    ("qpxd-previous", 2), ("qpxd", 2),
                    ("qpxd", 3), ("qpxd-previous", 3),
                ])
                self.assertTrue(all(r["read_mode"] == mode for r in raw))
                self.assertFalse((out / "paired-confirmation").exists())

    def test_pair_only_rejects_an_unavailable_pinned_binary(self):
        result, out, trace = self.run_comparator(pair_only="fast", previous=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires the pinned reference", result.stderr)
        self.assertFalse(any(line.startswith("sample") for line in trace))


class ConfirmationEvidenceTest(unittest.TestCase):
    def test_only_complete_first_misses_are_scheduled_for_confirmation(self):
        first = FIXTURES["reference_report"](fast_median=2)
        self.assertEqual(streaming_confirmation.missed_modes(first, 1.25), ["fast"])
        self.assertEqual(
            streaming_confirmation.missed_modes(
                FIXTURES["reference_report"](fast_median=1), 1.25
            ),
            [],
        )
        first["complete_modes"]["fast"] = False
        self.assertEqual(streaming_confirmation.missed_modes(first, 1.25), [])
        first["complete_modes"]["fast"] = True
        first["read_modes"]["fast"]["metrics"][
            streaming_confirmation.METRIC
        ]["paired_rounds"] = 2
        self.assertEqual(streaming_confirmation.missed_modes(first, 1.25), [])

    def test_expected_source_and_pin_must_match_even_if_reports_agree(self):
        first = FIXTURES["reference_report"](fast_median=2)
        confirmation = FIXTURES["reference_report"]()
        for variable in ("GITHUB_SHA", "QPX_PREVIOUS_SOURCE_SHA"):
            expected = {"GITHUB_SHA": "a" * 40, "QPX_PREVIOUS_SOURCE_SHA": "b" * 40}
            expected[variable] = "c" * 40
            with self.subTest(variable=variable), patch.dict(os.environ, expected):
                result = streaming_confirmation.resolve(first, confirmation, "fast", 1.25, "a" * 40)
                self.assertEqual(result["status"], "REGRESSED")
                self.assertIn("identity mismatch", result["reason"])

    def test_incomplete_or_invalid_raw_confirmation_is_not_decisive(self):
        first = FIXTURES["reference_report"](fast_median=2)
        records = []
        for n in range(1, 4):
            for proxy in ("qpxd", "qpxd-previous"):
                record = copy.deepcopy(FIXTURES["FAST_LANE"]["qpxd"])
                record.update(proxy=proxy, sample_round=n, sample_attempts=1,
                              valid_samples=1, aggregation="single_sample",
                              scheduler_queue_delay_us_per_transfer=100)
                records.append(record)
        invalids = [records[:-1], records + [records[0]]]
        for field, value in (("valid", False), ("kernel_resource_metrics", False),
                             ("scheduler_queue_delay_us_per_transfer", 0),
                             ("bytes", 1), ("commit", "c" * 40), ("valid_samples", 0)):
            invalid = copy.deepcopy(records)
            invalid[0][field] = value
            invalids.append(invalid)
        with tempfile.TemporaryDirectory() as directory:
            raw, report = Path(directory) / "raw.jsonl", Path(directory) / "report.json"
            for invalid in invalids:
                raw.write_text("".join(json.dumps(r) + "\n" for r in invalid))
                with contextlib.redirect_stdout(io.StringIO()):
                    streaming_confirmation.write_report(raw, report, "a" * 40, "b" * 40,
                                                        3, first["workload"])
                confirmation = json.loads(report.read_text())
                self.assertFalse(confirmation["complete_modes"]["fast"])
                result = streaming_confirmation.resolve(first, confirmation, "fast", 1.25, "a" * 40)
                self.assertEqual(result["status"], "REGRESSED")


if __name__ == "__main__":
    unittest.main()
