#!/usr/bin/env python3
"""Fixture checks for the CI runner-minute report; no network and no runner."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))

from ci_runner_minutes import (  # noqa: E402
    build_report,
    format_report,
    job_day,
    job_interval,
    parse_timestamp,
    summarize_jobs,
    write_jsonl,
)

SPEC = importlib.util.spec_from_file_location(
    "runner_minutes_driver", ROOT / "scripts/ci-runner-minutes.py"
)
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)

CAPTURED = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)


def job(name, started, completed, status="completed", conclusion="success", run_id="7"):
    """One job record."""
    return {
        "workflow": "ci",
        "run_id": run_id,
        "name": name,
        "status": status,
        "conclusion": conclusion,
        "started_at": started,
        "completed_at": completed,
    }


def run(run_id="7", created="2026-10-20T10:00:00Z", started="2026-10-20T10:01:00Z"):
    """One run record."""
    return {
        "run_id": run_id,
        "workflow": "ci",
        "head_sha": "a" * 40,
        "created_at": created,
        "run_started_at": started,
        "status": "completed",
        "conclusion": "success",
        "event": "push",
        "url": "https://github.com/t-koba/qpx/actions/runs/7",
    }


class Timestamps(unittest.TestCase):
    def test_api_timestamps_parse_to_utc(self):
        parsed = parse_timestamp("2026-10-20T16:51:47.000Z")
        self.assertEqual(parsed, datetime(2026, 10, 20, 16, 51, 47, tzinfo=timezone.utc))

    def test_unusable_timestamps_are_rejected(self):
        for value in (None, "", "not a timestamp", "2026-13-40T00:00:00Z"):
            self.assertIsNone(parse_timestamp(value))

    def test_a_job_without_a_usable_interval_has_no_runner_time(self):
        self.assertIsNone(job_interval(job("a", "2026-10-20T10:00:00Z", None)))
        self.assertIsNone(job_interval(job("a", None, "2026-10-20T10:05:00Z")))
        self.assertIsNone(
            job_interval(job("a", "2026-10-20T10:05:00Z", "2026-10-20T10:00:00Z"))
        )


class Totals(unittest.TestCase):
    def test_overlapping_jobs_sum_above_the_elapsed_span(self):
        records = [
            job("a", "2026-10-20T10:01:00Z", "2026-10-20T10:11:00Z"),
            job("b", "2026-10-20T10:01:00Z", "2026-10-20T10:11:00Z"),
        ]
        summary = summarize_jobs(records, {"7": parse_timestamp("2026-10-20T10:01:00Z")})
        self.assertEqual(summary["runner_minutes"], 20.0)
        self.assertEqual(summary["elapsed_minutes"], 10.0)
        self.assertFalse(summary["partial"])

    def test_a_queued_or_running_job_is_not_counted_and_marks_the_total_partial(self):
        records = [
            job("a", "2026-10-20T10:01:00Z", "2026-10-20T10:06:00Z"),
            job("b", "2026-10-20T10:02:00Z", None, status="in_progress", conclusion=""),
            job("c", None, None, status="queued", conclusion=""),
        ]
        summary = summarize_jobs(records)
        self.assertEqual(summary["runner_minutes"], 5.0)
        self.assertEqual(summary["jobs_counted"], 1)
        self.assertEqual(summary["jobs_total"], 3)
        self.assertEqual(summary["jobs_unfinished"], 2)
        self.assertTrue(summary["partial"])
        self.assertTrue(any("still queued or running" in r for r in summary["partial_reasons"]))

    def test_a_failed_job_still_consumed_runner_time(self):
        records = [job("a", "2026-10-20T10:01:00Z", "2026-10-20T10:04:00Z", conclusion="failure")]
        summary = summarize_jobs(records)
        self.assertEqual(summary["runner_minutes"], 3.0)
        self.assertEqual(summary["jobs_failed"], 1)
        self.assertFalse(summary["partial"])

    def test_a_skipped_job_never_ran(self):
        records = [
            job("a", "2026-10-20T10:01:00Z", "2026-10-20T10:04:00Z"),
            job("b", None, None, conclusion="skipped"),
        ]
        summary = summarize_jobs(records)
        self.assertEqual(summary["jobs_skipped"], 1)
        self.assertEqual(summary["runner_minutes"], 3.0)
        self.assertFalse(summary["partial"])

    def test_a_job_without_timestamps_marks_the_total_partial(self):
        records = [
            job("a", "2026-10-20T10:01:00Z", "2026-10-20T10:04:00Z"),
            job("b", "2026-10-20T10:01:00Z", None),
        ]
        summary = summarize_jobs(records)
        self.assertEqual(summary["jobs_without_timestamps"], 1)
        self.assertTrue(summary["partial"])
        self.assertTrue(any("no usable start or completion" in r for r in summary["partial_reasons"]))

    def test_the_queue_delay_is_measured_from_the_run_start(self):
        records = [job("a", "2026-10-20T10:04:00Z", "2026-10-20T10:06:00Z")]
        summary = summarize_jobs(records, {"7": parse_timestamp("2026-10-20T10:01:00Z")})
        self.assertEqual(summary["queue_delay_minutes_max"], 3.0)

    def test_the_queue_delay_ignores_a_job_that_started_before_the_run(self):
        records = [job("a", "2026-10-20T09:59:00Z", "2026-10-20T10:06:00Z")]
        summary = summarize_jobs(records, {"7": parse_timestamp("2026-10-20T10:01:00Z")})
        self.assertEqual(summary["queue_delay_minutes_max"], 0.0)


class DayGrouping(unittest.TestCase):
    def test_a_job_that_crosses_midnight_belongs_to_its_start_day(self):
        record = job("a", "2026-10-20T23:59:00Z", "2026-10-21T00:01:00Z")
        self.assertEqual(job_day(record), "2026-10-20")

    def test_the_day_total_only_counts_the_jobs_of_that_day(self):
        runs = [run()]
        jobs = [
            job("a", "2026-10-20T10:05:00Z", "2026-10-20T10:10:00Z"),
            job("b", "2026-10-21T00:05:00Z", "2026-10-21T00:10:00Z"),
        ]
        payload = build_report(runs, jobs, "7", CAPTURED)
        self.assertEqual(payload["day"]["day"], "2026-10-20")
        self.assertEqual(payload["day"]["runner_minutes"], 5.0)


class Report(unittest.TestCase):
    def test_the_report_binds_the_sha_the_run_and_the_capture_time(self):
        payload = build_report(
            [run()],
            [job("a", "2026-10-20T10:05:00Z", "2026-10-20T10:10:00Z")],
            "7",
            CAPTURED,
        )
        self.assertEqual(payload["head_sha"], "a" * 40)
        self.assertEqual(payload["run_id"], "7")
        self.assertEqual(payload["workflow"], "ci")
        self.assertEqual(payload["captured_at"], "2026-10-20T12:00:00Z")
        self.assertEqual(payload["run"]["runner_minutes"], 5.0)

    def test_the_report_marks_a_day_with_uncounted_runs_as_partial(self):
        runs = [run(), run(run_id="8", created="2026-10-20T11:00:00Z", started="2026-10-20T11:01:00Z")]
        jobs = [job("a", "2026-10-20T10:05:00Z", "2026-10-20T10:10:00Z")]
        payload = build_report(runs, jobs, "7", CAPTURED)
        self.assertTrue(payload["day"]["partial"])
        self.assertEqual(payload["day"]["runs_counted"], 1)
        self.assertEqual(payload["day"]["runs_total"], 2)

    def test_a_collection_that_left_runs_out_marks_the_day_partial(self):
        payload = build_report(
            [run()],
            [job("a", "2026-10-20T10:05:00Z", "2026-10-20T10:10:00Z")],
            "7",
            CAPTURED,
            {"runs_omitted": 3},
        )
        self.assertTrue(payload["day"]["partial"])
        self.assertTrue(any("were not collected" in r for r in payload["day"]["partial_reasons"]))

    def test_the_rendered_report_names_each_quantity(self):
        payload = build_report(
            [run()],
            [job("a", "2026-10-20T10:05:00Z", "2026-10-20T10:10:00Z")],
            "7",
            CAPTURED,
        )
        text = format_report(payload)
        self.assertIn("runner minutes 5.00", text)
        self.assertIn("elapsed minutes", text)
        self.assertIn("queue delay minutes", text)
        self.assertIn("day 2026-10-20", text)


class EmptyRun(unittest.TestCase):
    def test_a_run_without_a_counted_job_has_no_elapsed_time(self):
        jobs = [job("a", "2026-10-20T10:05:00Z", None, status="queued", conclusion="")]
        payload = build_report([run()], jobs, "7", CAPTURED)
        self.assertIsNone(payload["run"]["elapsed_minutes"])
        self.assertIn("elapsed minutes unknown", format_report(payload))


class ApiRecords(unittest.TestCase):
    def test_an_api_run_becomes_a_run_record(self):
        record = DRIVER.run_record(
            {
                "id": 7,
                "name": "ci",
                "head_sha": "b" * 40,
                "created_at": "2026-10-20T10:00:00Z",
                "run_started_at": "2026-10-20T10:01:00Z",
                "status": "completed",
                "conclusion": "success",
                "event": "push",
                "html_url": "https://github.com/t-koba/qpx/actions/runs/7",
            }
        )
        self.assertEqual(record["run_id"], "7")
        self.assertEqual(record["workflow"], "ci")
        self.assertEqual(record["head_sha"], "b" * 40)

    def test_an_api_job_becomes_a_job_record(self):
        record = DRIVER.job_record(
            {
                "run_id": 7,
                "name": "build",
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-10-20T10:01:00Z",
                "completed_at": "2026-10-20T10:05:00Z",
            },
            "ci",
        )
        self.assertEqual(record["run_id"], "7")
        self.assertEqual(record["workflow"], "ci")
        self.assertEqual(record["started_at"], "2026-10-20T10:01:00Z")


class Command(unittest.TestCase):
    def test_the_report_command_writes_the_report(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            write_jsonl(base / "runs.jsonl", [run()])
            write_jsonl(
                base / "jobs.jsonl",
                [job("a", "2026-10-20T10:05:00Z", "2026-10-20T10:10:00Z")],
            )
            out = base / "report.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/ci-runner-minutes.py"),
                    "report",
                    "--runs",
                    str(base / "runs.jsonl"),
                    "--jobs",
                    str(base / "jobs.jsonl"),
                    "--run-id",
                    "7",
                    "--out",
                    str(out),
                    "--captured-at",
                    "2026-10-20T12:00:00Z",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["run"]["runner_minutes"], 5.0)
            self.assertEqual(payload["captured_at"], "2026-10-20T12:00:00Z")
            self.assertIn("runner minutes 5.00", result.stdout)


if __name__ == "__main__":
    unittest.main()
