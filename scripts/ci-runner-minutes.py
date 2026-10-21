#!/usr/bin/env python3
"""Collect CI job records and report the runner-minutes a run consumed.

The report is read-only: it reads the run and job records the GitHub Actions
API already holds, sums the runner time of the completed jobs, and writes a
report that says which records it could not count. It never changes a gate,
and it never writes outside the directory it is given.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))

from ci_runner_minutes import (  # noqa: E402
    build_report,
    format_report,
    format_timestamp,
    load_jsonl,
    parse_timestamp,
    write_json,
    write_jsonl,
)

API_ROOT = "https://api.github.com"
RUNS_PER_PAGE = 100
JOBS_PER_PAGE = 100
MAX_PAGES = 10
MAX_RUNS = 100


def api_get(path, token):
    """Reads one API resource. The token never reaches the output."""
    request = urllib.request.Request(
        f"{API_ROOT}{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "qpx-ci-runner-minutes",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def run_record(payload):
    """Turns an API run into the record the report uses."""
    return {
        "run_id": str(payload.get("id")),
        "workflow": payload.get("name"),
        "head_sha": payload.get("head_sha"),
        "created_at": payload.get("created_at"),
        "run_started_at": payload.get("run_started_at"),
        "status": payload.get("status"),
        "conclusion": payload.get("conclusion"),
        "event": payload.get("event"),
        "url": payload.get("html_url"),
    }


def job_record(payload, workflow):
    """Turns an API job into the record the report uses."""
    return {
        "workflow": workflow,
        "run_id": str(payload.get("run_id")),
        "name": payload.get("name"),
        "status": payload.get("status"),
        "conclusion": payload.get("conclusion"),
        "started_at": payload.get("started_at"),
        "completed_at": payload.get("completed_at"),
    }


def list_runs(repo, token, day_start):
    """Lists the runs created on or after `day_start`, newest first."""
    runs = []
    truncated = False
    for page in range(1, MAX_PAGES + 1):
        payload = api_get(
            f"/repos/{repo}/actions/runs?per_page={RUNS_PER_PAGE}&page={page}", token
        )
        batch = payload.get("workflow_runs") or []
        if not batch:
            break
        runs.extend(batch)
        created = [
            parse_timestamp(record.get("created_at"))
            for record in batch
            if parse_timestamp(record.get("created_at")) is not None
        ]
        if created and min(created) < day_start:
            break
        if len(batch) < RUNS_PER_PAGE:
            break
    else:
        truncated = True
    selected = []
    for record in runs:
        created = parse_timestamp(record.get("created_at"))
        if created is None or created >= day_start:
            selected.append(record)
    return selected, truncated


def list_jobs(repo, token, run_id, workflow):
    """Lists the jobs of one run."""
    jobs = []
    for page in range(1, MAX_PAGES + 1):
        payload = api_get(
            f"/repos/{repo}/actions/runs/{run_id}/jobs?per_page={JOBS_PER_PAGE}&page={page}",
            token,
        )
        batch = payload.get("jobs") or []
        if not batch:
            break
        jobs.extend(job_record(record, workflow) for record in batch)
        if len(batch) < JOBS_PER_PAGE:
            break
    return jobs


def select_runs(target, listed, workflow, max_runs):
    """Chooses the runs to collect: the target first, then its workflow's day.

    The target run is always kept, so a report can never lose the run it
    describes, and the oldest runs of the day are the ones dropped when the
    day holds more runs than the collector keeps.
    """
    same_workflow = [record for record in listed if record.get("name") == workflow]
    same_workflow = [
        record for record in same_workflow if str(record.get("id")) != str(target.get("id"))
    ]
    selected = [target] + same_workflow
    omitted = 0
    if len(selected) > max_runs:
        omitted = len(selected) - max_runs
        selected = selected[:max_runs]
    return selected, omitted


def collect(repo, token, run_id, out_dir, reporter=None):
    """Writes the run and job records of the target run and of its UTC day.

    The day view covers the runs of the target run's own workflow, so the
    collection stays small enough to be cheap and complete. The target run is
    always collected, even when the day holds more runs than the collector
    keeps, because a report without its own run cannot say what it measured.
    """
    target = api_get(f"/repos/{repo}/actions/runs/{run_id}", token)
    target_record = run_record(target)
    started = parse_timestamp(target_record["run_started_at"]) or parse_timestamp(
        target_record["created_at"]
    )
    if started is None:
        raise SystemExit("the target run has no usable start timestamp")
    day_start = started.replace(hour=0, minute=0, second=0, microsecond=0)
    workflow = target_record["workflow"]
    listed, truncated = list_runs(repo, token, day_start)
    selected, omitted = select_runs(target, listed, workflow, MAX_RUNS)
    runs = [run_record(record) for record in selected]
    jobs = []
    for record in selected:
        jobs.extend(list_jobs(repo, token, record.get("id"), record.get("name")))
    if reporter and not any(
        job.get("name") == reporter and str(job.get("run_id")) == str(run_id) for job in jobs
    ):
        print(f"the reporting job {reporter!r} is not among the run's jobs", file=sys.stderr)
        reporter = None
    out_path = Path(out_dir)
    write_jsonl(out_path / "runs.jsonl", runs)
    write_jsonl(out_path / "jobs.jsonl", jobs)
    write_json(
        out_path / "collection.json",
        {
            "collected_at": format_timestamp(datetime.now(timezone.utc)),
            "day": day_start.date().isoformat(),
            "workflow": workflow,
            "reporter_job": reporter,
            "runs_selected": len(runs),
            "runs_omitted": omitted,
            "run_list_truncated": truncated,
        },
    )
    if omitted:
        print(f"{omitted} run(s) of the day were not collected", file=sys.stderr)
    if truncated:
        print("the run list was truncated at the page limit", file=sys.stderr)
    return out_path


def report(runs_path, jobs_path, run_id, out_path, captured_at, collection_path=None):
    """Builds the report and writes it."""
    runs = load_jsonl(runs_path)
    jobs = load_jsonl(jobs_path)
    collection = None
    if collection_path and Path(collection_path).exists():
        collection = json.loads(Path(collection_path).read_text(encoding="utf-8"))
    payload = build_report(runs, jobs, run_id, captured_at, collection)
    write_json(out_path, payload)
    print(format_report(payload))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    collect_parser = commands.add_parser("collect", help="write the run and job records")
    collect_parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    collect_parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", ""))
    collect_parser.add_argument("--out-dir", required=True)
    collect_parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    collect_parser.add_argument("--reporter", default=os.environ.get("QPX_REPORTER_JOB", ""))

    report_parser = commands.add_parser("report", help="write the runner-minute report")
    report_parser.add_argument("--runs", required=True)
    report_parser.add_argument("--jobs", required=True)
    report_parser.add_argument("--run-id", required=True)
    report_parser.add_argument("--out", required=True)
    report_parser.add_argument("--captured-at", default="")
    report_parser.add_argument("--collection", default="")

    args = parser.parse_args(argv)
    if args.command == "collect":
        if not args.repo or not args.run_id or not args.token:
            raise SystemExit("collect needs a repository, a run identifier, and a token")
        collect(args.repo, args.token, args.run_id, args.out_dir, args.reporter or None)
        return 0
    captured = parse_timestamp(args.captured_at) or datetime.now(timezone.utc)
    report(args.runs, args.jobs, args.run_id, args.out, captured, args.collection or None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
