"""Runner-minute accounting for CI runs.

Runner-minutes are the summed wall-clock time each completed job occupied a
runner. That sum is not the run's elapsed time: jobs run in parallel, so the
sum is the larger number and the elapsed span is the smaller one. The queue
delay before the first job starts is a third quantity again. Every number in a
report therefore carries its own name, and a report whose totals are
incomplete says which records are missing instead of quietly reporting less.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

MINUTES_PER_SECOND = 60.0


def parse_timestamp(value):
    """Parses an API timestamp into an aware UTC datetime, or None."""
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_timestamp(moment):
    """Formats an aware datetime the way the API writes timestamps."""
    if moment is None:
        return None
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_jsonl(path):
    """Reads a JSONL file into a list of records."""
    records = []
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def write_jsonl(path, records):
    """Writes records as JSONL, one object per line."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


def write_json(path, payload):
    """Writes one JSON object."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def job_interval(record):
    """The runner time a job consumed, or None when it has no usable interval."""
    started = parse_timestamp(record.get("started_at"))
    completed = parse_timestamp(record.get("completed_at"))
    if started is None or completed is None or completed < started:
        return None
    return (completed - started).total_seconds() / MINUTES_PER_SECOND


def job_day(record):
    """The UTC day a job started on, or None when it has no start timestamp."""
    started = parse_timestamp(record.get("started_at"))
    return None if started is None else started.date().isoformat()


def summarize_jobs(records, run_starts=None, reporter=None):
    """Sums the runner time of job records and reports what it could not count.

    `run_starts` maps a run identifier to the moment that run started, which
    is what the queue delay is measured against. `reporter` is the name and
    the run identifier of the job that writes the report: it is running while
    it reports, so it is counted separately and never makes the total
    partial. Only that one job is exempt - another run's job of the same
    name is ordinary unfinished work, and the workflow runs more than one
    push and pull-request run at a time.
    """
    run_starts = run_starts or {}
    reporter_name, reporter_run = reporter if reporter else (None, None)
    minutes = 0.0
    counted = 0
    unfinished = 0
    reporter_unfinished = 0
    skipped = 0
    failed = 0
    missing = 0
    earliest = None
    latest = None
    queue_max = 0.0
    for record in records:
        status = str(record.get("status") or "").lower()
        conclusion = str(record.get("conclusion") or "").lower()
        if status and status != "completed":
            if (
                reporter_name
                and record.get("name") == reporter_name
                and str(record.get("run_id")) == str(reporter_run)
            ):
                reporter_unfinished += 1
            else:
                unfinished += 1
            continue
        if conclusion == "skipped":
            skipped += 1
            continue
        interval = job_interval(record)
        if interval is None:
            missing += 1
            continue
        counted += 1
        minutes += interval
        if conclusion == "failure":
            failed += 1
        started = parse_timestamp(record.get("started_at"))
        completed = parse_timestamp(record.get("completed_at"))
        if earliest is None or started < earliest:
            earliest = started
        if latest is None or completed > latest:
            latest = completed
        reference = run_starts.get(str(record.get("run_id")))
        if reference is not None and started >= reference:
            queue_max = max(queue_max, (started - reference).total_seconds() / MINUTES_PER_SECOND)
    reasons = []
    if unfinished:
        reasons.append(f"{unfinished} job(s) are still queued or running")
    if missing:
        reasons.append(f"{missing} job(s) have no usable start or completion timestamp")
    elapsed = None
    if earliest is not None and latest is not None:
        elapsed = (latest - earliest).total_seconds() / MINUTES_PER_SECOND
    return {
        "runner_minutes": round(minutes, 2),
        "jobs_total": len(records),
        "jobs_counted": counted,
        "jobs_unfinished": unfinished,
        "jobs_reporter_unfinished": reporter_unfinished,
        "jobs_skipped": skipped,
        "jobs_failed": failed,
        "jobs_without_timestamps": missing,
        "elapsed_minutes": None if elapsed is None else round(elapsed, 2),
        "queue_delay_minutes_max": round(queue_max, 2),
        "partial": bool(unfinished or missing),
        "partial_reasons": reasons,
    }


def summarize_day(day, records, run_starts=None, reporter=None):
    """Sums the runner time of the jobs that started on one UTC day."""
    summary = summarize_jobs(records, run_starts, reporter)
    summary["day"] = day
    summary["timezone"] = "UTC"
    return summary


def run_start_map(runs):
    """Maps a run identifier to the moment that run started."""
    starts = {}
    for record in runs:
        started = parse_timestamp(record.get("run_started_at")) or parse_timestamp(
            record.get("created_at")
        )
        if started is not None:
            starts[str(record.get("run_id"))] = started
    return starts


def build_report(runs, jobs, run_id, captured_at, collection=None):
    """Builds the report for one run and for the UTC day that run started on.

    `collection` is the note the collector wrote about the records it read. A
    collection that left runs out says so in the day's total rather than
    reporting a smaller number as if it were the whole day.
    """
    run_id = str(run_id)
    run = next((record for record in runs if str(record.get("run_id")) == run_id), None)
    run_jobs = [record for record in jobs if str(record.get("run_id")) == run_id]
    starts = run_start_map(runs)
    reporter_name = (collection or {}).get("reporter_job")
    reporter = (reporter_name, run_id) if reporter_name else None
    run_summary = summarize_jobs(run_jobs, starts, reporter)
    if run is None:
        # The run's records were not collected, so nothing about its cost is
        # known. A missing run must never read as a run that cost nothing.
        run_summary["partial"] = True
        run_summary["partial_reasons"] = run_summary["partial_reasons"] + [
            "the run's records were not collected"
        ]
    reference = parse_timestamp((run or {}).get("run_started_at")) or parse_timestamp(
        (run or {}).get("created_at")
    ) or captured_at
    day = reference.date().isoformat()
    day_jobs = [record for record in jobs if job_day(record) == day]
    day_summary = summarize_day(day, day_jobs, starts, reporter)
    day_run_ids = {str(job.get("run_id")) for job in day_jobs}
    day_runs = {str(record.get("run_id")) for record in runs if str(record.get("run_id")) in day_run_ids}
    selected_runs = {str(record.get("run_id")) for record in runs}
    day_summary["runs_total"] = len(selected_runs)
    day_summary["runs_counted"] = len(day_runs)
    if day_summary["runs_counted"] < day_summary["runs_total"]:
        day_summary["partial"] = True
        day_summary["partial_reasons"] = day_summary["partial_reasons"] + [
            f"{day_summary['runs_total'] - day_summary['runs_counted']} selected run(s) "
            "have no counted job yet"
        ]
    omitted = int((collection or {}).get("runs_omitted") or 0)
    if omitted:
        day_summary["partial"] = True
        day_summary["partial_reasons"] = day_summary["partial_reasons"] + [
            f"{omitted} run(s) of the day were not collected"
        ]
    breakdown = []
    for record in runs:
        record_id = str(record.get("run_id"))
        summary = summarize_jobs(
            [job for job in jobs if str(job.get("run_id")) == record_id],
            starts,
            reporter if record_id == run_id else None,
        )
        breakdown.append(
            {
                "run_id": record_id,
                "workflow": record.get("workflow"),
                "head_sha": record.get("head_sha"),
                "runner_minutes": summary["runner_minutes"],
                "jobs_counted": summary["jobs_counted"],
                "jobs_total": summary["jobs_total"],
                "partial": summary["partial"],
            }
        )
    return {
        "captured_at": format_timestamp(captured_at),
        "head_sha": (run or {}).get("head_sha"),
        "workflow": (run or {}).get("workflow"),
        "run_id": run_id,
        "run_conclusion": (run or {}).get("conclusion"),
        "reporter_job": reporter_name,
        "run": run_summary,
        "day": day_summary,
        "runs": breakdown,
    }


def format_report(report):
    """Renders a report as short human-readable lines."""
    run = report["run"]
    day = report["day"]
    elapsed = run["elapsed_minutes"]
    lines = [
        f"run {report['run_id']} sha {report['head_sha']} captured {report['captured_at']}",
        f"runner minutes {run['runner_minutes']:.2f} "
        f"({run['jobs_counted']}/{run['jobs_total']} jobs counted)",
        f"elapsed minutes {'unknown' if elapsed is None else elapsed} "
        f"queue delay minutes {run['queue_delay_minutes_max']}",
        f"day {day['day']} runner minutes {day['runner_minutes']:.2f} "
        f"({day['runs_counted']}/{day['runs_total']} runs)",
    ]
    if report.get("reporter_job"):
        lines.append(f"the reporting job {report['reporter_job']} is not in the run total")
    for reason in run["partial_reasons"]:
        lines.append(f"run total is partial: {reason}")
    for reason in day["partial_reasons"]:
        lines.append(f"day total is partial: {reason}")
    return "\n".join(lines)
